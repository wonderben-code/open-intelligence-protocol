// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Finding minds by what they can do (Layer 1, Section 18).
 *
 * An indexer's answer is advice from a stranger. It names records, and does
 * not carry them. Each record it names is fetched from where its author is
 * served and verified as its author's own before the client returns it
 * (18.4). What an indexer named that does not check out is told, with why,
 * and not returned.
 */

import { canonicalize, OipError, utf8 } from "@oip/core";
import { type JudgedRecord, judgeRecord, ownSignedTime, witnessRecord } from "@oip/identity";
import { verifyParticipant } from "@oip/net";
import {
  type Capability,
  type CapabilityQuery,
  type Intent,
  type Offer,
  type Participant,
  type QueryResult,
  validateRecordOfType,
} from "@oip/schema";

import { accepted } from "./accepted.ts";
import type { Clock, Lookup } from "./lookup.ts";
import { askRecord, TransportError, type TransportOptions } from "./transport.ts";

/** A record an indexer lists: a profile, an Offer or an Intent. */
export type Listed = Participant | Offer | Intent;

/** Something a query found: a record, fetched and verified as its author's own. */
export interface Found {
  /** The mind the record is of. */
  readonly mind: string;
  /** The record's content ID. */
  readonly id: string;
  /** The record. */
  readonly record: Listed;
  /** The capability of a profile that an indexer named, as the profile has it. */
  readonly capability?: Capability;
  /**
   * Whether a profile is the mind's current one (Layer 1, 16.4): the one its
   * current location record names. An indexer may list one the mind has
   * since replaced. `true` for a record that is no profile.
   */
  readonly current: boolean;
  /** The indexers that named it, each with its own ranking, in the order the client names them. */
  readonly by: readonly Ranking[];
}

/** What one indexer said of a record it named. Ranking is the indexer's own policy (18.4). */
export interface Ranking {
  /** The indexer's origin. */
  readonly indexer: string;
  /** Its score, a decimal string from "0" to "1". Scores of two indexers do not compare. */
  readonly score: string;
  /** Its reason, in its own words. They are a stranger's words. */
  readonly why?: string;
}

/** A record an indexer named that the client does not return. */
export interface NotFound {
  /** The indexer's origin. */
  readonly indexer: string;
  /** The mind it named. */
  readonly mind: string;
  /** The content ID it named. */
  readonly record: string;
  /** Why: the code of a problem (core 10.2), or the failure of the transport. */
  readonly failure: string;
}

/** What one indexer answered to a query. */
export interface IndexerAnswer {
  /** The indexer's origin. */
  readonly indexer: string;
  /** The mind that signed the answer, if the answer was the indexer's own. */
  readonly mind?: string;
  /** How many results it gave, or `undefined` if its answer was not taken. */
  readonly results: number | undefined;
  /** Why its answer was not taken. */
  readonly failure?: string;
}

/** What a query found. */
export interface Finding {
  /** The records found, each verified: by indexer as the client names them, then by rank. */
  readonly found: readonly Found[];
  /** What was named and is not returned. */
  readonly refused: readonly NotFound[];
  /** What each indexer answered. */
  readonly sources: readonly IndexerAnswer[];
}

/** What finding needs. */
export interface Finder {
  readonly lookup: Lookup;
  readonly transport: TransportOptions;
  readonly clock: Clock;
  /** The indexers asked, as HTTPS origins. */
  readonly indexers: readonly string[];
}

/** The most results of one indexer that are looked at, whatever it sends (18.2). */
export const MAX_RESULTS = 100;
/** The results of a query that says no `limit` (18.2). */
const DEFAULT_LIMIT = 20;
/** How many records are fetched and judged at once. */
const AT_ONCE = 8;

type Failure = OipError | TransportError;
const codeOf = (failure: Failure): string =>
  failure instanceof OipError ? failure.code : failure.failure;

/** An indexer's results as taken, or why they were not. */
type Asked =
  | { indexer: string; mind: string; results: QueryResult["results"] }
  | { indexer: string; failure: Failure };

/** Whether a tag of a capability is one a query asks for (18.2). */
function carries(tags: readonly string[], asked: string): boolean {
  return asked.endsWith("/*")
    ? tags.some((tag) => tag.startsWith(asked.slice(0, -1)))
    : tags.includes(asked);
}

/** Runs `work` for each item, a few at a time, and gives the answers in the items' order. */
async function each<T, R>(items: readonly T[], work: (item: T) => Promise<R>): Promise<R[]> {
  const answers = new Array<R>(items.length);
  const waiting = [...items.entries()];
  const worker = async (): Promise<void> => {
    for (let next = waiting.shift(); next !== undefined; next = waiting.shift()) {
      answers[next[0]] = await work(next[1]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(AT_ONCE, items.length) }, worker));
  return answers;
}

/** A record an indexer named: the mind, the content ID, and the capability if it named one. */
interface Named {
  readonly key: string;
  readonly mind: string;
  readonly record: string;
  readonly capability?: string;
}

const keyOf = (result: QueryResult["results"][number]): string =>
  `${result.mind}\n${result.record}\n${result.capability ?? ""}`;

/**
 * Asks the indexers a capability query, and fetches and verifies what they
 * name: see `Lookup.find`.
 */
export async function find(finder: Finder, query: CapabilityQuery): Promise<Finding> {
  const asked = await Promise.all(finder.indexers.map((indexer) => ask(finder, indexer, query)));
  // Each record once, however many indexers named it, in the order it was first named.
  const named = new Map<string, Named>();
  for (const answer of asked) {
    for (const result of "results" in answer ? answer.results : []) {
      const key = keyOf(result);
      if (named.has(key)) continue;
      named.set(key, {
        key,
        mind: result.mind,
        record: result.record,
        ...(result.capability === undefined ? {} : { capability: result.capability }),
      });
    }
  }
  const checked = await each([...named.values()], async (item) => {
    try {
      return { item, outcome: await check(finder, query, item) };
    } catch (error) {
      if (error instanceof OipError || error instanceof TransportError) {
        return { item, failure: error };
      }
      throw error;
    }
  });
  const found: Found[] = [];
  const refused: NotFound[] = [];
  for (const { item, ...judged } of checked) {
    const by: Ranking[] = [];
    for (const answer of asked) {
      const result =
        "results" in answer ? answer.results.find((given) => keyOf(given) === item.key) : undefined;
      if (result === undefined) continue;
      if ("failure" in judged) {
        refused.push({
          indexer: answer.indexer,
          mind: item.mind,
          record: item.record,
          failure: codeOf(judged.failure),
        });
      } else {
        by.push({
          indexer: answer.indexer,
          score: result.score,
          ...(result.why === undefined ? {} : { why: result.why }),
        });
      }
    }
    if ("outcome" in judged) found.push({ ...judged.outcome, by });
  }
  return {
    found,
    refused,
    sources: asked.map((answer) =>
      "results" in answer
        ? { indexer: answer.indexer, mind: answer.mind, results: answer.results.length }
        : { indexer: answer.indexer, results: undefined, failure: codeOf(answer.failure) },
    ),
  };
}

/**
 * Asks one indexer, and takes its answer if it is the indexer's own: a
 * `QueryResult` to this query, signed by a mind the client can resolve.
 */
async function ask(finder: Finder, indexer: string, query: CapabilityQuery): Promise<Asked> {
  try {
    const record = await askRecord(
      {
        method: "POST",
        url: `${indexer}/oip/v1/query`,
        body: { bytes: utf8(JSON.stringify(query)), mediaType: "application/json" },
      },
      finder.transport,
    );
    const judged = accepted(
      judgeRecord(record),
      "invalid-record",
      `${indexer} answered what is no record`,
    );
    const result = accepted(
      validateRecordOfType("QueryResult", judged.record),
      "invalid-record",
      `${indexer} answered what is no result of a query`,
    );
    if (canonicalize(result.query) !== canonicalize(query)) {
      throw new OipError("invalid-record", `${indexer} answered another query than was asked`, {
        clause: "L1 18.3",
      });
    }
    // First seen now, and judged by the indexer's log as it stands no earlier (core 9.4).
    witnessRecord(judged, finder.clock.now(), finder.lookup.seen);
    await finder.lookup.resolve(result.author);
    if (ownSignedTime(judged, result.author, finder.lookup.view) === undefined) {
      throw new OipError("invalid-proof", `${indexer} answered what its author did not sign`, {
        clause: "L1 18.3",
      });
    }
    const most = Math.min(query.limit ?? DEFAULT_LIMIT, MAX_RESULTS);
    return { indexer, mind: result.author, results: result.results.slice(0, Math.max(most, 0)) };
  } catch (error) {
    if (error instanceof OipError || error instanceof TransportError) {
      return { indexer, failure: error };
    }
    throw error;
  }
}

/**
 * Fetches a record an indexer named and verifies it: it is of a kind the
 * query asks for, it is its author's own, it has not expired, and it is what
 * the query's tags ask for where the client can tell.
 *
 * @throws OipError or TransportError if it is not to be had, or does not check out.
 */
async function check(
  finder: Finder,
  query: CapabilityQuery,
  { mind, record: id, capability }: Named,
): Promise<Omit<Found, "by">> {
  const { lookup } = finder;
  const resolved = await lookup.resolve(mind);
  const kinds: readonly string[] = query.kinds ?? ["Participant"];
  let record: Listed;
  let current = true;
  if (resolved.participant?.id === id) {
    // The mind's current profile, which came verified with its log.
    record = resolved.participant.record;
  } else {
    const judged = await lookup.record(mind, id);
    // Judged by the log as it stands no earlier than the record was first seen (core 9.4).
    await lookup.resolve(mind);
    record = own(judged, mind, lookup, finder.clock);
    current = record.type !== "Participant";
  }
  if (!kinds.includes(record.type)) {
    throw new OipError(
      "invalid-record",
      `the record is a ${record.type}, which was not asked for`,
      {
        clause: "L1 18.2",
      },
    );
  }
  const capabilities = record.type === "Participant" ? (record.capabilities ?? []) : [];
  const named = capabilities.find((candidate) => candidate.id === capability);
  if (capability !== undefined && named === undefined) {
    throw new OipError("invalid-record", "the record has no capability of the name given", {
      clause: "L1 18.3",
    });
  }
  // The tags of a query are on the capabilities of profiles (18.2): a result carries every one.
  if (record.type === "Participant") {
    const among = named === undefined ? capabilities : [named];
    const carried = (query.tags ?? []).every((tag) =>
      among.some((candidate) => carries(candidate.tags ?? [], tag)),
    );
    if (!carried) {
      throw new OipError("invalid-record", "the profile does not carry the tags asked for", {
        clause: "L1 18.2",
      });
    }
  }
  return { mind, id, record, ...(named === undefined ? {} : { capability: named }), current };
}

/** A record that was fetched, as its author's own: or why it is not. */
function own(judged: JudgedRecord, mind: string, lookup: Lookup, clock: Clock): Listed {
  const { record } = judged;
  if (record.type !== "Participant" && record.type !== "Offer" && record.type !== "Intent") {
    throw new OipError("invalid-record", "the record is of no kind an indexer lists", {
      clause: "L1 18.1",
    });
  }
  const listed = record as Listed;
  if (listed.author !== mind) {
    throw new OipError("invalid-proof", "the record is another mind's than the one named", {
      clause: "L1 18.1",
    });
  }
  if (listed.type === "Participant") {
    accepted(verifyParticipant(judged, lookup.view), "invalid-proof", "the profile does not count");
    return listed;
  }
  if (ownSignedTime(judged, mind, lookup.view) === undefined) {
    throw new OipError("invalid-proof", "the record is not signed by its author's own authority", {
      clause: "L1 18.1",
    });
  }
  if (judged.expires !== undefined && judged.expires <= clock.now()) {
    throw new OipError("expired", "the record has expired", { clause: "core 2.4" });
  }
  return listed;
}
