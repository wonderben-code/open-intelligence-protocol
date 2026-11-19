// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * An indexer (Layer 1, Section 18): what minds publish of themselves, made
 * findable by a capability query, and each answer signed.
 *
 * - **Submission** (18.1). A `Bundle` brings a mind's log, and its current
 *   profile with it. A `Participant`, an `Offer` or an `Intent` is listed if
 *   its author's own authority signed it, by a log the indexer holds. What
 *   does not verify is not listed, and nothing is kept of it.
 * - **Query** (18.2, 18.3). The words of `want` are matched against the text
 *   of what is listed and ranked by SQLite's FTS5; `tags` must all match.
 *   The answer is a `QueryResult` the indexer signs.
 *
 * An indexer does not say that a record still stands: an Offer may have
 * been taken up, a profile replaced elsewhere. A client fetches and
 * verifies what a result names before it acts on it (18.4).
 */

import {
  contentId,
  createProofSync,
  formatKeyRef,
  formatTimestamp,
  type Instant,
  type JsonObject,
  mindId,
  OipError,
  type SyncSigner,
  withProofs,
} from "@oip/core";
import {
  type JudgedRecord,
  judgeRecord,
  latestState,
  ownSignedTime,
  witnessRecord,
} from "@oip/identity";
import { verifyParticipant } from "@oip/net";
import {
  type Bundle,
  type CapabilityQuery,
  type Participant,
  type Proof,
  type QueryResult,
  validateRecord,
  validateRecordOfType,
} from "@oip/schema";
import {
  type Clock,
  type Database,
  type LogArchive,
  overlaid,
  publicationProblem,
  seenAt,
  standing,
} from "@oip/server";

import { type Found, IndexStore, type Item, type Kind } from "./store.ts";

/** How much an indexer lists for one mind, and how much of a query it reads. */
export interface IndexerLimits {
  /** The most Offers listed for one mind. */
  readonly offers: number;
  /** The most Intents listed for one mind. */
  readonly intents: number;
  /** The most tags a query may ask for. */
  readonly queryTags: number;
  /** The most words of a query's `want` that are matched. */
  readonly queryWords: number;
}

/** A thousand Offers and a thousand Intents for a mind; sixteen tags and thirty-two words in a query. */
export const DEFAULT_INDEXER_LIMITS: IndexerLimits = {
  offers: 1000,
  intents: 1000,
  queryTags: 16,
  queryWords: 32,
};

/** How an indexer is made. */
export interface IndexerOptions {
  /** Its database, opened with `INDEXER_MIGRATIONS`. */
  readonly db: Database;
  /** The identity logs it holds, its own among them, and its record of first sight. */
  readonly archive: LogArchive;
  readonly clock: Clock;
  /** The indexer's own address: the author of what it signs. */
  readonly address: string;
  /** An operational key of the indexer's own mind. */
  readonly signer: SyncSigner;
  readonly limits?: Partial<IndexerLimits>;
}

/** What became of the records of one submission. */
export interface Submission {
  /** How many were taken: listed, merged, or held already. */
  readonly taken: number;
  /** Those that were not, each by its place in the submission, with the problem (core 10.2). */
  readonly refused: readonly {
    readonly index: number;
    readonly type: string;
    readonly detail: string;
  }[];
}

const KINDS: readonly Kind[] = ["Participant", "Offer", "Intent"];

/** The words of a text, as a query matches them: letters and digits, in lower case, each once. */
function wordsOf(text: string, most: number): string[] {
  const words = text.toLowerCase().match(/[\p{L}\p{N}]+/gu) ?? [];
  return [...new Set(words)].slice(0, most);
}

/**
 * A score from a place in the ranking: 1 for the first of `of`, and less
 * for each after it, in thousandths. A decimal string, worked out in whole
 * numbers: a record carries no float (core 1.3).
 */
function scoreAt(place: number, of: number): string {
  const thousandths = Math.floor((1000 * (of - place)) / of);
  if (thousandths >= 1000) return "1";
  return `0.${String(thousandths).padStart(3, "0").replace(/0+$/u, "")}`;
}

/** An indexer. */
export class Indexer {
  readonly #db: Database;
  readonly #archive: LogArchive;
  readonly #clock: Clock;
  readonly #store: IndexStore;
  readonly #limits: IndexerLimits;
  readonly #address: string;
  readonly #signer: SyncSigner;
  /** A proof of the indexer's own, by which a draft is checked for its form before anything is searched. */
  readonly #form: Proof;

  /**
   * @throws TypeError if the archive holds no log of the indexer's own mind
   *   that verifies, or the key is no operational key of its latest state.
   */
  constructor(options: IndexerOptions) {
    this.#db = options.db;
    this.#archive = options.archive;
    this.#clock = options.clock;
    this.#store = new IndexStore(options.db);
    this.#limits = { ...DEFAULT_INDEXER_LIMITS, ...options.limits };
    this.#address = options.address;
    this.#signer = options.signer;
    const now = this.#clock.now();
    const draft = this.#draft({}, [], now);
    this.#form = createProofSync(draft, this.#method(now), this.#signer);
  }

  /** The indexer's own address. */
  get address(): string {
    return this.#address;
  }

  /** What the indexer signs with now: a key of the latest state of its own log. */
  #method(now: Instant): { verificationMethod: string; created: string } {
    const log = this.#archive.view(now).log(this.#address);
    if (!log.ok) throw new TypeError("the indexer holds no log of its own mind that verifies");
    const state = latestState(log.value);
    if (!state.keys.includes(this.#signer.publicKey)) {
      throw new TypeError("the indexer's key is no operational key of its own mind now");
    }
    return {
      verificationMethod: formatKeyRef(this.#address, state.versionId, this.#signer.publicKey),
      created: formatTimestamp(now),
    };
  }

  #draft(query: unknown, results: QueryResult["results"], now: Instant): JsonObject {
    return {
      oip: "1",
      type: "QueryResult",
      author: this.#address,
      created: formatTimestamp(now),
      query: query as JsonObject,
      results: results,
    };
  }

  /**
   * Layer 1, 18.1: takes in records that were submitted.
   *
   * Each is judged by itself, in the order given, so a `Bundle` that brings
   * a mind's log may be followed by the mind's records. One that is refused
   * stops none of the others.
   *
   * @throws Unavailable if a record could not be judged just now. Those
   *   before it were taken: submitting again takes the rest.
   */
  submit(records: readonly unknown[]): Submission {
    let taken = 0;
    const refused: { index: number; type: string; detail: string }[] = [];
    for (const [index, value] of records.entries()) {
      try {
        this.#take(value);
        taken++;
      } catch (error) {
        if (!(error instanceof OipError)) throw error;
        const problem = error.toProblem();
        refused.push({ index, type: problem.type, detail: problem.detail ?? problem.title });
      }
    }
    return { taken, refused };
  }

  /** One submitted record. @throws OipError where it is not taken. */
  #take(value: unknown): void {
    const formed = standing(() => validateRecord(value));
    if (!formed.ok) {
      const [first] = formed.issues;
      throw new OipError("invalid-record", first.message, {
        clause: first.clause,
        issues: formed.issues,
      });
    }
    const record = formed.value;
    if (record.type === "Bundle") {
      this.#bundle(record);
      return;
    }
    if (!KINDS.includes(record.type as Kind)) {
      throw new OipError(
        "invalid-record",
        "an indexer takes a Bundle, a Participant, an Offer or an Intent",
        { clause: "L1 18.1" },
      );
    }
    this.#archive.witnessing((seen, now) => {
      const judged = this.#own(value, now);
      this.#list(judged, now);
      witnessRecord(judged, now, seen);
    });
  }

  /** A bundle: the mind's log, and its current profile if it brings one. */
  #bundle(bundle: Bundle): void {
    const id = mindId(bundle.mind);
    if (id === undefined) throw new OipError("invalid-record", "the bundle names no mind");
    const problem = publicationProblem(this.#archive.publish(id, bundle));
    if (problem !== undefined) throw problem;
    // The profile the archive now serves for the mind: the one its location record names.
    const profile = this.#archive.resolve(id)?.participant;
    if (profile === undefined) return;
    this.#archive.witnessing((_seen, now) => {
      this.#list(this.#own(profile, now), now);
    });
  }

  /**
   * A record as it was judged, if its author's own authority signed it, by
   * the log the indexer holds, judged as first seen now.
   */
  #own(value: unknown, now: Instant): JudgedRecord {
    const judged = standing(() => judgeRecord(value));
    if (!judged.ok) {
      const [first] = judged.issues;
      throw new OipError("invalid-record", first.message, {
        clause: first.clause,
        issues: judged.issues,
      });
    }
    const { author } = judged.value.record as { author?: unknown };
    const view = this.#archive.view(now);
    if (typeof author !== "string" || !view.log(author).ok) {
      throw new OipError(
        "stale-version",
        "the indexer holds no log of the record's author that verifies: submit the author's Bundle first",
        { clause: "L1 18.1" },
      );
    }
    // Said before its signature is weighed: a proof on a record long expired counts for
    // nothing (core 9.6), and that is not the author's signature being wrong.
    if (judged.value.expires !== undefined && judged.value.expires < now) {
      throw new OipError("expired", "the record has expired");
    }
    const digests = new Set(judged.value.proofs.map((proof) => proof.digest));
    const own = overlaid(view, seenAt(digests, now));
    const counts =
      judged.value.record.type === "Participant"
        ? standing(() => verifyParticipant(judged.value, own)).ok
        : standing(() => ownSignedTime(judged.value, author, own)) !== undefined;
    if (!counts) {
      throw new OipError(
        "invalid-proof",
        "the record is not signed by its author's own authority, or is no profile of its author",
        { clause: judged.value.record.type === "Participant" ? "L1 16.1" : "L1 6.1" },
      );
    }
    return judged.value;
  }

  /** Lists a record that counts for its author, in place of what it replaces. */
  #list(judged: JudgedRecord, now: Instant): void {
    const record = judged.record as unknown as {
      type: Kind;
      author: string;
      supersedes?: string;
      status?: string;
      audience?: unknown;
    };
    const id = contentId(judged.record);
    const mind = record.author;
    if (this.#store.holderOf(id) === mind) return;
    const common = {
      mind,
      record: id,
      kind: record.type,
      ...(judged.expires === undefined ? {} : { expires: judged.expires }),
    };
    if (record.type === "Participant") {
      const profile = judged.record as unknown as Participant;
      // One profile is listed for a mind: the one brought last.
      this.#store.removeProfile(mind);
      this.#store.add(
        { ...common, text: [profile.name, profile.summary ?? ""].join("\n"), tags: [] },
        now,
      );
      for (const capability of profile.capabilities ?? []) {
        const item: Item = {
          ...common,
          capability: capability.id,
          text: [capability.id, capability.summary, capability.subject ?? ""].join("\n"),
          tags: capability.tags ?? [],
        };
        this.#store.add(item, now);
      }
      return;
    }
    if (record.audience !== undefined && record.audience !== "public") {
      throw new OipError(
        "forbidden",
        "the record is not for everyone: an indexer lists what is public",
        {
          clause: "L2 4.1",
        },
      );
    }
    // What it supersedes is no longer listed, if it was its author's. A record that
    // states a status closes the one before it, and is not listed itself (Layer 2, 2).
    const before = record.supersedes?.slice(record.supersedes.lastIndexOf("/") + 1);
    if (before !== undefined && this.#store.holderOf(before) === mind) {
      this.#store.removeRecord(before);
    }
    if (record.status !== undefined) return;
    const most = record.type === "Offer" ? this.#limits.offers : this.#limits.intents;
    if (this.#store.records(mind, record.type) >= most) {
      throw new OipError(
        "rate-limited",
        `as many ${record.type}s of this mind are listed as the indexer lists for one`,
      );
    }
    const said = judged.record as unknown as {
      want?: string;
      provides?: string;
      terms?: { summary?: string };
      capability?: string;
    };
    this.#store.add(
      {
        ...common,
        ...(said.capability === undefined ? {} : { capability: said.capability }),
        text: [said.want ?? "", said.provides ?? "", said.terms?.summary ?? ""].join("\n"),
        tags: [],
      },
      now,
    );
  }

  /**
   * What a query finds, best first.
   *
   * @param query - A capability query that is well formed.
   * @param limit - The most to find. The query's own `limit` by default, and 20 if it has none.
   */
  #find(query: CapabilityQuery, now: Instant, limit = query.limit ?? 20): Found[] {
    const tags = query.tags ?? [];
    if (tags.length > this.#limits.queryTags) {
      throw new OipError(
        "invalid-record",
        `a query asks for at most ${this.#limits.queryTags} tags here`,
        {
          clause: "L1 18.2",
        },
      );
    }
    // An indexer claims no match it did not check. This one checks no constraint and no
    // evidence, so a query that asks for either finds nothing.
    const unchecked = [query.constraints, query.evidence].some(
      (asked) => asked !== undefined && Object.keys(asked).length > 0,
    );
    if (unchecked) return [];
    const words = wordsOf(query.want ?? "", this.#limits.queryWords);
    return this.#store.search({
      // Each word between quotes is a word to FTS5, and nothing of its query language.
      ...(words.length === 0 ? {} : { match: words.map((word) => `"${word}"`).join(" OR ") }),
      kinds: [...new Set<Kind>(query.kinds ?? ["Participant"])],
      tags: tags.map((tag) =>
        tag.endsWith("/*")
          ? { value: tag.slice(0, -1), prefix: true }
          : { value: tag, prefix: false },
      ),
      now,
      limit: Math.min(limit, 100),
    });
  }

  /** A query that is well formed (18.2). @throws OipError `invalid-record` if it is not. */
  #asked(query: unknown, now: Instant): CapabilityQuery {
    const draft = { ...this.#draft(query, [], now), proof: [this.#form] };
    const formed = standing(() => validateRecordOfType("QueryResult", draft));
    if (!formed.ok) {
      const [first] = formed.issues;
      throw new OipError("invalid-record", `the query is not well formed: ${first.message}`, {
        clause: "L1 18.2",
        issues: formed.issues,
      });
    }
    return formed.value.query;
  }

  /**
   * Layer 1, 18.2, 18.3: answers a capability query.
   *
   * @param query - The query, as it was parsed.
   * @returns A `QueryResult`, signed by the indexer.
   * @throws OipError `invalid-record` if the query is not well formed.
   */
  query(query: unknown): QueryResult {
    const now = this.#clock.now();
    const asked = this.#asked(query, now);
    const found = this.#find(asked, now);
    const view = this.#archive.view(now);
    const results = found.map((item, place) => {
      const log = view.log(item.mind);
      const homes = log.ok ? latestState(log.value).homes : [];
      const id = mindId(item.mind) ?? "";
      return {
        mind: item.mind,
        record: item.record,
        ...(item.capability === null ? {} : { capability: item.capability }),
        score: scoreAt(place, found.length),
        // Where the record's author is served, by its own log: the client fetches there.
        ...(homes.length === 0
          ? {}
          : { hints: homes.map((home) => `${home}/.well-known/oip/mind/${id}`) }),
      };
    });
    const draft = this.#draft(asked, results, now);
    const proof = createProofSync(draft, this.#method(now), this.#signer);
    return withProofs(draft, [proof]) as unknown as QueryResult;
  }

  /**
   * Layer 1, 18.5: the minds a query matches, best first, each once, for a
   * broker that forwards a packet to them.
   *
   * @param query - A capability query that is well formed: a packet's `to.query`.
   */
  matching(query: CapabilityQuery, most: number): string[] {
    const found = this.#find(query, this.#clock.now(), 100);
    return [...new Set(found.map((item) => item.mind))].slice(0, most);
  }

  /** Takes out what has expired. An indexer calls it now and then. How many items went. */
  prune(now: Instant): number {
    return this.#db.transaction(() => this.#store.expire(now));
  }

  /** @internal The indexer's own tables, for its broker. */
  get store(): IndexStore {
    return this.#store;
  }
}
