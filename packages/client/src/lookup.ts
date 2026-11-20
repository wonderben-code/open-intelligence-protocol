// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What a client knows of other minds: their identity logs, as the resolvers
 * it trusts served them, and when each event was first seen.
 *
 * This is where the witness rule of core 9.4 is applied, once, for every
 * question a client asks about a key. Before a proof by a mind's key counts,
 * the verifier holds that mind's log as a witness it trusts served it, no
 * earlier than the proof was first seen, with the witness's own first-seen
 * times. A `Lookup` fetches the log afresh, takes the times, and holds both.
 *
 * It records no first sight of its own for an identity event. A client that
 * meets a log late must not date its events by its own late look: the former
 * holder of a removed key could then sign after the removal and be believed
 * (core 9.4).
 */

import {
  contentId,
  type Instant,
  mindId,
  OipError,
  type OipRecord,
  parseTimestamp,
  type ProblemCode,
  proofDigest,
} from "@oip/core";
import {
  type DidResolution,
  didDocument,
  earliestEvidence,
  FirstSeen,
  type IdentityState,
  type IdentityView,
  type JudgedRecord,
  judgeRecord,
  latestState,
  LogBook,
  type VerifiedLog,
  verifyLog,
  witnessRecord,
} from "@oip/identity";
import {
  currentLocation,
  type HeldLocation,
  type HeldParticipant,
  isStale,
  type VerifiedFeed,
  verifyFeed,
  verifyParticipant,
} from "@oip/net";
import { type Bundle, type Entry, validateRecordOfType, type Validation } from "@oip/schema";

import { askRecord, httpsOrigin, TransportError, type TransportOptions } from "./transport.ts";

/** The present: a reading of the clock, in nanoseconds since the epoch. */
export interface Clock {
  /** The time now. */
  now(): Instant;
}

/** The clock of the machine. */
export const systemClock: Clock = { now: () => BigInt(Date.now()) * 1_000_000n };

/** How far ahead of a verifier's clock a time may be and still be read (core 9.5). */
const SKEW = 300_000_000_000n;

/** What a `Lookup` takes. */
export interface LookupOptions extends TransportOptions {
  /**
   * The resolvers the client trusts as witnesses (Layer 1, Section 17), as
   * HTTPS origins: `https://resolver.example`. Their first-seen times are
   * taken as evidence of when an event existed (core 9.4). Choose more than
   * one, run by different people: a single resolver that serves a fork of a
   * log to one client is not found out by that client.
   */
  readonly resolvers: readonly string[];
  /** Default: the clock of the machine. */
  readonly clock?: Clock;
  /**
   * The most identity logs fetched to judge one mind: its own, and those of
   * the members a collective's log rests on, and of their members. Default 64.
   */
  readonly maxLogs?: number;
  /** The most entries of one feed that are read from one home. Default 10 000. */
  readonly maxFeedEntries?: number;
}

/** The most identity logs fetched to judge one mind, unless a client says otherwise. */
export const DEFAULT_MAX_LOGS = 64;
/** The most entries of a feed read from one home, unless a client says otherwise. */
export const DEFAULT_MAX_FEED_ENTRIES = 10_000;
/** The entries asked for in one page of a feed. A host may give fewer (Layer 1, 13.1). */
const FEED_PAGE = 100;

/** A mind as a client has resolved it. Everything here was verified. */
export interface Resolved {
  /** The mind's address. */
  readonly mind: string;
  /** Its identity log, verified, with the evaluation time of each event. */
  readonly log: VerifiedLog;
  /** Its identity state after the last event: its keys, its homes, whether it is retired. */
  readonly state: IdentityState;
  /**
   * Whether two valid events for one position of the log were seen, which
   * the evidence cannot tell apart (Layer 1, Section 7). The mind's
   * controller signed both: the log is verified up to that position and no
   * further.
   */
  readonly duplicitous: boolean;
  /** Its DID document and the metadata of the resolution (Layer 1, Section 5). */
  readonly did: DidResolution;
  /**
   * Its current location record (Layer 1, 15.2), if a resolver served one
   * that counts. It may be stale: see `stale`.
   */
  readonly location: HeldLocation | undefined;
  /**
   * Whether the location record is past its `ttl` (Layer 1, 15.2). A stale
   * record says where the mind was, and is a hint of where it is.
   */
  readonly stale: boolean;
  /**
   * Its current profile (Layer 1, 16.4): the one its current location record
   * names, if a resolver served it and it counts.
   */
  readonly participant: HeldParticipant | undefined;
  /** What each resolver answered, in the order the client names them. */
  readonly sources: readonly ResolverAnswer[];
}

/** A mind's feed as a client has read it from the mind's homes. The entries were verified. */
export interface ReadFeed {
  /** The feed, as far as it verifies (Layer 1, 10.1 to 10.4). */
  readonly feed: VerifiedFeed;
  /** What each home served, in the order the mind names them. */
  readonly sources: readonly HomeAnswer[];
}

/** What one home served of a mind's feed. */
export interface HomeAnswer {
  /** The home's origin. */
  readonly home: string;
  /** How many entries it served, or `undefined` if it served none. */
  readonly entries: number | undefined;
  /** Why it served none: the code of its problem, or the failure of the transport. */
  readonly failure?: string;
}

/** What one resolver answered for a mind. */
export interface ResolverAnswer {
  /** The resolver's origin. */
  readonly resolver: string;
  /** How many events of the mind's log it served, or `undefined` if it served none. */
  readonly events: number | undefined;
  /**
   * Why it served none: the code of its problem, such as `not-found`, or the
   * failure of the transport, such as `unreachable`.
   */
  readonly failure?: string;
}

/** A failure to get a mind's bundle from one resolver. */
type Failure = OipError | TransportError;

/** How much a failure says: one that answered and refused says the most, one that knows no such mind the least. */
const rank = (failure: Failure): number =>
  failure instanceof TransportError ? 1 : failure.code === "not-found" ? 2 : 0;

/** The value a judge answered with, or an `OipError` for its refusal. */
export function accepted<T>(judged: Validation<T>, code: ProblemCode, what: string): T {
  if (judged.ok) return judged.value;
  const [first] = judged.issues;
  throw new OipError(code, `${what}: ${first.message}`, {
    clause: first.clause,
    issues: judged.issues,
  });
}

/**
 * The logs a client holds of other minds, fetched from the resolvers it
 * trusts and verified with their first-seen times.
 */
export class Lookup {
  readonly #options: LookupOptions;
  readonly #resolvers: readonly string[];
  readonly #clock: Clock;
  /** What the resolvers said they first saw, and when. */
  readonly #witnessed = new FirstSeen();
  /** What this client first saw itself, and when. */
  readonly #seen = new FirstSeen();
  readonly #book: LogBook;
  /** The location records and profiles the resolvers served for each mind, as judged. */
  readonly #others = new Map<string, Map<string, JudgedRecord>>();

  /**
   * @throws TypeError if no resolver is given, or one is not an HTTPS origin.
   */
  constructor(options: LookupOptions) {
    const resolvers = [...options.resolvers];
    if (resolvers.length === 0) throw new TypeError("a client trusts at least one resolver");
    for (const resolver of resolvers) {
      if (httpsOrigin(resolver) !== resolver) {
        throw new TypeError(
          "a resolver is named by its HTTPS origin, such as https://resolver.example",
        );
      }
    }
    this.#options = options;
    this.#resolvers = resolvers;
    this.#clock = options.clock ?? systemClock;
    this.#book = new LogBook(earliestEvidence(this.#witnessed, this.#seen));
  }

  /**
   * The logs held and the evidence for them, for the judges of the other
   * packages: `ownSignedTime`, `receivePacket`, `countsFor`. Call `resolve`
   * for a mind before a proof by one of its keys is judged against this.
   */
  get view(): IdentityView {
    return this.#book;
  }

  /**
   * The client's own record of first sight (core 9.4, item 1), for the judges
   * that record one: `receivePacket`, `verifyHello`, `witnessRecord`.
   */
  get seen(): FirstSeen {
    return this.#seen;
  }

  /**
   * Resolves a mind: fetches its identity log from every resolver the client
   * trusts, takes their first-seen times as evidence, and verifies the log
   * with them. For a collective, the logs its own rests on are fetched first.
   *
   * Call it again before judging something new by the mind's keys: a log
   * held from an earlier fetch may lack the event that removed a key (core
   * 9.4).
   *
   * @throws OipError `not-found` if no resolver holds the mind;
   *   `invalid-proof` if a resolver served a log that does not verify;
   *   `invalid-record` if the address is none, or a resolver served what is
   *   no bundle of that mind. TransportError if no resolver could be asked.
   */
  async resolve(mind: string): Promise<Resolved> {
    idOf(mind);
    const budget = { left: this.#options.maxLogs ?? DEFAULT_MAX_LOGS };
    const sources = await this.#learn(mind, budget, new Set());
    const log = accepted(
      this.#book.log(mind),
      "invalid-proof",
      `the log of ${mind} does not verify`,
    );
    const did = accepted(didDocument(log), "invalid-record", `${mind} has no DID document`);
    const others = [...(this.#others.get(mind)?.values() ?? [])];
    const location = currentLocation(others, mind, this.#book);
    return {
      mind,
      log,
      state: latestState(log),
      duplicitous: log.duplicitous,
      did,
      location,
      stale: location !== undefined && isStale(location.record, this.#clock.now()),
      participant: profileNamed(location, others, this.#book),
      sources,
    };
  }

  /**
   * Reads a mind's public feed from its homes (Layer 1, 13.1) and verifies
   * it (10.1 to 10.4). The mind is resolved first.
   *
   * Every home is asked, and what they served is judged together: a home
   * that withholds the end of a feed is made up for by one that serves it,
   * and two valid entries for one position are found whichever home each
   * came from. An entry counts from when this client first saw it, unless it
   * holds earlier evidence.
   *
   * @throws OipError `not-found` if the mind names no home; the failure of
   *   the first home, if none served the feed. What `resolve` throws.
   */
  async feed(mind: string): Promise<ReadFeed> {
    const { state } = await this.resolve(mind);
    if (state.homes.length === 0) {
      throw new OipError("not-found", `${mind} names no home that serves a feed`, {
        clause: "L1 13.1",
      });
    }
    const answers = await Promise.all(state.homes.map((home) => this.#feedAt(home, mind)));
    const [failed] = answers.flatMap((answer) => ("failure" in answer ? [answer.failure] : []));
    if (failed !== undefined && answers.every((answer) => "failure" in answer)) throw failed;
    const now = this.#clock.now();
    const entries = answers.flatMap((answer) => ("entries" in answer ? answer.entries : []));
    for (const entry of entries) {
      // First seen now, by this client (core 9.4, item 1): a host is no witness.
      const judged = judgeRecord(entry);
      if (judged.ok) witnessRecord(judged.value, now, this.#seen);
    }
    // The log as it stands no earlier than the entries were first seen: a key that signed one
    // may have been removed since the homes were looked up (core 9.4).
    await this.resolve(mind);
    const feed = accepted(
      verifyFeed(entries, mind, this.#book),
      "invalid-record",
      `the feed of ${mind} cannot be read`,
    );
    return {
      feed,
      sources: answers.map((answer) =>
        "entries" in answer
          ? { home: answer.home, entries: answer.entries.length }
          : { home: answer.home, entries: undefined, failure: codeOf(answer.failure) },
      ),
    };
  }

  /** The entries one home serves of a mind's feed, page by page, as far as a client reads. */
  async #feedAt(
    home: string,
    mind: string,
  ): Promise<{ home: string; entries: Entry[] } | { home: string; failure: Failure }> {
    const most = this.#options.maxFeedEntries ?? DEFAULT_MAX_FEED_ENTRIES;
    const entries: Entry[] = [];
    try {
      if (httpsOrigin(home) !== home) {
        throw new TransportError("url", home, "a home is an HTTPS origin");
      }
      let after: number | undefined;
      for (;;) {
        const query = `limit=${String(FEED_PAGE)}${after === undefined ? "" : `&after=${String(after)}`}`;
        const record = await askRecord(
          { method: "GET", url: `${home}/.well-known/oip/mind/${idOf(mind)}/feed?${query}` },
          this.#options,
        );
        const page = accepted(
          validateRecordOfType("FeedPage", record),
          "invalid-record",
          `${home} served what is no page of a feed`,
        );
        if (page.mind !== mind) {
          throw new OipError("invalid-record", `${home} served the feed of another mind`, {
            clause: "L1 13.1",
          });
        }
        entries.push(...page.entries);
        if (entries.length > most) {
          throw new OipError("too-large", `${home} serves a longer feed than this client reads`, {
            clause: "implementation limit",
          });
        }
        // A page that does not go forward ends the reading, whatever it says comes next.
        if (page.next === undefined || page.entries.length === 0) break;
        if (after !== undefined && page.next <= after) break;
        after = page.next;
      }
      return { home, entries };
    } catch (error) {
      if (error instanceof OipError || error instanceof TransportError) {
        return { home, failure: error };
      }
      throw error;
    }
  }

  /**
   * Fetches a mind's log from every resolver and holds what they served. The
   * logs of the members it names are fetched before it is judged.
   */
  async #learn(
    mind: string,
    budget: { left: number },
    learning: Set<string>,
  ): Promise<ResolverAnswer[]> {
    if (learning.has(mind)) return [];
    learning.add(mind);
    if (budget.left <= 0) {
      throw new OipError(
        "too-large",
        "the mind's log rests on more other logs than this client fetches for one mind",
        { clause: "implementation limit" },
      );
    }
    budget.left -= 1;
    const answers = await Promise.all(this.#resolvers.map((resolver) => this.#ask(resolver, mind)));
    const served = answers.flatMap((answer) => ("bundle" in answer ? [answer] : []));
    if (served.length === 0) {
      // Unknown to every resolver, unless one of them said more than that.
      let worst: Failure = new OipError("not-found", `no resolver holds a log of ${mind}`, {
        clause: "L1 17.1",
      });
      for (const answer of answers) {
        if ("failure" in answer && rank(answer.failure) < rank(worst)) worst = answer.failure;
      }
      throw worst;
    }

    // The logs a collective's log rests on, before its own is held and judged.
    for (const member of membersNamed(served.map(({ bundle }) => bundle.log))) {
      await this.#learn(member, budget, learning);
    }

    const now = this.#clock.now();
    for (const { resolver, bundle } of served) {
      this.#takeTimes(bundle, now);
      // Each resolver's copy by itself, every event of it: a resolver serves nothing it cannot
      // verify (Layer 1, 17.2), and one that does is not a witness to go by.
      accepted(
        verifyLog(bundle.log, {
          evidence: this.#book.evidence,
          asOf: now,
          memberLog: (member) => this.#book.log(member),
        }),
        "invalid-proof",
        `${resolver} served a log of ${mind} that does not verify`,
      );
      // Held with the others. Two copies that differ at one position are duplicity, which the
      // book finds, and which is the mind's doing and not the resolver's.
      this.#book.hold(bundle.log, now);
      this.#takeOthers(mind, bundle);
    }
    return answers.map((answer) =>
      "bundle" in answer
        ? { resolver: answer.resolver, events: answer.bundle.log.length }
        : { resolver: answer.resolver, events: undefined, failure: codeOf(answer.failure) },
    );
  }

  /**
   * Asks one resolver for a mind's bundle. A resolver that refuses, cannot be
   * reached or serves what is no bundle of that mind has failed, and the
   * others are still asked. Anything else that goes wrong is nobody's
   * answer, and is not caught.
   */
  async #ask(
    resolver: string,
    mind: string,
  ): Promise<{ resolver: string; bundle: Bundle } | { resolver: string; failure: Failure }> {
    try {
      const record = await askRecord(
        { method: "GET", url: `${resolver}/oip/v1/resolve/${idOf(mind)}` },
        this.#options,
      );
      return { resolver, bundle: bundleOf(record, mind, resolver) };
    } catch (error) {
      if (error instanceof OipError || error instanceof TransportError) {
        return { resolver, failure: error };
      }
      throw error;
    }
  }

  /**
   * Takes a resolver's first-seen times as evidence (core 9.4, item 2): for
   * the events of the log it served, and for the proofs of the location
   * record and of the profile it served, and for nothing else it may name.
   */
  #takeTimes(bundle: Bundle, now: Instant): void {
    const times = bundle.firstSeen ?? {};
    const timeOf = (name: string): Instant | undefined => {
      const said = Object.hasOwn(times, name) ? parseTimestamp(times[name]) : undefined;
      if (said === undefined) return undefined;
      // A time ahead of this clock is evidence of nothing earlier than now.
      return said > now + SKEW ? undefined : said > now ? now : said;
    };
    for (const event of bundle.log) {
      const id = contentId(event);
      const at = timeOf(id);
      if (at !== undefined) this.#witnessed.sawEvent(id, at);
    }
    for (const proof of [...(bundle.location?.proof ?? []), ...(bundle.participant?.proof ?? [])]) {
      const digest = proofDigest(proof);
      const at = timeOf(digest);
      if (at !== undefined) this.#witnessed.sawProof(digest, at);
    }
  }

  /** Keeps the location record and the profile a resolver served, to be judged with the others. */
  #takeOthers(mind: string, bundle: Bundle): void {
    for (const record of [bundle.location, bundle.participant]) {
      if (record?.author !== mind) continue;
      const judged = judgeRecord(record);
      if (!judged.ok) continue;
      let held = this.#others.get(mind);
      if (held === undefined) this.#others.set(mind, (held = new Map<string, JudgedRecord>()));
      // One copy of each record: a later copy is the same record, as a resolver holds it now.
      held.set(contentId(record), judged.value);
    }
  }
}

/** The code of a failure: of the service's problem, or of the transport. */
const codeOf = (failure: Failure): string =>
  failure instanceof OipError ? failure.code : failure.failure;

/**
 * Layer 1, 16.4: the profile a location record names, if it is held and
 * counts for the mind.
 */
function profileNamed(
  location: HeldLocation | undefined,
  others: readonly JudgedRecord[],
  view: IdentityView,
): HeldParticipant | undefined {
  const named = location?.record.participant;
  if (named === undefined) return undefined;
  for (const other of others) {
    if (other.record.type !== "Participant" || contentId(other.record) !== named) continue;
    const verified = verifyParticipant(other, view);
    if (verified.ok) return verified.value;
  }
  return undefined;
}

/** What a resolver served, as a bundle of the mind that was asked for. */
function bundleOf(record: OipRecord, mind: string, resolver: string): Bundle {
  const bundle = accepted(
    validateRecordOfType("Bundle", record),
    "invalid-record",
    `${resolver} served what is no bundle`,
  );
  if (bundle.mind !== mind) {
    throw new OipError("invalid-record", `${resolver} served the bundle of another mind`, {
      clause: "L1 13.1",
    });
  }
  return bundle;
}

/**
 * The members the controllers of some logs name: the minds whose logs judge
 * those logs. The logs are of bundles that were read as bundles, so a
 * controller's members are addresses.
 */
function membersNamed(logs: readonly Bundle["log"][]): Set<string> {
  const members = new Set<string>();
  for (const log of logs) {
    for (const event of log) {
      const controller = (event as { controller?: { members?: readonly string[] } }).controller;
      for (const member of controller?.members ?? []) members.add(member);
    }
  }
  return members;
}

/**
 * The identifier of a mind: its address without `did:oip:`.
 *
 * @throws OipError `invalid-record` if it is not the address of a mind.
 */
function idOf(mind: string): string {
  const id = mindId(mind);
  if (id === undefined) {
    throw new OipError("invalid-record", "that is not the address of a mind", { clause: "L1 2" });
  }
  return id;
}
