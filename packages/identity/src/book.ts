// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The identity logs a verifier holds, with the evidence it holds of when
 * their events existed: what every question about a mind's keys is asked of.
 */

import {
  canonicalize,
  canonicalSizeUpTo,
  contentId,
  type Instant,
  type JsonObject,
  MAX_PROOFS,
  MAX_RECORD_BYTES,
  mindAddress,
} from "@oip/core";
import {
  IMPLEMENTATION_LIMIT,
  type JsonValue,
  type Validation,
  validateJson,
  validateWithoutProof,
  CUT_SHORT,
  cutShort,
  cutShortCount,
  judging,
  noteCutShort,
} from "@oip/schema";

import type { EvidenceView, FirstSeen } from "./evidence.ts";
import {
  cannotRead,
  type LogContext,
  LogRun,
  MAX_HEIGHT,
  maxEventsOf,
  understoodOf,
  Unread,
} from "./log.ts";
import { deepFreeze, isJsonObject, no, ok, own, type Rejection } from "./result.ts";
import type { LogEntry, Revocation, VerifiedLog } from "./state.ts";

/** The verified logs a verifier holds, and its evidence of time. */
export interface IdentityView {
  /** When each proof and each event is known to have existed (core 9.4). */
  readonly evidence: EvidenceView;
  /**
   * The verified log of a mind, as held: its events, the state after each and
   * each event's evaluation time. A rejection if no log is held for the mind
   * or the log held does not verify.
   */
  log(mind: string): Validation<VerifiedLog>;
}

/** Where two logs of one mind part: the position, and the event each has there. */
export interface Divergence {
  /** The position at which the two logs hold different events. */
  readonly position: number;
  /** The two events, in the order the logs were given. Each is valid against the same predecessor. */
  readonly events: readonly [LogEntry["event"], LogEntry["event"]];
}

/**
 * Layer 1, 7.1: whether two verified logs show duplicity, and where. They do
 * when they are logs of the same mind and hold different events at one
 * position; a log that is the beginning of the other does not. The pair of
 * events is what a resolver publishes as evidence (Layer 1, 7.2).
 */
export function divergence(a: VerifiedLog, b: VerifiedLog): Divergence | undefined {
  if (a.mind !== b.mind) return undefined;
  for (const [position, entry] of a.entries.entries()) {
    const other = b.entries[position];
    if (other === undefined) return undefined;
    if (other.state.head !== entry.state.head) {
      return { position, events: [entry.event, other.event] };
    }
  }
  return undefined;
}

/** What a `LogBook` is made with. */
export interface LogBookOptions {
  /** The longest log to read. See `LogContext.maxEvents`. */
  readonly maxEvents?: number;
  /** core 8.3: the extension namespaces the caller implements. See `LogContext.understood`. */
  readonly understood?: Iterable<string>;
}

/** What a verifier that is its own witness says with a reading of its clock. */
export interface ReadingOptions {
  /**
   * The minds whose logs the verifier follows itself, as a witness: whatever
   * is published of them reaches it. With the reading, every copy the book
   * holds of each is known up to that reading (core 9.4), every branch of
   * it. Default: none, and each log is known up to when it was last held. A
   * name that is no string, or of a mind not held, names no log. One
   * address by itself names that one mind.
   */
  readonly following?: Iterable<string> | string;
}

/** The minds a caller says it follows. One that says nothing readable follows none. */
function followingOf(options: unknown): ReadonlySet<string> {
  const following = new Set<string>();
  try {
    const named = own(options, "following") ?? [];
    // One address is one mind. Read as a list, a string is its characters.
    for (const mind of typeof named === "string" ? [named] : (named as Iterable<unknown>)) {
      if (typeof mind === "string") following.add(mind);
    }
  } catch (error) {
    noteCutShort(error);
    // Not a list of minds: no more are followed than were read.
  }
  return following;
}

/**
 * One event of a mind's log, in its place in a copy: what the event says.
 * Its proofs are held apart, for the event wherever it stands (`Tree.proofs`).
 */
interface Held {
  /**
   * The event without its proofs, as the book's own plain copy. Or what
   * stands for a value that could not be kept as one: `Unread` if the
   * verifier cannot read it (Layer 1, 4.9), and otherwise a value that is no
   * event at all.
   */
  readonly body: unknown;
  /**
   * The event's content ID, which its proofs are held under. `undefined`
   * for a value that has no place in a log (Layer 1, 7.1): what stands for
   * it is held, and nothing after it.
   */
  readonly id: string | undefined;
  /** The events held after this one, by what each says. */
  readonly next: Map<string, Held>;
  /** core 9.4: the latest time up to which a copy that ended with this event was known. */
  asOf: Instant | undefined;
}

/** Everything held of one mind's log: a tree of events, from its genesis. */
interface Tree {
  readonly genesis: Held;
  /**
   * Layer 1, 7.1: every proof held for each event, by the event's content
   * ID. The same event with another set of proofs is the same event, and
   * each proof stands on its own (core 5.5), so the proofs of every
   * well-formed copy are kept together.
   */
  readonly proofs: Map<string, Pool>;
  /** The places where a copy ended: those that have an `asOf`. */
  readonly ends: Set<Held>;
  /**
   * Set when a copy could not be taken in whole. The book has then been
   * shown something it does not hold, and no longer answers for the mind.
   */
  full: boolean;
}

/** The proofs held for one event. */
interface Pool {
  /** Each proof once, by its canonical form. */
  readonly proofs: Map<string, JsonObject>;
  /** core 1.6: the size of the event's canonical form with these proofs, kept as they are added. */
  bytes: number;
}

/** One proof of a copy of an event. */
interface TakenProof {
  /** Its canonical form, which tells it from another. */
  readonly key: string;
  readonly proof: JsonObject;
  /** The size of that form, in bytes. */
  readonly bytes: number;
}

/** One event as given, sorted for the tree. */
interface Taken {
  /** What tells this event from another at its position: its content ID, where it has one. */
  readonly key: string;
  readonly body: unknown;
  /** Its content ID, if it has a place in a log (Layer 1, 7.1). */
  readonly id: string | undefined;
  /**
   * The proofs this copy of the event adds to it: all of them if the copy
   * is well formed, and none if it is not (Layer 1, 7.1).
   */
  readonly proofs: readonly TakenProof[];
  /** core 1.6: the size of the event's canonical form with no proof. */
  readonly bare: number;
  /** Whether a copy goes on after it. Nothing follows a value that is no event. */
  readonly last: boolean;
}

/**
 * What stands in a tree for a value that has no place in a log and says
 * nothing a verifier could wait for: it is no record under core Section 1.
 */
const NO_EVENT = Symbol("no event");

const refusal = (message: string, clause: string): Rejection =>
  deepFreeze({ ok: false, issues: [{ path: "", message, clause }] });

const TOO_MANY = refusal(
  `the book was shown more proofs for one event of this mind's log than one record carries: ${MAX_PROOFS}, and 1 MiB with the event`,
  IMPLEMENTATION_LIMIT,
);

const TOO_DEEP = refusal(`collectives nest at most ${MAX_HEIGHT} deep`, "L1 4.7");

const IN_ITSELF = refusal("no collective is a member of itself, directly or indirectly", "L1 4.7");

/** What a value is held as, if reading it failed in a way nothing here foresaw. */
const COULD_NOT_BE_READ = refusal(
  "a value in the copy could not be read, so it cannot be judged",
  IMPLEMENTATION_LIMIT,
);

/** The end of a copy at a value that could not be sorted: held as an event that cannot be judged. */
const UNSORTED: Taken = {
  key: "unsorted",
  body: new Unread(COULD_NOT_BE_READ),
  id: undefined,
  proofs: [],
  bare: 0,
  last: true,
};

const NOT_A_LOG: Rejection = deepFreeze({
  ok: false,
  issues: [
    {
      path: "",
      message: "an identity log is an array of at least one event, the first a Genesis",
      clause: "L1 3.1",
    },
  ],
});

/** The event a run is given for a held event: what it says, with every proof held for it. */
function eventOf(tree: Tree, held: Held): unknown {
  return held.id === undefined
    ? held.body
    : { ...(held.body as object), proof: [...(tree.proofs.get(held.id)?.proofs.values() ?? [])] };
}

/** A place in a tree for an event as it was taken. */
function placeFor(event: Taken): Held {
  return { body: event.body, id: event.id, next: new Map(), asOf: undefined };
}

/**
 * core 1.6: the size of a value's canonical form, if it is within the size
 * of a record, and `undefined` if it is not. It is counted, not written
 * out, and as the value stands, whatever it says its type is: the value is
 * not a validated record, and an event is no container.
 */
function sizeOf(value: JsonValue): number | undefined {
  const size = canonicalSizeUpTo(value, MAX_RECORD_BYTES);
  return size > MAX_RECORD_BYTES ? undefined : size;
}

/**
 * Layer 1, 7.1: the proofs that a copy of an event adds to it. All of them,
 * if its `proof` is what core 5.1 says and the event is within core 1.6
 * with it; and otherwise none.
 *
 * A copy that is not well formed cannot be allowed to add any: the content
 * ID does not cover `proof`, so anyone can make such a copy of any event,
 * and one entry that is no object would make the event, with every proof
 * held for it, a record that is not well formed.
 *
 * @param bare - The size of the event's canonical form with no proof.
 */
function proofsOf(proof: JsonValue | undefined, bare: number): readonly TakenProof[] {
  if (!Array.isArray(proof) || proof.length === 0 || proof.length > MAX_PROOFS) return [];
  if (!proof.every(isJsonObject)) return [];
  const proofs = proof.map((entry) => ({
    key: canonicalize(entry),
    proof: entry,
    // No further than one byte past what a record may be: a larger one counts for nothing.
    bytes: canonicalSizeUpTo(entry, MAX_RECORD_BYTES),
  }));
  // The canonical form with these proofs is the form with none, the proofs, and a comma
  // between each two.
  const size = proofs.reduce((sum, entry) => sum + entry.bytes, bare + proofs.length - 1);
  return size > MAX_RECORD_BYTES ? [] : proofs;
}

/** The latest time up to which any copy that ended at or after an event was known. */
function latestBelow(held: Held): Instant | undefined {
  let latest: Instant | undefined;
  // A copy may hold thousands of values after this one, each below the last, and an
  // event may have as many beside one another: no recursion, and no call with them all.
  const pending = [held];
  for (let at = pending.pop(); at !== undefined; at = pending.pop()) {
    if (at.asOf !== undefined && (latest === undefined || at.asOf > latest)) latest = at.asOf;
    for (const next of at.next.values()) pending.push(next);
  }
  return latest;
}

/** What `witnessHeld` answers when its look went through. */
const LOOKED: Validation<true> = Object.freeze({ ok: true, value: true });

/**
 * The identity logs a verifier holds, verified when first asked for against
 * the evidence the book was made with.
 *
 * It holds a log only as data: nothing is fetched and no clock is read. A
 * copy is held with the time up to which it is known to be complete (core
 * 9.4), which the caller states. A copy is for a source the verifier trusts
 * to serve the whole log: nothing in a log can show that it lacks nothing.
 *
 * What it is shown, it keeps (Layer 1, 4.9). Every event of every copy is
 * held, in a tree from the genesis, with every proof it came with. Taking a
 * copy in judges nothing and discards nothing, so no copy can undo what
 * another showed, in whatever order they come. `drop` is how a caller says
 * a copy was wrong.
 *
 * It judges when it is asked. `log` walks the tree from the genesis. At each
 * position it judges every event held there. One that is invalid is no
 * event. One that the verifier cannot judge stops the log: it may be the
 * mind's own. One that verifies carries the log on, and where several do,
 * the evidence decides between them, never their order or their number
 * (Layer 1, 7.3). What follows an event that lost is not judged at all.
 *
 * A verdict is kept until a log it rests on changes. The book cannot see its
 * evidence change: call `forget` when a time it has given may have moved.
 */
export class LogBook implements IdentityView {
  /** The evidence every log and proof is judged against. */
  readonly evidence: EvidenceView;
  readonly #maxEvents: number;
  readonly #understood: ReadonlySet<string>;
  readonly #held = new Map<string, Tree>();
  readonly #verified = new Map<string, Validation<VerifiedLog>>();
  /** For each mind, the minds whose verdicts asked for its log. */
  readonly #askedBy = new Map<string, Set<string>>();
  /**
   * For each mind, the minds held whose logs have asked for its log, at any
   * time. Unlike `#askedBy` it outlives the verdicts: it says whose events
   * may verify when this mind's log changes, whatever has been forgotten.
   */
  readonly #restingOn = new Map<string, Set<string>>();
  readonly #visiting = new Set<string>();
  /** How often a log was refused for where it was asked from, and not for what it is. */
  #refusals = 0;

  /**
   * @throws Error if the options could not be read for want of room on the
   *   call stack: a book keeps them for as long as it lives, so one made
   *   then would keep what it never read (ADR-0010). Make it again.
   */
  constructor(evidence: EvidenceView, options?: LogBookOptions) {
    const before = cutShortCount();
    this.evidence = evidence;
    this.#maxEvents = maxEventsOf(own(options, "maxEvents"));
    this.#understood = understoodOf(own(options, "understood"));
    if (cutShortCount() !== before) throw new Error(CUT_SHORT);
  }

  /**
   * Holds `events` as a copy of a mind's log, as a source the verifier
   * trusts to serve the whole log served it. The book takes its own copy:
   * changing `events` afterwards changes nothing here.
   *
   * Every event of the copy is kept, beside whatever is held already, with
   * its proofs. Nothing is judged and nothing gives way: an event the copy
   * lacks stays held, and one it has where another is held is held too.
   * `log` judges them when it is asked. So an earlier state of the log
   * changes nothing, and neither does the order copies come in.
   *
   * @param asOf - The time up to which the log is known to be complete: when
   *   a witness the verifier trusts served it, or the present for a verifier
   *   that follows the log itself (core 9.4).
   * @returns The mind's address. Or why the copy was not taken: it is no
   *   log; or it shows more proofs for one event than one record carries,
   *   with those held already, and the book then answers for that mind no
   *   longer, until the mind is dropped.
   */
  hold(events: unknown, asOf: Instant): Validation<string> {
    return judging(() => this.#hold(events, asOf));
  }

  #hold(events: unknown, asOf: Instant): Validation<string> {
    const before = cutShortCount();
    const taken = this.#take(events, asOf);
    // A value that could not be read for want of room would be held as one the
    // verifier cannot judge, and stop the mind for good: nothing of such a reading is kept.
    if (cutShortCount() !== before) return cutShort();
    if (!taken.ok) return taken;
    const { mind, copy } = taken.value;
    const [first] = copy;
    let tree = this.#held.get(mind);
    if (tree === undefined) {
      tree = { genesis: placeFor(first), proofs: new Map(), ends: new Set(), full: false };
      this.#held.set(mind, tree);
    }
    // Shown more proofs for an event than it holds, the book takes nothing more of this mind.
    if (tree.full) return TOO_MANY;
    /** Whether the copy has changed what is held. */
    let changed = false;
    /**
     * Forgets the verdicts that rest on what is held, before it changes.
     * Whatever happens after, no verdict outlives what it was given for.
     */
    const change = (): void => {
      if (changed) return;
      changed = true;
      this.#changed(mind);
    };
    let at = tree.genesis;
    for (const [position, event] of copy.entries()) {
      // A place is kept for one event more than the book reads, so that a log too
      // long is seen to be. Further on, no event is ever judged where it stands, but
      // its proofs are proofs of the event wherever it stands (Layer 1, 7.1).
      if (position > 0 && position <= this.#maxEvents) {
        let next = at.next.get(event.key);
        if (next === undefined) {
          change();
          next = placeFor(event);
          at.next.set(event.key, next);
        }
        at = next;
      }
      if (event.id === undefined || event.proofs.length === 0) continue;
      let pool = tree.proofs.get(event.id);
      if (pool === undefined) {
        change();
        pool = { proofs: new Map<string, JsonObject>(), bytes: event.bare };
        tree.proofs.set(event.id, pool);
      }
      for (const { key, proof, bytes } of event.proofs) {
        if (pool.proofs.has(key)) continue;
        change();
        // With a proof before it, a comma between the two.
        const grown = pool.bytes + bytes + (pool.proofs.size === 0 ? 0 : 1);
        // The proofs of several copies may be more together than one record carries
        // (core 1.6, 5.1). The book cannot tell which to leave out, and takes no more.
        if (pool.proofs.size >= MAX_PROOFS || grown > MAX_RECORD_BYTES) {
          tree.full = true;
          return TOO_MANY;
        }
        pool.proofs.set(key, proof);
        pool.bytes = grown;
      }
    }
    // The latest time up to which a copy that ended here was known.
    if (at.asOf === undefined || asOf > at.asOf) {
      change();
      at.asOf = asOf;
      tree.ends.add(at);
    }
    return ok(mind);
  }

  /**
   * Holds `events` as `hold` does, and then records the verifier's own
   * first sight (core 9.5) of every event that verifies now and that it has
   * not recorded, as seen at `now`. It is how a verifier that follows a log
   * itself takes a copy in.
   *
   * An event is judged here as the book judges it: with the proofs of every
   * copy held (Layer 1, 7.1), and as if each event not seen before were
   * first seen at `now`, which is what is about to be recorded. So an event
   * that arrives in two copies, each with some of its proofs, is recorded
   * when the second arrives, and not later, when some copy happens to carry
   * them all: a removal counts from when the verifier first held it whole.
   *
   * A collective's event verifies only if every log it rests on is known up
   * to `now` as well (core 9.4). Name the logs the verifier follows in
   * `following`, with every copy it takes in: they are known up to `now`,
   * and the event is recorded now. Left out, a member's log is known only
   * up to when it was last held, the event waits for the next reading that
   * names it, and a proof by a key the event removes that is first seen in
   * between counts.
   *
   * The events looked at are those of the copy's mind, those of every mind
   * held whose log has asked for that mind's log, or for a log that is now
   * known further than it was, and so on up.
   *
   * An event that does not verify is not recorded, and neither is anything
   * after it, nor any event of a mind the book answers for no longer. Where
   * the evidence already has a time for an event, the event is judged at
   * the earlier of that time and `now`, which is the time the evidence
   * gives once this sight is recorded, and recorded if it verifies so. The
   * earlier of the two stands, and the verifier's own sight is what is left
   * if the other is ever withdrawn.
   *
   * @param now - The time the verifier obtained the copy: its own clock,
   *   read by the caller. It is also the time the copy is known up to.
   * @param seen - The verifier's own record, which is written to. It should
   *   be, or be part of, the evidence the book was made with.
   * @returns What `hold` returns. A copy that is not taken is not looked at,
   *   and the logs named in `following` are left as they were. A copy
   *   refused for showing more proofs than the book holds for one event is
   *   the one refusal that changes something: the book answers for that mind
   *   no longer, as `hold` says.
   *
   *   A refusal with the clause `implementation limit` is another matter:
   *   the look was cut short, for want of room on the call stack. The copy
   *   may be held, and an event that verifies may not be recorded. Call
   *   again with the same copy and the same reading: a look that ends a
   *   reading late records a removal late, and a proof by the removed key
   *   seen in between counts.
   */
  witness(
    events: unknown,
    now: Instant,
    seen: FirstSeen,
    options?: ReadingOptions,
  ): Validation<string> {
    // A look that was cut short, anywhere in it, has recorded nothing of what it could not
    // judge. The caller must know, to look again: the copy is held, and the answer is a
    // refusal for want of room (ADR-0010).
    return judging(() => this.#witnessed(events, now, seen, options));
  }

  #witnessed(
    events: unknown,
    now: Instant,
    seen: FirstSeen,
    options: ReadingOptions | undefined,
  ): Validation<string> {
    const following = followingOf(options);
    const held = this.#hold(events, now);
    if (!held.ok) return held;
    const minds = [held.value];
    const reached = new Set(minds);
    const reach = (mind: string): void => {
      for (const resting of this.#restingOn.get(mind) ?? []) {
        if (reached.has(resting)) continue;
        reached.add(resting);
        minds.push(resting);
      }
    };
    this.#follow(following, now);
    // What rests on a log that is followed is looked at whether or not this call moved the
    // log. A look that was cut short has moved it already, and the look made again with the
    // same reading would otherwise pass over what waited on it.
    for (const mind of following) if (this.#held.has(mind)) reach(mind);
    for (const mind of minds) reach(mind);
    this.#witness(minds, now, seen);
    return held;
  }

  /**
   * Records the verifier's own first sight (core 9.5) of every event held,
   * of any mind, that verifies now and that it has not recorded, as seen at
   * `now`. `witness` does this for one copy that arrives. This is for
   * everything else that may let an event verify:
   *
   * - the clock. An event dated more than 300 seconds ahead of the clock
   *   does not verify until the clock is within 300 seconds of its date
   *   (core 9.5). Seen then, it takes effect at its date. Seen later than
   *   its date, it takes effect when it is seen, and a proof by a key it
   *   removes that was first seen in between counts. A verifier that calls
   *   this at least every 300 seconds is never late;
   * - a log held from a witness the verifier trusts, or that witness's
   *   first-seen times taken into the evidence, after `forget`.
   *
   * The logs named in `following` are known up to `now`, as for `witness`.
   * A verifier begins to follow a log by taking a fresh copy of it in with
   * `witness` at that reading. To name a log it holds from an older fetch,
   * without a fresh copy, is to say the old copy is complete, and a key
   * removed since would count.
   *
   * Its cost is that of verifying every log held that has an event the
   * verifier has not recorded.
   *
   * @param now - The present: the verifier's own clock, read by the caller.
   * @param seen - The verifier's own record, as for `witness`.
   * @returns That the look went through. Or a refusal with the clause
   *   `implementation limit`: the look was cut short, and an event that
   *   verifies may not be recorded. Call again with the same reading.
   * @throws TypeError if `now` is not a time.
   */
  witnessHeld(now: Instant, seen: FirstSeen, options?: ReadingOptions): Validation<true> {
    if (typeof (now as unknown) !== "bigint") throw new TypeError("now is not a time");
    return judging(() => {
      this.#follow(followingOf(options), now);
      this.#witness([...this.#held.keys()], now, seen);
      return LOOKED;
    });
  }

  /**
   * core 9.4: a log the verifier follows itself is known up to its reading
   * of the clock: every copy held of it, wherever it ended. A mind held in
   * two branches is known up to the least of them, so each is moved.
   */
  #follow(following: ReadonlySet<string>, now: Instant): void {
    for (const mind of following) {
      const ends = [...(this.#held.get(mind)?.ends ?? [])].filter(
        (end) => end.asOf !== undefined && end.asOf < now,
      );
      if (ends.length === 0) continue;
      // Before anything changes, as in `hold`.
      this.#changed(mind);
      for (const end of ends) end.asOf = now;
    }
  }

  /** Records first sight of what verifies now in the logs of `minds`. */
  #witness(minds: readonly string[], now: Instant, seen: FirstSeen): void {
    // No event is recorded twice in one call, whatever `seen` keeps of what it is told.
    const recorded = new Set<string>();
    // What is recorded for one mind may be what an event of another waited on, in
    // whatever order they stand here: so again, until nothing more is recorded.
    for (let again = true; again;) {
      again = false;
      for (const mind of minds) {
        if (this.#sight(mind, now, seen, recorded)) again = minds.length > 1;
      }
    }
  }

  /**
   * Records first sight of every event held of one mind's log that
   * verifies now and that the verifier has not recorded.
   *
   * @param recorded - The events recorded in this call, to which it adds.
   * @returns Whether anything was recorded.
   */
  #sight(mind: string, now: Instant, seen: FirstSeen, recorded: Set<string>): boolean {
    const tree = this.#held.get(mind);
    // Shown more proofs for an event than it holds, the book treats the log as not
    // verified (Layer 1, 7.1): no event of it has verified.
    if (tree === undefined || tree.full) return false;
    // Nothing is verified where there is nothing to record: most logs, at most looks.
    let all = true;
    for (const id of tree.proofs.keys()) {
      all = seen.eventSeen(id) !== undefined;
      if (!all) break;
    }
    if (all) return false;
    const context = this.#context(mind, 0);
    const checks = cutShortCount();
    const first = new LogRun({
      ...context,
      evidence: {
        proofSeen: (digest) => this.evidence.proofSeen(digest),
        // Each event is judged at the time the evidence will give it once this sight is
        // recorded: the earlier of what the evidence gives now and `now`. An event the
        // verifier has recorded before keeps the time the evidence gives.
        eventSeen: (id) => {
          const dated = this.evidence.eventSeen(id);
          if (dated === undefined) return now;
          return dated > now && seen.eventSeen(id) === undefined ? now : dated;
        },
      },
    });
    const found: string[] = [];
    // Every event held, each from the state its place gives it, whichever would win
    // a contested position: a verifier records every valid event it sees (Layer 1, 7.2).
    const pending = [{ at: tree.genesis, run: first }];
    // As when the log is verified: a collective that is a member of itself is found out.
    const visited = this.#visiting.has(mind);
    this.#visiting.add(mind);
    try {
      for (let next = pending.pop(); next !== undefined; next = pending.pop()) {
        const { at, run } = next;
        if (run.advance(eventOf(tree, at)) !== undefined) continue;
        const id = run.entries.at(-1)?.state.head;
        // The event verified as seen at `now`, or at an earlier time the evidence gives.
        // Where the evidence has a time for it, the earlier of the two stands, and the
        // verifier's own sight is what is left if the other is ever withdrawn (Layer 1, 7.2).
        if (id !== undefined && !recorded.has(id) && seen.eventSeen(id) === undefined) {
          recorded.add(id);
          found.push(id);
        }
        // As far as the book reads, and no further.
        if (run.entries.length >= this.#maxEvents) continue;
        for (const child of at.next.values()) {
          pending.push({ at: child, run: at.next.size === 1 ? run : run.fork() });
        }
      }
    } finally {
      if (!visited) this.#visiting.delete(mind);
    }
    // An event that failed because its check was cut short may be one that verifies,
    // and what followed it was not looked at: nothing is recorded of such a look.
    if (found.length === 0 || cutShortCount() !== checks) return false;
    try {
      for (const id of found) seen.sawEvent(id, now);
    } finally {
      // A verdict given for want of this evidence is given no longer, whatever
      // became of the rest.
      this.#changed(mind);
    }
    return true;
  }

  /**
   * Stops holding anything of a mind's log.
   *
   * @returns Whether anything was held.
   */
  drop(mind: string): boolean {
    const held = this.#held.delete(mind);
    if (held) {
      this.#changed(mind);
      // Nothing of it is left to verify. What rests on it still does.
      for (const [member, resting] of this.#restingOn) {
        resting.delete(mind);
        if (resting.size === 0) this.#restingOn.delete(member);
      }
    }
    return held;
  }

  /**
   * Forgets every verdict, so that each log is verified again when next
   * asked for. Call it when the evidence may give an earlier time than it
   * gave before: the book keeps the times it was first given.
   */
  forget(): void {
    this.#verified.clear();
    this.#askedBy.clear();
  }

  /**
   * The book's own copy of a log, value by value: its genesis, which gives
   * the address, and every value after it as far as the first that has no
   * place in a log. The address comes from the copy that is verified later,
   * never from a second reading of what the caller holds.
   *
   * Only a first value that has no place makes the copy no log. A value
   * after it that could not be sorted costs the copy nothing that came
   * before: it is held as an event the verifier cannot judge.
   */
  #take(
    events: unknown,
    asOf: Instant,
  ): Validation<{ readonly mind: string; readonly copy: readonly [Taken, ...Taken[]] }> {
    if (typeof (asOf as unknown) !== "bigint") {
      return no("the time up to which the log is known is not a time", "core 9.4");
    }
    let length: number;
    let first: Taken;
    let mind: string;
    try {
      if (!Array.isArray(events)) return NOT_A_LOG;
      const given: unknown = events.length;
      if (typeof given !== "number" || !Number.isSafeInteger(given)) return NOT_A_LOG;
      length = given;
      first = this.#sorted(events[0]);
      // A first value with no content ID is the genesis of no mind.
      if (first.id === undefined) return NOT_A_LOG;
      mind = mindAddress(first.id);
    } catch (error) {
      noteCutShort(error);
      // What cannot be read as far as its first event is no log.
      return NOT_A_LOG;
    }
    const copy: [Taken, ...Taken[]] = [first];
    // Every value of the copy, as far as the first that has no place in a log.
    for (let i = 1; i < length && !copy[i - 1]?.last; i++) {
      let next: Taken;
      try {
        next = this.#sorted((events as readonly unknown[])[i]);
      } catch (error) {
        noteCutShort(error);
        // Whatever went wrong, the events before it were shown and are kept. A value
        // the book could not so much as sort may be an event: the log stops at it.
        next = UNSORTED;
      }
      copy.push(next);
    }
    return ok({ mind, copy });
  }

  /**
   * One event as given, as the tree keeps it. It judges nothing but what
   * kind of value it is.
   *
   * Layer 1, 7.1: a value has a place in a log if, apart from its `proof`,
   * it is a JSON object within core Section 1: plain data (1.1, 1.2, 1.9) of
   * at most 1 MiB (1.6). That is what its content ID covers (core 3.1), and
   * so what tells which event it is a copy of, whatever came as its proofs.
   * Nothing follows a value that has no place, for nothing tells what it
   * would follow.
   */
  #sorted(raw: unknown): Taken {
    const whole = validateJson(raw);
    // If the value is not plain data, its proofs may be all that is wrong with it.
    const content = whole.ok ? whole : validateWithoutProof(raw);
    const { proof, ...body } =
      content.ok && isJsonObject(content.value) ? content.value : { proof: undefined };
    const size = content.ok && isJsonObject(content.value) ? sizeOf(body) : undefined;
    if (size === undefined) {
      // No event of this version. If the verifier cannot read it for what it
      // says of itself, it may be an event all the same, and is kept as that
      // (Layer 1, 4.9). Otherwise it is nothing, and all such values at one
      // place are held as one.
      const unread = cannotRead(whole.ok ? whole.value : raw, this.#understood, "");
      return unread === undefined
        ? { key: "no event", body: NO_EVENT, id: undefined, proofs: [], bare: 0, last: true }
        : {
            // By its clause, and by nothing the value says: one such value at a
            // place stops the log as well as another.
            key: `unread ${unread.issues[0].clause}`,
            body: new Unread(unread),
            id: undefined,
            proofs: [],
            bare: 0,
            last: true,
          };
    }
    // The proofs are kept apart, to be held with any others of the same
    // event. So the event has its place whatever came as its proofs, and
    // what follows it is kept. That holds for an event the verifier cannot
    // read, too: it is judged by what it says of itself (Layer 1, 4.9).
    const id = contentId(body);
    // With no proof, the event is its content and the member `"proof":[]`, after a comma
    // if it has another member.
    const bare = size + (Object.keys(body).length === 0 ? 10 : 11);
    // Proofs that are not plain data are no proofs: the value was then read without
    // them, and has none here.
    return { key: id, body, id, proofs: proofsOf(proof, bare), bare, last: false };
  }

  /** Forgets the verdict on a mind, and every verdict that asked for its log, and so on up. */
  #changed(mind: string): void {
    const pending = [mind];
    for (let next = pending.pop(); next !== undefined; next = pending.pop()) {
      this.#verified.delete(next);
      const askers = this.#askedBy.get(next);
      if (askers === undefined) continue;
      this.#askedBy.delete(next);
      for (const asker of askers) pending.push(asker);
    }
  }

  /**
   * The verified log of a mind: verified when first asked for, with its
   * members' logs, and with duplicity resolved among the events held. The
   * answer is frozen if the book keeps it.
   */
  log(mind: string): Validation<VerifiedLog> {
    if (typeof (mind as unknown) !== "string") {
      return no("a mind is named by its address, a string", "L1 2.2");
    }
    return judging(() => this.#log(mind, 0));
  }

  /** `depth` counts the collectives between the log asked for and this one (Layer 1, 4.7). */
  #log(mind: string, depth: number): Validation<VerifiedLog> {
    const known = this.#verified.get(mind);
    if (known !== undefined) return known;
    const tree = this.#held.get(mind);
    if (tree === undefined) return no(`no identity log is held for ${mind}`, "L1 6.3");
    if (depth > MAX_HEIGHT) return this.#here(TOO_DEEP);
    if (this.#visiting.has(mind)) return this.#here(IN_ITSELF);
    const before = this.#refusals;
    const checks = cutShortCount();
    this.#visiting.add(mind);
    let result: Validation<VerifiedLog>;
    try {
      result = deepFreeze(this.#resolve(mind, tree, depth));
    } finally {
      this.#visiting.delete(mind);
    }
    // An event refused because its check was cut short may have been the one that
    // removed a key, or the branch that had the position. Whatever came of it is no
    // verdict on the log: it is neither given nor kept.
    if (cutShortCount() !== checks) return cutShort();
    // A log that verifies is the same log wherever it is asked from: no
    // event of it rests on a log that was refused, for an event that does is
    // one the verifier cannot judge, and stops the log. A refusal may be for
    // where the log was asked from: a log below it nests too deep there, or
    // is being verified above. That one is kept only at the top, where it
    // is the log's own (Layer 1, 4.7).
    if (result.ok || depth === 0 || this.#refusals === before) this.#verified.set(mind, result);
    return result;
  }

  /**
   * A refusal for where a log was asked from. It is not the log's own
   * answer, and it is counted so that no refusal that rests on it is kept
   * as one.
   */
  #here(refused: Rejection): Rejection {
    this.#refusals++;
    return refused;
  }

  #context(mind: string, depth: number): Omit<LogContext, "asOf"> {
    return {
      evidence: this.evidence,
      memberLog: (member) => {
        let askers = this.#askedBy.get(member);
        if (askers === undefined) this.#askedBy.set(member, (askers = new Set()));
        askers.add(mind);
        let resting = this.#restingOn.get(member);
        if (resting === undefined) this.#restingOn.set(member, (resting = new Set()));
        resting.add(mind);
        return this.#log(member, depth + 1);
      },
      maxEvents: this.#maxEvents,
      understood: this.#understood,
    };
  }

  /** Layer 1, 4.9 and 7.3: one log from everything held of a mind's log. */
  #resolve(mind: string, tree: Tree, depth: number): Validation<VerifiedLog> {
    if (tree.full) return TOO_MANY;
    let run = new LogRun(this.#context(mind, depth));
    let at = tree.genesis;
    const first = run.advance(eventOf(tree, at));
    if (first !== undefined) return first.failure;
    for (;;) {
      // Every event held for the next position is judged, each from here.
      const held = [...at.next.values()];
      if (held.length > 0 && run.entries.length >= this.#maxEvents) {
        return tooLong(this.#maxEvents);
      }
      const going: { readonly held: Held; readonly run: LogRun }[] = [];
      for (const next of held) {
        const forked = held.length === 1 ? run : run.fork();
        const refused = forked.advance(eventOf(tree, next));
        // One that cannot be judged may be the mind's own, so no other takes the position.
        if (refused?.undecided === true) return refused.failure;
        // One that is invalid is no event, and nothing that follows it is one.
        if (refused === undefined) going.push({ held: next, run: forked });
      }
      const [one, ...others] = going;
      if (one === undefined) {
        // The log ends here, as far as any copy that reached this event was known.
        const asOf = latestBelow(at);
        const log = asOf === undefined ? undefined : run.log(asOf);
        if (log === undefined) return NOT_A_LOG;
        return log.mind === mind
          ? ok(log)
          : no("the log held for this mind is the log of another", "L1 2.2");
      }
      let winner = others.length === 0 ? one : undefined;
      if (winner === undefined) {
        // Several events verify at this position: the one with strictly the earliest evidence has it.
        let earliest: Instant | undefined;
        for (const candidate of going) {
          const seen = this.evidence.eventSeen(candidate.run.entries.at(-1)?.state.head ?? "");
          // An event that verified had evidence. One whose evidence is gone cannot win.
          if (seen === undefined) continue;
          if (earliest === undefined || seen < earliest) {
            earliest = seen;
            winner = candidate;
          } else if (seen === earliest) {
            winner = undefined;
          }
        }
        if (winner === undefined) return this.#duplicitous(tree, run, going);
      }
      ({ held: at, run } = winner);
    }
  }

  /**
   * Layer 1, 7.3: the log of a mind whose events at one position the
   * evidence cannot separate. It stops before that position, and every
   * event held after it applies, so that the removals and the compromise
   * declarations of every branch do: each is judged, and one that cannot be
   * stops the log.
   *
   * @param tree - Everything held of the mind's log.
   * @param shared - The run up to the last event the branches share.
   * @param branches - The events that verify at the position where they part.
   */
  #duplicitous(
    tree: Tree,
    shared: LogRun,
    branches: readonly { readonly held: Held; readonly run: LogRun }[],
  ): Validation<VerifiedLog> {
    const tails: LogEntry[] = [];
    const revocations: Revocation[] = [];
    // Known only as far as the branch that is known least far.
    let asOf: Instant | undefined;
    const pending = [...branches];
    for (let branch = pending.pop(); branch !== undefined; branch = pending.pop()) {
      const { held, run } = branch;
      const entry = run.entries.at(-1);
      if (entry !== undefined) tails.push(entry);
      revocations.push(
        ...run.revocations.filter((made) => made.position === run.entries.length - 1),
      );
      let ends = true;
      if (held.next.size > 0 && run.entries.length >= this.#maxEvents) {
        return tooLong(this.#maxEvents);
      }
      for (const next of held.next.values()) {
        const forked = held.next.size === 1 ? run : run.fork();
        const refused = forked.advance(eventOf(tree, next));
        if (refused?.undecided === true) return refused.failure;
        if (refused !== undefined) continue;
        pending.push({ held: next, run: forked });
        ends = false;
      }
      if (!ends) continue;
      const known = latestBelow(held);
      if (known !== undefined && (asOf === undefined || known < asOf)) asOf = known;
    }
    const log = asOf === undefined ? undefined : shared.log(asOf);
    if (log === undefined) return NOT_A_LOG;
    return ok(
      deepFreeze({
        ...log,
        // What the branches share, once, and then what each declares after they part.
        revocations: [...log.revocations, ...revocations],
        duplicitous: true,
        branchTails: tails,
      }),
    );
  }
}

function tooLong(most: number): Rejection {
  return refusal(
    `the log has more than ${most} events, the most this verifier was set to read`,
    IMPLEMENTATION_LIMIT,
  );
}
