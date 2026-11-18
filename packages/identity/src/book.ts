// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The identity logs a verifier holds, with the evidence it holds of when
 * their events existed: what every question about a mind's keys is asked of.
 */

import {
  canonicalBytes,
  canonicalize,
  contentId,
  type Instant,
  type JsonObject,
  MAX_PROOFS,
  MAX_RECORD_BYTES,
  mindAddress,
} from "@oip/core";
import { IMPLEMENTATION_LIMIT, type JsonValue, type Validation, validateJson } from "@oip/schema";

import type { EvidenceView } from "./evidence.ts";
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
   * for a value that has none: it is no object of plain data, and is held
   * whole, as what stands for it.
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
   * ID and then by the proof's canonical form. The same event with another
   * set of proofs is the same event, and each proof stands on its own (core
   * 5.5), so the proofs of every well-formed copy are kept together.
   */
  readonly proofs: Map<string, Map<string, JsonObject>>;
  /** The ends of the tree: the copies held, less every copy that is the beginning of another. */
  ends: number;
  /**
   * Set when a copy could not be taken in whole. The book has then been
   * shown something it does not hold, and no longer answers for the mind.
   */
  full: boolean;
}

/** One event as given, sorted for the tree. */
interface Taken {
  /** What tells this event from another at its position: its content ID, where it has one. */
  readonly key: string;
  readonly body: unknown;
  /** Its content ID, if it is an object of plain data. */
  readonly id: string | undefined;
  /**
   * The proofs this copy of the event adds to it: all of them if the copy
   * is well formed, and none if it is not (Layer 1, 7.1).
   */
  readonly proofs: readonly JsonObject[];
  /** Whether a copy goes on after it. Nothing follows a value that is no event. */
  readonly last: boolean;
}

/** What stands in a tree for a value that is not plain data and says nothing a verifier could wait for. */
const NOT_DATA = Symbol("not plain data");

/**
 * The most ends one mind's tree may have: the copies of its log that are
 * held and are not the beginning of one another. Two that conflict are
 * duplicity; a mind with more is rare.
 */
const MAX_COPIES = 8;

const refusal = (message: string, clause: string): Rejection =>
  deepFreeze({ ok: false, issues: [{ path: "", message, clause }] });

const TOO_MANY = refusal(
  `the book was shown more of this mind's log than it holds: more than ${MAX_COPIES} copies that are not the beginning of one another, or more proofs for one event than one record carries (${MAX_PROOFS}, and 1 MiB with the event)`,
  IMPLEMENTATION_LIMIT,
);

const TOO_DEEP = refusal(`collectives nest at most ${MAX_HEIGHT} deep`, "L1 4.7");

const IN_ITSELF = refusal("no collective is a member of itself, directly or indirectly", "L1 4.7");

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
    : { ...(held.body as object), proof: [...(tree.proofs.get(held.id)?.values() ?? [])] };
}

/** A place in a tree for an event as it was taken. */
function placeFor(event: Taken): Held {
  return { body: event.body, id: event.id, next: new Map(), asOf: undefined };
}

/**
 * core 1.6: whether an event is within the size of a record, with the proofs
 * it is given. It is measured as it stands, whatever it says its type is:
 * the value is not a validated record, and an event is no container.
 */
function fits(event: JsonObject): boolean {
  return canonicalBytes(event).length <= MAX_RECORD_BYTES;
}

/**
 * Layer 1, 7.1: whether a copy of an event is one whose proofs count. Its
 * `proof` is what core 5.1 says, and the event is within core 1.6 with it.
 *
 * A copy that is not adds nothing. It cannot be allowed to: the content ID
 * does not cover `proof`, so anyone can make such a copy of any event, and
 * one entry that is no object would make the event with every proof held
 * for it a record that is not well formed.
 */
function proofsOf(event: JsonObject, proof: JsonValue | undefined): readonly JsonObject[] {
  return Array.isArray(proof) &&
    proof.length > 0 &&
    proof.length <= MAX_PROOFS &&
    proof.every(isJsonObject) &&
    fits(event)
    ? proof
    : [];
}

/** The latest time up to which any copy that ended at or after an event was known. */
function latestBelow(held: Held): Instant | undefined {
  let latest = held.asOf;
  for (const next of held.next.values()) {
    const below = latestBelow(next);
    if (below !== undefined && (latest === undefined || below > latest)) latest = below;
  }
  return latest;
}

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
  readonly #visiting = new Set<string>();
  /** How often a log was refused for where it was asked from, and not for what it is. */
  #refusals = 0;

  constructor(evidence: EvidenceView, options?: LogBookOptions) {
    this.evidence = evidence;
    this.#maxEvents = maxEventsOf(own(options, "maxEvents"));
    this.#understood = understoodOf(own(options, "understood"));
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
   *   log; or it is more than the book holds of one mind, and the book then
   *   answers for that mind no longer, until the mind is dropped.
   */
  hold(events: unknown, asOf: Instant): Validation<string> {
    const taken = this.#take(events, asOf);
    if (!taken.ok) return taken;
    const { mind, copy } = taken.value;
    const [first] = copy;
    let tree = this.#held.get(mind);
    if (tree === undefined) {
      tree = { genesis: placeFor(first), proofs: new Map(), ends: 1, full: false };
      this.#held.set(mind, tree);
    }
    // Shown more than it holds once, the book takes nothing more of this mind.
    if (tree.full) return TOO_MANY;
    /** Whether the copy showed an event or a proof that was not held. */
    let added = false;
    let branched = false;
    let at = tree.genesis;
    for (const event of copy) {
      if (event !== first) {
        let next = at.next.get(event.key);
        if (next === undefined) {
          // An event beside another at one position is one more end; one after the last is not.
          if (!branched && at.next.size > 0) tree.ends++;
          next = placeFor(event);
          at.next.set(event.key, next);
          added = branched = true;
        }
        at = next;
      }
      if (event.id === undefined || event.proofs.length === 0) continue;
      let proofs = tree.proofs.get(event.id);
      if (proofs === undefined) tree.proofs.set(event.id, (proofs = new Map<string, JsonObject>()));
      const before = proofs.size;
      for (const proof of event.proofs) {
        const key = canonicalize(proof);
        if (proofs.has(key)) continue;
        if (proofs.size < MAX_PROOFS) proofs.set(key, proof);
        else tree.full = true;
        added = true;
      }
      // The proofs of several copies may be more together than one record
      // carries (core 1.6). The book cannot tell which to leave out.
      if (before > 0 && proofs.size > before && !fits(eventOf(tree, at) as JsonObject)) {
        tree.full = true;
      }
    }
    if (tree.ends > MAX_COPIES) tree.full = true;
    // The latest time up to which a copy that ended here was known.
    const further = at.asOf === undefined || asOf > at.asOf;
    if (further) at.asOf = asOf;
    if (added || further) this.#changed(mind);
    return tree.full ? TOO_MANY : ok(mind);
  }

  /**
   * Stops holding anything of a mind's log.
   *
   * @returns Whether anything was held.
   */
  drop(mind: string): boolean {
    const held = this.#held.delete(mind);
    if (held) this.#changed(mind);
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
   * The book's own copy of a log, event by event: its genesis, which gives
   * the address, and one event more than it will read, so that a log too
   * long is seen to be. The address comes from the copy that is verified
   * later, never from a second reading of what the caller holds.
   */
  #take(
    events: unknown,
    asOf: Instant,
  ): Validation<{ readonly mind: string; readonly copy: readonly [Taken, ...Taken[]] }> {
    try {
      if (typeof (asOf as unknown) !== "bigint") {
        return no("the time up to which the log is known is not a time", "core 9.4");
      }
      if (!Array.isArray(events)) return NOT_A_LOG;
      const length: unknown = events.length;
      if (typeof length !== "number" || !Number.isSafeInteger(length)) return NOT_A_LOG;
      const genesis = validateJson(events[0]);
      if (!genesis.ok) return NOT_A_LOG;
      const first = this.#sorted(genesis.value);
      // A first value with no content ID is the genesis of no mind.
      if (first.id === undefined) return NOT_A_LOG;
      const copy: [Taken, ...Taken[]] = [first];
      const mind = mindAddress(first.id);
      for (let i = 1; i < length && i <= this.#maxEvents && !copy[i - 1]?.last; i++) {
        copy.push(this.#sorted(events[i]));
      }
      return ok({ mind, copy });
    } catch {
      // The first event has no content ID, so it is no genesis.
      return NOT_A_LOG;
    }
  }

  /** One event as given, as the tree keeps it. It judges nothing but what kind of value it is. */
  #sorted(raw: unknown): Taken {
    const plain = validateJson(raw);
    if (!plain.ok) {
      // Not plain data of this version. If the verifier cannot read it for
      // what it says of itself, it may be an event all the same, and is kept
      // as that (Layer 1, 4.9). Otherwise it is nothing.
      const unread = cannotRead(raw, this.#understood, "");
      return unread === undefined
        ? { key: "not data", body: NOT_DATA, id: undefined, proofs: [], last: true }
        : {
            key: `unread ${canonicalize(unread.issues[0])}`,
            body: new Unread(unread),
            id: undefined,
            proofs: [],
            last: true,
          };
    }
    const value = plain.value;
    if (!isJsonObject(value)) {
      // No event, and nothing tells what would follow it. What it is, is said when it is judged.
      return {
        key: `odd ${canonicalize(value)}`,
        body: value,
        id: undefined,
        proofs: [],
        last: true,
      };
    }
    // The proofs are kept apart, to be held with any others of the same
    // event: a content ID does not cover them (core 3.1). So the event has
    // its place whatever came as its proofs, and what follows it is kept.
    // That holds for an event the verifier cannot read, too: it is judged by
    // what it says of itself, whatever its proofs are (Layer 1, 4.9).
    const { proof, ...body } = value;
    const id = contentId(value);
    return { key: id, body, id, proofs: proofsOf(value, proof), last: false };
  }

  /** Forgets the verdict on a mind, and every verdict that asked for its log, and so on up. */
  #changed(mind: string): void {
    const pending = [mind];
    for (let next = pending.pop(); next !== undefined; next = pending.pop()) {
      this.#verified.delete(next);
      const askers = this.#askedBy.get(next);
      if (askers === undefined) continue;
      this.#askedBy.delete(next);
      pending.push(...askers);
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
    return this.#log(mind, 0);
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
    this.#visiting.add(mind);
    let result: Validation<VerifiedLog>;
    try {
      result = deepFreeze(this.#resolve(mind, tree, depth));
    } finally {
      this.#visiting.delete(mind);
    }
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
