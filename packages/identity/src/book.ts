// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The identity logs a verifier holds, with the evidence it holds of when
 * their events existed: what every question about a mind's keys is asked of.
 */

import { contentId, type Instant, mindAddress } from "@oip/core";
import { IMPLEMENTATION_LIMIT, type Validation, validateJson } from "@oip/schema";

import type { EvidenceView } from "./evidence.ts";
import {
  type LogContext,
  MAX_HEIGHT,
  maxEventsOf,
  type Replayed,
  understoodOf,
  verifyLogPrefix,
  whole,
} from "./log.ts";
import { deepFreeze, no, ok, own, type Rejection } from "./result.ts";
import type { LogEntry, VerifiedLog } from "./state.ts";

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

/** One copy of a mind's log, as held. */
interface HeldBranch {
  /** The book's own copy of the events. */
  readonly events: readonly unknown[];
  /** core 9.4: the time up to which this copy is known to be complete. */
  readonly asOf: Instant;
}

/** One log, or the conflicting branches of one (Layer 1, Section 7). */
type Held = readonly [HeldBranch, ...HeldBranch[]];

/** The content ID of an event as held, or `undefined` if it has none. */
function idOf(event: unknown): string | undefined {
  try {
    return contentId(event);
  } catch {
    return undefined;
  }
}

/**
 * What a copy of a log shows, as this verifier judges it now (Layer 1, 4.9):
 * the events that verify, and the event after them if the verifier could not
 * judge it. An invalid event shows nothing, being no event.
 */
interface Shown {
  /** The content IDs of the events that verify, from the first. */
  readonly ids: readonly string[];
  /** The event after them that did not verify, if the copy has one. */
  readonly next:
    | {
        /** Whether the verifier could not judge it. It may then be an event of the log. */
        readonly undecided: boolean;
        /** Its content ID, if it has one. */
        readonly id: string | undefined;
      }
    | undefined;
}

/**
 * Whether `a` is the beginning of `b`, or all of it. Each event names the
 * one before it, so two verified logs of one mind that hold the same event
 * at a position hold the same events up to it.
 */
function begins(a: readonly string[], b: readonly string[]): boolean {
  return a.length <= b.length && (a.length === 0 || a.at(-1) === b[a.length - 1]);
}

/**
 * Whether copy `b` shows everything copy `a` shows: every event of `a` that
 * verifies, and the event of `a` that the verifier could not judge, if there
 * is one. That event may be an event of the log, and may remove a key (Layer
 * 1, 4.9), so `b` must hold the same event at that position, verified or
 * unjudged in its turn. Another event there, or none, is not the same.
 */
function covers(b: Shown, a: Shown): boolean {
  if (!begins(a.ids, b.ids)) return false;
  const open = a.next;
  if (open?.undecided !== true) return true;
  if (open.id === undefined) return false;
  const position = a.ids.length;
  if (b.ids.length > position) return b.ids[position] === open.id;
  return b.next?.undecided === true && b.next.id === open.id;
}

/** What a `LogBook` is made with. */
export interface LogBookOptions {
  /** The longest log to read. See `LogContext.maxEvents`. */
  readonly maxEvents?: number;
  /** core 8.3: the extension namespaces the caller implements. See `LogContext.understood`. */
  readonly understood?: Iterable<string>;
}

/** A branch of a mind's log, as far as it verified. */
interface Branch {
  readonly log: VerifiedLog;
  /** Why it verified no further, if it did not verify to its end. */
  readonly failure: Rejection | undefined;
}

type Branches = readonly [Branch, ...Branch[]];

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

/**
 * Layer 1, 7.3: one log from the copies held for a mind. Never by length or
 * by recency: where two copies part, the event with strictly the earliest
 * evidence wins. If the evidence cannot separate them the mind is
 * duplicitous: only the events before that position stand, and the later
 * events of every copy are kept, so that their removals all apply.
 *
 * A copy takes part with the events it has that verify. But the verifier
 * knows the log only as far as the copies it relies on verify: a copy that
 * is still in the contest when a position is reached, and holds an event
 * there that did not verify, makes the log one that does not verify,
 * whatever another copy holds at that position. That event may be the
 * mind's own (Layer 1, 4.9).
 *
 * @param branches - The copies whose genesis verified. At least one.
 */
function resolveBranches(branches: Branches, evidence: EvidenceView): Validation<VerifiedLog> {
  let candidates: Branches = branches;
  for (let position = 0; ; position++) {
    const stuck = candidates.find(
      (branch) => branch.failure !== undefined && branch.log.entries.length === position,
    );
    if (stuck?.failure !== undefined) return stuck.failure;
    // The copies that go on, by the event each has at this position.
    const heads = new Map<string, [Branch, ...Branch[]]>();
    for (const branch of candidates) {
      const head = branch.log.entries[position]?.state.head;
      if (head === undefined) continue;
      const same = heads.get(head);
      if (same === undefined) heads.set(head, [branch]);
      else same.push(branch);
    }
    const [first, ...others] = heads.values();
    // Every copy left has ended here, so they are one log.
    if (first === undefined) return ok(candidates[0].log);
    if (others.length === 0) {
      // One event at this position. A copy that has ended is a beginning, not a fork.
      candidates = first;
      continue;
    }
    let earliest: { readonly seen: Instant; readonly branches: Branches } | undefined;
    let tied = false;
    for (const [head, same] of heads) {
      const seen = evidence.eventSeen(head);
      // A copy that verified had evidence for its events. One whose evidence is gone cannot win.
      if (seen === undefined) continue;
      if (earliest === undefined || seen < earliest.seen) {
        earliest = { seen, branches: same };
        tied = false;
      } else if (seen === earliest.seen) {
        tied = true;
      }
    }
    if (earliest === undefined || tied) {
      // The later events of every copy that is left apply, so each must have verified to its end.
      const unread = candidates.find((branch) => branch.failure !== undefined);
      return unread?.failure ?? ok(duplicitous(candidates, position));
    }
    candidates = earliest.branches;
  }
}

/**
 * @param position - Where the branches part. Never 0: logs with two geneses are two minds.
 */
function duplicitous(candidates: Branches, position: number): VerifiedLog {
  const logs = candidates.map((branch) => branch.log);
  const [base] = candidates;
  const [genesis, ...later] = base.log.entries;
  return deepFreeze({
    ...base.log,
    // Known only as far as the branch that is known least far.
    asOf: logs.reduce(
      (earliest, log) => (log.asOf < earliest ? log.asOf : earliest),
      base.log.asOf,
    ),
    entries: [genesis, ...later.slice(0, position - 1)],
    children: base.log.children.filter((entry) => entry.position < position),
    // What the branches share, once, and then what each declares after they part.
    revocations: [
      ...base.log.revocations.filter((entry) => entry.position < position),
      ...logs.flatMap((log) => log.revocations.filter((entry) => entry.position >= position)),
    ],
    duplicitous: true,
    branchTails: logs.flatMap((log): LogEntry[] => log.entries.slice(position)),
  });
}

/** What is held in the place of an event that was not plain data: nothing that can be read again, and no event. */
const UNREADABLE = Symbol("not plain data");

/**
 * The most copies of one mind's log a book holds. Two that conflict are
 * duplicity; a mind with more is rare, and every copy held is judged again
 * with every question about the mind.
 */
const MAX_COPIES = 8;

const refusal = (message: string, clause: string): Rejection =>
  deepFreeze({ ok: false, issues: [{ path: "", message, clause }] });

const EARLIER = refusal(
  "the log held for this mind verifies further than this one, which is an earlier state of it: a log is not replaced by an earlier state of itself",
  "L1 4.9",
);

const UNJUDGED = refusal(
  "the log held for this mind has an event this verifier cannot judge, which this copy does not have: it may be an event of the log, so the copy does not take its place",
  "L1 4.9",
);

const TOO_MANY = refusal(
  `more than ${MAX_COPIES} copies of this mind's log would be held, none of which shows what another does`,
  IMPLEMENTATION_LIMIT,
);

const TOO_DEEP = refusal(`collectives nest at most ${MAX_HEIGHT} deep`, "L1 4.7");

const IN_ITSELF = refusal("no collective is a member of itself, directly or indirectly", "L1 4.7");

const TOO_MUCH = refusal(
  "this question has asked for more logs than a sound set of the logs held would need",
  IMPLEMENTATION_LIMIT,
);

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

/**
 * The identity logs a verifier holds, one or more copies for each mind,
 * verified when first asked for against the evidence the book was made with.
 *
 * It holds a log only as data: nothing is fetched and no clock is read. A
 * log is held with the time up to which it is known to be complete (core
 * 9.4), which the caller states. A copy is for a source the verifier trusts
 * to serve the whole log: nothing in a log can show that it lacks nothing.
 *
 * It judges what it holds as it is. A copy with an event that does not
 * verify is a log that does not verify, and the book does not shorten it.
 * A verifier that takes logs from outside asks `witnessLog` first, which
 * says what to hold.
 *
 * It keeps what it has been shown (Layer 1, 4.9). A copy takes the place of
 * another only if it shows everything the other does: every event that
 * verifies, and the event the verifier could not judge, if the other has
 * one. So no copy undoes a removal the verifier knows of, or may be looking
 * at without being able to read it. `drop` is how a caller says otherwise.
 *
 * A verdict is kept until a log it rests on changes. The book cannot see its
 * evidence change: call `forget` when a time it has given may have moved.
 */
export class LogBook implements IdentityView {
  /** The evidence every log and proof is judged against. */
  readonly evidence: EvidenceView;
  readonly #maxEvents: number;
  readonly #understood: ReadonlySet<string>;
  readonly #held = new Map<string, Held>();
  readonly #verified = new Map<string, Validation<VerifiedLog>>();
  /** For each mind, the minds whose verdicts asked for its log. */
  readonly #askedBy = new Map<string, Set<string>>();
  readonly #visiting = new Set<string>();
  /** How often a log was refused for where it was asked from, and not for what it is. */
  #refusals = 0;
  /** The logs still to be verified for the question being answered, before it is refused. */
  #budget = 0;

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
   * The copy takes the place of every copy held that shows nothing more than
   * it does. Beside a copy that it conflicts with, or that holds an event it
   * lacks which the verifier cannot judge, it is held too, and `log`
   * resolves them (Layer 1, 7.3): never by which came later.
   *
   * It is not held if a copy held already shows everything it does:
   *
   * - an earlier state of the log held is refused, so that a source that
   *   lags or lies does not undo a removal the verifier knows of;
   * - a copy without an event that the copy held has, and that the verifier
   *   cannot judge, is refused: that event may be a removal;
   * - a copy that ends in an invalid event, beside the same log without it,
   *   is refused with what is wrong with that event.
   *
   * To go back all the same, `drop` the mind first.
   *
   * @param asOf - The time up to which the log is known to be complete: when
   *   a witness the verifier trusts served it, or the present for a verifier
   *   that follows the log itself (core 9.4).
   * @returns The mind's address, or why the copy was not held.
   */
  hold(events: unknown, asOf: Instant): Validation<string> {
    return this.#admit(events, asOf).answer;
  }

  /**
   * As `hold`, for a copy that is expected to conflict with the log held, or
   * to add nothing: it returns the mind's address whenever the copy could be
   * read, whether or not it was held.
   */
  holdBranch(events: unknown, asOf: Instant): Validation<string> {
    const { mind, answer } = this.#admit(events, asOf);
    return mind === undefined ? answer : ok(mind);
  }

  /**
   * Stops holding any log for a mind.
   *
   * @returns Whether one was held.
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
   * Takes a copy in, or says why not.
   *
   * @returns The answer `hold` gives, and the mind if the copy could be read.
   */
  #admit(
    events: unknown,
    asOf: Instant,
  ): { readonly mind?: string; readonly answer: Validation<string> } {
    const taken = this.#take(events, asOf);
    if (!taken.ok) return { answer: taken };
    const { mind, branch } = taken.value;
    const held = this.#held.get(mind);
    if (held === undefined) {
      // Nothing to weigh it against: it is verified when it is first asked for.
      this.#held.set(mind, [branch]);
      this.#changed(mind);
      return { mind, answer: ok(mind) };
    }
    const replayed = this.#replay(mind, branch);
    const shown = shownBy(branch, replayed);
    const kept: HeldBranch[] = [];
    for (const other of held) {
      const theirs = this.#shown(mind, other);
      const all = covers(shown, theirs);
      if (covers(theirs, shown)) {
        // The copy held shows everything this one does. If each shows what
        // the other does, the one without an invalid event stays, and then
        // the one known up to the later time.
        const cleaner = (theirs.next === undefined) !== (shown.next === undefined);
        const stays = cleaner ? theirs.next === undefined : other.asOf > branch.asOf;
        if (!all) {
          const answer = shown.ids.length < theirs.ids.length ? EARLIER : UNJUDGED;
          return { mind, answer };
        }
        if (stays) {
          // The same log with an invalid event after it: say what is wrong
          // with that event. The same copy, known less far: nothing is wrong.
          return { mind, answer: (cleaner ? replayed.failure : undefined) ?? ok(mind) };
        }
      }
      if (!all) kept.push(other);
    }
    if (kept.length >= MAX_COPIES) return { mind, answer: TOO_MANY };
    const [first, ...rest] = kept;
    this.#held.set(mind, first === undefined ? [branch] : [first, ...rest, branch]);
    this.#changed(mind);
    // Verified a moment ago, alone and from the top: that is the verdict on it.
    if (kept.length === 0) this.#verified.set(mind, deepFreeze(whole(replayed)));
    return { mind, answer: ok(mind) };
  }

  /**
   * The book's own copy of a log: its genesis, which gives the address, and
   * one event more than it will read, so that a log too long is seen to be.
   * The address comes from the copy that is verified later, never from a
   * second reading of what the caller holds.
   */
  #take(
    events: unknown,
    asOf: Instant,
  ): Validation<{ readonly mind: string; readonly branch: HeldBranch }> {
    try {
      if (typeof (asOf as unknown) !== "bigint") {
        return no("the time up to which the log is known is not a time", "core 9.4");
      }
      if (!Array.isArray(events)) return NOT_A_LOG;
      const length: unknown = events.length;
      if (typeof length !== "number" || !Number.isSafeInteger(length)) return NOT_A_LOG;
      const genesis = validateJson(events[0]);
      if (!genesis.ok) return NOT_A_LOG;
      const mind = mindAddress(contentId(genesis.value));
      const branch: unknown[] = [genesis.value];
      for (let i = 1; i < length && i <= this.#maxEvents; i++) {
        const copy = validateJson(events[i]);
        // What is not plain data is no event, now or when the log is verified.
        branch.push(copy.ok ? copy.value : UNREADABLE);
      }
      return ok({ mind, branch: { events: branch, asOf } });
    } catch {
      // The first event has no content ID, so it is no genesis.
      return NOT_A_LOG;
    }
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

  /** One copy of a mind's log, verified as far as it goes, as a question of its own. */
  #replay(mind: string, copy: HeldBranch): Replayed {
    this.#begin();
    this.#visiting.add(mind);
    try {
      return verifyLogPrefix(copy.events, this.#context(mind, copy.asOf, 0));
    } finally {
      this.#visiting.delete(mind);
    }
  }

  /** What a copy held for a mind shows. */
  #shown(mind: string, copy: HeldBranch): Shown {
    const held = this.#held.get(mind);
    const verdict = this.#verified.get(mind);
    // The one copy held, already verified: every event of it verifies.
    if (held?.length === 1 && held[0] === copy && verdict?.ok === true) {
      return { ids: verdict.value.entries.map((entry) => entry.state.head), next: undefined };
    }
    return shownBy(copy, this.#replay(mind, copy));
  }

  /** A question starts: it may verify each log held twice over, and a few more. */
  #begin(): void {
    this.#budget = 2 * this.#held.size + 16;
  }

  /**
   * The verified log of a mind: verified when first asked for, with its
   * members' logs, and with duplicity resolved among the copies held. The
   * answer is frozen if the book keeps it.
   */
  log(mind: string): Validation<VerifiedLog> {
    if (typeof (mind as unknown) !== "string") {
      return no("a mind is named by its address, a string", "L1 2.2");
    }
    this.#begin();
    return this.#log(mind, 0);
  }

  /** `depth` counts the collectives between the log asked for and this one (Layer 1, 4.7). */
  #log(mind: string, depth: number): Validation<VerifiedLog> {
    const known = this.#verified.get(mind);
    if (known !== undefined) return known;
    const held = this.#held.get(mind);
    if (held === undefined) return no(`no identity log is held for ${mind}`, "L1 6.3");
    if (depth > MAX_HEIGHT) return this.#here(TOO_DEEP);
    if (this.#visiting.has(mind)) return this.#here(IN_ITSELF);
    // A sound set of logs asks for each once: its answer is kept. Only logs
    // that nest too deep, or in a ring, are verified again from each place
    // they are asked from, and a hostile set of them could ask without end.
    if (this.#budget <= 0) return this.#here(TOO_MUCH);
    this.#budget--;
    const before = this.#refusals;
    this.#visiting.add(mind);
    let result: Validation<VerifiedLog>;
    try {
      result = deepFreeze(this.#verify(mind, held, depth));
    } finally {
      this.#visiting.delete(mind);
    }
    // An answer may depend on where the log was asked from: a log below it
    // was refused for the depth, for being verified already, or for the work
    // the question had done by then. With copies that conflict, even a log
    // that verifies may then be another log than it is. Such an answer is
    // kept only at the top, where it is the log's own (Layer 1, 4.7).
    if (depth === 0 || this.#refusals === before) this.#verified.set(mind, result);
    return result;
  }

  /**
   * A refusal for where a log was asked from, or for the work its question
   * had done by then. It is not the log's own answer, and it is counted so
   * that no answer that rests on it is kept as one.
   */
  #here(refused: Rejection): Rejection {
    this.#refusals++;
    return refused;
  }

  #context(mind: string, asOf: Instant, depth: number): LogContext {
    return {
      evidence: this.evidence,
      asOf,
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

  #verify(mind: string, held: Held, depth: number): Validation<VerifiedLog> {
    const replayed = held.map((copy) =>
      verifyLogPrefix(copy.events, this.#context(mind, copy.asOf, depth)),
    );
    const [only, ...others] = replayed;
    if (only === undefined) return NOT_A_LOG;
    const resolved = others.length === 0 ? whole(only) : resolve(replayed, this.evidence);
    if (resolved.ok && resolved.value.mind !== mind) {
      return no("the log held for this mind is the log of another", "L1 2.2");
    }
    return resolved;
  }
}

/** What a copy shows, from how far it verified. */
function shownBy(copy: HeldBranch, replayed: Replayed): Shown {
  const ids = replayed.log?.entries.map((entry) => entry.state.head) ?? [];
  if (replayed.failure === undefined) return { ids, next: undefined };
  return { ids, next: { undecided: replayed.undecided, id: idOf(copy.events[ids.length]) } };
}

/** One log from several copies of it, each verified as far as it goes (Layer 1, 7.3). */
function resolve(replayed: readonly Replayed[], evidence: EvidenceView): Validation<VerifiedLog> {
  const branches: Branch[] = [];
  for (const { log, failure } of replayed) {
    // A copy whose first event did not verify is in the contest, and holds
    // an event at the first position that did not verify.
    if (log === undefined) return failure ?? NOT_A_LOG;
    branches.push({ log, failure });
  }
  const [first, ...rest] = branches;
  return first === undefined ? NOT_A_LOG : resolveBranches([first, ...rest], evidence);
}
