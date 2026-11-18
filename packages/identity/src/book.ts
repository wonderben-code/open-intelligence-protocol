// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The identity logs a verifier holds, with the evidence it holds of when
 * their events existed: what every question about a mind's keys is asked of.
 */

import { canonicalize, contentId, type Instant, mindAddress } from "@oip/core";
import { type Validation, validateJson } from "@oip/schema";

import type { EvidenceView } from "./evidence.ts";
import {
  type LogContext,
  MAX_HEIGHT,
  maxEventsOf,
  understoodOf,
  verifyLog,
  verifyLogPrefix,
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
 * Whether `a` is the beginning of `b`, or all of it. Each event names the
 * one before it, so two logs of one mind that hold the same event at a
 * position hold the same events up to it.
 */
function begins(a: readonly unknown[], b: readonly unknown[]): boolean {
  if (a.length > b.length) return false;
  const last = idOf(a.at(-1));
  return last !== undefined && last === idOf(b[a.length - 1]);
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
 * The branches that are left when the evidence has decided must each have
 * verified to its end. The book judges the copies it holds as they are: one
 * that did not verify to its end may hold a later event this verifier could
 * not judge, a removal among them, so what is left is not known to be the
 * whole log (Layer 1, 4.9, 7.3).
 */
function settled(branches: Branches, log: VerifiedLog): Validation<VerifiedLog> {
  return branches.find((branch) => branch.failure !== undefined)?.failure ?? ok(log);
}

/**
 * Layer 1, 7.3: one log from the branches held for a mind. Never by length
 * or by recency: where two branches part, the event with strictly the
 * earliest evidence wins. If the evidence cannot separate them the mind is
 * duplicitous: only the events before that position stand, and the later
 * events of every branch are kept, so that their removals all apply.
 *
 * A branch takes part with the events it has that verify, even if it does
 * not verify to its end: an event this verifier cannot read further than is
 * no reason for the other branch to win.
 *
 * @param branches - The branches whose genesis verified. At least one.
 */
function resolveBranches(branches: Branches, evidence: EvidenceView): Validation<VerifiedLog> {
  let candidates: Branches = branches;
  for (let position = 0; ; position++) {
    // The branches that go on, by the event each has at this position.
    const heads = new Map<string, [Branch, ...Branch[]]>();
    for (const branch of candidates) {
      const head = branch.log.entries[position]?.state.head;
      if (head === undefined) continue;
      const same = heads.get(head);
      if (same === undefined) heads.set(head, [branch]);
      else same.push(branch);
    }
    const [first, ...others] = heads.values();
    // Every branch left has ended here, so they are one log.
    if (first === undefined) return settled(candidates, candidates[0].log);
    if (others.length === 0) {
      // One event at this position. A branch that has ended is a prefix, not a fork.
      candidates = first;
      continue;
    }
    let earliest: { readonly seen: Instant; readonly branches: Branches } | undefined;
    let tied = false;
    for (const [head, same] of heads) {
      const seen = evidence.eventSeen(head);
      // A branch that verified had evidence for its events. One whose evidence is gone cannot win.
      if (seen === undefined) continue;
      if (earliest === undefined || seen < earliest.seen) {
        earliest = { seen, branches: same };
        tied = false;
      } else if (seen === earliest.seen) {
        tied = true;
      }
    }
    if (earliest === undefined || tied) {
      return settled(candidates, duplicitous(candidates, position));
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

/** Whether two copies hold the same events, proofs and all, as far as the shorter goes. */
function identical(a: readonly unknown[], b: readonly unknown[]): boolean {
  try {
    for (let i = Math.min(a.length, b.length) - 1; i >= 0; i--) {
      if (canonicalize(a[i]) !== canonicalize(b[i])) return false;
    }
    return true;
  } catch {
    // A copy with something in it that has no canonical form is like no other.
    return false;
  }
}

/** What is held in the place of an event that was not plain data: nothing that can be read again, and no event. */
const UNREADABLE = Symbol("not plain data");

const EARLIER: Rejection = deepFreeze({
  ok: false,
  issues: [
    {
      path: "",
      message:
        "the log held for this mind verifies further than this one, which is an earlier state of it: a log is not replaced by an earlier state of itself",
      clause: "L1 4.9",
    },
  ],
});

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
 * The identity logs a verifier holds, one or more branches for each mind,
 * verified when first asked for against the evidence the book was made with.
 *
 * It holds a log only as data: nothing is fetched and no clock is read. A
 * log is held with the time up to which it is known to be complete (core
 * 9.4), which the caller states.
 *
 * It holds whatever it is given and judges it when asked, as it is: a copy
 * with an event that does not verify is a log that does not verify, and the
 * book answers with that rejection until a copy that verifies as far is held
 * in its place, or the mind is dropped. A verifier that takes logs from
 * outside asks `witnessLog` first, which says what verified, and whether
 * what did not is invalid or only beyond this verifier's judgement.
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
  /**
   * Answers that held only where they were asked from, by the path of minds
   * that led there. They are kept for the length of one question, so that a
   * log asked for again along the same path is not verified again.
   */
  readonly #here = new Map<string, Validation<VerifiedLog>>();
  /** How often a log was refused, or answered, for where it was asked from and not for what it is. */
  #refusals = 0;

  constructor(evidence: EvidenceView, options?: LogBookOptions) {
    this.evidence = evidence;
    this.#maxEvents = maxEventsOf(own(options, "maxEvents"));
    this.#understood = understoodOf(own(options, "understood"));
  }

  /**
   * Holds `events` as a mind's log, in place of whatever was held for it.
   * The book takes its own copy: changing `events` afterwards changes
   * nothing here.
   *
   * A log is not replaced by an earlier state of itself: a source that lags
   * must not undo a removal the verifier already knows of (Layer 1, 4.9).
   * "Earlier" is judged by what verifies. A copy held that ends in an
   * invalid event, or whose proofs were lost, gives way to a clean one; a
   * clean one does not give way to a copy of its beginning. To go back all
   * the same, `drop` the mind first. A log that conflicts with the one held
   * is replaced without being weighed against it; to weigh them by evidence,
   * use `holdBranch`.
   *
   * @param asOf - The time up to which the log is known to be complete: when
   *   a witness the verifier trusts served it, or the present for a verifier
   *   that follows the log itself (core 9.4).
   * @returns The mind's address, or why nothing was held.
   */
  hold(events: unknown, asOf: Instant): Validation<string> {
    const taken = this.#take(events, asOf);
    if (!taken.ok) return taken;
    const { mind, branch } = taken.value;
    const held = this.#held.get(mind) ?? [];
    const earlier = held.some(
      (other) => begins(branch.events, other.events) && this.#further(mind, other, branch),
    );
    if (earlier) return EARLIER;
    this.#set(mind, [branch]);
    return ok(mind);
  }

  /**
   * Holds `events` as a further branch of a mind's log (Layer 1, Section 7),
   * beside what is held for it. Each branch is known up to its own time.
   *
   * It returns the address whether or not the copy added anything. A copy
   * that is the beginning of a branch held, and verifies no further than
   * that branch does, adds nothing and is not held. A branch held that is
   * the beginning of the new copy, and verifies no further than it, gives
   * way to it.
   */
  holdBranch(events: unknown, asOf: Instant): Validation<string> {
    const taken = this.#take(events, asOf);
    if (!taken.ok) return taken;
    const { mind, branch } = taken.value;
    const held = this.#held.get(mind) ?? [];
    const nothingNew = held.some(
      (other) => begins(branch.events, other.events) && !this.#further(mind, branch, other),
    );
    if (nothingNew) return ok(mind);
    // What is left conflicts with the new branch, is unlike it, or verifies further than it.
    const [first, ...rest] = held.filter(
      (other) => !(begins(other.events, branch.events) && !this.#further(mind, other, branch)),
    );
    this.#set(mind, first === undefined ? [branch] : [first, ...rest, branch]);
    return ok(mind);
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

  #set(mind: string, held: Held): void {
    this.#held.set(mind, held);
    this.#changed(mind);
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
   * Whether copy `a` of a mind's log verifies further than copy `b`: more of
   * its events, from the first, verify.
   */
  #further(mind: string, a: HeldBranch, b: HeldBranch): boolean {
    if (identical(a.events, b.events)) {
      // The same events as far as the shorter goes, so the shorter verifies
      // no further than the longer, and the longer further only past its end.
      return a.events.length > b.events.length && this.#reach(mind, a) > b.events.length;
    }
    return this.#reach(mind, a) > this.#reach(mind, b);
  }

  /** How many events of a copy of a mind's log verify, from the first. */
  #reach(mind: string, copy: HeldBranch): number {
    const held = this.#held.get(mind);
    const verdict = this.#verified.get(mind);
    // The one copy held, already verified: its log is what verified of it.
    if (held?.length === 1 && held[0] === copy && verdict?.ok === true) {
      return verdict.value.entries.length;
    }
    this.#visiting.add(mind);
    try {
      const replayed = verifyLogPrefix(copy.events, this.#context(mind, copy.asOf, 0));
      return replayed.log?.entries.length ?? 0;
    } finally {
      this.#visiting.delete(mind);
      this.#here.clear();
    }
  }

  /**
   * The verified log of a mind: verified when first asked for, with its
   * members' logs, and with duplicity resolved among the branches held. The
   * answer is frozen.
   */
  log(mind: string): Validation<VerifiedLog> {
    if (typeof (mind as unknown) !== "string") {
      return no("a mind is named by its address, a string", "L1 2.2");
    }
    try {
      return this.#log(mind, 0);
    } finally {
      this.#here.clear();
    }
  }

  /** `depth` counts the collectives between the log asked for and this one (Layer 1, 4.7). */
  #log(mind: string, depth: number): Validation<VerifiedLog> {
    const known = this.#verified.get(mind);
    if (known !== undefined) return known;
    const held = this.#held.get(mind);
    if (held === undefined) return no(`no identity log is held for ${mind}`, "L1 6.3");
    if (depth > MAX_HEIGHT) {
      this.#refusals++;
      return no(`collectives nest at most ${MAX_HEIGHT} deep`, "L1 4.7");
    }
    if (this.#visiting.has(mind)) {
      this.#refusals++;
      return no("no collective is a member of itself, directly or indirectly", "L1 4.7");
    }
    const path = [...this.#visiting, mind].join(" ");
    const here = this.#here.get(path);
    if (here !== undefined) {
      this.#refusals++;
      return here;
    }
    const before = this.#refusals;
    this.#visiting.add(mind);
    let result: Validation<VerifiedLog>;
    try {
      result = deepFreeze(this.#verify(mind, held, depth));
    } finally {
      this.#visiting.delete(mind);
    }
    // An answer may depend on where the log was asked from: a log below it
    // was refused for the depth, or for being verified already, and with
    // branches held even a log that verifies may then be another log than
    // it is. Such an answer is kept only at the top, where it is the log's
    // own (Layer 1, 4.7), and otherwise for this question alone.
    if (depth === 0 || this.#refusals === before) this.#verified.set(mind, result);
    else this.#here.set(path, result);
    return result;
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
    const [first, ...others] = held;
    const context = this.#context(mind, first.asOf, depth);
    const resolved =
      others.length > 0 ? this.#resolve(mind, held, depth) : verifyLog(first.events, context);
    if (resolved.ok && resolved.value.mind !== mind) {
      return no("the log held for this mind is the log of another", "L1 2.2");
    }
    return resolved;
  }

  #resolve(mind: string, held: Held, depth: number): Validation<VerifiedLog> {
    const replayed = held.map((branch) =>
      verifyLogPrefix(branch.events, this.#context(mind, branch.asOf, depth)),
    );
    const verified = replayed.flatMap(({ log, failure }): Branch[] =>
      log === undefined ? [] : [{ log, failure }],
    );
    const [one, ...rest] = verified;
    // A branch whose genesis does not verify is no branch. With none that
    // does, the reasons of the first are given.
    if (one === undefined) return replayed[0]?.failure ?? NOT_A_LOG;
    return resolveBranches([one, ...rest], this.evidence);
  }
}
