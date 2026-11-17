// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The identity logs a verifier holds, with the evidence it holds of when
 * their events existed: what every question about a mind's keys is asked of.
 */

import { contentId, type Instant, mindAddress } from "@oip/core";
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
 * verified to its end. One that did not may hold a later event this verifier
 * could not judge, a removal among them, so what is left is not known to be
 * the whole log.
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

/** Whether `held` has every event of `branch` and more: `branch` is an earlier state of it. */
function longer(held: HeldBranch, branch: HeldBranch): boolean {
  return held.events.length > branch.events.length && begins(branch.events, held.events);
}

const EARLIER: Rejection = {
  ok: false,
  issues: [
    {
      path: "",
      message:
        "the log is the beginning of a longer log already held for this mind, and a log is not replaced by an earlier state of itself",
      clause: "L1 7.2",
    },
  ],
};

const NOT_A_LOG: Rejection = {
  ok: false,
  issues: [
    {
      path: "",
      message: "an identity log is an array of at least one event, the first a Genesis",
      clause: "L1 3.1",
    },
  ],
};

/**
 * The identity logs a verifier holds, one or more branches for each mind,
 * verified when first asked for against the evidence the book was made with.
 *
 * It holds a log only as data: nothing is fetched and no clock is read. A
 * log is held with the time up to which it is known to be complete (core
 * 9.4), which the caller states.
 *
 * It holds whatever it is given and judges it when asked, so a log that
 * does not verify stays held, and answers with its rejection, until another
 * is held in its place or it is dropped. A verifier that takes logs from
 * outside holds what `witnessLog` found to verify.
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
  /** How often a log was refused for where it was asked from, not for what it is. */
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
   * must not undo a removal the verifier already knows of (Layer 1, 7.2).
   * To go back all the same, `drop` the mind first. A log that conflicts
   * with the one held is replaced without being weighed against it; to weigh
   * them by evidence, use `holdBranch`.
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
    if (held.some((other) => longer(other, branch))) return EARLIER;
    this.#set(mind, [branch]);
    return ok(mind);
  }

  /**
   * Holds `events` as a further branch of a mind's log (Layer 1, Section 7),
   * beside what is held for it. Each branch is known up to its own time.
   *
   * A log that continues a branch held takes its place. One that is the
   * beginning of a branch held adds nothing, and is not held.
   */
  holdBranch(events: unknown, asOf: Instant): Validation<string> {
    const taken = this.#take(events, asOf);
    if (!taken.ok) return taken;
    const { mind, branch } = taken.value;
    const held = this.#held.get(mind) ?? [];
    if (held.some((other) => longer(other, branch))) return ok(mind);
    // What is left conflicts with the new branch, or is unlike it.
    const [first, ...rest] = held.filter((other) => !begins(other.events, branch.events));
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
        const raw: unknown = events[i];
        const copy = validateJson(raw);
        // An event that is not plain data is refused when the log is verified.
        branch.push(copy.ok ? copy.value : raw);
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
   * The verified log of a mind: verified when first asked for, with its
   * members' logs, and with duplicity resolved among the branches held. The
   * log is frozen.
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
    const before = this.#refusals;
    this.#visiting.add(mind);
    let result: Validation<VerifiedLog>;
    try {
      result = this.#verify(mind, held, depth);
    } finally {
      this.#visiting.delete(mind);
    }
    // A log verifies only if every member's log it asks for does, so one
    // that verifies does so wherever it is asked for. One that fails may
    // have failed for where it was asked from: a log below it was refused
    // for the depth, or for being verified already. That verdict is kept
    // only at the top, where it is the log's own (Layer 1, 4.7).
    if (result.ok || depth === 0 || this.#refusals === before) this.#verified.set(mind, result);
    return result;
  }

  #verify(mind: string, held: Held, depth: number): Validation<VerifiedLog> {
    const context = (asOf: Instant): LogContext => ({
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
    });
    const [first, ...others] = held;
    const resolved =
      others.length === 0
        ? verifyLog(first.events, context(first.asOf))
        : this.#resolve(held, context);
    if (resolved.ok && resolved.value.mind !== mind) {
      return no("the log held for this mind is the log of another", "L1 2.2");
    }
    return resolved;
  }

  #resolve(held: Held, context: (asOf: Instant) => LogContext): Validation<VerifiedLog> {
    const replayed = held.map((branch) => verifyLogPrefix(branch.events, context(branch.asOf)));
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
