// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The identity logs a verifier holds, with the evidence it holds of when
 * their events existed: what every question about a mind's keys is asked of.
 */

import { contentId, type Instant, mindAddress } from "@oip/core";
import type { Validation } from "@oip/schema";

import type { EvidenceView } from "./evidence.ts";
import { type LogContext, MAX_HEIGHT, verifyLog } from "./log.ts";
import { no, ok } from "./result.ts";
import type { BranchTail, VerifiedLog } from "./state.ts";

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

interface Held {
  /** One log, or the conflicting branches of one (Layer 1, Section 7). */
  readonly branches: unknown[];
  readonly asOf: Instant;
}

/** What a `LogBook` is made with. */
export interface LogBookOptions {
  /** The longest log to read. See `LogContext.maxEvents`. */
  readonly maxEvents?: number;
}

/**
 * Layer 1, 7.3: one log from the branches held for a mind. Never by length
 * or by recency: where two branches part, the event with strictly the
 * earliest evidence wins. If the evidence cannot separate them the mind is
 * duplicitous: only the events before that position stand, and the later
 * events of every branch are kept, so that their removals all apply.
 *
 * @param branches - The branches that verified. At least one.
 */
function resolveBranches(
  branches: readonly [VerifiedLog, ...VerifiedLog[]],
  evidence: EvidenceView,
): VerifiedLog {
  let candidates: readonly VerifiedLog[] = branches;
  for (let position = 0; ; position++) {
    const heads = new Map<string, VerifiedLog[]>();
    for (const log of candidates) {
      const state = log.states[position];
      if (state === undefined) continue;
      heads.set(state.head, [...(heads.get(state.head) ?? []), log]);
    }
    // Every branch left has ended here, so they are one log.
    if (heads.size === 0) return candidates[0]!;
    if (heads.size > 1) {
      // A branch that verified has evidence for each of its events.
      const seen = new Map([...heads.keys()].map((head) => [head, evidence.eventSeen(head)!]));
      const first = [...seen.values()].reduce((a, b) => (b < a ? b : a));
      const winners = [...seen].filter(([, time]) => time === first).map(([head]) => head);
      if (winners.length > 1) return duplicitous(candidates, position);
      candidates = heads.get(winners[0]!)!;
      continue;
    }
    // One event at this position. A branch that has ended is a prefix, not a fork.
    candidates = [...heads.values()][0]!;
  }
}

function duplicitous(candidates: readonly VerifiedLog[], position: number): VerifiedLog {
  const base = candidates[0]!;
  const branchTails: BranchTail[] = [];
  for (const log of candidates) {
    for (let i = position; i < log.events.length; i++) {
      branchTails.push({
        time: log.times[i]!,
        state: log.states[i]!,
        event: log.events[i]!,
      });
    }
  }
  return {
    ...base,
    events: base.events.slice(0, position),
    states: base.states.slice(0, position),
    times: base.times.slice(0, position),
    duplicitous: true,
    branchTails,
  };
}

/**
 * The identity logs a verifier holds, one or more branches for each mind,
 * verified when first asked for against the evidence the book was made with.
 *
 * It holds a log only as data: nothing is fetched and no clock is read. A
 * log is held with the time up to which it is known to be complete (core
 * 9.4), which the caller states.
 */
export class LogBook implements IdentityView {
  readonly evidence: EvidenceView;
  readonly #maxEvents: number | undefined;
  readonly #held = new Map<string, Held>();
  readonly #verified = new Map<string, Validation<VerifiedLog>>();
  readonly #visiting = new Set<string>();

  constructor(evidence: EvidenceView, options?: LogBookOptions) {
    this.evidence = evidence;
    this.#maxEvents =
      options !== undefined && Object.hasOwn(options, "maxEvents") ? options.maxEvents : undefined;
  }

  /**
   * Holds `events` as a mind's log, in place of whatever was held for it.
   *
   * @param asOf - The time up to which the log is known to be complete: when
   *   a witness the verifier trusts served it, or the present for a verifier
   *   that follows the log itself (core 9.4).
   * @returns The mind's address, or why the events name none.
   */
  hold(events: unknown, asOf: Instant): Validation<string> {
    const mind = addressOf(events);
    if (mind.ok) this.#set(mind.value, { branches: [events], asOf });
    return mind;
  }

  /**
   * Holds `events` as a further branch of a mind's log (Layer 1, Section 7),
   * beside what is held for it. The time up to which the mind's log is known
   * is the earlier of the two.
   */
  holdBranch(events: unknown, asOf: Instant): Validation<string> {
    const mind = addressOf(events);
    if (mind.ok) {
      const held = this.#held.get(mind.value);
      this.#set(mind.value, {
        branches: [...(held?.branches ?? []), events],
        asOf: held !== undefined && held.asOf < asOf ? held.asOf : asOf,
      });
    }
    return mind;
  }

  #set(mind: string, held: Held): void {
    this.#held.set(mind, held);
    // Any log may be a member of another, so nothing verified before stands.
    this.#verified.clear();
  }

  log(mind: string): Validation<VerifiedLog> {
    return this.#log(mind, 0);
  }

  /** `depth` counts the collectives between the log asked for and this one (Layer 1, 4.7). */
  #log(mind: string, depth: number): Validation<VerifiedLog> {
    const known = this.#verified.get(mind);
    if (known !== undefined) return known;
    const held = this.#held.get(mind);
    if (held === undefined) return no(`no identity log is held for ${mind}`, "L1 6.3");
    if (depth > MAX_HEIGHT) {
      return no(`collectives nest at most ${MAX_HEIGHT} deep`, "L1 4.7");
    }
    if (this.#visiting.has(mind)) {
      return no("no collective is a member of itself, directly or indirectly", "L1 4.7");
    }
    this.#visiting.add(mind);
    let result: Validation<VerifiedLog>;
    try {
      result = this.#verify(held, depth);
    } finally {
      this.#visiting.delete(mind);
    }
    // A log that verifies does so wherever it is asked for. One that fails
    // may have failed for where it was asked from: the depth, or a mind
    // already being verified. Only a failure at the top is the log's own.
    if (result.ok || depth === 0) this.#verified.set(mind, result);
    return result;
  }

  #verify(held: Held, depth: number): Validation<VerifiedLog> {
    const context: LogContext = {
      evidence: this.evidence,
      asOf: held.asOf,
      memberLog: (member) => this.#log(member, depth + 1),
      ...(this.#maxEvents === undefined ? {} : { maxEvents: this.#maxEvents }),
    };
    const results = held.branches.map((branch) => verifyLog(branch, context));
    const [first, ...rest] = results.flatMap((result) => (result.ok ? [result.value] : []));
    // A branch that does not verify is no event at all. With no branch that
    // verifies, the reasons of the first are given.
    if (first === undefined) return results[0]!;
    return ok(resolveBranches([first, ...rest], this.evidence));
  }
}

function addressOf(events: unknown): Validation<string> {
  try {
    if (Array.isArray(events) && events.length > 0) {
      return ok(mindAddress(contentId(events[0])));
    }
  } catch {
    // The first event has no content ID, so it is no genesis.
  }
  return no("an identity log is an array of at least one event, the first a Genesis", "L1 3.1");
}
