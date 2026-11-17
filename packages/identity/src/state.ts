// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Identity state (Layer 1, 5.1) and a verified identity log. */

import type { Instant } from "@oip/core";
import type { IdentityEvent } from "@oip/schema";

/** Layer 1, 3.4: who may extend a log. The kind is fixed at genesis. */
export type ControllerState =
  | {
      readonly kind: "key";
      /** Commitments to the keys that sign the next event. Empty: the log can never be extended. */
      readonly next: readonly string[];
      /** How many of them must sign. 0 when `next` is empty. */
      readonly nextThreshold: number;
    }
  | {
      readonly kind: "member";
      /** The addresses of the member minds. */
      readonly members: readonly string[];
      /** How many of them must sign. */
      readonly threshold: number;
    };

/** A parent a genesis names (Layer 1, 8.1). */
export interface Parent {
  readonly mind: string;
  /** The version of the parent the mind was forked from. */
  readonly at: string;
}

/** Layer 1, 5.1: what replaying a log up to one event gives. */
export interface IdentityState {
  /** The mind's address. */
  readonly mind: string;
  readonly kind: string;
  readonly controller: ControllerState;
  /** Operational keys, as Multikeys: they sign the mind's everyday records. */
  readonly keys: readonly string[];
  /** Invocation keys: they sign other minds' identity events, for a member. */
  readonly invocation: readonly string[];
  /** Agreement keys, for encryption. */
  readonly agreement: readonly string[];
  readonly homes: readonly string[];
  /** Aliases as the log lists them. None is verified here (Layer 1, 5.3). */
  readonly alsoKnownAs: readonly string[];
  readonly parents: readonly Parent[];
  /** Children acknowledged by `Fork` events. */
  readonly children: readonly string[];
  /**
   * Every key ever revoked, with the earliest time it was declared compromised
   * from, or `undefined` if no revocation gave one. A revoked key never returns.
   */
  readonly revoked: ReadonlyMap<string, Instant | undefined>;
  /** The position of the latest event; 0 for the genesis. */
  readonly seq: number;
  /** The content ID of the latest event. */
  readonly head: string;
  /** The version identifier of the latest event, `<seq>-<contentId>` (Layer 1, 3.3). */
  readonly versionId: string;
  /** The latest event's own `created`. */
  readonly created: Instant;
  readonly retired: boolean;
}

/** An event after the point where a duplicitous log diverges, with its state and time. */
export interface BranchTail {
  readonly time: Instant;
  readonly state: IdentityState;
  readonly event: IdentityEvent;
}

/**
 * An identity log that verified (Layer 1, Section 4), with the state after
 * each event and each event's evaluation time (core 9.5). The times come
 * from the evidence the log was verified with, so nothing that reads this
 * can be asked about a log whose times are unknown (ADR-0003).
 */
export interface VerifiedLog {
  /** The mind's address: `did:oip:` and the content ID of the genesis. */
  readonly mind: string;
  /** The events, as validated copies. */
  readonly events: readonly IdentityEvent[];
  /** `states[i]` is the state after `events[i]`. */
  readonly states: readonly IdentityState[];
  /** `times[i]` is the evaluation time of `events[i]`. It never decreases. */
  readonly times: readonly Instant[];
  /** Layer 1, 4.7: 0 for a key-controlled mind; fixed by the genesis for a collective. */
  readonly height: number;
  /**
   * core 9.4: the time up to which this log is known to be complete: when a
   * witness the verifier trusts served it, or the present for a verifier that
   * follows the log itself.
   */
  readonly asOf: Instant;
  /**
   * Layer 1, 7.3: the mind signed two events for one position and the
   * evidence cannot separate them. `events` then stops before that position.
   */
  readonly duplicitous: boolean;
  /** The later events of every conflicting branch: their removals all apply. */
  readonly branchTails: readonly BranchTail[];
}

/** The state after the latest event. */
export function latestState(log: VerifiedLog): IdentityState {
  // A verified log has at least its genesis.
  return log.states[log.states.length - 1]!;
}

/** The position of the event a version identifier names, or `undefined` if the log has none. */
export function positionOf(log: VerifiedLog, versionId: string): number | undefined {
  const position = log.states.findIndex((state) => state.versionId === versionId);
  return position === -1 ? undefined : position;
}

/**
 * Layer 1, 6.1 item 3 and 6.4 item 3: the evaluation time of the first event
 * after `position` that removes the key from the set or retires the mind, or
 * `undefined` if none does. Under duplicity the removals of every branch
 * apply (Layer 1, 7.3), so duplicity never revives a key.
 */
export function removalTime(
  log: VerifiedLog,
  position: number,
  key: string,
  set: "keys" | "invocation",
): Instant | undefined {
  let earliest: Instant | undefined;
  const consider = (time: Instant, state: IdentityState): void => {
    if (!state.retired && state[set].includes(key)) return;
    if (earliest === undefined || time < earliest) earliest = time;
  };
  for (let i = position + 1; i < log.states.length; i++) {
    consider(log.times[i]!, log.states[i]!);
  }
  for (const tail of log.branchTails) consider(tail.time, tail.state);
  return earliest;
}

/**
 * Layer 1, 6.1 item 4: the earliest time from which the log declares the key
 * compromised, or `undefined`. Under duplicity every branch's declarations apply.
 */
export function compromisedSince(log: VerifiedLog, key: string): Instant | undefined {
  let earliest: Instant | undefined;
  for (const state of [latestState(log), ...log.branchTails.map((tail) => tail.state)]) {
    const since = state.revoked.get(key);
    if (since !== undefined && (earliest === undefined || since < earliest)) earliest = since;
  }
  return earliest;
}

/**
 * Layer 1, 9.5: the state after the last event whose evaluation time is at
 * or before `time`, or `undefined` if the mind did not yet exist then.
 */
export function stateAt(log: VerifiedLog, time: Instant): IdentityState | undefined {
  let found: IdentityState | undefined;
  for (let i = 0; i < log.states.length; i++) {
    if (log.times[i]! > time) break;
    found = log.states[i];
  }
  return found;
}
