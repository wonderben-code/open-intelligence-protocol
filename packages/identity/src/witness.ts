// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Recording a verifier's own first sight (core 9.4, 9.5) of what arrives
 * from outside, only once it has verified.
 *
 * Evidence for an identity event is evidence that the event existed with
 * proofs that make it valid, and an event's content ID does not cover its
 * proofs. A verifier that noted the time it first saw an event's content,
 * signed or not, would later judge a signature made with a removed key at
 * that early time: the attack that evidence of time exists to stop (Layer
 * 1, 9.6). So nothing is recorded here before it has verified.
 */

import type { Instant } from "@oip/core";

import { earliestEvidence, type EvidenceView, type FirstSeen } from "./evidence.ts";
import { type LogContext, type Replayed, verifyLogPrefix } from "./log.ts";
import { own } from "./result.ts";
import type { JudgedRecord } from "./signing.ts";

/** What a log is witnessed with. */
export interface WitnessOptions {
  /**
   * The other evidence the verifier holds: the first-seen times of a witness
   * it trusts, or anchors. An event they show is judged at the time they
   * give. Default: none but the verifier's own record.
   */
  readonly evidence?: EvidenceView;
  /** The verified logs of the members, for a member-controlled log. A `LogBook` gives them. */
  readonly memberLog?: LogContext["memberLog"];
  /** The longest log to read. See `LogContext.maxEvents`. */
  readonly maxEvents?: number;
  /** core 8.3: the extension namespaces the caller implements. See `LogContext.understood`. */
  readonly understood?: Iterable<string>;
}

/** What `witnessLog` found of a log, and what to hold of it. */
export interface Witnessed extends Replayed {
  /**
   * What to hold of the log, as known up to `now` (Layer 1, 4.9):
   *
   * - the log as it was given, if every event verified;
   * - the log as it was given, if the first event that did not verify is
   *   undecided. A `LogBook` refuses that log until the event can be judged,
   *   and that is the point: the events before it are not the mind's log,
   *   because the event may remove a key;
   * - the events before the first that did not verify, if that event is
   *   invalid. They are the log, whoever appended the rest;
   * - `undefined` if that leaves nothing.
   */
  readonly toHold: readonly unknown[] | undefined;
}

/**
 * Records a verifier's own first sight of the events of a log it has just
 * obtained (core 9.5), and of those only that verify.
 *
 * The log is verified as if every event not seen before were first seen at
 * `now`, which is what the verifier is about to record. Each event that
 * verifies, from the first, is then recorded as seen at `now`; an earlier
 * time already held for it stays. An event that does not verify is not
 * recorded, and neither is any event after it. So a copy of an event that is
 * not yet validly signed leaves no trace, and a signature added to it later
 * is judged when the signed event is seen.
 *
 * It does not throw on anything given as `events`.
 *
 * @param now - The time the verifier obtained the log: its own clock, read by the caller.
 * @param seen - The verifier's own record, which is written to.
 * @returns The events that verified, why the next one did not, if there is
 *   one, whether that event is invalid or undecided, and what to hold.
 */
export function witnessLog(
  events: unknown,
  now: Instant,
  seen: FirstSeen,
  options?: WitnessOptions,
): Witnessed {
  const given = <K extends keyof WitnessOptions>(name: K): WitnessOptions[K] | undefined =>
    own(options, name) as WitnessOptions[K] | undefined;
  const others = given("evidence");
  // What is held already: the verifier's own record, and what other sources show.
  const held: EvidenceView = others === undefined ? seen : earliestEvidence(seen, others);
  const memberLog = given("memberLog");
  const maxEvents = given("maxEvents");
  const understood = given("understood");
  const context: LogContext = {
    evidence: {
      proofSeen: held.proofSeen.bind(held),
      eventSeen: (id) => held.eventSeen(id) ?? now,
    },
    asOf: now,
    ...(memberLog === undefined ? {} : { memberLog }),
    ...(maxEvents === undefined ? {} : { maxEvents }),
    ...(understood === undefined ? {} : { understood }),
  };
  const replayed = verifyLogPrefix(events, context);
  for (const entry of replayed.log?.entries ?? []) seen.sawEvent(entry.state.head, now);
  // Layer 1, 4.9: the events before an invalid event may be held as the log.
  // Those before an undecided one may not, so that log is held as it came.
  const asGiven = replayed.failure === undefined || replayed.undecided;
  const toHold = asGiven
    ? Array.isArray(events)
      ? (events as readonly unknown[])
      : undefined
    : replayed.log && Object.freeze(replayed.log.entries.map((entry) => entry.event));
  return Object.freeze({ ...replayed, toHold });
}

/**
 * Records a verifier's own first sight of the proofs on a record it has just
 * obtained (core 9.4): each proof that verifies, as seen at `now`. An earlier
 * time already held for a proof stays.
 *
 * @param judged - The record, from `judgeRecord`: only its verified proofs are recorded.
 * @param now - The time the verifier obtained the record.
 * @param seen - The verifier's own record, which is written to.
 */
export function witnessRecord(judged: JudgedRecord, now: Instant, seen: FirstSeen): void {
  for (const proof of judged.proofs) seen.sawProof(proof.digest, now);
}
