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
import { cutShort, cutShortCount } from "@oip/schema";

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
 *   one, and whether that event is invalid or undecided by this copy alone.
 *
 * This judges one copy alone. A verifier that holds logs in a book takes a
 * copy in with `LogBook.witness` instead: the book keeps every event of the
 * copy as it came and judges each with the proofs of every copy it holds
 * (Layer 1, 7.1), so an event that is invalid here, for the proofs this copy
 * lacks, may verify there, and is recorded as seen when it does (core 9.5).
 * Holding only the events that verified here would lose it.
 */
export function witnessLog(
  events: unknown,
  now: Instant,
  seen: FirstSeen,
  options?: WitnessOptions,
): Replayed {
  const before = cutShortCount();
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
  // A look that was cut short, here or below, is no look: nothing is recorded, and the
  // answer says so (ADR-0010). The caller looks again, at the same reading.
  if (cutShortCount() !== before) {
    return Object.freeze({ log: undefined, failure: cutShort(), undecided: true });
  }
  for (const entry of replayed.log?.entries ?? []) seen.sawEvent(entry.state.head, now);
  return Object.freeze(replayed);
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
