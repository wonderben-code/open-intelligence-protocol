// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Evidence of time (core Section 9, ADR-0003). Every rule that depends on
 * when a signature was made is judged on evidence that it existed, never on
 * the date its signer wrote: a stolen or removed key can write any date.
 *
 * The two formulas of core 9.3 and 9.5 are here, and nowhere else.
 */

import { CLOCK_SKEW, type Instant } from "@oip/core";
import type { Validation } from "@oip/schema";

import { no, ok } from "./result.ts";

/**
 * What a verifier can show about when things existed (core 9.4): its own
 * first sight, the first sight of a witness it trusts, an anchored checkpoint
 * or an acknowledgement. `undefined` means that no evidence is held. It never
 * means "assume the date the signer wrote".
 */
export interface EvidenceView {
  /** The earliest time the verifier can show this proof existed, by proof digest (core 9.4). */
  proofSeen(digest: string): Instant | undefined;
  /**
   * The earliest time the verifier can show this identity event existed with
   * proofs that make it valid, by content ID (core 9.5). A content ID does
   * not cover proofs, so whatever fills a view answers for the difference:
   * sight of the content alone is no such evidence, and neither is a feed
   * entry or an anchor that does not commit to proofs that make the event
   * valid.
   */
  eventSeen(contentId: string): Instant | undefined;
}

/** When a proof or an identity event existed, and when it takes effect. */
export interface Evaluation {
  /** `τ`: the earliest time for which evidence is held that it existed (core 9.4). */
  readonly seen: Instant;
  /** The evaluation time (core 9.3, 9.5): every rule about time is judged at it. */
  readonly time: Instant;
  /**
   * The evaluation time as evidence alone gives it: `τ`, and for an identity
   * event never before what the evidence gives for the event it follows. No
   * signer's own date is part of it. A log that is asked about this
   * evaluation must be known up to this time (core 9.4).
   */
  readonly evidenced: Instant;
}

const later = (a: Instant, b: Instant): Instant => (a > b ? a : b);

/**
 * core 9.3: the evaluation time of a proof, `t(p) = max(p.created, τ(p))`.
 * A proof with no evidence, or dated more than 300 seconds after its
 * evidence, counts for nothing.
 *
 * @param created - The proof's own `created`.
 * @param seen - `τ(p)`: the earliest evidence that the proof existed.
 */
export function proofTime(created: Instant, seen: Instant | undefined): Validation<Evaluation> {
  if (seen === undefined) {
    return no("no evidence is held of when this proof existed", "core 9.4");
  }
  if (created > seen + CLOCK_SKEW) {
    return no(
      "the proof is dated more than 300 seconds after the evidence that it existed",
      "core 9.3",
    );
  }
  return ok({ seen, time: later(created, seen), evidenced: seen });
}

/**
 * core 9.5: the evaluation time of an identity event,
 * `max(e.created, τ(e), eventTime(previous))`. An event with no evidence, or
 * dated more than 300 seconds after its evidence, does not verify for this
 * verifier: with other evidence it might (Layer 1, 4.9).
 *
 * @param created - The event's own `created`.
 * @param seen - `τ(e)`: the earliest evidence that the event existed.
 * @param previous - The evaluation of the event before it in the log.
 */
export function eventTime(
  created: Instant,
  seen: Instant | undefined,
  previous?: Pick<Evaluation, "time" | "evidenced">,
): Validation<Evaluation> {
  if (seen === undefined) {
    return no("no evidence is held of when this event existed", "core 9.5");
  }
  if (created > seen + CLOCK_SKEW) {
    return no(
      "the event is dated more than 300 seconds after the evidence that it existed",
      "core 9.5",
    );
  }
  const time = later(created, seen);
  if (previous === undefined) return ok({ seen, time, evidenced: seen });
  return ok({ seen, time: later(time, previous.time), evidenced: later(seen, previous.evidenced) });
}

/**
 * Layer 1, 4.2: whether an event is dated before the event it follows. Both
 * dates are their signers' own claims, so this is a rule of form and orders
 * nothing in time. It is kept here, with the only other code that compares a
 * `created`.
 */
export function datedBefore(created: Instant, previous: Instant): boolean {
  return created < previous;
}

/**
 * A verifier's own record of when it first saw each proof and each identity
 * event. It keeps the earliest time it is told, so telling it again later
 * changes nothing. It holds everything in memory; a service keeps the same
 * facts in an append-only table.
 *
 * It believes what it is told. Evidence for an identity event is evidence
 * that the event existed with proofs that make it valid (core 9.5), and an
 * event's content ID does not cover its proofs: recording the time an
 * unsigned or wrongly signed copy was seen would let anyone who later signs
 * it claim that time. `witnessLog` and `witnessRecord` record only what has
 * verified. Use them for everything that arrives from outside.
 */
export class FirstSeen implements EvidenceView {
  readonly #proofs = new Map<string, Instant>();
  readonly #events = new Map<string, Instant>();

  /** Records that a proof was seen at a time. Returns the earliest time now held for it. */
  sawProof(digest: string, at: Instant): Instant {
    return keepEarliest(this.#proofs, digest, at);
  }

  /**
   * Records that an identity event was seen, with proofs that make it valid
   * (core 9.5), at a time. Returns the earliest time now held for it.
   *
   * Call it only for an event that has verified in its log, or whose time a
   * witness the verifier trusts has given. `witnessLog` does the first.
   */
  sawEvent(contentId: string, at: Instant): Instant {
    return keepEarliest(this.#events, contentId, at);
  }

  /** The earliest time recorded for a proof, or `undefined`. */
  proofSeen(digest: string): Instant | undefined {
    return this.#proofs.get(digest);
  }

  /** The earliest time recorded for an identity event, or `undefined`. */
  eventSeen(contentId: string): Instant | undefined {
    return this.#events.get(contentId);
  }
}

function keepEarliest(times: Map<string, Instant>, name: string, at: Instant): Instant {
  const held = times.get(name);
  const earliest = held === undefined || at < held ? at : held;
  times.set(name, earliest);
  return earliest;
}

/**
 * The evidence of several sources as one view: for each proof and event, the
 * earliest time any of them can show (core 9.4).
 */
export function earliestEvidence(...sources: readonly EvidenceView[]): EvidenceView {
  const earliest = (times: readonly (Instant | undefined)[]): Instant | undefined => {
    let found: Instant | undefined;
    for (const time of times) {
      if (time !== undefined && (found === undefined || time < found)) found = time;
    }
    return found;
  };
  return {
    proofSeen: (digest) => earliest(sources.map((source) => source.proofSeen(digest))),
    eventSeen: (contentId) => earliest(sources.map((source) => source.eventSeen(contentId))),
  };
}
