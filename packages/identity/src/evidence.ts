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
  /** The earliest time the verifier can show this identity event existed, by content ID (core 9.5). */
  eventSeen(contentId: string): Instant | undefined;
}

/** When a proof or an identity event existed, and when it takes effect. */
export interface Evaluation {
  /** `τ`: the earliest time for which evidence is held that it existed (core 9.4). */
  readonly seen: Instant;
  /** The evaluation time (core 9.3, 9.5): every rule about time is judged at it. */
  readonly time: Instant;
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
  return ok({ seen, time: later(created, seen) });
}

/**
 * core 9.5: the evaluation time of an identity event,
 * `max(e.created, τ(e), eventTime(previous))`. An event with no evidence, or
 * dated more than 300 seconds after its evidence, is invalid.
 *
 * @param created - The event's own `created`.
 * @param seen - `τ(e)`: the earliest evidence that the event existed.
 * @param previous - The evaluation time of the event before it in the log.
 */
export function eventTime(
  created: Instant,
  seen: Instant | undefined,
  previous?: Instant,
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
  return ok({ seen, time: previous === undefined ? time : later(time, previous) });
}

/**
 * A verifier's own record of when it first saw each proof and each identity
 * event. It keeps the earliest time it is told, so telling it again later
 * changes nothing. It holds everything in memory; a service keeps the same
 * facts in an append-only table.
 */
export class FirstSeen implements EvidenceView {
  readonly #proofs = new Map<string, Instant>();
  readonly #events = new Map<string, Instant>();

  /** Records that a proof was seen at a time. Returns the earliest time now held for it. */
  sawProof(digest: string, at: Instant): Instant {
    return keepEarliest(this.#proofs, digest, at);
  }

  /** Records that an identity event was seen at a time. Returns the earliest time now held for it. */
  sawEvent(contentId: string, at: Instant): Instant {
    return keepEarliest(this.#events, contentId, at);
  }

  proofSeen(digest: string): Instant | undefined {
    return this.#proofs.get(digest);
  }

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
