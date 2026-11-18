// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** A verifier's own first sight of a record that arrives, with what its proofs carry. */

import type { Instant } from "@oip/core";
import {
  type FirstSeen,
  type JudgedRecord,
  type JudgeOptions,
  judgeRecord,
  witnessRecord,
} from "@oip/identity";

import { judging, type Validation } from "@oip/schema";

import { MAX_CHAIN } from "./chain.ts";

/**
 * Records a verifier's own first sight (core 9.4) of the proofs on a record
 * it has just obtained, and of the proofs on each delegation or charter that
 * those proofs carry whole in `authority`: each proof that verifies, as seen
 * at `now`. An earlier time already held for a proof stays.
 *
 * A delegation carried inline is as new to the verifier as the record is,
 * and its author's signature needs evidence of its own: a chain is valid
 * only if each delegation was signed no later than the proof that uses it
 * (Layer 1, 11.4, item 1), and nothing counts without evidence. A verifier
 * that recorded the record's own proofs alone would never count a proof
 * that carries its chain.
 *
 * What is carried by reference is a record the verifier holds already, and
 * saw when it took it in.
 *
 * @param judged - The record, from `judgeRecord`.
 * @param now - The time the verifier obtained the record: its own clock.
 * @param seen - The verifier's own record, which is written to.
 * @param options - What the carried records are judged with: see `judgeRecord`.
 * @returns A refusal with the clause `implementation limit` if the look was
 *   cut short ([ADR-0010](../../../docs/adr/0010-checks-cut-short.md)): a
 *   delegation carried whole may not be recorded then. Call again with the
 *   same reading of the clock. A delegation first recorded at a later
 *   reading would be seen after the proof that uses it, and the record
 *   would never count.
 */
export function witnessProofs(
  judged: JudgedRecord,
  now: Instant,
  seen: FirstSeen,
  options?: JudgeOptions,
): Validation<true> {
  return judging(() => {
    witnessRecord(judged, now, seen);
    for (const proof of judged.proofs) {
      const listed: unknown = proof.proof.authority;
      if (!Array.isArray(listed)) continue;
      // No chain is longer, and a longer list is no chain (Layer 1, 11.4).
      for (const entry of (listed as readonly unknown[]).slice(0, MAX_CHAIN)) {
        if (typeof entry !== "object" || entry === null) continue;
        const carried = judgeRecord(entry, options);
        if (carried.ok) witnessRecord(carried.value, now, seen);
      }
    }
    return LOOKED;
  });
}

const LOOKED: Validation<true> = Object.freeze({ ok: true, value: true });
