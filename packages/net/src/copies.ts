// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * One record held in several copies. The same record with other proofs is
 * the same record (core 3.1), and anyone who holds a record may hold it with
 * some of its proofs and not others: two members of a collective may each
 * have sent the copy that carries their own.
 */

import { contentId } from "@oip/core";
import type { JudgedRecord } from "@oip/identity";

/** A record with the proofs of another copy of it that it did not have. */
export function withProofsOf(known: JudgedRecord, copy: JudgedRecord): JudgedRecord {
  const digests = new Set(known.proofs.map((proof) => proof.digest));
  const more = copy.proofs.filter((proof) => !digests.has(proof.digest));
  return more.length === 0 ? known : { ...known, proofs: [...known.proofs, ...more] };
}

/**
 * Each record among those given that is wanted, once, by its content ID,
 * with every proof that verified on any copy of it.
 */
export function oneOfEach(
  records: Iterable<JudgedRecord>,
  wanted: (record: JudgedRecord["record"]) => boolean,
): Map<string, JudgedRecord> {
  const held = new Map<string, JudgedRecord>();
  for (const judged of records) {
    if (!wanted(judged.record)) continue;
    const id = contentId(judged.record);
    const known = held.get(id);
    held.set(id, known === undefined ? judged : withProofsOf(known, judged));
  }
  return held;
}
