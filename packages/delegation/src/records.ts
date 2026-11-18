// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The records a verifier holds besides identity logs: the delegations a
 * proof names by reference, and the revocations that may have ended them.
 */

import { contentId, type PlacedProof } from "@oip/core";
import { type JudgedRecord, type JudgeOptions, judgeRecord } from "@oip/identity";
import type { Validation } from "@oip/schema";

import { ok } from "./result.ts";

/** The records a verifier holds, as far as delegation asks for them. */
export interface RecordView {
  /** The record with this content ID, with every proof on it that verified, if one is held. */
  record(id: string): JudgedRecord | undefined;
  /**
   * Layer 1, 11.5: the `Revocation` records held whose `revokes` names this
   * content ID. Whether one takes effect is for its author's log and the
   * evidence to say.
   */
  revocationsOf(id: string): readonly JudgedRecord[];
}

/** The content ID a `Revocation` names in `revokes`, if the record is one. */
function revoked(judged: JudgedRecord): string | undefined {
  const record = judged.record as { readonly type?: unknown; readonly revokes?: unknown };
  if (record.type !== "Revocation" || typeof record.revokes !== "string") return undefined;
  // A record-ref is an address, a slash and a content ID (core 6.3). The schema has checked it.
  return record.revokes.slice(record.revokes.lastIndexOf("/") + 1);
}

/**
 * Records held in memory, each judged once when it is given.
 *
 * **What it is shown, it keeps.** A record is its content, and proofs are
 * added to a record without changing its content ID (core 3.1). So the same
 * record given twice, with other proofs, is one record: every proof that
 * verified is kept, from whichever copy, and no copy takes a proof away. A
 * revocation given first with its author's proof and then with none is
 * still signed; a delegation whose co-signer's proof arrives later gains it.
 *
 * It does no I/O and reads no clock. What a proof is worth is not judged
 * here: that takes the signer's log and the evidence.
 */
export class RecordSet implements RecordView {
  readonly #records = new Map<string, JudgedRecord>();
  readonly #revocations = new Map<string, Set<string>>();
  readonly #options: JudgeOptions | undefined;

  /** @param options - What records are judged with: see `judgeRecord`. */
  constructor(options?: JudgeOptions) {
    this.#options = options;
  }

  /**
   * Holds a record.
   *
   * @returns The record's content ID. Or why the record is not held: it is
   *   not well formed, or it depends on an extension the caller does not
   *   implement (core 8.3).
   */
  add(record: unknown): Validation<string> {
    const judged = judgeRecord(record, this.#options);
    if (!judged.ok) return judged;
    const id = contentId(judged.value.record);
    const held = this.#records.get(id);
    if (held === undefined) {
      this.#records.set(id, judged.value);
      const target = revoked(judged.value);
      if (target !== undefined) {
        const naming = this.#revocations.get(target) ?? new Set<string>();
        naming.add(id);
        this.#revocations.set(target, naming);
      }
      return ok(id);
    }
    // The same record, perhaps with proofs not seen before: each is kept, once.
    const known = new Set(held.proofs.map((proof) => proof.digest));
    const more: PlacedProof[] = judged.value.proofs.filter((proof) => !known.has(proof.digest));
    if (more.length > 0) {
      this.#records.set(
        id,
        Object.freeze({ ...held, proofs: Object.freeze([...held.proofs, ...more]) }),
      );
    }
    return ok(id);
  }

  record(id: string): JudgedRecord | undefined {
    return this.#records.get(id);
  }

  revocationsOf(id: string): readonly JudgedRecord[] {
    const found: JudgedRecord[] = [];
    for (const naming of this.#revocations.get(id) ?? []) {
      const judged = this.#records.get(naming);
      if (judged !== undefined) found.push(judged);
    }
    return found;
  }
}
