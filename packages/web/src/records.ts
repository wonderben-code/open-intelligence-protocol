// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The records a verifier holds, as far as Layer 2 asks for them: what
 * supersedes a record, which Commitments resolve it, and which Receipts are
 * about it.
 */

import { type DelegationContext, RecordSet, type RecordView } from "@oip/delegation";
import type { JudgedRecord, JudgeOptions } from "@oip/identity";
import type { Validation } from "@oip/schema";

/** The records a verifier holds, as far as status (Layer 2, Section 8) asks for them. */
export interface WebRecords extends RecordView {
  /**
   * The records held whose `supersedes` names this content ID. Whether one
   * is by the same author, of the same type and signed is for the caller.
   */
  supersedersOf(id: string): readonly JudgedRecord[];
  /** The Commitments held that list this content ID in `resolves`. */
  resolversOf(id: string): readonly JudgedRecord[];
  /** The Receipts held whose `about` names this content ID. */
  receiptsAbout(id: string): readonly JudgedRecord[];
}

/** What a question of Layer 2 is asked with: the logs, the evidence and the records held. */
export interface WebContext extends DelegationContext {
  readonly records: WebRecords;
}

/**
 * The content ID a record-ref names (core 6.3). The mind before the slash is
 * a hint where to look, and takes no part in telling which record is meant.
 */
export function referenced(ref: unknown): string | undefined {
  return typeof ref === "string" ? ref.slice(ref.lastIndexOf("/") + 1) : undefined;
}

function index(found: Map<string, Set<string>>, by: string | undefined, id: string): void {
  if (by === undefined) return;
  const ids = found.get(by) ?? new Set<string>();
  ids.add(id);
  found.set(by, ids);
}

/**
 * Records held in memory, each judged once when it is given, and found by
 * what they refer to. It keeps what it is shown, as a `RecordSet` does: the
 * same record given again adds the proofs not seen before, and takes none
 * away.
 *
 * It does no I/O and reads no clock.
 */
export class WebRecordSet implements WebRecords {
  readonly #records: RecordSet;
  readonly #superseders = new Map<string, Set<string>>();
  readonly #resolvers = new Map<string, Set<string>>();
  readonly #receipts = new Map<string, Set<string>>();

  /** @param options - What records are judged with: see `judgeRecord`. */
  constructor(options?: JudgeOptions) {
    this.#records = new RecordSet(options);
  }

  /**
   * Holds a record.
   *
   * @returns The record's content ID, or why the record is not held.
   */
  add(record: unknown): Validation<string> {
    const added = this.#records.add(record);
    if (!added.ok) return added;
    const id = added.value;
    const held = this.#records.record(id)?.record as
      | {
          readonly type: string;
          readonly supersedes?: unknown;
          readonly resolves?: unknown;
          readonly about?: unknown;
        }
      | undefined;
    index(this.#superseders, referenced(held?.supersedes), id);
    if (held?.type === "Commitment" && Array.isArray(held.resolves)) {
      for (const ref of held.resolves as readonly unknown[]) {
        index(this.#resolvers, referenced(ref), id);
      }
    }
    if (held?.type === "Receipt") index(this.#receipts, referenced(held.about), id);
    return added;
  }

  record(id: string): JudgedRecord | undefined {
    return this.#records.record(id);
  }

  revocationsOf(id: string): readonly JudgedRecord[] {
    return this.#records.revocationsOf(id);
  }

  chartersOf(mind: string): readonly JudgedRecord[] {
    return this.#records.chartersOf(mind);
  }

  supersedersOf(id: string): readonly JudgedRecord[] {
    return this.#listed(this.#superseders.get(id));
  }

  resolversOf(id: string): readonly JudgedRecord[] {
    return this.#listed(this.#resolvers.get(id));
  }

  receiptsAbout(id: string): readonly JudgedRecord[] {
    return this.#listed(this.#receipts.get(id));
  }

  #listed(ids: ReadonlySet<string> | undefined): JudgedRecord[] {
    // What is indexed is held: nothing is ever taken out.
    return [...(ids ?? [])]
      .map((id) => this.#records.record(id))
      .filter((judged) => judged !== undefined);
  }
}
