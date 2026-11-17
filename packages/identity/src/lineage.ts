// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Lineage (Layer 1, Section 8): whether a parent acknowledges a child that names it. */

import type { IdentityView } from "./book.ts";
import { type JudgedRecord, ownSignedTime } from "./signing.ts";
import { type IdentityState, positionOf, type VerifiedLog } from "./state.ts";

/** A parent a mind's genesis names, and whether the parent acknowledges the mind. */
export interface Lineage {
  /** The parent's address. */
  readonly mind: string;
  /** The version of the parent the child says it was forked from. */
  readonly at: string;
  /**
   * `acknowledged`: the parent's log has a `Fork` event for the child at or
   * after that version, or the parent signed a `Lineage` record naming the
   * child. Otherwise `claimed`: only the child says so.
   */
  readonly status: "acknowledged" | "claimed";
}

/**
 * Layer 1, 8.2: the lineage of a mind, one entry for each parent its genesis
 * names, in that order.
 *
 * @param child - The verified log of the mind.
 * @param records - The records the verifier holds. Only `Lineage` records
 *   matter: one acknowledges the child if its author is the parent, it names
 *   the child, and the parent signed it by its own authority (Layer 1, 8.3).
 */
export function lineage(
  child: VerifiedLog,
  view: IdentityView,
  records: readonly JudgedRecord[] = [],
): Lineage[] {
  const genesis = child.states[0] as IdentityState;
  return genesis.parents.map(({ mind, at }) => {
    const claimed: Lineage = { mind, at, status: "claimed" };
    const held = view.log(mind);
    if (!held.ok) return claimed;
    const parent = held.value;
    const from = positionOf(parent, at);
    if (from === undefined) return claimed;
    const forked = parent.events
      .slice(from)
      .some((event) => event.type === "Fork" && event.child === child.mind);
    const signed = records.some((judged) => {
      const record = judged.record as { type: string; author?: unknown; child?: unknown };
      return (
        record.type === "Lineage" &&
        record.author === mind &&
        record.child === child.mind &&
        ownSignedTime(judged, mind, view) !== undefined
      );
    });
    return forked || signed ? { mind, at, status: "acknowledged" } : claimed;
  });
}
