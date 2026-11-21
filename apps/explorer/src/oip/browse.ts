// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The minds an indexer lists, as the Explorer shows them: what a reader
 * browses where they have no address to ask for.
 *
 * An indexer's answer is a stranger's. The client verifies each record in
 * it as its author's own before it is returned, and this module shows only
 * what came back.
 */

import type { Lookup } from "@oip/client";

/** One mind an indexer listed, with what its profile says. */
export interface ListedMind {
  readonly address: string;
  /** The name its profile gives. Any text: it is the mind's own word. */
  readonly name: string;
  readonly kind: string;
  readonly summary?: string;
  /** The `id` of each capability its profile lists. */
  readonly capabilities: readonly string[];
  /** Whether the profile is the mind's current one. An indexer may list one the mind has replaced. */
  readonly current: boolean;
}

/** What browsing found. */
export interface Listing {
  readonly minds: readonly ListedMind[];
  /** What each indexer answered. */
  readonly sources: readonly { readonly indexer: string; readonly failure?: string }[];
}

/**
 * Asks the indexers for minds.
 *
 * @param tags - Tags a mind's capability has, such as `lang:sw`. None, for whatever an indexer lists.
 * @param limit - How many results to ask each indexer for.
 */
export async function browse(
  lookup: Lookup,
  tags: readonly string[] = [],
  limit = 50,
): Promise<Listing> {
  const finding = await lookup.find({ ...(tags.length === 0 ? {} : { tags: [...tags] }), limit });
  const minds = new Map<string, ListedMind>();
  for (const { mind, record, current } of finding.found) {
    // A profile says what a mind is. An Offer or an Intent an indexer lists is not one.
    if (record.type !== "Participant" || minds.has(mind)) continue;
    minds.set(mind, {
      address: mind,
      name: record.name,
      kind: record.kind,
      ...(record.summary === undefined ? {} : { summary: record.summary }),
      capabilities: (record.capabilities ?? []).map(({ id }) => id),
      current,
    });
  }
  return {
    minds: [...minds.values()],
    sources: finding.sources.map((source) => {
      const { indexer, failure } = source as { indexer: string; failure?: string };
      return { indexer, ...(failure === undefined ? {} : { failure }) };
    }),
  };
}
