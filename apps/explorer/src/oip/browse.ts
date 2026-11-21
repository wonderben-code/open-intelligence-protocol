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

import type { Asked } from "./asked.ts";

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

/** What one indexer answered. */
export interface IndexerSaid {
  readonly indexer: string;
  /** How many results it gave, if its answer was taken. */
  readonly results?: number;
  /** Why its answer was not taken: it could not be reached, or what it sent is no answer of its own. */
  readonly failure?: string;
}

/** What browsing found. */
export interface Listing {
  readonly minds: readonly ListedMind[];
  /**
   * How many records an indexer named that are not listed, because they
   * could not be verified as their authors' own.
   */
  readonly unlisted: number;
  /**
   * The hosts that would have had to be asked to verify those, and were
   * not: homes of the minds named, which the reader did not choose. A
   * profile that is not the one the resolvers serve is at its author's home.
   */
  readonly notAsked: readonly string[];
  /** What each indexer answered. */
  readonly sources: readonly IndexerSaid[];
  /** Whether any indexer answered at all. */
  readonly answered: boolean;
}

/**
 * Asks the indexers for minds.
 *
 * @param asked - Keeps the requests to whom the reader chose, and says what was not asked.
 * @param tags - Tags a mind's capability has, such as `lang:sw`. None, for whatever an indexer lists.
 * @param limit - How many results to ask each indexer for.
 */
export async function browse(
  lookup: Lookup,
  asked: Pick<Asked, "kept">,
  tags: readonly string[] = [],
  limit = 50,
): Promise<Listing> {
  // What was kept before is another question's.
  asked.kept();
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
  const sources = finding.sources.map(({ indexer, results, failure }) => ({
    indexer,
    ...(results === undefined ? {} : { results }),
    ...(failure === undefined ? {} : { failure }),
  }));
  return {
    minds: [...minds.values()],
    unlisted: finding.refused.length,
    notAsked: asked.kept(),
    sources,
    answered: sources.some((source) => source.failure === undefined),
  };
}
