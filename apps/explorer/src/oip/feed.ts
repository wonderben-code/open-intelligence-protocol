// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What a mind has said publicly, as the Explorer shows it: its feed, the
 * records the feed lists, and how each of them stands.
 *
 * A feed is at the mind's homes, which its verified log names. Reading it
 * asks those homes, and so tells them that somebody looked. The page asks
 * only when its reader says to.
 */

import type { Lookup, Reader } from "@oip/client";
import { checkpointRoot } from "@oip/net";

/** One entry of a feed, with the record it lists if the home served it. */
export interface EntryView {
  /** Its place in the feed, from 0. */
  readonly seq: number;
  /** The entry's own content ID. */
  readonly id: string;
  /** The type of the record it lists: `Intent`, `Commitment`, `Receipt`. */
  readonly objectType: string;
  /** The content ID of the record it lists. */
  readonly object: string;
  /** When its author says the entry was made. */
  readonly created: string;
  /** The record, verified to be the one the entry names. */
  readonly record?: object;
  /** Why there is no record, where a home did not serve one that could be judged. */
  readonly missing?: string;
  /** How the record stands (Layer 2, Section 8), for a record that has a status. */
  readonly status?: string;
}

/** A feed, as a page shows it. */
export interface FeedView {
  readonly author: string;
  readonly entries: readonly EntryView[];
  /**
   * What a checkpoint over the feed as it was read must say (Layer 1, 10.5):
   * how many entries it covers, the last of them, and the Merkle root of
   * them all. A checkpoint the mind signed and published or anchored
   * elsewhere can be held against it. None for a feed with no entry.
   */
  readonly covering?: { readonly size: number; readonly head: string; readonly root: string };
  /** How many entries were found at a place the feed already had another (Layer 1, 10.3). */
  readonly equivocation: number;
  /** How many of the entries served did not verify. */
  readonly refused: number;
  /** What each home answered. */
  readonly sources: readonly { readonly home: string; readonly failure?: string }[];
}

const said = (error: unknown): string => (error instanceof Error ? error.message : String(error));

/**
 * Reads a mind's feed, fetches the records it lists, and works out how
 * each stands.
 *
 * @param reader - Holds the records, and judges them. Every record read
 *   here is held before any status is worked out, so that a Commitment is
 *   judged with the Receipts the same feed lists.
 * @throws Whatever the lookup throws if no home of the mind could be asked.
 */
export async function readFeed(lookup: Lookup, reader: Reader, mind: string): Promise<FeedView> {
  const { feed, sources } = await lookup.feed(mind);
  const read: {
    seq: number;
    id: string;
    objectType: string;
    object: string;
    created: string;
    record?: object;
    missing?: string;
  }[] = [];
  for (const { id, entry } of feed.entries) {
    const { seq, objectType, object, created } = entry;
    const one = { seq, id, objectType, object, created };
    try {
      const { record } = await lookup.record(mind, object);
      reader.hold(record);
      read.push({ ...one, record });
    } catch (error) {
      read.push({ ...one, missing: said(error) });
    }
  }
  const entries: EntryView[] = [];
  for (const one of read) {
    let status: string | undefined;
    if (one.record !== undefined) {
      try {
        status = await reader.status(one.record);
      } catch {
        // A Receipt, a profile, a delegation: a record that has no status of its own.
      }
    }
    entries.push({ ...one, ...(status === undefined ? {} : { status }) });
  }
  const root = checkpointRoot(feed.entries.map(({ id }) => id));
  const head = feed.entries.at(-1)?.id;
  return {
    author: feed.author,
    entries,
    ...(root === undefined || head === undefined
      ? {}
      : { covering: { size: feed.entries.length, head, root } }),
    equivocation: feed.equivocation.length,
    refused: feed.refused.length,
    sources: sources.map(({ home, failure }) => ({
      home,
      ...(failure === undefined ? {} : { failure }),
    })),
  };
}
