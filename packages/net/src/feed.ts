// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A mind's public feed (Layer 1, Section 10): the entries that publish its
 * records, in order, and the checkpoints that commit to a run of them.
 *
 * A feed is verified as an identity log is, on a smaller scale. Every rule
 * about time is a comparison of times that come from evidence: an entry
 * counts from the evaluation time of its author's signature, never from the
 * date written in it.
 */

import { contentId, type Instant } from "@oip/core";
import {
  type IdentityView,
  type JudgedRecord,
  type JudgeOptions,
  judgeRecord,
  ownSignedTime,
} from "@oip/identity";
import type { Checkpoint, Entry, Issue, Validation } from "@oip/schema";

import { withProofsOf } from "./copies.ts";
import { checkpointRoot } from "./merkle.ts";
import { finding, judging, no, ok } from "./result.ts";

/** One entry of a feed that has verified. */
export interface FeedEntry {
  /** The entry's content ID. */
  readonly id: string;
  /** The entry. */
  readonly entry: Entry;
  /** The entry as it was judged, with every proof that verified, from whichever copy. */
  readonly judged: JudgedRecord;
  /** The evaluation time of its author's signature: the time the entry counts from. */
  readonly time: Instant;
}

/** A feed, as far as a verifier has verified it. */
export interface VerifiedFeed {
  /** The mind whose feed it is. */
  readonly author: string;
  /** The entries that verify, from `seq` 0, each naming the one before it. */
  readonly entries: readonly FeedEntry[];
  /**
   * Layer 1, 10.3: the valid entries at the position after the last of
   * `entries`, when there is more than one. That is feed equivocation, and
   * the two are the evidence of it. The feed is then verified no further:
   * nothing tells which of them the mind stands by.
   */
  readonly equivocation: readonly FeedEntry[];
  /** The values given that are no entry of this feed, each with why and its place in what was given. */
  readonly refused: readonly { readonly index: number; readonly issues: readonly Issue[] }[];
}

/** An entry that is well formed and names this author, not yet placed in the feed. */
interface Candidate {
  readonly id: string;
  readonly entry: Entry;
  judged: JudgedRecord;
}

/**
 * Layer 1, 10.1 to 10.4: verifies the entries held of a mind's feed.
 *
 * An entry is valid if it is a well-formed `Entry` of this author, is
 * signed by its author's own authority (a valid operational key, Layer 1,
 * 6.1; for a collective also its threshold, 9.5), and stands where it says:
 * at `seq` 0 with no `prev`, or at the next `seq` after a valid entry that
 * its `prev` names.
 *
 * The values may come in any order and in several copies. The same entry
 * with other proofs is the same entry (core 3.1), and it is judged with the
 * proofs of every copy. A value that is no valid entry is no entry: it is
 * listed in `refused`, and it neither takes a position nor counts as
 * equivocation (10.4). So after a key is declared compromised, the entries
 * it signed from that time on fall away, and the feed goes on from the last
 * valid entry with whatever valid entry names it.
 *
 * It never throws.
 *
 * @param entries - The values held as entries of the feed.
 * @param author - The mind whose feed it is.
 * @param view - The identity logs held, and the evidence of time.
 */
export function verifyFeed(
  entries: unknown,
  author: string,
  view: IdentityView,
  options?: JudgeOptions,
): Validation<VerifiedFeed> {
  return judging(() => feedOf(entries, author, view, options));
}

/** The feed, as `verifyFeed` answers when no check is cut short. */
function feedOf(
  entries: unknown,
  author: string,
  view: IdentityView,
  options?: JudgeOptions,
): Validation<VerifiedFeed> {
  if (!Array.isArray(entries)) return no("a feed is a list of entries", "L1 10.1");
  if (typeof (author as unknown) !== "string") {
    return no("a mind is named by its address, a string", "L1 2.2");
  }
  const refused: { index: number; issues: readonly Issue[] }[] = [];
  const held = new Map<string, Candidate>();
  for (const [index, value] of (entries as readonly unknown[]).entries()) {
    const judged = judgeRecord(value, options);
    if (!judged.ok) {
      refused.push({ index, issues: judged.issues });
      continue;
    }
    const { type, author: by } = judged.value.record as { type: string; author?: unknown };
    if (type !== "Entry" || by !== author) {
      refused.push({
        index,
        issues: no("the value is not an entry of this mind's feed", "L1 10.1").issues,
      });
      continue;
    }
    const entry = judged.value.record as Entry;
    const id = contentId(entry);
    const known = held.get(id);
    if (known === undefined) {
      held.set(id, { id, entry, judged: judged.value });
      continue;
    }
    // The same entry, perhaps with proofs not seen before: each is kept, once.
    known.judged = withProofsOf(known.judged, judged.value);
  }
  // Each entry under the one it names, so that a long feed is walked once.
  const after = new Map<string | undefined, Candidate[]>();
  for (const candidate of held.values()) {
    const named = after.get(candidate.entry.prev);
    if (named === undefined) after.set(candidate.entry.prev, [candidate]);
    else named.push(candidate);
  }
  /** The valid entries at `seq` that follow `before`. */
  const following = (seq: number, before: FeedEntry | undefined): FeedEntry[] => {
    const found: FeedEntry[] = [];
    for (const candidate of after.get(before?.id) ?? []) {
      if (candidate.entry.seq !== seq) continue;
      const time = ownSignedTime(candidate.judged, author, view);
      if (time !== undefined) found.push({ ...candidate, time });
    }
    return found;
  };
  const verified: FeedEntry[] = [];
  let equivocation: FeedEntry[] = [];
  for (let next = following(0, undefined); next.length > 0;) {
    const [only, ...others] = next;
    if (only === undefined) break;
    if (others.length > 0) {
      // In the order of their content IDs, so that every verifier names them alike.
      equivocation = next.toSorted((a, b) => (a.id < b.id ? -1 : 1));
      break;
    }
    verified.push(only);
    next = following(verified.length, only);
  }
  return ok({ author, entries: verified, equivocation, refused });
}

/** What a verified checkpoint covers. */
export interface CoveredFeed {
  /** The evaluation time of the checkpoint's signature. */
  readonly time: Instant;
  /** The entries covered, from `seq` 0. */
  readonly entries: readonly FeedEntry[];
  /**
   * The digests of the proofs the covered entries commit to (Layer 1,
   * 10.1). A time at which the checkpoint is shown to have existed is
   * evidence for each of them (core 9.4, item 3).
   */
  readonly proofs: ReadonlySet<string>;
}

/**
 * Layer 1, 10.5: verifies a checkpoint against the feed it is of.
 *
 * The checkpoint is signed by its author's own authority, covers at least
 * one entry and no more than the verifier holds verified, names the last
 * covered entry in `head`, and its `root` is the Merkle Tree Hash of the
 * covered entries' content IDs.
 *
 * A checkpoint that is signed is evidence of nothing but itself. It becomes
 * evidence of time for the proofs it covers when something shows when it
 * existed, an anchor's attestation for one (10.6). How an attestation is
 * carried is not yet specified, so none is read here.
 *
 * @param checkpoint - The checkpoint, from `judgeRecord`.
 * @param feed - The author's feed, from `verifyFeed`.
 */
export function verifyCheckpoint(
  checkpoint: JudgedRecord,
  feed: VerifiedFeed,
  view: IdentityView,
): Validation<CoveredFeed> {
  return judging(() => checkpointOver(checkpoint, feed, view));
}

/** The checkpoint against its feed, as `verifyCheckpoint` answers when no check is cut short. */
function checkpointOver(
  checkpoint: JudgedRecord,
  feed: VerifiedFeed,
  view: IdentityView,
): Validation<CoveredFeed> {
  if (checkpoint.record.type !== "Checkpoint") {
    return no("the record is not a Checkpoint", "L1 10.5", "/type");
  }
  const record = checkpoint.record as Checkpoint;
  if (record.author !== feed.author) {
    return no("the checkpoint is of another mind's feed", "L1 10.5", "/author");
  }
  const time = ownSignedTime(checkpoint, record.author, view);
  if (time === undefined) {
    return no("the checkpoint is not signed by its author's own authority", "L1 10.5", "/proof");
  }
  if (record.size > feed.entries.length) {
    return no(
      "the checkpoint covers more entries than are held verified of this feed",
      "L1 10.5",
      "/size",
    );
  }
  const covered = feed.entries.slice(0, record.size);
  if (covered.at(-1)?.id !== record.head) {
    return no("`head` is not the last entry the checkpoint covers", "L1 10.5", "/head");
  }
  if (checkpointRoot(covered.map((entry) => entry.id)) !== record.root) {
    return no(
      "`root` is not the Merkle Tree Hash of the entries the checkpoint covers",
      "L1 10.5",
      "/root",
    );
  }
  const proofs = new Set<string>();
  for (const { entry } of covered) for (const digest of entry.proofs ?? []) proofs.add(digest);
  return ok({ time, entries: covered, proofs });
}

/**
 * Layer 1, 10.1: the proofs on a record that an entry commits to. The entry
 * names the record by its content ID and type, and lists the digests of the
 * proofs the record had when the entry was made. A record may have gained
 * proofs since, which the entry says nothing of.
 *
 * @param record - The record as held, from `judgeRecord`.
 * @returns The digests the entry lists that are of proofs on the record
 *   that verify. Or `undefined` if the entry is not about this record.
 */
export function committedProofs(entry: Entry, record: JudgedRecord): string[] | undefined {
  return finding(() => proofsCommitted(entry, record));
}

/** The proofs an entry commits to, as `committedProofs` answers when no check is cut short. */
function proofsCommitted(entry: Entry, record: JudgedRecord): string[] | undefined {
  if (entry.object !== contentId(record.record) || entry.objectType !== record.record.type) {
    return undefined;
  }
  const listed = new Set(entry.proofs ?? []);
  return record.proofs.map((proof) => proof.digest).filter((digest) => listed.has(digest));
}
