// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The Mind Network of the Open Intelligence Protocol (Layer 1, Sections 10
 * and 12 to 16): feeds and checkpoints, locations and profiles, packets,
 * sessions and sealing.
 *
 * The package is pure: it does no I/O and never reads the clock.
 *
 * @packageDocumentation
 */

export {
  committedProofs,
  type CoveredFeed,
  type FeedEntry,
  type VerifiedFeed,
  verifyCheckpoint,
  verifyFeed,
} from "./feed.ts";
export { checkpointRoot, merkleTreeHash } from "./merkle.ts";
