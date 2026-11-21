// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The Merkle Tree Hash of RFC 9162, Section 2.1.1, which a checkpoint signs
 * over the entries of a feed (Layer 1, 10.5).
 *
 * The hash of a list of one input is `SHA-256(0x00 ‖ input)`. The hash of a
 * longer list is `SHA-256(0x01 ‖ left ‖ right)`, where `left` is the hash
 * of its first `k` inputs and `right` that of the rest, `k` being the
 * largest power of two smaller than the length. The two prefixes keep a
 * leaf from being taken for an inner node.
 */

import { concatBytes, contentIdOfDigest, digestOfContentId, sha256 } from "@oip/core";

const LEAF = Uint8Array.of(0x00);
const NODE = Uint8Array.of(0x01);

/**
 * RFC 9162, 2.1.1: the Merkle Tree Hash of a list of inputs, in order.
 *
 * It keeps one hash for each level of the tree that has an odd subtree
 * waiting, so a feed of a million entries needs twenty hashes in memory and
 * no recursion.
 *
 * @throws TypeError if an input is not bytes.
 */
export function merkleTreeHash(inputs: Iterable<Uint8Array>): Uint8Array {
  // The roots of the complete subtrees so far, largest first, each with its number of leaves.
  const waiting: { hash: Uint8Array; leaves: number }[] = [];
  for (const input of inputs) {
    if (!(input instanceof Uint8Array)) throw new TypeError("a Merkle tree hashes bytes");
    let top = { hash: sha256(concatBytes(LEAF, input)), leaves: 1 };
    // Two complete subtrees of one size are the two halves of the next size up.
    for (let left = waiting.at(-1); left?.leaves === top.leaves; left = waiting.at(-1)) {
      waiting.pop();
      top = { hash: sha256(concatBytes(NODE, left.hash, top.hash)), leaves: 2 * top.leaves };
    }
    waiting.push(top);
  }
  // What is left is the split of 2.1.1 read from the right: each smaller subtree is
  // the right-hand part of the tree whose left-hand part is the next larger one.
  let root = waiting.pop()?.hash;
  // 2.1.1: the hash of an empty list is the hash of an empty string.
  if (root === undefined) return sha256(new Uint8Array());
  for (let left = waiting.pop(); left !== undefined; left = waiting.pop()) {
    root = sha256(concatBytes(NODE, left.hash, root));
  }
  return root;
}

/**
 * Layer 1, 10.5: the `root` of a checkpoint over a feed's entries, given
 * their content IDs in `seq` order. The input for each leaf is the 32-byte
 * digest inside the entry's content ID, and the root is written as a
 * content ID.
 *
 * @returns `undefined` if there is no entry, since a checkpoint covers at
 *   least one, or if one of the values is not a content ID.
 */
export function checkpointRoot(entries: readonly unknown[]): string | undefined {
  if (!Array.isArray(entries) || entries.length === 0) return undefined;
  const digests: Uint8Array[] = [];
  for (const entry of entries as readonly unknown[]) {
    const digest = digestOfContentId(entry);
    if (digest === undefined) return undefined;
    digests.push(digest);
  }
  return contentIdOfDigest(merkleTreeHash(digests));
}
