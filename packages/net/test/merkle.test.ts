// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import {
  bytesToHex,
  concatBytes,
  contentId,
  contentIdOfDigest,
  digestOfContentId,
  hexToBytes,
  isContentId,
  sha256,
} from "@oip/core";
import { clause, type JsonObject, readVectors } from "@oip/testkit";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { checkpointRoot, merkleTreeHash } from "../src/index.ts";

/**
 * The reference vectors of Certificate Transparency, which RFC 9162
 * standardises: the eight test leaves of its reference implementation's
 * Merkle tree test, and the root of the tree over the first one, two, and so
 * on to all eight of them. RFC 9162 prints no vectors of its own. Each root
 * was also computed here from the definition in Section 2.1.1 with another
 * implementation of SHA-256 (Python's `hashlib`), and agreed.
 */
const LEAVES = [
  "",
  "00",
  "10",
  "2021",
  "3031",
  "40414243",
  "5051525354555657",
  "606162636465666768696a6b6c6d6e6f",
].map((hex) => hexToBytes(hex));
const ROOTS = [
  "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
  "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
  "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
  "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
  "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
  "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
  "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
  "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
];

/** RFC 9162, 2.1.1, written as the RFC writes it: by splitting the list. */
function byDefinition(inputs: readonly Uint8Array[]): Uint8Array {
  const [only] = inputs;
  if (only === undefined) return sha256(new Uint8Array());
  if (inputs.length === 1) return sha256(concatBytes(Uint8Array.of(0), only));
  let k = 1;
  while (2 * k < inputs.length) k *= 2;
  return sha256(
    concatBytes(Uint8Array.of(1), byDefinition(inputs.slice(0, k)), byDefinition(inputs.slice(k))),
  );
}

describe(`${clause("L1 10.5")} the Merkle Tree Hash of RFC 9162`, () => {
  it("gives the roots of Certificate Transparency's reference vectors", () => {
    for (const [index, root] of ROOTS.entries()) {
      expect(bytesToHex(merkleTreeHash(LEAVES.slice(0, index + 1))), `${index + 1} leaves`).toBe(
        root,
      );
    }
  });

  it("is the hash of an empty string for an empty list", () => {
    expect(bytesToHex(merkleTreeHash([]))).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  it("hashes bytes and nothing else: another value is a mistake in the caller", () => {
    // And it says what is wrong, where the first thing done with the value would not.
    const mistake = new TypeError("a Merkle tree hashes bytes");
    expect(() => merkleTreeHash(["leaf" as never])).toThrow(mistake);
    expect(() => merkleTreeHash([new Uint8Array(1), undefined as never])).toThrow(mistake);
  });

  it("is what the definition gives, for a list of any length", () => {
    fc.assert(
      fc.property(fc.array(fc.uint8Array({ maxLength: 40 }), { maxLength: 70 }), (inputs) => {
        expect(bytesToHex(merkleTreeHash(inputs))).toBe(bytesToHex(byDefinition(inputs)));
      }),
    );
    // Every length up to a few past a power of two, where the tree changes shape.
    const inputs = Array.from({ length: 130 }, (_, n) => Uint8Array.of(n, n >> 8));
    for (let length = 0; length <= inputs.length; length++) {
      expect(bytesToHex(merkleTreeHash(inputs.slice(0, length))), `${length}`).toBe(
        bytesToHex(byDefinition(inputs.slice(0, length))),
      );
    }
  });

  it("tells a leaf from a node, and one order of the inputs from another", () => {
    const [a, b] = [Uint8Array.of(1), Uint8Array.of(2)];
    expect(bytesToHex(merkleTreeHash([a, b]))).not.toBe(bytesToHex(merkleTreeHash([b, a])));
    // The two leaf hashes side by side, given as one input, are not the tree over the two.
    const pair = concatBytes(merkleTreeHash([a]), merkleTreeHash([b]));
    expect(bytesToHex(merkleTreeHash([pair]))).not.toBe(bytesToHex(merkleTreeHash([a, b])));
  });

  it("reads its inputs once, from whatever gives them in order, and hashes only bytes", () => {
    function* once() {
      yield* LEAVES;
    }
    expect(bytesToHex(merkleTreeHash(once()))).toBe(ROOTS[7]);
    expect(() => merkleTreeHash(["00" as never])).toThrow(TypeError);
  });
});

describe(`${clause("L1 10.5")} the root of a checkpoint`, () => {
  const cases = (readVectors() as unknown as { cases: Record<string, JsonObject> }).cases;
  const [first, second] = [cases["feed_entry"]!, cases["feed_entry_1"]!];
  const checkpoint = cases["checkpoint"]!;

  it("reproduces the two-entry checkpoint of the test vectors", () => {
    expect(checkpoint["size"]).toBe(2);
    expect(checkpointRoot([contentId(first), contentId(second)])).toBe(checkpoint["root"]);
    expect(checkpoint["head"]).toBe(contentId(second));
  });

  it("hashes the digest inside each entry's content ID, and is written as a content ID", () => {
    const id = contentId(first);
    const digest = digestOfContentId(id);
    if (digest === undefined) throw new Error("a content ID has a digest");
    // One entry: SHA-256(0x00 ‖ digest), where the digest is that of the entry without its proof.
    const root = checkpointRoot([id]);
    expect(root).toBe(contentIdOfDigest(sha256(concatBytes(Uint8Array.of(0), digest))));
    expect(isContentId(root)).toBe(true);
    expect(root).not.toBe(id);
    expect(checkpointRoot([contentId(first), contentId(second)])).not.toBe(
      checkpointRoot([contentId(second), contentId(first)]),
    );
  });

  it("has no value for no entries, or for a value that is no content ID", () => {
    expect(checkpointRoot([])).toBeUndefined();
    for (const entry of [
      "",
      "b",
      "not an id",
      5,
      null,
      undefined,
      {},
      contentId(first).toUpperCase(),
    ]) {
      expect(checkpointRoot([contentId(first), entry]), JSON.stringify(entry)).toBeUndefined();
    }
    expect(checkpointRoot("abc" as never)).toBeUndefined();
  });
});
