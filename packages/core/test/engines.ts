// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Engines for the arithmetic of a signature, for the tests: one written out
 * from the definition, and OpenSSL. Whatever does the arithmetic, the rule
 * is core 4.4, and every test of the rule runs with each of them.
 */

import { createPublicKey, verify } from "node:crypto";

import { afterAll, beforeAll } from "vitest";

import { useEd25519Engine, usePortableEd25519 } from "../src/ed25519.ts";
import { bytesEqual, type Ed25519Engine, forgetVerifiedSignatures } from "../src/index.ts";
import { challenge, fromLittleEndian, L, Point } from "./curve.ts";

/**
 * The check of RFC 8032, 5.1.7 without the cofactor, written out: `S` is
 * below L, and `[S]B - [k]A` encodes as `R`. The key is decoded as OpenSSL
 * decodes one, with no rule against a `y` that is not reduced.
 */
export const cofactorless: Ed25519Engine = (signature, message, publicKey) => {
  const r = signature.subarray(0, 32);
  const s = fromLittleEndian(signature.subarray(32));
  if (s >= L) return false;
  const a = Point.fromBytes(publicKey, true);
  const k = challenge(r, publicKey, message);
  const sB = s === 0n ? Point.ZERO : Point.BASE.multiplyUnsafe(s);
  const kA = k === 0n ? Point.ZERO : a.multiplyUnsafe(k);
  return bytesEqual(sB.subtract(kA).toBytes(), r);
};

const SPKI_PREFIX = Uint8Array.of(
  0x30,
  0x2a,
  0x30,
  0x05,
  0x06,
  0x03,
  0x2b,
  0x65,
  0x70,
  0x03,
  0x21,
  0x00,
);

/** OpenSSL's answer, asked as `@oip/server` asks it. */
export const openssl: Ed25519Engine = (signature, message, publicKey) =>
  verify(
    null,
    message,
    createPublicKey({ key: Buffer.concat([SPKI_PREFIX, publicKey]), format: "der", type: "spki" }),
    signature,
  );

/** What does the arithmetic in a run of the tests: the library where there is no engine. */
export const ENGINES: [name: string, engine: Ed25519Engine | undefined][] = [
  ["the library", undefined],
  ["an engine written out from RFC 8032", cofactorless],
  ["OpenSSL", openssl],
];

/** Runs the tests of the `describe` it is called in with an engine, and with none after them. */
export function usingEngine(engine: Ed25519Engine | undefined): void {
  beforeAll(() => {
    usePortableEd25519();
    forgetVerifiedSignatures();
    if (engine !== undefined) useEd25519Engine(engine);
  });
  afterAll(() => {
    usePortableEd25519();
    forgetVerifiedSignatures();
  });
}
