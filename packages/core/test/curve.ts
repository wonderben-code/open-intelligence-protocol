// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Curve arithmetic for tests: the points and signatures that core 4.4 exists
 * to reject. A signer can make every one of them, and a permissive library
 * accepts them, so each test here states which side of the rule a value is
 * on. Nothing in this file is used outside tests.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha512 } from "@noble/hashes/sha2.js";

export const Point = ed25519.Point;

/** The order of the prime-order subgroup. */
export const L = Point.Fn.ORDER;

/** The field prime, 2^255 - 19. */
export const P = Point.Fp.ORDER;

export function littleEndian(value: bigint, length = 32): Uint8Array {
  const bytes = new Uint8Array(length);
  let rest = value;
  for (let i = 0; i < length; i++) {
    bytes[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return bytes;
}

export function fromLittleEndian(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) value = (value << 8n) | BigInt(bytes[i] ?? 0);
  return value;
}

const concat = (...parts: Uint8Array[]) => Uint8Array.from(parts.flatMap((part) => [...part]));

/** The eight points whose order divides 8, found by clearing the prime-order part of curve points. */
export function smallOrderPoints(): InstanceType<typeof Point>[] {
  const found = new Map<string, InstanceType<typeof Point>>();
  for (let y = 2n; found.size < 8; y++) {
    for (const sign of [0, 0x80]) {
      const encoded = littleEndian(y);
      encoded[31] = (encoded[31] ?? 0) | sign;
      let point;
      try {
        point = Point.fromBytes(encoded, false);
      } catch {
        continue; // no point has this y
      }
      // [L]Q, written so that the scalar stays below L.
      const cleared = point.multiplyUnsafe(L - 1n).add(point);
      found.set(cleared.toHex(), cleared);
    }
  }
  return [...found.values()];
}

/** The order of a small-order point: 1, 2, 4 or 8. */
export function orderOf(point: InstanceType<typeof Point>): number {
  let order = 1;
  for (let multiple = point; !multiple.is0(); multiple = multiple.add(point)) order++;
  return order;
}

/** What RFC 8032 derives from a private key: the secret scalar and the public key. */
export function expand(privateKey: Uint8Array): { scalar: bigint; publicKey: Uint8Array } {
  const { scalar, pointBytes } = ed25519.utils.getExtendedPublicKey(privateKey);
  return { scalar, publicKey: pointBytes };
}

/** k of RFC 8032, 5.1.7: SHA-512(R ‖ A ‖ M) as an integer modulo L. */
export function challenge(r: Uint8Array, a: Uint8Array, message: Uint8Array): bigint {
  return fromLittleEndian(sha512(concat(r, a, message))) % L;
}

/**
 * A signature made as a signer who knows the secret scalar can make it, with
 * the commitment `[nonce]B + offset` in place of the honest `[nonce]B`, and
 * for the public key bytes given (which may differ from the honest ones by a
 * small-order point). It satisfies the cofactored verification equation.
 */
export function craftSignature(
  scalar: bigint,
  publicKey: Uint8Array,
  message: Uint8Array,
  nonce: bigint,
  offset: InstanceType<typeof Point> = Point.ZERO,
): Uint8Array {
  const commitment = (nonce === 0n ? Point.ZERO : Point.BASE.multiply(nonce)).add(offset);
  const r = commitment.toBytes();
  const s = (nonce + challenge(r, publicKey, message) * scalar) % L;
  return concat(r, littleEndian(s));
}

/** The same signature with L added to S: another solution of the equation, with S not reduced. */
export function unreduced(signature: Uint8Array): Uint8Array {
  const s = fromLittleEndian(signature.subarray(32)) + L;
  return concat(signature.subarray(0, 32), littleEndian(s));
}
