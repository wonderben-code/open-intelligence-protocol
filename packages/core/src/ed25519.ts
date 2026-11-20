// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Ed25519 under the one rule of core 4.4, so that every verifier agrees on
 * which signatures are valid. The arithmetic is the library's
 * (`@noble/curves`, ADR-0002); this module only decides which keys and
 * signatures to accept.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToNumberLE } from "@noble/curves/utils.js";
import { noteCutShort } from "@oip/schema";

import { bytesToHex } from "./bytes.ts";
import { BoundedCache } from "./cache.ts";
import { sha256 } from "./hash.ts";

/** The length of an Ed25519 public key, and of an X25519 one: 32 bytes. */
export const PUBLIC_KEY_LENGTH = 32;

/** The length of an Ed25519 private key (the seed of RFC 8032): 32 bytes. */
export const PRIVATE_KEY_LENGTH = 32;

/** The length of an Ed25519 signature: 64 bytes, `R` then `S`. */
export const SIGNATURE_LENGTH = 64;

/**
 * core 4.4, items 2 and 3: whether 32 bytes are the canonical encoding of a
 * curve point of order exactly L. That excludes the identity point, every
 * small-order point and every point with a small-order component.
 */
function encodesPointOfOrderL(encoded: Uint8Array): boolean {
  try {
    // `false` selects the decoding of RFC 8032, 5.1.3, which rejects a
    // y-coordinate of 2^255 - 19 or more; ZIP 215 would accept it.
    const point = ed25519.Point.fromBytes(encoded, false);
    return !point.is0() && point.isTorsionFree();
  } catch (error) {
    noteCutShort(error);
    return false;
  }
}

/**
 * How many public keys are remembered as having passed the order check. A
 * check costs a scalar multiplication and honest keys repeat, so a key that
 * passes is checked once; the bound keeps a flood of distinct keys from
 * growing the memory.
 */
export const ORDER_CHECK_CACHE_SIZE = 4096;

const keysOfOrderL = new BoundedCache<true>(ORDER_CHECK_CACHE_SIZE);

/**
 * How many signatures are remembered as having verified. A signature costs
 * three scalar multiplications to check, and the same signature is checked
 * again whenever what carries it is read again: a log that is published a
 * second time, a record that a verifier judges once when it arrives and
 * once more when it is asked about it. The bound keeps a flood of distinct
 * signatures from growing the memory.
 */
export const SIGNATURE_CACHE_SIZE = 16_384;

const signaturesVerified = new BoundedCache<true>(SIGNATURE_CACHE_SIZE);

/**
 * What a signature is remembered under: a hash of every byte its verdict
 * depends on. The signature and the key have fixed lengths, so the three
 * are told apart wherever the message ends.
 */
function nameOf(signature: Uint8Array, publicKey: Uint8Array, message: Uint8Array): string {
  const all = new Uint8Array(SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH + message.length);
  all.set(signature);
  all.set(publicKey, SIGNATURE_LENGTH);
  all.set(message, SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH);
  return bytesToHex(sha256(all));
}

/**
 * Forgets every signature that is remembered as verified. Nothing but time
 * depends on what is remembered, so only a measurement needs this: one that
 * means to time the checking of a signature forgets it first.
 */
export function forgetVerifiedSignatures(): void {
  signaturesVerified.clear();
}

/**
 * A private copy of some bytes, or `undefined` if the value is not a byte
 * array of the length required. Every check and the library's verification
 * then read the same bytes: the caller's array may be shared with another
 * thread, or be an object that answers differently each time it is read.
 */
function snapshot(bytes: unknown, length?: number): Uint8Array | undefined {
  if (!(bytes instanceof Uint8Array)) return undefined;
  const copy = new Uint8Array(bytes);
  return length === undefined || copy.length === length ? copy : undefined;
}

/**
 * Only a yes is remembered. A no is worked out again each time, so a check
 * that was cut short, by an exhausted stack for example, can never leave an
 * honest key marked as bad.
 *
 * It is not part of the package's interface. `check` is the order check; a
 * test passes another to show what is remembered.
 */
export function hasOrderL(
  publicKey: Uint8Array,
  check: (encoded: Uint8Array) => boolean = encodesPointOfOrderL,
): boolean {
  const name = bytesToHex(publicKey);
  if (!keysOfOrderL.has(name) && !check(publicKey)) return false;
  return keysOfOrderL.get(name, () => true);
}

/**
 * Whether some bytes are an Ed25519 public key this revision accepts: the
 * canonical encoding of a point of order exactly L (core 4.4). A key that
 * fails must be rejected wherever it appears, including in identity logs.
 * A key that passes is remembered. It never throws.
 */
export function isEd25519PublicKey(publicKey: Uint8Array): boolean {
  try {
    const key = snapshot(publicKey, PUBLIC_KEY_LENGTH);
    return key !== undefined && hasOrderL(key);
  } catch (error) {
    noteCutShort(error);
    return false;
  }
}

/**
 * core 4.4 for one signature, with nothing remembered of it: the order
 * checks of `A` and `R`, and the library's strict verification. The three
 * arrays are the verifier's own copies.
 */
function checked(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  if (!hasOrderL(publicKey)) return false;
  if (!encodesPointOfOrderL(signature.subarray(0, PUBLIC_KEY_LENGTH))) return false;
  const valid = ed25519.verify(signature, message, publicKey, { zip215: false });
  // A `false` may be the library's answer to a failure of its own: see `retraced`.
  if (!valid) retraced(signature, publicKey, RETRACE_DEPTH);
  return valid;
}

/**
 * Whether a signature verifies, checked once: a yes is remembered under the
 * signature, the message and the key together, and given at once when the
 * same three come again. A no is worked out again each time, as for a key,
 * so a check that was cut short can never leave an honest signature marked
 * as bad.
 *
 * It is not part of the package's interface. `check` is the verification; a
 * test passes another to show what is remembered.
 */
export function verifiedOnce(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
  check: (signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) => boolean = checked,
): boolean {
  const name = nameOf(signature, publicKey, message);
  // Asking marks it as used, so that what is verified often is what is kept.
  if (signaturesVerified.has(name)) return signaturesVerified.get(name, () => true);
  return check(signature, message, publicKey) && signaturesVerified.get(name, () => true);
}

/**
 * Verifies an Ed25519 signature under core 4.4. A signature (`R`, `S`) by
 * public key `A` is valid only if:
 *
 *   1. `S` is less than the group order L;
 *   2. `A` and `R` are canonical encodings of curve points;
 *   3. `A` and `R` each have order exactly L;
 *   4. the verification equation of RFC 8032 holds.
 *
 * The library checks 1, 2 and 4 in its strict mode. It accepts points with a
 * small-order component, so 3 is checked here, for `A` and for `R`.
 *
 * A signature that verifies is remembered, with its message and its key, and
 * verifies at once when the same three come again (`SIGNATURE_CACHE_SIZE`).
 *
 * It never throws: anything that is not a valid signature gives `false`.
 */
export function verifyEd25519(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  try {
    // One copy of each input, taken once: the order checks and the equation
    // must be about the same bytes.
    const sig = snapshot(signature, SIGNATURE_LENGTH);
    const text = snapshot(message);
    const key = snapshot(publicKey, PUBLIC_KEY_LENGTH);
    if (sig === undefined || text === undefined || key === undefined) return false;
    return verifiedOnce(sig, text, key);
  } catch (error) {
    noteCutShort(error);
    return false;
  }
}

/**
 * How many frames of `retraced` lie above the steps taken again.
 *
 * Depth is what matters. The library takes the steps one frame below
 * `checked`, the frame of its own `verify`. Taken again from no
 * deeper than that, they have room wherever the library had, and a failure
 * of the library's goes unseen: with the steps one frame of `retraced`
 * down, a process that had verified often answered `false` for a valid
 * signature, with nothing noted, at one depth in some hundreds. One frame
 * more was enough there. How large a frame is belongs to the engine and to
 * how it has compiled each function, so the margin is wide: sixteen frames
 * more, where one was enough. A spent stack on the way down is thrown
 * through `checked` to `verifyEd25519`, which notes it. The steps are taken only after a
 * `false`: a signature that verifies pays nothing for the depth.
 */
const RETRACE_DEPTH = 16;

/**
 * Takes again, and deeper, the steps the library takes inside a `catch` of
 * its own, so that a failure there for want of room is noted (ADR-0010).
 *
 * The library decodes the key and `R` and multiplies the base point by `S`
 * in a `try` that answers `false` for whatever is thrown. That is right for
 * a point that is none and for an `S` that is not below L, which is how it
 * applies those rules. It is also what it answers when the call stack is
 * spent at that moment, and then the `false` says nothing of the signature.
 * After a `false`, the same three steps are taken here from further down,
 * where a spent stack is not caught unseen. Their results are not used: no
 * part of the verification is done here.
 *
 * @param deeper - How many frames further down the steps are taken.
 */
function retraced(signature: Uint8Array, publicKey: Uint8Array, deeper: number): void {
  if (deeper > 0) {
    retraced(signature, publicKey, deeper - 1);
    return;
  }
  try {
    ed25519.Point.fromBytes(publicKey, false);
    ed25519.Point.fromBytes(signature.subarray(0, PUBLIC_KEY_LENGTH), false);
    ed25519.Point.BASE.multiplyUnsafe(bytesToNumberLE(signature.subarray(PUBLIC_KEY_LENGTH)));
  } catch (error) {
    // A point that is none, an `S` out of range: the library's reasons, and not noted. A
    // spent stack: noted.
    noteCutShort(error);
  }
}

function privateKeyBytes(privateKey: Uint8Array): Uint8Array {
  if (!(privateKey instanceof Uint8Array) || privateKey.length !== PRIVATE_KEY_LENGTH) {
    // A constant message: nothing about the key, not even its length, is repeated.
    throw new TypeError("an Ed25519 private key is 32 bytes");
  }
  return privateKey;
}

/**
 * The public key of an Ed25519 private key (RFC 8032, 5.1.5).
 *
 * @throws TypeError if the private key is not 32 bytes.
 */
export function ed25519PublicKey(privateKey: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(privateKeyBytes(privateKey));
}

/**
 * Signs a message with Ed25519 (RFC 8032, 5.1.6). Signing is deterministic:
 * the same key and message always give the same signature.
 *
 * @throws TypeError if the private key is not 32 bytes or the message is not bytes.
 */
export function signEd25519(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
  const key = privateKeyBytes(privateKey);
  if (!(message instanceof Uint8Array)) throw new TypeError("a message to sign is bytes");
  return ed25519.sign(message, key);
}
