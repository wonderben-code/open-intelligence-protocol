// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * HPKE (RFC 9180) in the one suite the protocol uses to seal a packet
 * (Layer 1, 12.6): base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and
 * ChaCha20-Poly1305, one message for each encapsulation.
 *
 * The construction is the library's (ADR-0011).
 * What is here is the choice of suite, the checks on what goes in, and the
 * rule that nothing a caller sends from outside makes these functions throw.
 * The package draws no randomness: the sender's is a parameter.
 */

import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { x25519 } from "@noble/curves/ed25519.js";
import { noteCutShort } from "@oip/schema";

/** Layer 1, 12.6: the name of the suite, as a `Sealed` record gives it. */
export const HPKE_SUITE = "hpke-base-x25519-sha256-chacha20poly1305";

/** The length of an X25519 key, private or public, and of the randomness a sender gives: 32 bytes. */
const KEY_LENGTH = 32;

/**
 * The parts of the library's suite that are used here. Its own declarations
 * name the platform's key type, which not every platform this package runs
 * on declares: a key the library has read is opaque here, and only handed
 * back to it.
 */
interface Suite {
  readonly kem: {
    deserializePublicKey(key: Uint8Array): Promise<unknown>;
    deserializePrivateKey(key: Uint8Array): Promise<unknown>;
  };
  seal(
    params: { recipientPublicKey: unknown; info: Uint8Array; ekm: Uint8Array },
    plaintext: Uint8Array,
    aad: Uint8Array,
  ): Promise<{ readonly enc: ArrayBuffer; readonly ct: ArrayBuffer }>;
  open(
    params: { recipientKey: unknown; enc: Uint8Array; info: Uint8Array },
    ciphertext: Uint8Array,
    aad: Uint8Array,
  ): Promise<ArrayBuffer>;
}

const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Chacha20Poly1305(),
}) as unknown as Suite;

function bytesOf(value: unknown, what: string, length?: number): Uint8Array {
  if (!(value instanceof Uint8Array) || (length !== undefined && value.length !== length)) {
    // A constant message: nothing about a key or about randomness is repeated.
    throw new TypeError(what);
  }
  // A copy of our own: what is sealed is what was given, whatever the caller does meanwhile.
  return Uint8Array.from(value);
}

/**
 * The public key of an X25519 private key (RFC 7748): a mind's agreement
 * key, as its identity log lists it.
 *
 * @throws TypeError if the private key is not 32 bytes.
 */
export function x25519PublicKey(privateKey: Uint8Array): Uint8Array {
  return x25519.getPublicKey(bytesOf(privateKey, "an X25519 private key is 32 bytes", KEY_LENGTH));
}

/** What a sender seals. */
export interface HpkeSealInput {
  /** The recipient's X25519 public key, 32 bytes. */
  readonly recipientPublicKey: Uint8Array;
  /** The application's `info`. */
  readonly info: Uint8Array;
  /** The associated data: authenticated, not encrypted. */
  readonly aad: Uint8Array;
  /** What is encrypted. */
  readonly plaintext: Uint8Array;
  /**
   * 32 bytes from a cryptographically secure random source, used for this
   * one message and never again. The sender's ephemeral key is derived from
   * them: the same bytes for two messages to one recipient give both the
   * same key and nonce, which reveals the two plaintexts to anyone who sees
   * both.
   */
  readonly randomness: Uint8Array;
}

/** A sealed message: the encapsulated key and the ciphertext. */
export interface HpkeSealed {
  /** The encapsulated key, 32 bytes. */
  readonly enc: Uint8Array;
  /** The ciphertext, 16 bytes longer than the plaintext. */
  readonly ciphertext: Uint8Array;
}

/**
 * Seals one message to a recipient's X25519 key (RFC 9180, 6.1, base mode).
 *
 * @returns The sealed message, or `undefined` if nothing can be sealed to
 *   that key: it is a point of small order, with which every sender would
 *   share the same secret (RFC 9180, 7.1.4).
 * @throws TypeError if an argument is not bytes, or a key or the randomness
 *   is not 32 bytes.
 */
export async function hpkeSeal(input: HpkeSealInput): Promise<HpkeSealed | undefined> {
  const key = bytesOf(input.recipientPublicKey, "an X25519 public key is 32 bytes", KEY_LENGTH);
  const info = bytesOf(input.info, "`info` is bytes");
  const aad = bytesOf(input.aad, "the associated data is bytes");
  const plaintext = bytesOf(input.plaintext, "the plaintext is bytes");
  const ekm = bytesOf(input.randomness, "the randomness of a sender is 32 bytes", KEY_LENGTH);
  try {
    const recipientPublicKey = await suite.kem.deserializePublicKey(key);
    const sealed = await suite.seal({ recipientPublicKey, info, ekm }, plaintext, aad);
    return { enc: new Uint8Array(sealed.enc), ciphertext: new Uint8Array(sealed.ct) };
  } catch (error) {
    noteCutShort(error);
    // The library's reason is not passed on: it may speak of key material.
    return undefined;
  }
}

/** What a recipient opens. */
export interface HpkeOpenInput {
  /** The recipient's X25519 private key, 32 bytes. */
  readonly recipientPrivateKey: Uint8Array;
  /** The encapsulated key, as it arrived. */
  readonly enc: Uint8Array;
  /** The application's `info`. */
  readonly info: Uint8Array;
  /** The associated data. */
  readonly aad: Uint8Array;
  /** The ciphertext, as it arrived. */
  readonly ciphertext: Uint8Array;
}

/**
 * Opens a message sealed to this recipient (RFC 9180, 6.1, base mode).
 *
 * It never throws on what arrived. The private key is the caller's own.
 *
 * @returns The plaintext, or `undefined` if the message does not open: it
 *   was sealed to another key, with another `info` or other associated
 *   data, or it was changed on the way.
 * @throws TypeError if the private key is not 32 bytes, or `info` or the
 *   associated data is not bytes.
 */
export async function hpkeOpen(input: HpkeOpenInput): Promise<Uint8Array | undefined> {
  const key = bytesOf(input.recipientPrivateKey, "an X25519 private key is 32 bytes", KEY_LENGTH);
  const info = bytesOf(input.info, "`info` is bytes");
  const aad = bytesOf(input.aad, "the associated data is bytes");
  const { enc, ciphertext } = input as { readonly enc: unknown; readonly ciphertext: unknown };
  // What arrived is anything at all. Its length is the library's to judge, with the rest.
  if (!(enc instanceof Uint8Array) || !(ciphertext instanceof Uint8Array)) return undefined;
  const arrived = { enc: Uint8Array.from(enc), ciphertext: Uint8Array.from(ciphertext) };
  try {
    const recipientKey = await suite.kem.deserializePrivateKey(key);
    const opened = await suite.open(
      { recipientKey, enc: arrived.enc, info },
      arrived.ciphertext,
      aad,
    );
    return new Uint8Array(opened);
  } catch (error) {
    noteCutShort(error);
    return undefined;
  }
}
