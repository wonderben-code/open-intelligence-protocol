// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** A signer that holds its private key in memory. */

import { ed25519PublicKey, signEd25519 } from "./ed25519.ts";
import { encodeEd25519Multikey } from "./multikey.ts";
import type { Signer } from "./proof.ts";

/**
 * A signer for an Ed25519 private key held in memory. It is the simplest
 * signer, for tests, tools and keystores that have already unlocked a key.
 *
 * The signer keeps a copy of the key, never exposes it, and puts it in no
 * message. A program that must not hold private keys uses a `Signer` backed
 * by a keystore or a hardware key instead.
 *
 * @throws TypeError if the private key is not 32 bytes.
 */
export function signerFromPrivateKey(privateKey: Uint8Array): Signer {
  const publicKey = encodeEd25519Multikey(ed25519PublicKey(privateKey));
  // A copy, so that the signer keeps working if the caller wipes its own array.
  const key = Uint8Array.from(privateKey);
  // The key lives in the closure, not on the object: printing the signer shows only the public key.
  return Object.freeze({
    publicKey,
    sign: (message: Uint8Array) => signEd25519(message, key),
  });
}
