// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Ed25519 by OpenSSL, for a service: the arithmetic of a signature in a
 * tenth of the time the portable library takes (ADR-0016).
 *
 * The rule a signature is held to is core 4.4, and it stays in `@oip/core`,
 * which gives OpenSSL one question only: whether `S` is below L and
 * `[S]B - [k]A` encodes as `R`. `@oip/core` tries the engine on signatures
 * whose answers are known before it uses it, and goes on checking for
 * itself what OpenSSL does not: that the key has order L, and that `R` is
 * not the identity.
 */

import { createPublicKey, verify } from "node:crypto";

import { type Ed25519Engine, useEd25519Engine } from "@oip/core";

/**
 * An Ed25519 public key as a SubjectPublicKeyInfo (RFC 8410, Section 4)
 * is these twelve bytes and then the 32 bytes of the key.
 */
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

/**
 * OpenSSL's answer for one signature, as an engine for `@oip/core`. It
 * throws for a key OpenSSL will not read, which `@oip/core` takes for a no.
 */
export const nativeEd25519: Ed25519Engine = (signature, message, publicKey) => {
  const key = createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, publicKey]),
    format: "der",
    type: "spki",
  });
  return verify(null, message, key, signature);
};

/**
 * Has this process check signatures with OpenSSL. A service calls it once,
 * when it starts.
 *
 * @returns Whether OpenSSL is now in use. `false` if the OpenSSL of this
 *   platform does not answer as the rule needs, or another engine is in use
 *   already: the process then goes on as it was.
 */
export function useNativeEd25519(): boolean {
  try {
    useEd25519Engine(nativeEd25519);
    return true;
  } catch {
    // `@oip/core` refused it, and said why to nobody: the caller says that it was not taken.
    return false;
  }
}
