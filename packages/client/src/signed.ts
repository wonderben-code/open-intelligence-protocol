// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Requests a mind signs (Layer 1, 13.3): an RFC 9421 signature over the
 * method, the target URI and the digest of the body, by one of the mind's
 * operational keys.
 */

import { bytesToBase64url, type Instant, type Signer } from "@oip/core";
import type { Randomness } from "@oip/keystore";
import { signRequest } from "@oip/net";

import type { Asking } from "./transport.ts";

const SECOND = 1_000_000_000n;
/** The bytes of a nonce: as many as a server's challenge has at least (Layer 1, 13.4). */
const NONCE_LENGTH = 16;

/** The key a mind signs its requests with. */
export interface RequestKey {
  /** The key as a `key-ref` of the mind, at the version of its identity that lists it. */
  readonly keyRef: string;
  /** What signs with it. */
  readonly signer: Signer;
}

/**
 * A request with the headers of its signature (Layer 1, 13.3).
 *
 * The signature is made at the whole second before `now`, is good for 300
 * seconds, and carries a nonce of its own: a request that is sent again is
 * signed again.
 *
 * @param now - The present, by the client's clock. A service refuses a
 *   signature made more than 300 seconds from its own.
 */
export async function signedAsking(
  asking: Asking,
  key: RequestKey,
  now: Instant,
  randomness: Randomness,
): Promise<Asking> {
  const nonce = randomness.bytes(NONCE_LENGTH);
  if (!(nonce instanceof Uint8Array) || nonce.length !== NONCE_LENGTH) {
    throw new TypeError("the source of randomness did not give what was asked");
  }
  const added = await signRequest(
    {
      method: asking.method,
      url: asking.url,
      headers: [],
      ...(asking.body === undefined ? {} : { body: asking.body.bytes }),
    },
    { keyRef: key.keyRef, created: now - (now % SECOND), nonce: bytesToBase64url(nonce) },
    key.signer,
  );
  return { ...asking, headers: [...(asking.headers ?? []), ...added] };
}
