// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The edges of a service: the clock and the source of randomness.
 *
 * The packages below this one read neither. A service must: the time it
 * first saw a proof is evidence (core 9.4), and a challenge is random
 * (Layer 1, 13.4). Each is read here, through an interface, and given to
 * whatever needs it. A test gives its own.
 */

import type { Instant } from "@oip/core";

/** The present, as a service reads it. */
export interface Clock {
  /** The time now, in nanoseconds since the Unix epoch. */
  now(): Instant;
}

/** The clock of the machine. It is read in milliseconds. */
export const systemClock: Clock = {
  now: () => BigInt(Date.now()) * 1_000_000n,
};

/** A source of bytes nobody can predict. */
export interface Randomness {
  /** `length` random bytes. */
  bytes(length: number): Uint8Array;
}

/** The most bytes one call may ask of the platform's generator. */
const MOST_AT_ONCE = 65_536;

/** The platform's generator for cryptographic use. */
export const systemRandomness: Randomness = {
  bytes: (length) => {
    if (!Number.isSafeInteger(length) || length < 0 || length > MOST_AT_ONCE) {
      throw new TypeError(`a number of random bytes is from 0 to ${MOST_AT_ONCE}`);
    }
    return crypto.getRandomValues(new Uint8Array(length));
  },
};
