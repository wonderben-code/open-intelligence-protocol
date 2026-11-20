// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Rate limits (BUILD.md 3.7): so many requests at once, and so many a
 * minute after, for each client. A service keeps one limiter for each thing
 * it limits by, an address and a mind among them, and asks each.
 *
 * The time is the caller's clock, and the arithmetic is in whole
 * nanoseconds: the same requests at the same times always get the same
 * answers. The clock is the one the service tells the time by, which may be
 * set back: a limiter then gives no client more than its allowance, and
 * keeps none out for longer than an empty allowance takes to fill.
 */

import type { Instant } from "@oip/core";

import type { Clock } from "./edges.ts";
import { parseAddress } from "./ip.ts";

/** How much one client may ask. */
export interface RateLimit {
  /** How many requests may come at once, after a pause. At least 1. */
  readonly burst: number;
  /** How many requests a minute may follow. At least 1. */
  readonly perMinute: number;
}

/** Whether a request may go ahead, and if not, when to ask again. */
export type Allowance =
  | { readonly ok: true }
  | {
      readonly ok: false;
      /** Whole seconds until a request of the same cost would be allowed. At least 1. */
      readonly retryAfter: number;
    };

const MINUTE = 60_000_000_000n;
const SECOND = 1_000_000_000n;

/**
 * A limiter for one kind of client. It keeps one time for each client it
 * has heard from lately, and at most `maxClients` of them: a flood of new
 * clients pushes out the ones heard from longest ago, whose allowance is
 * then whole again, which is the most it can win them.
 */
export class RateLimiter {
  /** The time between two requests at the steady rate. */
  readonly #interval: bigint;
  /** How far ahead of the clock a client's time may run: the burst. */
  readonly #tolerance: bigint;
  readonly #clock: Clock;
  readonly #maxClients: number;
  /** For each client, the time at which its allowance would be whole again. */
  readonly #clients = new Map<string, Instant>();

  constructor(limit: RateLimit, clock: Clock, maxClients = 100_000) {
    for (const [name, value] of [
      ["burst", limit.burst],
      ["perMinute", limit.perMinute],
      ["maxClients", maxClients],
    ] as const) {
      if (!Number.isSafeInteger(value) || value < 1) {
        throw new TypeError(`${name} is a whole number, at least 1`);
      }
    }
    this.#interval = MINUTE / BigInt(limit.perMinute);
    if (this.#interval === 0n) throw new TypeError("perMinute is at most one request a nanosecond");
    this.#tolerance = this.#interval * BigInt(limit.burst);
    this.#clock = clock;
    this.#maxClients = maxClients;
  }

  /** How many clients the limiter holds a time for. */
  get size(): number {
    return this.#clients.size;
  }

  /**
   * Counts a request of a client, if it is within the limit.
   *
   * @param client - Who asks: an address, a mind. Any string.
   * @param cost - How many requests this one counts as. A whole number, at least 1.
   */
  take(client: string, cost = 1): Allowance {
    if (!Number.isSafeInteger(cost) || cost < 1)
      throw new TypeError("a cost is a whole number, at least 1");
    const now = this.#clock.now();
    let held = this.#clients.get(client);
    // A request is taken only if its time stays within the allowance of now, so a clock that
    // goes forward never finds a time further ahead than that. One that does was written
    // before the clock was set back. The client then has nothing left and gains at the steady
    // rate from now: it is not kept out for as long as the clock went back.
    if (held !== undefined && held - now > this.#tolerance) {
      held = now + this.#tolerance;
      this.#clients.set(client, held);
    }
    const from = held === undefined || held < now ? now : held;
    const next = from + this.#interval * BigInt(cost);
    if (next - now > this.#tolerance) {
      const wait = next - now - this.#tolerance;
      return { ok: false, retryAfter: Number((wait + SECOND - 1n) / SECOND) };
    }
    // Last in the map's order is the one heard from last.
    this.#clients.delete(client);
    this.#clients.set(client, next);
    if (this.#clients.size > this.#maxClients) {
      for (const oldest of this.#clients.keys()) {
        this.#clients.delete(oldest);
        break;
      }
    }
    return { ok: true };
  }
}

/**
 * What to limit an IP address by. An IPv4 address is one client. An IPv6
 * client is usually given a whole /64, and can take any address in it, so
 * the first 64 bits are the client.
 *
 * @returns The key, or `undefined` for what is no IP address.
 */
export function addressKey(address: string): string | undefined {
  const read = parseAddress(address);
  if (read === undefined) return undefined;
  if (read.family === 4) return address;
  const groups = [0, 2, 4, 6].map((at) =>
    (((read.bytes[at] ?? 0) << 8) | (read.bytes[at + 1] ?? 0)).toString(16),
  );
  return `${groups.join(":")}::/64`;
}
