// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { addressKey, type Clock, RateLimiter } from "../src/index.ts";

const SECOND = 1_000_000_000n;

/** A clock a test moves by hand. */
function handClock(start = 1_000n * SECOND): Clock & { at: bigint } {
  const clock = { at: start, now: () => clock.at };
  return clock;
}

describe("a rate limit", () => {
  it("lets a burst through at once, and then one request each interval", () => {
    const clock = handClock();
    const limiter = new RateLimiter({ burst: 3, perMinute: 60 }, clock);
    expect([1, 2, 3].map(() => limiter.take("a"))).toStrictEqual([
      { ok: true },
      { ok: true },
      { ok: true },
    ]);
    expect(limiter.take("a")).toStrictEqual({ ok: false, retryAfter: 1 });
    // A refusal costs nothing: a second later, exactly one more goes through.
    clock.at += SECOND - 1n;
    expect(limiter.take("a")).toStrictEqual({ ok: false, retryAfter: 1 });
    clock.at += 1n;
    expect(limiter.take("a")).toStrictEqual({ ok: true });
    expect(limiter.take("a")).toStrictEqual({ ok: false, retryAfter: 1 });
  });

  it("is whole again after a pause, and no more than whole", () => {
    const clock = handClock();
    const limiter = new RateLimiter({ burst: 2, perMinute: 6 }, clock);
    limiter.take("a");
    limiter.take("a");
    // Ten seconds for each request at six a minute.
    expect(limiter.take("a")).toStrictEqual({ ok: false, retryAfter: 10 });
    clock.at += 3_600n * SECOND;
    expect(limiter.take("a").ok).toBe(true);
    expect(limiter.take("a").ok).toBe(true);
    expect(limiter.take("a").ok).toBe(false);
  });

  it("counts each client by itself", () => {
    const clock = handClock();
    const limiter = new RateLimiter({ burst: 1, perMinute: 1 }, clock);
    expect(limiter.take("a").ok).toBe(true);
    expect(limiter.take("b").ok).toBe(true);
    expect(limiter.take("a")).toStrictEqual({ ok: false, retryAfter: 60 });
    expect(limiter.size).toBe(2);
  });

  it("counts a request that costs more as that many, and says when one of that cost may come", () => {
    const clock = handClock();
    const limiter = new RateLimiter({ burst: 10, perMinute: 60 }, clock);
    expect(limiter.take("a", 10).ok).toBe(true);
    expect(limiter.take("a")).toStrictEqual({ ok: false, retryAfter: 1 });
    expect(limiter.take("a", 5)).toStrictEqual({ ok: false, retryAfter: 5 });
    // A cost beyond the burst is never allowed, and the wait is still a number.
    expect(limiter.take("b", 11)).toStrictEqual({ ok: false, retryAfter: 1 });
    clock.at += 5n * SECOND;
    expect(limiter.take("a", 5).ok).toBe(true);
  });

  it("rounds the wait up to a whole second, and never says none", () => {
    const clock = handClock();
    const limiter = new RateLimiter({ burst: 1, perMinute: 600 }, clock);
    limiter.take("a");
    // A tenth of a second to wait.
    expect(limiter.take("a")).toStrictEqual({ ok: false, retryAfter: 1 });
    const slow = new RateLimiter({ burst: 1, perMinute: 40 }, clock);
    slow.take("a");
    // A second and a half.
    expect(slow.take("a")).toStrictEqual({ ok: false, retryAfter: 2 });
  });

  it("holds a bounded number of clients, and lets go of the one heard from longest ago", () => {
    const clock = handClock();
    const limiter = new RateLimiter({ burst: 1, perMinute: 1 }, clock, 3);
    for (const client of ["a", "b", "c"]) limiter.take(client);
    // Heard from again, and refused: a refusal keeps a client's place as it was.
    expect(limiter.take("a").ok).toBe(false);
    clock.at += 60n * SECOND;
    expect(limiter.take("b").ok).toBe(true);
    limiter.take("d");
    expect(limiter.size).toBe(3);
    // `a` was let go: its allowance is whole. `c` and `b` are held.
    limiter.take("e");
    expect(limiter.size).toBe(3);
    expect(limiter.take("b").ok).toBe(false);
  });

  it("takes limits and costs that are whole numbers, at least 1", () => {
    const clock = handClock();
    for (const wrong of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => new RateLimiter({ burst: wrong, perMinute: 60 }, clock)).toThrow(TypeError);
      expect(() => new RateLimiter({ burst: 1, perMinute: wrong }, clock)).toThrow(TypeError);
      expect(() => new RateLimiter({ burst: 1, perMinute: 60 }, clock, wrong)).toThrow(TypeError);
      expect(() => new RateLimiter({ burst: 1, perMinute: 60 }, clock).take("a", wrong)).toThrow(
        TypeError,
      );
    }
    expect(() => new RateLimiter({ burst: 1, perMinute: 60_000_000_001 }, clock)).toThrow(
      TypeError,
    );
    expect(new RateLimiter({ burst: 1, perMinute: 60_000_000_000 }, clock).take("a").ok).toBe(true);
  });

  it("never lets through more than the burst and the steady rate allow, whatever the times", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 20 }),
        fc.integer({ min: 1, max: 600 }),
        fc.array(fc.integer({ min: 0, max: 5_000 }), { minLength: 1, maxLength: 200 }),
        (burst, perMinute, gaps) => {
          const clock = handClock(0n);
          const limiter = new RateLimiter({ burst, perMinute }, clock);
          let allowed = 0;
          for (const milliseconds of gaps) {
            clock.at += BigInt(milliseconds) * 1_000_000n;
            if (limiter.take("a").ok) allowed++;
          }
          const interval = 60_000_000_000n / BigInt(perMinute);
          // What the steady rate gives in the time passed, and the burst on top.
          expect(BigInt(allowed)).toBeLessThanOrEqual(BigInt(burst) + clock.at / interval);
        },
      ),
    );
  });
});

describe("what an address is limited by", () => {
  it("is an IPv4 address itself", () => {
    expect(addressKey("203.0.113.7")).toBe("203.0.113.7");
    expect(addressKey("0.0.0.0")).toBe("0.0.0.0");
  });

  it("is the first 64 bits of an IPv6 address, however it is written", () => {
    for (const address of [
      "2001:db8:1:2:3:4:5:6",
      "2001:0db8:0001:0002:ffff:ffff:ffff:ffff",
      "2001:DB8:1:2::",
      "2001:db8:1:2::1",
      "2001:db8:1:2:0:0:192.0.2.1",
      "2001:db8:1:2::192.0.2.1",
      "2001:db8:1:2::1%eth0",
    ]) {
      expect(addressKey(address), address).toBe("2001:db8:1:2::/64");
    }
    expect(addressKey("::1")).toBe("0:0:0:0::/64");
    expect(addressKey("::")).toBe("0:0:0:0::/64");
    expect(addressKey("2001:db8::1")).toBe("2001:db8:0:0::/64");
    expect(addressKey("::ffff:192.0.2.1")).toBe("0:0:0:0::/64");
    expect(addressKey("1::")).toBe("1:0:0:0::/64");
    expect(addressKey("1:2:3::192.0.2.1")).toBe("1:2:3:0::/64");
    expect(addressKey("1:2:3:4:5:6:192.0.2.1")).toBe("1:2:3:4::/64");
  });

  it("is nothing for what is no IP address", () => {
    for (const other of [
      "",
      "example.com",
      "203.0.113",
      "203.0.113.256",
      "2001:db8::g",
      "1:2:3:4:5:6:7:8:9",
      " 203.0.113.7",
    ]) {
      expect(addressKey(other), other).toBeUndefined();
    }
  });
});
