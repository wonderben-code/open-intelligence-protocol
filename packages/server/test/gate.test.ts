// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { OipError, PROBLEM_MEDIA_TYPE } from "@oip/core";
import { clause } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import { type Asked, gate, Log, Metrics, RateLimiter, Unavailable } from "../src/index.ts";

function made() {
  const clock = { at: 1_000_000_000n, now: () => clock.at };
  const lines: Record<string, unknown>[] = [];
  const log = new Log({
    service: "test",
    clock,
    sink: (line) => lines.push(JSON.parse(line) as Record<string, unknown>),
  });
  const metrics = new Metrics();
  const gated = gate({ clock, log, metrics, service: "test" });
  const limiter = new RateLimiter({ burst: 2, perMinute: 6 }, clock);
  const asked = (address?: string, id = "one"): Asked => ({
    req: { raw: new Request("http://service.example/things/one"), param: () => id },
    env: address === undefined ? undefined : { address },
  });
  return { clock, lines, metrics, gated, limiter, asked };
}

describe(`${clause("core 10.2")} the gate a request passes`, () => {
  it("hands the request and the parameters of its path to the handler, and marks the answer", async () => {
    const { gated, limiter, asked, metrics, clock } = made();
    const handler = gated("thing", limiter, (request, param) => {
      clock.at += 250_000_000n;
      return new Response(`${request.method} ${param("id")}`);
    });
    const response = await handler(asked("203.0.113.7", "seven"));
    expect(await response.text()).toBe("GET seven");
    expect(response.headers.get("access-control-allow-origin")).toBe("*");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    const text = metrics.render();
    expect(text).toContain('oip_test_requests_total{route="thing",status="200"} 1');
    expect(text).toContain('oip_test_request_seconds_bucket{route="thing",le="0.25"} 1');
    expect(text).toContain('oip_test_request_seconds_bucket{route="thing",le="0.1"} 0');
  });

  it("limits what one address asks, and counts an address that is none as one client", async () => {
    const { gated, limiter, asked } = made();
    let handled = 0;
    const handler = gated("thing", limiter, () => {
      handled++;
      return new Response("ok");
    });
    for (let n = 0; n < 2; n++) expect((await handler(asked("203.0.113.7"))).status).toBe(200);
    const limited = await handler(asked("203.0.113.7"));
    expect(limited.status).toBe(429);
    expect(limited.headers.get("content-type")).toBe(PROBLEM_MEDIA_TYPE);
    expect(limited.headers.get("retry-after")).toBe("10");
    expect(limited.headers.get("access-control-allow-origin")).toBe("*");
    expect(((await limited.json()) as { type: string }).type).toBe("urn:oip:error:rate-limited");
    expect(handled).toBe(2);
    // Another address is another client. No address, and what is no address, are one more.
    expect((await handler(asked("198.51.100.9"))).status).toBe(200);
    expect((await handler(asked())).status).toBe(200);
    expect((await handler(asked("not an address"))).status).toBe(200);
    expect((await handler(asked(""))).status).toBe(429);
  });

  it("answers what a handler throws, and logs only the failure nobody expected", async () => {
    const { gated, clock, asked, lines, metrics } = made();
    const generous = new RateLimiter({ burst: 100, perMinute: 6000 }, clock);
    const thrown = (error: unknown) =>
      gated("thing", generous, () => {
        throw error;
      })(asked("203.0.113.7"));
    const refused = await thrown(new OipError("forbidden", "not yours"));
    expect(refused.status).toBe(403);
    expect(((await refused.json()) as { detail: string }).detail).toBe("not yours");
    const later = await thrown(new Unavailable("busy", 7));
    expect(later.status).toBe(503);
    expect(later.headers.get("retry-after")).toBe("7");
    expect(lines).toHaveLength(0);
    const failed = await gated("thing", generous, () =>
      Promise.reject(new Error("the password is hunter2")),
    )(asked("203.0.113.7"));
    expect(failed.status).toBe(500);
    expect(await failed.text()).not.toContain("hunter2");
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatchObject({ level: "error", event: "request failed", route: "thing" });
    expect(metrics.render()).toContain('oip_test_requests_total{route="thing",status="500"} 1');
  });
});
