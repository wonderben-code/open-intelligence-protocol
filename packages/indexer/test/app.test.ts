// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { type JsonObject, MEDIA_TYPE, mindId, parseRecord, PROBLEM_MEDIA_TYPE } from "@oip/core";
import type { Bundle } from "@oip/schema";
import { Database, Log, LogArchive, Metrics, RateLimiter, Shutdown } from "@oip/server";
import { clause } from "@oip/testkit";
import { at, KeyMind, locationBy, type Mind, T } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  Broker,
  Indexer,
  INDEXER_MIGRATIONS,
  indexerApp,
  type IndexerAppOptions,
} from "../src/index.ts";

let directory: string;
let db: Database;
let clock: { at: bigint; now: () => bigint };
let lines: Record<string, unknown>[];
let metrics: Metrics;
let shutdown: Shutdown;
let broker: Broker;
let posted: string[];

const ian = new KeyMind("ian");
const ada = new KeyMind("ada");
const bob = new KeyMind("bob");

const idOf = (mind: Mind): string => mindId(mind.address) ?? "";
const bundleOf = (mind: Mind, more: JsonObject = {}): Bundle =>
  ({
    oip: "1",
    type: "Bundle",
    mind: mind.address,
    log: mind.events,
    ...more,
  }) as unknown as Bundle;
const located = (mind: Mind): Bundle =>
  bundleOf(mind, {
    location: mind.sign({
      ...locationBy(mind, 100),
      endpoints: [{ binding: "https", url: `https://${mind.name}.example/oip`, priority: 1 }],
    }),
  } as never);
const profile = (mind: Mind, summary: string) =>
  mind.sign({
    oip: "1",
    type: "Participant",
    author: mind.address,
    created: T(100),
    name: mind.name,
    kind: "agent",
    capabilities: [{ id: "work", summary, tags: ["domain:legal"] }],
  });

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "oip-indexer-app-"));
  clock = { at: at(110), now: () => clock.at };
  db = Database.open(
    { path: join(directory, "indexer.db"), durable: false },
    INDEXER_MIGRATIONS,
    clock,
  );
  lines = [];
  posted = [];
});
afterEach(() => {
  try {
    db.close();
  } catch {
    // A test closed it.
  }
  rmSync(directory, { recursive: true, force: true });
});

/** The indexer's interface, with what a test changes of it. The indexer is the mind Ian. */
function service(more: Partial<IndexerAppOptions> = {}) {
  const log = new Log({
    service: "indexer",
    clock,
    sink: (line) => lines.push(JSON.parse(line) as Record<string, unknown>),
  });
  metrics = new Metrics();
  shutdown = new Shutdown({ log });
  const archive = new LogArchive({ db, clock });
  archive.publish(idOf(ian), bundleOf(ian));
  const indexer = new Indexer({
    db,
    archive,
    clock,
    address: ian.address,
    signer: ian.operational(),
  });
  const generous = (): RateLimiter => new RateLimiter({ burst: 1000, perMinute: 60_000 }, clock);
  broker = new Broker({
    indexer,
    archive,
    log,
    metrics,
    post: (url) => {
      posted.push(url);
      return Promise.resolve({ status: 202 });
    },
    perSender: generous(),
  });
  const app = indexerApp({
    indexer,
    broker,
    archive,
    clock,
    log,
    metrics,
    limits: { query: generous(), submit: generous(), deliver: generous() },
    shutdown,
    ready: { database: () => true },
    ...more,
  });
  const ask = (path: string, init: RequestInit = {}, address = "203.0.113.7"): Promise<Response> =>
    Promise.resolve(app.fetch(new Request(`http://10.0.0.7:8080${path}`, init), { address }));
  return { ask };
}

const sending = (body: unknown, type = "application/json"): RequestInit => ({
  method: "POST",
  body: typeof body === "string" ? body : JSON.stringify(body),
  headers: { "content-type": type },
});

async function problemOf(response: Response): Promise<{ status: number; type: string }> {
  expect(response.headers.get("content-type")).toBe(PROBLEM_MEDIA_TYPE);
  const body = (await response.json()) as { type: string };
  return { status: response.status, type: body.type };
}

const asking = (from: Mind, more: JsonObject = {}) =>
  from.sign({
    oip: "1",
    type: "Packet",
    from: from.address,
    to: { query: { want: "contracts" } },
    created: T(100),
    expires: T(3700),
    nonce: "nonce-0001",
    purpose: { verb: "request" },
    content: { mediaType: "text/plain", body: "Who reviews contracts?" },
    ...more,
  });

describe(`${clause("L1 18.1")} records submitted over HTTP`, () => {
  it("are answered 202, with how many were taken and why each of the others was not", async () => {
    const { ask } = service();
    const response = await ask(
      "/oip/v1/submit",
      sending({
        records: [bundleOf(ada), profile(ada, "Reviews contracts"), profile(bob, "Bakes")],
      }),
    );
    expect(response.status).toBe(202);
    expect(response.headers.get("content-type")).toBe("application/json");
    expect(response.headers.get("access-control-allow-origin")).toBe("*");
    const body = (await response.json()) as {
      taken: number;
      refused: { index: number; type: string }[];
    };
    expect(body.taken).toBe(2);
    expect(body.refused.map((refusal) => [refusal.index, refusal.type])).toStrictEqual([
      [2, "urn:oip:error:stale-version"],
    ]);
    const text = metrics.render();
    expect(text).toContain('oip_indexer_records_submitted_total{outcome="taken"} 2');
    expect(text).toContain('oip_indexer_records_submitted_total{outcome="refused"} 1');
  });

  it("are refused as a whole where the body is no submission, or holds too much", async () => {
    const { ask } = service({ maxRecords: 2, maxBodyBytes: 20_000 });
    const cases: [string, RequestInit, number, string][] = [
      ["no JSON", sending("{"), 400, "invalid-record"],
      ["a number that is no integer", sending('{"records":[{"n":1.5}]}'), 400, "invalid-record"],
      ["no object", sending([bundleOf(ada)]), 400, "invalid-record"],
      ["null", sending("null"), 400, "invalid-record"],
      ["no list of records", sending({ records: "all" }), 400, "invalid-record"],
      ["no record at all", sending({ records: [] }), 400, "invalid-record"],
      ["more records than are taken at once", sending({ records: [1, 2, 3] }), 413, "too-large"],
      ["a longer body than is read", sending({ records: ["x".repeat(20_000)] }), 413, "too-large"],
    ];
    for (const [name, init, status, type] of cases) {
      expect(await problemOf(await ask("/oip/v1/submit", init)), name).toStrictEqual({
        status,
        type: `urn:oip:error:${type}`,
      });
    }
    const other = await ask("/oip/v1/submit", sending({ records: [bundleOf(ada)] }, MEDIA_TYPE));
    expect(other.status).toBe(415);
    expect(other.headers.get("accept")).toBe("application/json");
    expect((await ask("/oip/v1/submit")).status).toBe(404);
  });
});

describe(`${clause("L1 18.2", "L1 18.3")} a capability query over HTTP`, () => {
  it("is answered with a signed QueryResult, as a record, that nothing between may keep", async () => {
    const { ask } = service();
    await ask(
      "/oip/v1/submit",
      sending({ records: [bundleOf(ada), profile(ada, "Reviews contracts")] }),
    );
    const response = await ask("/oip/v1/query", sending({ want: "contracts", limit: 3 }));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe(MEDIA_TYPE);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const result = parseRecord(await response.text());
    expect(result.ok && result.value).toMatchObject({
      type: "QueryResult",
      author: ian.address,
      query: { want: "contracts", limit: 3 },
      results: [{ mind: ada.address, capability: "work", score: "1" }],
    });
    expect((result.ok ? (result.value as unknown as { proof: unknown[] }).proof : []).length).toBe(
      1,
    );
  });

  it("is refused where it is not well formed, or is no JSON", async () => {
    const { ask } = service();
    for (const body of [{ want: 7 }, { limit: 101 }, { kinds: ["Bundle"] }, "[", 7]) {
      expect(
        await problemOf(await ask("/oip/v1/query", sending(body))),
        JSON.stringify(body),
      ).toStrictEqual({
        status: 400,
        type: "urn:oip:error:invalid-record",
      });
    }
    expect((await ask("/oip/v1/query", sending({}, "text/plain"))).status).toBe(415);
  });
});

describe(`${clause("L1 18.5")} a packet sent to the indexer's inbox`, () => {
  it("is answered 202 with how many minds it goes to, and is forwarded to their inboxes", async () => {
    const { ask } = service();
    await ask(
      "/oip/v1/submit",
      sending({ records: [bundleOf(ada), located(bob), profile(bob, "Reviews contracts")] }),
    );
    const response = await ask("/oip/v1/inbox", sending(asking(ada), MEDIA_TYPE));
    expect([response.status, await response.json()]).toStrictEqual([
      202,
      { stored: true, forwarding: 1 },
    ]);
    await broker.idle();
    expect(posted).toStrictEqual(["https://bob.example/oip/inbox"]);
    // The same packet again is answered the same, and goes nowhere.
    const again = await ask("/oip/v1/inbox", sending(asking(ada), MEDIA_TYPE));
    expect(await again.json()).toStrictEqual({ stored: true, forwarding: 1 });
    await broker.idle();
    expect(posted).toHaveLength(1);
  });

  it("is refused where a broker may not forward it, each with its problem", async () => {
    const { ask } = service();
    await ask("/oip/v1/submit", sending({ records: [bundleOf(ada)] }));
    const cases: [string, RequestInit, number, string][] = [
      [
        "addressed to a mind by name",
        sending(asking(ada, { to: [bob.address] }), MEDIA_TYPE),
        403,
        "forbidden",
      ],
      [
        "one that names other brokers",
        sending(asking(ada, { to: { query: {}, brokers: [bob.address] } }), MEDIA_TYPE),
        403,
        "forbidden",
      ],
      [
        "from a mind the indexer cannot judge",
        sending(asking(bob), MEDIA_TYPE),
        409,
        "stale-version",
      ],
      ["no packet", sending(profile(ada, "x"), MEDIA_TYPE), 400, "invalid-record"],
      ["no record", sending("{", MEDIA_TYPE), 400, "invalid-record"],
    ];
    for (const [name, init, status, type] of cases) {
      expect(await problemOf(await ask("/oip/v1/inbox", init)), name).toStrictEqual({
        status,
        type: `urn:oip:error:${type}`,
      });
    }
    expect((await ask("/oip/v1/inbox", sending(asking(ada)))).status).toBe(415);
  });
});

describe("what an indexer serves besides", () => {
  it("serves the bundle of its own mind, by which what it signs is judged, and no other", async () => {
    const { ask } = service();
    await ask("/oip/v1/submit", sending({ records: [bundleOf(ada)] }));
    const own = await ask(`/.well-known/oip/mind/${idOf(ian)}`);
    expect(own.status).toBe(200);
    expect(own.headers.get("content-type")).toBe(MEDIA_TYPE);
    expect(await own.json()).toMatchObject({ type: "Bundle", mind: ian.address, log: ian.events });
    for (const id of [idOf(ada), "nobody"]) {
      expect(await problemOf(await ask(`/.well-known/oip/mind/${id}`))).toStrictEqual({
        status: 404,
        type: "urn:oip:error:not-found",
      });
    }
  });

  it("limits what one address asks, submits and sends, each apart", async () => {
    const tight = (): RateLimiter => new RateLimiter({ burst: 1, perMinute: 6 }, clock);
    const { ask } = service({ limits: { query: tight(), submit: tight(), deliver: tight() } });
    expect((await ask("/oip/v1/query", sending({}))).status).toBe(200);
    const limited = await ask("/oip/v1/query", sending({}));
    expect(await problemOf(limited)).toStrictEqual({
      status: 429,
      type: "urn:oip:error:rate-limited",
    });
    expect(limited.headers.get("retry-after")).toBe("10");
    expect((await ask("/oip/v1/query", sending({}), "198.51.100.9")).status).toBe(200);
    expect((await ask("/oip/v1/submit", sending({ records: [bundleOf(ada)] }))).status).toBe(202);
    expect((await ask("/oip/v1/submit", sending({ records: [bundleOf(ada)] }))).status).toBe(429);
    expect((await ask("/oip/v1/inbox", sending(asking(ada), MEDIA_TYPE))).status).toBe(202);
    expect((await ask("/oip/v1/inbox", sending(asking(ada), MEDIA_TYPE))).status).toBe(429);
    await broker.idle();
  });

  it("answers a browser that asks first, says whether it is alive and ready, and counts by route", async () => {
    let database = true;
    const { ask } = service({ ready: { database: () => database } });
    for (const path of ["/oip/v1/query", `/.well-known/oip/mind/${idOf(ian)}`]) {
      const preflight = await ask(path, { method: "OPTIONS" });
      expect(preflight.status).toBe(204);
      expect(preflight.headers.get("access-control-allow-methods")).toBe("GET, POST");
      // A submission may be signed (13.3): the headers of a signature are let through too.
      expect(preflight.headers.get("access-control-allow-headers")).toBe(
        "content-type, content-digest, signature, signature-input",
      );
    }
    expect((await ask("/healthz")).status).toBe(200);
    expect((await ask("/readyz")).status).toBe(200);
    database = false;
    expect((await ask("/readyz")).status).toBe(503);
    await ask("/oip/v1/query", sending({ want: "anything" }));
    const text = await (await ask("/metrics")).text();
    expect(text).toContain('oip_indexer_requests_total{route="query",status="200"} 1');
    expect(text).not.toContain(idOf(ian));
    expect((await ask("/nowhere")).status).toBe(404);
  });

  it("tells a client nothing of a failure nobody expected, and logs it", async () => {
    const { ask } = service();
    db.close();
    const response = await ask("/oip/v1/query", sending({ want: "anything" }));
    expect(response.status).toBe(500);
    expect(await response.json()).toStrictEqual({
      type: "about:blank",
      title: "Internal Server Error",
      status: 500,
    });
    expect(lines.at(-1)).toMatchObject({ level: "error", event: "request failed", route: "query" });
  });
});
