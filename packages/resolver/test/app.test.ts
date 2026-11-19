// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { formatKeyRef, MEDIA_TYPE, mindId, parseRecord, PROBLEM_MEDIA_TYPE, utf8 } from "@oip/core";
import { signRequest } from "@oip/net";
import {
  Database,
  Log,
  LogArchive,
  Metrics,
  RateLimiter,
  Shutdown,
  StoredNonces,
} from "@oip/server";
import { clause } from "@oip/testkit";
import { at, Collective, intentBy, KeyMind, type Mind, rawSign } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { RESOLVER_MIGRATIONS, resolverApp, type ResolverAppOptions } from "../src/index.ts";

const ORIGIN = "https://resolver.example";

let directory: string;
let db: Database;
let clock: { at: bigint; now: () => bigint };
let lines: Record<string, unknown>[];
let shutdown: Shutdown;
let metrics: Metrics;

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "oip-resolver-app-"));
  clock = { at: at(100), now: () => clock.at };
  db = Database.open(
    { path: join(directory, "resolver.db"), durable: false },
    RESOLVER_MIGRATIONS,
    clock,
  );
  lines = [];
});
afterEach(() => {
  db.close();
  rmSync(directory, { recursive: true, force: true });
});

/** The resolver's interface, with what a test changes of it. */
function service(more: Partial<ResolverAppOptions> = {}) {
  const log = new Log({
    service: "resolver",
    clock,
    sink: (line) => lines.push(JSON.parse(line) as Record<string, unknown>),
  });
  metrics = new Metrics();
  shutdown = new Shutdown({ log });
  const generous = (): RateLimiter => new RateLimiter({ burst: 1000, perMinute: 60_000 }, clock);
  const app = resolverApp({
    resolver: new LogArchive({ db, clock }),
    clock,
    log,
    metrics,
    origin: ORIGIN,
    nonces: new StoredNonces(db),
    authenticatedPublication: false,
    limits: { read: generous(), publish: generous() },
    shutdown,
    ready: { database: () => true },
    ...more,
  });
  const ask = (path: string, init: RequestInit = {}, address = "203.0.113.7"): Promise<Response> =>
    Promise.resolve(app.fetch(new Request(`http://10.0.0.7:8080${path}`, init), { address }));
  return { app, ask };
}

const idOf = (mind: Mind): string => mindId(mind.address) ?? "";
const pathOf = (mind: Mind): string => `/oip/v1/resolve/${idOf(mind)}`;
const bundleOf = (mind: Mind, events: readonly unknown[] = mind.events): string =>
  JSON.stringify({ oip: "1", type: "Bundle", mind: mind.address, log: events });
const put = (body: string, headers: Record<string, string> = {}): RequestInit => ({
  method: "PUT",
  body,
  headers: { "content-type": MEDIA_TYPE, ...headers },
});

async function problemOf(
  response: Response,
): Promise<{ status: number; type: string; detail?: string }> {
  expect(response.headers.get("content-type")).toBe(PROBLEM_MEDIA_TYPE);
  const body = (await response.json()) as { type: string; detail?: string };
  return {
    status: response.status,
    type: body.type,
    ...(body.detail === undefined ? {} : { detail: body.detail }),
  };
}

describe(`${clause("L1 17.1")} the resolver's interface`, () => {
  it("takes a bundle that is published, and serves the mind's bundle", async () => {
    const ada = new KeyMind("ada").update(10);
    const { ask } = service();
    const published = await ask(pathOf(ada), put(bundleOf(ada)));
    expect(published.status).toBe(202);
    expect(await published.json()).toStrictEqual({ added: 2 });
    const served = await ask(pathOf(ada));
    expect(served.status).toBe(200);
    expect(served.headers.get("content-type")).toBe(MEDIA_TYPE);
    expect(served.headers.get("access-control-allow-origin")).toBe("*");
    expect(served.headers.get("x-content-type-options")).toBe("nosniff");
    // What is served is a record a client's reader takes.
    const bundle = parseRecord(await served.text());
    expect(bundle.ok && bundle.value).toMatchObject({
      type: "Bundle",
      mind: ada.address,
      log: ada.events,
    });
    const firstSeen = bundle.ok ? (bundle.value as { firstSeen?: object }).firstSeen : undefined;
    expect(Object.keys(firstSeen ?? {})).toHaveLength(2);
  });

  it("answers 404 for a mind it holds no log of, and for what names no mind", async () => {
    const { ask } = service();
    for (const path of [pathOf(new KeyMind("ada")), "/oip/v1/resolve/not-a-content-id"]) {
      expect(await problemOf(await ask(path))).toMatchObject({
        status: 404,
        type: "urn:oip:error:not-found",
      });
      const duplicity = await ask(path.replace("/resolve/", "/duplicity/"));
      expect(await problemOf(duplicity)).toMatchObject({
        status: 404,
        type: "urn:oip:error:not-found",
      });
    }
    expect(await problemOf(await ask("/oip/v1/resolve/not-a-content-id", put("{}")))).toMatchObject(
      {
        status: 404,
      },
    );
    expect(await problemOf(await ask("/oip/v2/anything"))).toStrictEqual({
      status: 404,
      type: "about:blank",
    });
  });

  it("refuses what is no bundle: another media type, another record, no record, or too long a one", async () => {
    const ada = new KeyMind("ada");
    const { ask } = service({ maxBundleBytes: 4096 });
    const cases: [RequestInit, number, string][] = [
      [put(bundleOf(ada), { "content-type": "application/json" }), 415, "about:blank"],
      [put(JSON.stringify(ada.sign(intentBy(ada, 10)))), 400, "urn:oip:error:invalid-record"],
      [put("{"), 400, "urn:oip:error:invalid-record"],
      [put(`${" ".repeat(5000)}${bundleOf(ada)}`), 413, "urn:oip:error:too-large"],
    ];
    for (const [init, status, type] of cases) {
      expect(await problemOf(await ask(pathOf(ada), init))).toMatchObject({ status, type });
    }
    expect((await ask(pathOf(ada))).status).toBe(404);
    // And a bundle under another mind's name.
    const bob = new KeyMind("bob");
    expect(await problemOf(await ask(pathOf(bob), put(bundleOf(ada))))).toMatchObject({
      status: 400,
      type: "urn:oip:error:invalid-record",
    });
  });
});

describe(`${clause("L1 17.2", "core 10.2")} a published log with an event that does not verify`, () => {
  it("is answered with why: an invalid proof, a log it cannot reach, an extension it lacks", async () => {
    const ada = new KeyMind("ada").update(10);
    const eve = new KeyMind("eve");
    const { ask } = service();
    const forged = rawSign(ada.events[1] as object, [{ control: eve.control(0) }]);
    const invalid = await problemOf(
      await ask(pathOf(ada), put(bundleOf(ada, [ada.events[0], forged]))),
    );
    expect(invalid).toMatchObject({ status: 400, type: "urn:oip:error:invalid-proof" });
    expect(invalid.detail).toMatch(/^event 1 of the log: /u);
    // What verified before it was taken.
    expect((await ask(pathOf(ada))).status).toBe(200);

    const [a, b, c] = ["a", "b", "c"].map((name) => new KeyMind(name)) as [
      KeyMind,
      KeyMind,
      KeyMind,
    ];
    const club = new Collective("club", [a, b, c], 2, 5);
    expect(await problemOf(await ask(pathOf(club), put(bundleOf(club))))).toMatchObject({
      status: 409,
      type: "urn:oip:error:stale-version",
    });

    const extended = new KeyMind("zed").update(10, {
      ext: { "ext.example": { rule: "new" } },
      critical: ["ext.example"],
    });
    expect(await problemOf(await ask(pathOf(extended), put(bundleOf(extended))))).toMatchObject({
      status: 400,
      type: "urn:oip:error:unsupported-critical",
    });
  });
});

describe(`${clause("L1 7.2", "L1 17.1")} a published log that shows duplicity`, () => {
  it("is answered 409, and the pair is served as evidence", async () => {
    const first = new KeyMind("ada").update(10);
    const other = new KeyMind("ada").update(11);
    const { ask } = service();
    expect((await ask(pathOf(first), put(bundleOf(first)))).status).toBe(202);
    clock.at = at(200);
    expect(await problemOf(await ask(pathOf(other), put(bundleOf(other))))).toMatchObject({
      status: 409,
      type: "urn:oip:error:duplicity",
    });
    const evidence = await ask(`/oip/v1/duplicity/${idOf(first)}`);
    expect(evidence.status).toBe(200);
    const read = parseRecord(await evidence.text());
    expect(read.ok && read.value).toMatchObject({
      type: "DuplicityEvidence",
      mind: first.address,
      pairs: [[first.events[1], other.events[1]]],
    });
    // The log served is the one seen first.
    const served = (await (await ask(pathOf(first))).json()) as { log: unknown[] };
    expect(served.log).toStrictEqual(first.events);
  });
});

describe(`${clause("L1 17.3")} what a resolver asks of its clients`, () => {
  it("limits what one address publishes, and tells it when to ask again", async () => {
    const ada = new KeyMind("ada");
    const { ask } = service({
      limits: {
        read: new RateLimiter({ burst: 1000, perMinute: 60_000 }, clock),
        publish: new RateLimiter({ burst: 2, perMinute: 6 }, clock),
      },
    });
    for (let n = 0; n < 2; n++)
      expect((await ask(pathOf(ada), put(bundleOf(ada)))).status).toBe(202);
    const limited = await ask(pathOf(ada), put(bundleOf(ada)));
    expect(await problemOf(limited)).toMatchObject({
      status: 429,
      type: "urn:oip:error:rate-limited",
    });
    expect(limited.headers.get("retry-after")).toBe("10");
    // Another address is another client, and reading has a limit of its own.
    expect((await ask(pathOf(ada), put(bundleOf(ada)), "198.51.100.9")).status).toBe(202);
    expect((await ask(pathOf(ada))).status).toBe(200);
    // Every address of one IPv6 network is one client.
    for (const address of ["2001:db8:1:2::1", "2001:db8:1:2::2"]) {
      expect((await ask(pathOf(ada), put(bundleOf(ada)), address)).status).toBe(202);
    }
    expect((await ask(pathOf(ada), put(bundleOf(ada)), "2001:db8:1:2::3")).status).toBe(429);
  });

  /** A publication signed by a mind for the resolver's own origin. */
  async function signedPut(mind: Mind, by: Mind, nonce = "nonce-0001"): Promise<RequestInit> {
    const body = utf8(bundleOf(mind));
    const added = await signRequest(
      {
        method: "PUT",
        url: `${ORIGIN}${pathOf(mind)}`,
        headers: [["Content-Type", MEDIA_TYPE]],
        body,
      },
      {
        keyRef: formatKeyRef(by.address, by.versionId(), by.operational().publicKey),
        created: clock.at,
        nonce,
      },
      by.operational(),
    );
    return {
      method: "PUT",
      body,
      headers: [["Content-Type", MEDIA_TYPE], ...added] as [string, string][],
    };
  }

  it("may ask that a mind signs what is published, and a mind may publish its own log so", async () => {
    const [ada, bob, eve] = [new KeyMind("ada"), new KeyMind("bob"), new KeyMind("eve")];
    const { ask } = service({ authenticatedPublication: true });
    // Not signed at all.
    expect(await problemOf(await ask(pathOf(ada), put(bundleOf(ada))))).toMatchObject({
      status: 401,
      type: "urn:oip:error:unauthorised",
    });
    expect((await ask(pathOf(ada))).status).toBe(404);
    // Signed by the mind whose log it is, which the resolver has never seen.
    const own = await signedPut(ada, ada);
    expect((await ask(pathOf(ada), own)).status).toBe(202);
    // The same request again: its nonce has been used.
    expect((await problemOf(await ask(pathOf(ada), own))).status).toBe(401);
    // Signed by a mind the resolver holds, for another's log.
    expect((await ask(pathOf(bob), await signedPut(bob, ada, "nonce-0002"))).status).toBe(202);
    // Signed by a mind it does not hold.
    expect(
      (await problemOf(await ask(pathOf(bob), await signedPut(bob, eve, "nonce-0003")))).status,
    ).toBe(401);
    // Reading asks for no signature.
    expect((await ask(pathOf(ada))).status).toBe(200);
  });

  it("answers a browser that asks before it sends a signed request", async () => {
    const { ask } = service();
    const response = await ask("/oip/v1/resolve/anything", { method: "OPTIONS" });
    expect(response.status).toBe(204);
    expect(response.headers.get("access-control-allow-origin")).toBe("*");
    expect(response.headers.get("access-control-allow-methods")).toBe("GET, PUT");
    expect(response.headers.get("access-control-allow-headers")).toContain("signature-input");
  });
});

describe(`${clause("L1 17.1")} the stream of what a resolver takes in`, () => {
  /** Reads a stream of server-sent events, one event or comment at a time. */
  function reading(response: Response) {
    const reader = (response.body as ReadableStream<Uint8Array>).getReader();
    const decoder = new TextDecoder();
    let buffered = "";
    const next = async (): Promise<string | undefined> => {
      for (;;) {
        const end = buffered.indexOf("\n\n");
        if (end >= 0) {
          const event = buffered.slice(0, end);
          buffered = buffered.slice(end + 2);
          return event;
        }
        const { done, value } = await reader.read();
        if (done) return undefined;
        buffered += decoder.decode(value, { stream: true });
      }
    };
    /** The next event that is no comment: its `id`, and what its `data` holds. */
    const event = async (): Promise<{
      id: string;
      data: { cursor: string; mind: string; record: unknown };
    }> => {
      for (;;) {
        const text = await next();
        if (text === undefined) throw new Error("the stream ended");
        if (text.startsWith(":")) continue;
        const [id = "", data = ""] = text.split("\n");
        return {
          id: id.replace(/^id: /u, ""),
          data: JSON.parse(data.replace(/^data: /u, "")) as never,
        };
      }
    };
    return { next, event, cancel: () => reader.cancel() };
  }

  it("tells of each event from the beginning, and of what is taken in while it is open", async () => {
    const [ada, bob] = [new KeyMind("ada").update(10), new KeyMind("bob")];
    const { ask } = service();
    await ask(pathOf(ada), put(bundleOf(ada)));
    const response = await ask("/oip/v1/stream");
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("text/event-stream");
    const stream = reading(response);
    expect(await stream.event()).toStrictEqual({
      id: "1",
      data: { cursor: "1", mind: ada.address, record: ada.events[0] },
    });
    expect((await stream.event()).data).toMatchObject({ cursor: "2", record: ada.events[1] });
    // Nothing more is held. What is published now reaches the open stream.
    const waiting = stream.event();
    await ask(pathOf(bob), put(bundleOf(bob)));
    expect(await waiting).toStrictEqual({
      id: "3",
      data: { cursor: "3", mind: bob.address, record: bob.events[0] },
    });
    expect(await (await ask("/metrics")).text()).toContain("oip_resolver_streams_open 1");
    await stream.cancel();
    expect(await (await ask("/metrics")).text()).toContain("oip_resolver_streams_open 0");
  });

  it("goes on from a cursor, given in the query or as the last event a client had", async () => {
    const ada = new KeyMind("ada").update(10).update(20);
    const { ask } = service();
    await ask(pathOf(ada), put(bundleOf(ada)));
    for (const response of [
      await ask("/oip/v1/stream?since=2"),
      await ask("/oip/v1/stream", { headers: { "last-event-id": "2" } }),
    ]) {
      const stream = reading(response);
      expect((await stream.event()).id).toBe("3");
      await stream.cancel();
    }
    for (const since of ["x", "-1", "1.5", "01", "", "9".repeat(16)]) {
      expect((await ask(`/oip/v1/stream?since=${since}`)).status, since).toBe(400);
    }
  });

  it("says that it is there while there is nothing to tell", async () => {
    const { ask } = service({ heartbeatMs: 20 });
    const stream = reading(await ask("/oip/v1/stream"));
    expect(await stream.next()).toBe(": here");
    expect(await stream.next()).toBe(": here");
    await stream.cancel();
  });

  it("is one of a bounded number, and ends when the resolver stops", async () => {
    const { ask } = service({ maxStreams: 2 });
    const [first, second] = [
      reading(await ask("/oip/v1/stream")),
      reading(await ask("/oip/v1/stream")),
    ];
    // Asked for something, so that each is waiting.
    const [one, two] = [first.next(), second.next()];
    const refused = await ask("/oip/v1/stream");
    expect(refused.status).toBe(503);
    expect(refused.headers.get("retry-after")).toBe("30");
    await shutdown.run("test");
    expect(await one).toBeUndefined();
    expect(await two).toBeUndefined();
    expect(await (await ask("/metrics")).text()).toContain("oip_resolver_streams_open 0");
  });
});

describe("a resolver's own endpoints", () => {
  it("says it is alive, and ready until it stops or a check fails", async () => {
    let database = true;
    const { ask } = service({ ready: { database: () => database } });
    expect((await ask("/healthz")).status).toBe(200);
    expect((await ask("/readyz")).status).toBe(200);
    database = false;
    const failing = await ask("/readyz");
    expect(failing.status).toBe(503);
    expect(await failing.json()).toStrictEqual({ status: "not ready", failing: ["database"] });
    database = true;
    await shutdown.run("test");
    expect((await ask("/readyz")).status).toBe(503);
    expect((await ask("/healthz")).status).toBe(200);
  });

  it("counts what it answered by route and status, and names no mind", async () => {
    const ada = new KeyMind("ada");
    const { ask } = service();
    await ask(pathOf(ada), put(bundleOf(ada)));
    await ask(pathOf(ada));
    await ask(pathOf(new KeyMind("bob")));
    const response = await ask("/metrics");
    expect(response.headers.get("content-type")).toMatch(/^text\/plain; version=0\.0\.4/u);
    const text = await response.text();
    expect(text).toContain('oip_resolver_requests_total{route="publish",status="202"} 1');
    expect(text).toContain('oip_resolver_requests_total{route="resolve",status="200"} 1');
    expect(text).toContain('oip_resolver_requests_total{route="resolve",status="404"} 1');
    expect(text).toContain("oip_resolver_events_merged_total 1");
    expect(text).toContain('oip_resolver_request_seconds_count{route="resolve"} 2');
    expect(text).not.toContain(idOf(ada));
  });

  it("tells a client nothing of a failure nobody expected, and logs it", async () => {
    const ada = new KeyMind("ada");
    const { ask } = service();
    await ask(pathOf(ada), put(bundleOf(ada)));
    // The database goes away under the running service.
    db.close();
    const response = await ask(`/oip/v1/duplicity/${idOf(ada)}`);
    expect(await problemOf(response)).toStrictEqual({ status: 500, type: "about:blank" });
    expect(lines).toMatchObject([
      {
        level: "error",
        event: "request failed",
        route: "duplicity",
        error: "Error",
        code: "ERR_INVALID_STATE",
      },
    ]);
    expect(JSON.stringify(lines)).not.toContain("database is not open");
  });
});
