// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  contentId,
  type JsonObject,
  MEDIA_TYPE,
  mindId,
  OipError,
  type OipRecord,
  utf8,
} from "@oip/core";
import { LogBook } from "@oip/identity";
import { receivePacket } from "@oip/net";
import { type Bundle, noteCutShort } from "@oip/schema";
import { Database, Log, LogArchive, Lookup, Metrics, RateLimiter, Unavailable } from "@oip/server";
import { clause } from "@oip/testkit";
import { at, KeyMind, LATER, locationBy, type Mind, T, witness } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Broker, type BrokerOptions, Indexer, INDEXER_MIGRATIONS } from "../src/index.ts";

let directory: string;
let db: Database;
let clock: { at: bigint; now: () => bigint };
let archive: LogArchive;
let indexer: Indexer;
let metrics: Metrics;
let lines: Record<string, unknown>[];
/** Every post the broker made: where to, and the record it carried. */
let posted: { url: string; type: string; record: JsonObject }[];
/** What each URL answers. A URL that is not here answers 202. */
let answers: Map<string, () => Promise<{ status: number }>>;

const ian = new KeyMind("ian");
const ada = new KeyMind("ada");
const bob = new KeyMind("bob");
const cyd = new KeyMind("cyd");
const eve = new KeyMind("eve");
const zed = new KeyMind("zed");

const idOf = (mind: Mind): string => mindId(mind.address) ?? "";
/** A mind's bundle, with a location record that gives its inboxes. */
const bundleOf = (
  mind: Mind,
  urls: readonly string[] = [`https://${mind.name}.example/oip`],
): Bundle =>
  ({
    oip: "1",
    type: "Bundle",
    mind: mind.address,
    log: mind.events,
    ...(urls.length === 0
      ? {}
      : {
          location: mind.sign({
            ...locationBy(mind, 100),
            endpoints: urls.map((url, priority) => ({
              binding: url.startsWith("mailbox:") ? "mailbox" : "https",
              url: url.replace(/^mailbox:/u, ""),
              priority,
            })),
          }),
        }),
  }) as unknown as Bundle;

const translator = (mind: Mind, summary = "Translates leases from Dutch to English") =>
  mind.sign({
    oip: "1",
    type: "Participant",
    author: mind.address,
    created: T(100),
    name: mind.name,
    kind: "agent",
    capabilities: [{ id: "translate", summary, tags: ["domain:legal"] }],
  });

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "oip-broker-"));
  clock = { at: at(110), now: () => clock.at };
  db = Database.open(
    { path: join(directory, "indexer.db"), durable: false },
    INDEXER_MIGRATIONS,
    clock,
  );
  posted = [];
  answers = new Map();
  lines = [];
});
afterEach(() => {
  vi.restoreAllMocks();
  db.close();
  rmSync(directory, { recursive: true, force: true });
});

/** A broker whose indexer lists Bob, Cyd and Eve as translators, and holds Ada's log. */
function broker(more: Partial<BrokerOptions> = {}): Broker {
  archive = new LogArchive({ db, clock });
  archive.publish(idOf(ian), bundleOf(ian, []));
  indexer = new Indexer({ db, archive, clock, address: ian.address, signer: ian.operational() });
  indexer.submit([
    bundleOf(ada),
    bundleOf(bob),
    bundleOf(cyd, ["https://cyd.example/first", "https://cyd.example/second"]),
    bundleOf(eve),
    translator(bob),
    translator(cyd),
    translator(eve, "Translates leases"),
  ]);
  metrics = new Metrics();
  return new Broker({
    indexer,
    archive,
    log: new Log({
      service: "indexer",
      clock,
      sink: (line) => lines.push(JSON.parse(line) as Record<string, unknown>),
    }),
    metrics,
    post: (url, body, type) => {
      posted.push({ url, type, record: JSON.parse(new TextDecoder().decode(body)) as JsonObject });
      return (answers.get(url) ?? (() => Promise.resolve({ status: 202 })))();
    },
    perSender: new RateLimiter({ burst: 100, perMinute: 6000 }, clock),
    ...more,
  });
}

/** A packet from a mind to whoever matches a query. */
function asking(
  from: Mind,
  to: JsonObject = {},
  more: JsonObject = {},
  by: Mind = from,
): OipRecord {
  return by.sign({
    oip: "1",
    type: "Packet",
    from: from.address,
    to: { query: { want: "translate a lease" }, ...to },
    created: T(100),
    expires: T(3700),
    nonce: "nonce-0001",
    purpose: { verb: "request" },
    content: { mediaType: "text/plain", body: "Who translates a lease?" },
    ...more,
  }) as unknown as OipRecord;
}

/** What is thrown that is no error at all. */
const NO_ERROR = { name: "something else" } as unknown as Error;

function problem(work: () => unknown): string {
  try {
    work();
  } catch (error) {
    return error instanceof OipError ? error.code : String(error);
  }
  return "none";
}

describe(`${clause("L1 18.5")} a packet addressed to a query`, () => {
  it("is forwarded unchanged to the minds that match, each in a wrapper the broker signs for that mind", async () => {
    const forwarding = broker();
    const packet = asking(ada);
    expect(forwarding.accept(packet)).toStrictEqual({ forwarding: 3 });
    await forwarding.idle();
    expect(posted.map((post) => post.url).sort()).toStrictEqual([
      "https://bob.example/oip/inbox",
      "https://cyd.example/first/inbox",
      "https://eve.example/oip/inbox",
    ]);
    for (const { type, record } of posted) {
      expect(type).toBe(MEDIA_TYPE);
      expect(record).toMatchObject({ type: "Forwarded", broker: ian.address, packet });
      // Made at the reading the broker took the packet at.
      expect(record["created"]).toMatch(/^2026-01-01T00:01:50(?:\.\d+)?Z$/u);
    }
    // A recipient takes it as 12.4 has it: for it, from this broker, the packet as it was sent.
    const toBob = posted.find((post) => post.record["to"] === bob.address)?.record;
    const seen = witness([ian, ada, bob].map((mind) => mind.events));
    const book = new LogBook(seen);
    for (const mind of [ian, ada, bob]) book.hold(mind.events, LATER);
    const received = receivePacket(toBob, {
      address: bob.address,
      now: at(120),
      view: book,
      seen,
      accepted: () => false,
      window: 0n,
    });
    if (!received.ok) throw new Error(JSON.stringify(received.issues));
    expect([received.value.id, received.value.broker]).toStrictEqual([
      contentId(packet),
      ian.address,
    ]);
    expect(metrics.render()).toContain('oip_indexer_deliveries_total{outcome="delivered"} 3');
  });

  it("is forwarded once: the same packet again is answered the same and goes nowhere", async () => {
    const forwarding = broker();
    const packet = asking(ada);
    void forwarding.accept(packet);
    await forwarding.idle();
    clock.at = at(500);
    expect(forwarding.accept(packet)).toStrictEqual({ forwarding: 3 });
    await forwarding.idle();
    expect(posted).toHaveLength(3);
    // Until it can no longer be accepted, the broker remembers it, and then no longer.
    expect(indexer.prune(at(3700 + 300))).toBe(0);
    expect(indexer.prune(at(3700 + 301))).toBe(1);
  });

  it("goes to as many minds as it says, ten where it does not say, and never to its sender", async () => {
    const forwarding = broker({ fanout: 2 });
    expect(forwarding.accept(asking(ada, { maxFanout: 1 }))).toStrictEqual({ forwarding: 1 });
    expect(forwarding.accept(asking(ada, {}, { nonce: "nonce-0002" }))).toStrictEqual({
      forwarding: 2,
    });
    expect(
      forwarding.accept(asking(ada, { maxFanout: 50 }, { nonce: "nonce-0003" })),
    ).toStrictEqual({
      forwarding: 3,
    });
    // One who matches its own query is not sent its own packet.
    expect(forwarding.accept(asking(bob, { maxFanout: 50 }))).toStrictEqual({ forwarding: 2 });
    expect(
      forwarding.accept(
        asking(ada, { query: { want: "zzzunheardofzzz" } }, { nonce: "nonce-0004" }),
      ),
    ).toStrictEqual({
      forwarding: 0,
    });
    await forwarding.idle();
    expect(posted).toHaveLength(1 + 2 + 3 + 2);
    // Bob matches his own query, and is sent everyone's packets but his own.
    const toBob = posted.filter((post) => post.record["to"] === bob.address);
    expect(toBob.length).toBeGreaterThan(0);
    for (const { record } of toBob) {
      expect((record["packet"] as JsonObject)["from"]).toBe(ada.address);
    }
  });

  it("is refused where the broker may not forward it, and nothing is kept of it", async () => {
    const forwarding = broker();
    const cases: [string, unknown, string][] = [
      ["no packet", translator(ada), "invalid-record"],
      ["a packet that is not well formed", { ...asking(ada), nonce: 7 }, "invalid-record"],
      ["addressed to minds by name", asking(ada, {}, { to: [bob.address] }), "forbidden"],
      ["addressed to a subject", asking(ada, {}, { to: { subject: "weather" } }), "forbidden"],
      ["one that names other brokers", asking(ada, { brokers: [eve.address] }), "forbidden"],
      ["expired", asking(ada, {}, { created: T(-9000), expires: T(-8000) }), "expired"],
      [
        "good for longer than a query's packet may be",
        asking(ada, {}, { expires: T(3701) }),
        "expired",
      ],
      ["one its sender did not sign", asking(ada, {}, {}, eve), "invalid-proof"],
      ["one from a mind the broker cannot judge", asking(zed), "stale-version"],
    ];
    for (const [name, record, code] of cases) {
      expect(
        problem(() => forwarding.accept(record as OipRecord)),
        name,
      ).toBe(code);
    }
    await forwarding.idle();
    expect(posted).toStrictEqual([]);
    expect(db.prepare("SELECT COUNT(*) AS n FROM forwarded").get()).toEqual({ n: 0 });
    // One that names this broker among its brokers is taken.
    expect(forwarding.accept(asking(ada, { brokers: [eve.address, ian.address] }))).toStrictEqual({
      forwarding: 3,
    });
    await forwarding.idle();
  });

  it("is limited for each sender, whatever address it sends from", async () => {
    const forwarding = broker({ perSender: new RateLimiter({ burst: 2, perMinute: 6 }, clock) });
    for (const nonce of ["nonce-0001", "nonce-0002"])
      void forwarding.accept(asking(ada, {}, { nonce }));
    expect(problem(() => forwarding.accept(asking(ada, {}, { nonce: "nonce-0003" })))).toBe(
      "rate-limited",
    );
    // A packet forwarded before costs nothing to send again, and another sender has its own allowance.
    expect(forwarding.accept(asking(ada))).toStrictEqual({ forwarding: 3 });
    expect(forwarding.accept(asking(bob))).toStrictEqual({ forwarding: 2 });
    await forwarding.idle();
    expect(db.prepare("SELECT COUNT(*) AS n FROM forwarded").get()).toEqual({ n: 3 });
  });

  it("is not called forged where it could not be judged (ADR-0010)", async () => {
    const forwarding = broker();
    const view = archive.view.bind(archive);
    vi.spyOn(archive, "view").mockImplementationOnce((now) => {
      const held = view(now);
      return {
        evidence: held.evidence,
        log: (mind) => {
          noteCutShort(new RangeError("Maximum call stack size exceeded"));
          return held.log(mind);
        },
      };
    });
    expect(() => forwarding.accept(asking(ada))).toThrow(Unavailable);
    expect(forwarding.accept(asking(ada))).toStrictEqual({ forwarding: 3 });
    await forwarding.idle();
  });
});

describe(`${clause("L1 18.5", "L1 15.3")} the delivery of a forwarded packet`, () => {
  it("tries a mind's inboxes in the order its location record gives, until one takes it", async () => {
    const forwarding = broker();
    answers.set("https://cyd.example/first/inbox", () => Promise.resolve({ status: 503 }));
    answers.set("https://bob.example/oip/inbox", () =>
      Promise.reject(new TypeError("fetch failed: 10.0.0.9")),
    );
    answers.set("https://eve.example/oip/inbox", () => Promise.reject(NO_ERROR));
    void forwarding.accept(asking(ada));
    await forwarding.idle();
    const urls = posted.map((post) => post.url);
    expect([...urls].sort()).toStrictEqual([
      "https://bob.example/oip/inbox",
      "https://cyd.example/first/inbox",
      "https://cyd.example/second/inbox",
      "https://eve.example/oip/inbox",
    ]);
    // The second of a mind's inboxes is tried after its first has refused.
    expect(urls.indexOf("https://cyd.example/second/inbox")).toBeGreaterThan(
      urls.indexOf("https://cyd.example/first/inbox"),
    );
    const text = metrics.render();
    expect(text).toContain('oip_indexer_deliveries_total{outcome="delivered"} 1');
    expect(text).toContain('oip_indexer_deliveries_total{outcome="refused"} 2');
    // A failure is logged by its kind, and by nothing it carried.
    expect(lines.map((line) => [line["event"], line["reason"]]).sort()).toStrictEqual([
      ["delivery failed", "TypeError"],
      ["delivery failed", "unknown"],
    ]);
    expect(JSON.stringify(lines)).not.toContain("10.0.0.9");
  });

  it("goes to a mind's mailbox where no inbox takes it, and nowhere for a mind with no endpoint", async () => {
    archive = new LogArchive({ db, clock });
    archive.publish(idOf(ian), bundleOf(ian, []));
    indexer = new Indexer({ db, archive, clock, address: ian.address, signer: ian.operational() });
    indexer.submit([
      bundleOf(ada),
      bundleOf(bob, []),
      // A mailbox, listed before an inbox that refuses and an endpoint that is no HTTPS URL.
      bundleOf(cyd, [
        "mailbox:https://cyd.example/mailbox",
        "https://cyd.example/oip",
        "http://cyd.example/plain",
      ]),
      translator(bob),
      translator(cyd),
    ]);
    metrics = new Metrics();
    const forwarding = new Broker({
      indexer,
      archive,
      log: new Log({ service: "indexer", clock, sink: () => undefined }),
      metrics,
      post: (url) => {
        posted.push({ url, type: "", record: {} });
        return Promise.resolve({ status: url.endsWith("/inbox") ? 503 : 202 });
      },
      perSender: new RateLimiter({ burst: 100, perMinute: 6000 }, clock),
    });
    expect(forwarding.accept(asking(ada))).toStrictEqual({ forwarding: 2 });
    await forwarding.idle();
    // The inbox first, whatever order the record lists them in, and the mailbox after it.
    expect(posted.map((post) => post.url)).toStrictEqual([
      "https://cyd.example/oip/inbox",
      "https://cyd.example/mailbox",
    ]);
    const text = metrics.render();
    expect(text).toContain('oip_indexer_deliveries_total{outcome="delivered"} 1');
    expect(text).toContain('oip_indexer_deliveries_total{outcome="nowhere"} 1');
  });

  it("is made a few at a time, and packets are refused for now when too many wait", async () => {
    let underWay = 0;
    let most = 0;
    const release: (() => void)[] = [];
    const forwarding = broker({
      maxAtOnce: 2,
      maxWaiting: 3,
      post: () => {
        most = Math.max(most, ++underWay);
        return new Promise((resolve) => {
          release.push(() => {
            underWay--;
            resolve({ status: 202 });
          });
        });
      },
    });
    void forwarding.accept(asking(ada));
    void forwarding.accept(asking(ada, {}, { nonce: "nonce-0002" }));
    // Two are under way and four wait.
    expect(() => forwarding.accept(asking(ada, {}, { nonce: "nonce-0003" }))).toThrow(Unavailable);
    const idle = forwarding.idle();
    while (release.length > 0 || underWay > 0) {
      release.shift()?.();
      await Promise.resolve();
      await Promise.resolve();
    }
    await idle;
    expect(most).toBe(2);
    expect(forwarding.accept(asking(ada, {}, { nonce: "nonce-0003" }))).toStrictEqual({
      forwarding: 3,
    });
    for (const done of release.splice(0)) done();
  });
});

describe(`${clause("L1 18.5", "L1 17.1")} a packet from a sender the broker has not met`, () => {
  it("is forwarded once the sender's log is learned, and refused as it was if it is not", async () => {
    const url = `https://resolver.example/oip/v1/resolve/${idOf(zed)}`;
    let known = false;
    const looking = (): Lookup =>
      new Lookup({
        archive,
        get: (asked) =>
          Promise.resolve(
            known && asked === url
              ? { status: 200, body: utf8(JSON.stringify(bundleOf(zed, []))) }
              : { status: 404, body: new Uint8Array(0) },
          ),
        resolvers: ["https://resolver.example"],
        clock,
        log: new Log({ service: "indexer", clock, sink: () => undefined }),
        metrics: new Metrics(),
        service: "indexer",
      });
    broker();
    const withLookup = new Broker({
      indexer,
      archive,
      log: new Log({ service: "indexer", clock, sink: () => undefined }),
      metrics: new Metrics(),
      post: () => Promise.resolve({ status: 202 }),
      perSender: new RateLimiter({ burst: 100, perMinute: 6000 }, clock),
      lookup: looking(),
    });
    await expect(withLookup.accept(asking(zed))).rejects.toMatchObject({ code: "stale-version" });
    known = true;
    clock.at = at(200);
    expect(await withLookup.accept(asking(zed))).toStrictEqual({ forwarding: 3 });
    // One that is refused for another reason asks nobody.
    expect(problem(() => withLookup.accept(asking(ada, { brokers: [eve.address] })))).toBe(
      "forbidden",
    );
    await withLookup.idle();
  });
});
