// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { type JsonObject, MEDIA_TYPE, mindId, OipError, type OipRecord, utf8 } from "@oip/core";
import type { Bundle } from "@oip/schema";
import {
  Database,
  FetchRefused,
  Log,
  LogArchive,
  Metrics,
  RateLimiter,
  Shutdown,
  StoredNonces,
} from "@oip/server";
import { clause } from "@oip/testkit";
import { at, KeyMind, type Mind, T } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  deliverLearning,
  Host,
  HOST_MIGRATIONS,
  hostApp,
  Lookup,
  type LookupOptions,
  Sockets,
} from "../src/index.ts";

const ORIGIN = "https://host.example";
const FIRST = "https://one.resolver.example";
const SECOND = "https://two.resolver.example";

let directory: string;
let db: Database;
let clock: { at: bigint; now: () => bigint };
let lines: Record<string, unknown>[];
let metrics: Metrics;
let archive: LogArchive;
let host: Host;
let log: Log;
/** What each resolver answers for a path, and every URL that was asked for. */
let served: Map<string, () => { status: number; body: Uint8Array } | Promise<never>>;
let asked: string[];

const ada = new KeyMind("ada");
const bob = new KeyMind("bob");
const zed = new KeyMind("zed");

const idOf = (mind: Mind): string => mindId(mind.address) ?? "";
const bundleOf = (mind: Mind, events: readonly unknown[] = mind.events): Bundle =>
  ({ oip: "1", type: "Bundle", mind: mind.address, log: events }) as unknown as Bundle;
const urlOf = (resolver: string, mind: Mind): string => `${resolver}/oip/v1/resolve/${idOf(mind)}`;
const ok = (value: unknown) => () => ({ status: 200, body: utf8(JSON.stringify(value)) });

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "oip-host-lookup-"));
  clock = { at: at(110), now: () => clock.at };
  db = Database.open({ path: join(directory, "host.db"), durable: false }, HOST_MIGRATIONS, clock);
  lines = [];
  served = new Map();
  asked = [];
  metrics = new Metrics();
  log = new Log({
    service: "host",
    clock,
    sink: (line) => lines.push(JSON.parse(line) as Record<string, unknown>),
  });
  archive = new LogArchive({ db, clock });
  for (const mind of [ada, bob]) archive.publish(idOf(mind), bundleOf(mind));
  host = new Host({ db, archive });
  host.adopt(bob.address);
});
afterEach(() => {
  db.close();
  rmSync(directory, { recursive: true, force: true });
});

/** A lookup with a registry of its own, which `metrics` is from then on. */
function lookup(more: Partial<LookupOptions> = {}): Lookup {
  metrics = new Metrics();
  return new Lookup({
    archive,
    get: (url, accept) => {
      asked.push(url);
      expect(accept).toBe(MEDIA_TYPE);
      const answer = served.get(url);
      return Promise.resolve(
        answer === undefined ? { status: 404, body: new Uint8Array(0) } : answer(),
      );
    },
    resolvers: [FIRST, SECOND],
    clock,
    log,
    metrics,
    ...more,
  });
}

const holds = (mind: Mind): boolean => archive.view(clock.now()).log(mind.address).ok;

function packet(from: Mind, to: readonly Mind[], more: JsonObject = {}): OipRecord {
  return from.sign({
    oip: "1",
    type: "Packet",
    from: from.address,
    to: to.map((mind) => mind.address),
    created: T(100),
    expires: T(3700),
    nonce: "nonce-0001",
    purpose: { verb: "inform" },
    content: { mediaType: "text/plain", body: "Hello." },
    ...more,
  }) as unknown as OipRecord;
}

describe(`${clause("L1 17.1", "L1 12.4")} the log of a mind the host has not met`, () => {
  it("is asked of the resolvers in order, and what verifies of it is kept", async () => {
    served.set(urlOf(SECOND, zed), ok(bundleOf(zed)));
    const looking = lookup();
    expect(holds(zed)).toBe(false);
    expect(await looking.learn(zed.address)).toBe(true);
    expect(asked).toStrictEqual([urlOf(FIRST, zed), urlOf(SECOND, zed)]);
    expect(holds(zed)).toBe(true);
    expect(metrics.render()).toContain('oip_host_lookups_total{outcome="learned"} 1');
  });

  it("is not asked after again for a while, whatever came of asking", async () => {
    const looking = lookup({ resolvers: [FIRST] });
    expect(await looking.learn(zed.address)).toBe(false);
    served.set(urlOf(FIRST, zed), ok(bundleOf(zed)));
    clock.at = at(169.999);
    expect(await looking.learn(zed.address)).toBe(false);
    expect(asked).toHaveLength(1);
    // Another mind is another matter.
    expect(await looking.learn(ada.address)).toBe(false);
    expect(asked).toHaveLength(2);
    clock.at = at(170);
    expect(await looking.learn(zed.address)).toBe(true);
    // A log the host holds already teaches nothing, and is asked after no sooner.
    clock.at = at(300);
    expect(await looking.learn(zed.address)).toBe(false);
    expect(asked).toHaveLength(4);
    const text = metrics.render();
    expect(text).toContain('oip_host_lookups_total{outcome="not-asked"} 1');
    expect(text).toContain('oip_host_lookups_total{outcome="nothing"} 3');
    expect(await lookup({ rest: 5_000_000_000n, resolvers: [FIRST] }).learn(zed.address)).toBe(
      false,
    );
  });

  it("is not learned from a resolver that fails or says what does not verify", async () => {
    const grown = new KeyMind("zed").update(50);
    const answers: [string, () => { status: number; body: Uint8Array } | Promise<never>][] = [
      [
        "a refusal to fetch",
        () => Promise.reject(new FetchRefused("address", "10.0.0.1 is not public")),
      ],
      ["another status", () => ({ status: 500, body: utf8(JSON.stringify(bundleOf(zed))) })],
      ["no record", () => ({ status: 200, body: utf8("<html>") })],
      [
        "another record",
        ok(zed.sign({ oip: "1", type: "Intent", author: zed.address, created: T(1), want: "x" })),
      ],
      ["another mind's bundle", ok(bundleOf(ada))],
      [
        "a log whose first event does not verify",
        ok(bundleOf(zed, [{ ...zed.events[0], created: T(9) }])),
      ],
    ];
    for (const [name, answer] of answers) {
      clock.at += 61_000_000_000n;
      served.set(urlOf(FIRST, zed), answer);
      expect(await lookup({ resolvers: [FIRST] }).learn(zed.address), name).toBe(false);
      expect(holds(zed), name).toBe(false);
    }
    // What failed is logged by where and by the kind of failure, and by nothing it carried.
    expect(lines.map((line) => [line["event"], line["resolver"], line["reason"]])).toStrictEqual([
      ["lookup failed", FIRST, "FetchRefused"],
      ["lookup failed", FIRST, "OipError"],
      ["lookup failed", FIRST, "OipError"],
    ]);
    expect(JSON.stringify(lines)).not.toContain("10.0.0.1");
    // What is thrown that is no error is logged as that.
    clock.at += 61_000_000_000n;
    const noError = { name: "something else" } as unknown as Error;
    served.set(urlOf(FIRST, zed), () => Promise.reject(noError));
    expect(await lookup({ resolvers: [FIRST] }).learn(zed.address)).toBe(false);
    expect(lines.at(-1)).toMatchObject({ event: "lookup failed", reason: "unknown" });
    // A log that verifies as far as it goes is kept that far.
    served.set(
      urlOf(FIRST, zed),
      ok(bundleOf(grown, [grown.events[0], { ...grown.events[1], created: T(51) }])),
    );
    expect(await lookup({ resolvers: [FIRST] }).learn(zed.address)).toBe(true);
    expect(holds(zed)).toBe(true);
  });

  it("is asked after for an address only, with resolvers to ask, and for so many at once", async () => {
    served.set(urlOf(FIRST, zed), ok(bundleOf(zed)));
    for (const mind of ["not an address", "", 7 as unknown as string]) {
      expect(await lookup().learn(mind)).toBe(false);
    }
    expect(await lookup({ resolvers: [] }).learn(zed.address)).toBe(false);
    expect(asked).toStrictEqual([]);
    // Two that ask after one mind at once are one question.
    const looking = lookup({ maxAtOnce: 1 });
    const [first, second, other] = [
      looking.learn(zed.address),
      looking.learn(zed.address),
      looking.learn(ada.address),
    ];
    expect(await Promise.all([first, second, other])).toStrictEqual([true, true, false]);
    expect(asked).toStrictEqual([urlOf(FIRST, zed)]);
    // Once it is answered there is room for another.
    expect(await looking.learn(ada.address)).toBe(false);
    expect(asked).toHaveLength(3);
  });
});

describe("what a lookup remembers", () => {
  it("is so many minds, and the one asked after longest ago goes first", async () => {
    const [yan, xia] = [new KeyMind("yan"), new KeyMind("xia")];
    const looking = lookup({ remembered: 2, resolvers: [FIRST] });
    for (const mind of [zed, yan, xia]) await looking.learn(mind.address);
    expect(asked).toStrictEqual([urlOf(FIRST, zed), urlOf(FIRST, yan), urlOf(FIRST, xia)]);
    // The two asked after last are remembered, and not asked after again yet.
    await looking.learn(yan.address);
    await looking.learn(xia.address);
    expect(asked).toHaveLength(3);
    // Zed is forgotten, and asked after again: and now yan is the one forgotten.
    await looking.learn(zed.address);
    expect(asked).toHaveLength(4);
    await looking.learn(xia.address);
    expect(asked).toHaveLength(4);
    await looking.learn(yan.address);
    expect(asked).toHaveLength(5);
  });
});

describe(`${clause("L1 13.2")} a packet whose sender the host cannot judge`, () => {
  it("is judged again once the sender's log is learned, and refused as it was if it is not", async () => {
    const sent = packet(zed, [bob]);
    const stale = (work: () => unknown): string => {
      try {
        work();
      } catch (error) {
        if (error instanceof OipError) return error.code;
      }
      return "taken";
    };
    expect(stale(() => deliverLearning(host, undefined, bob.address, sent))).toBe("stale-version");
    // Nothing is learned: the refusal is the one the packet had.
    await expect(deliverLearning(host, lookup(), bob.address, sent)).rejects.toMatchObject({
      code: "stale-version",
    });
    clock.at = at(200);
    served.set(urlOf(FIRST, zed), ok(bundleOf(zed)));
    expect(await deliverLearning(host, lookup(), bob.address, sent)).toStrictEqual({
      stored: true,
    });
    // A packet the host can judge is answered at once, with nobody asked.
    const before = asked.length;
    expect(deliverLearning(host, lookup(), bob.address, packet(ada, [bob]))).toStrictEqual({
      stored: true,
    });
    // One that is refused for another reason asks nobody either.
    expect(stale(() => deliverLearning(host, lookup(), bob.address, packet(ada, [zed])))).toBe(
      "forbidden",
    );
    expect(asked).toHaveLength(before);
  });

  it("is refused as it was, with nobody asked, where its sender's log is not what is wanting", () => {
    const full = new Host({ db, archive, limits: { mailboxItems: 0 } });
    let thrown: unknown;
    try {
      void deliverLearning(full, lookup(), bob.address, packet(ada, [bob]));
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toMatchObject({ status: 507 });
    expect(asked).toStrictEqual([]);
  });

  it("is taken from a sender whose log has grown since the host saw it", async () => {
    const grown = new KeyMind("ada").update(50, { keys: [{ key: ada.operational(1).publicKey }] });
    const sent = grown.sign(
      {
        oip: "1",
        type: "Packet",
        from: ada.address,
        to: [bob.address],
        created: T(100),
        expires: T(3700),
        nonce: "nonce-0002",
        purpose: { verb: "inform" },
        content: { mediaType: "text/plain", body: "Hello." },
      },
      { key: 1 },
    ) as unknown as OipRecord;
    await expect(deliverLearning(host, lookup(), bob.address, sent)).rejects.toMatchObject({
      code: "invalid-proof",
    });
    clock.at = at(200);
    served.set(urlOf(FIRST, ada), ok(bundleOf(grown)));
    expect(await deliverLearning(host, lookup(), bob.address, sent)).toStrictEqual({
      stored: true,
    });
  });

  it("is taken at the inbox and over a socket the same way", async () => {
    served.set(urlOf(FIRST, zed), ok(bundleOf(zed)));
    const generous = (): RateLimiter => new RateLimiter({ burst: 1000, perMinute: 60_000 }, clock);
    const app = hostApp({
      host,
      archive,
      clock,
      log,
      metrics,
      origin: ORIGIN,
      nonces: new StoredNonces(db),
      limits: { read: generous(), deliver: generous(), owner: generous() },
      shutdown: new Shutdown({ log }),
      ready: {},
      lookup: lookup(),
    });
    const post = (record: OipRecord): Promise<Response> =>
      Promise.resolve(
        app.fetch(
          new Request(`http://10.0.0.7/oip/v1/minds/${idOf(bob)}/inbox`, {
            method: "POST",
            body: JSON.stringify(record),
            headers: { "content-type": MEDIA_TYPE },
          }),
          { address: "203.0.113.7" },
        ),
      );
    const taken = await post(packet(zed, [bob]));
    expect([taken.status, await taken.json()]).toStrictEqual([202, { stored: true }]);
    const unknown = new KeyMind("yan");
    expect((await post(packet(unknown, [bob]))).status).toBe(409);
    expect(host.drain(bob.address, 0, 10).items).toHaveLength(1);
  });
});

describe(`${clause("L1 13.4")} a socket opened by a mind the host has not met`, () => {
  const hello = (mind: Mind, challenge: string): string =>
    JSON.stringify(
      mind.sign(
        { oip: "1", type: "Hello", author: mind.address, created: T(110) },
        { more: { challenge, domain: ORIGIN } },
      ),
    );

  function open(more: { maxWaiting?: number } = {}, looking = lookup()) {
    const sockets = new Sockets({
      host,
      archive,
      clock,
      randomness: { bytes: (length) => new Uint8Array(length).fill(asked.length + 1) },
      log,
      metrics,
      origin: ORIGIN,
      deliver: new RateLimiter({ burst: 1000, perMinute: 60_000 }, clock),
      lookup: looking,
      ...more,
    });
    const sent: JsonObject[] = [];
    const state = { closed: undefined as [number, string] | undefined };
    const connection = sockets.connect(
      bob.address,
      {
        send: (text) => sent.push(JSON.parse(text) as JsonObject),
        close: (code, reason) => {
          state.closed = [code, reason];
        },
        buffered: 0,
      },
      "203.0.113.7",
    );
    return { sockets, connection, sent, state, nonce: sent[0]?.["nonce"] as string };
  }
  /** Lets everything that waits on the lookup run. */
  const settled = async (): Promise<void> => {
    for (let turn = 0; turn < 20; turn++) await Promise.resolve();
  };

  it("is welcomed once its log is learned, and what it sent meanwhile is taken in order", async () => {
    served.set(urlOf(FIRST, zed), ok(bundleOf(zed)));
    const { connection, sent, state } = open();
    connection.message(hello(zed, nonce(sent)));
    // Asked after, and not yet answered: nothing is said, and what follows waits.
    expect(sent).toHaveLength(1);
    const records = ["nonce-0001", "nonce-0002", "nonce-0003"].map((nonce) =>
      packet(zed, [bob], { nonce }),
    );
    for (const record of records) connection.message(JSON.stringify(record));
    expect(host.drain(bob.address, 0, 10).items).toHaveLength(0);
    await settled();
    expect(sent[1]).toStrictEqual({ type: "Welcome", mind: zed.address });
    expect(state.closed).toBeUndefined();
    expect(host.drain(bob.address, 0, 10).items.map((item) => item.record)).toStrictEqual(records);
    // The connection is as any other from then on.
    connection.message(JSON.stringify(packet(zed, [bob], { nonce: "nonce-0004" })));
    expect(host.drain(bob.address, 0, 10).items).toHaveLength(4);
  });

  it("is closed with 4401 if nothing is learned of the mind", async () => {
    const { connection, sent, state } = open();
    connection.message(hello(zed, nonce(sent)));
    connection.message(JSON.stringify(packet(zed, [bob])));
    expect(state.closed).toBeUndefined();
    await settled();
    expect(state.closed?.[0]).toBe(4401);
    expect(sent).toHaveLength(1);
    expect(host.drain(bob.address, 0, 10).items).toHaveLength(0);
  });

  it("may leave only so many messages waiting while a resolver is asked", async () => {
    served.set(urlOf(FIRST, zed), ok(bundleOf(zed)));
    const { connection, sent, state } = open({ maxWaiting: 2 });
    connection.message(hello(zed, nonce(sent)));
    for (const nonce of ["nonce-0001", "nonce-0002"]) {
      connection.message(JSON.stringify(packet(zed, [bob], { nonce })));
    }
    expect(state.closed).toBeUndefined();
    connection.message(JSON.stringify(packet(zed, [bob], { nonce: "nonce-0003" })));
    expect(state.closed).toStrictEqual([1008, "too many messages at once"]);
    await settled();
    // What waited on a connection that closed is not taken.
    expect(host.drain(bob.address, 0, 10).items).toHaveLength(0);
    expect(sent).toHaveLength(1);
  });

  it("asks nobody about a Hello that names no mind, and says nothing to a socket that has gone", async () => {
    served.set(urlOf(FIRST, zed), ok(bundleOf(zed)));
    for (const said of ["7", "null", '{"author":7}']) {
      const { connection, state } = open();
      connection.message(said);
      expect(state.closed?.[0], said).toBe(4401);
    }
    expect(asked).toStrictEqual([]);
    // The socket closes while its mind is asked after: the answer finds nobody.
    const gone = open();
    gone.connection.message(hello(zed, nonce(gone.sent)));
    gone.connection.closed();
    await settled();
    expect(gone.sent).toHaveLength(1);
    expect(gone.state.closed).toBeUndefined();
    // And while a packet's sender is asked after: its refusal closes nothing twice.
    const { connection, sent, state } = open();
    connection.message(hello(ada, nonce(sent)));
    connection.message(JSON.stringify(packet(new KeyMind("yan"), [bob])));
    connection.closed();
    await settled();
    expect(state.closed).toBeUndefined();
    expect(sent).toHaveLength(2);
  });

  it("takes a packet from a sender it has not met, on a socket of a mind it has", async () => {
    served.set(urlOf(FIRST, zed), ok(bundleOf(zed)));
    const { connection, sent, state } = open();
    connection.message(hello(ada, nonce(sent)));
    expect(sent[1]).toStrictEqual({ type: "Welcome", mind: ada.address });
    const first = packet(zed, [bob]);
    const second = packet(ada, [bob], { nonce: "nonce-0002" });
    connection.message(JSON.stringify(first));
    connection.message(JSON.stringify(second));
    await settled();
    expect(state.closed).toBeUndefined();
    expect(host.drain(bob.address, 0, 10).items.map((item) => item.record)).toStrictEqual([
      first,
      second,
    ]);
    // One whose sender stays unknown closes the connection as it would have at once.
    connection.message(JSON.stringify(packet(new KeyMind("yan"), [bob])));
    await settled();
    expect(state.closed).toStrictEqual([1008, "stale-version"]);
  });

  const nonce = (sent: JsonObject[]): string => sent[0]?.["nonce"] as string;
});
