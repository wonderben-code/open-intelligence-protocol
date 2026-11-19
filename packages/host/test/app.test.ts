// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  contentId,
  formatKeyRef,
  type JsonObject,
  MEDIA_TYPE,
  mindId,
  type OipRecord,
  parseRecord,
  PROBLEM_MEDIA_TYPE,
  utf8,
} from "@oip/core";
import { signRequest } from "@oip/net";
import type { Bundle } from "@oip/schema";
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
import { at, intentBy, KeyMind, locationBy, type Mind, T } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  Host,
  HOST_MIGRATIONS,
  hostApp,
  type HostAppOptions,
  type HostOptions,
} from "../src/index.ts";

const ORIGIN = "https://host.example";

let directory: string;
let db: Database;
let clock: { at: bigint; now: () => bigint };
let lines: Record<string, unknown>[];
let metrics: Metrics;
let shutdown: Shutdown;
let archive: LogArchive;
let host: Host;
let nonce = 0;

const ada = new KeyMind("ada");
const bob = new KeyMind("bob");
const eve = new KeyMind("eve");

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "oip-host-app-"));
  clock = { at: at(110), now: () => clock.at };
  db = Database.open({ path: join(directory, "host.db"), durable: false }, HOST_MIGRATIONS, clock);
  lines = [];
});
afterEach(() => {
  vi.restoreAllMocks();
  try {
    db.close();
  } catch {
    // A test closed it.
  }
  rmSync(directory, { recursive: true, force: true });
});

const idOf = (mind: Mind): string => mindId(mind.address) ?? "";
const bundleOf = (mind: Mind, more: JsonObject = {}): Bundle =>
  ({
    oip: "1",
    type: "Bundle",
    mind: mind.address,
    log: mind.events,
    ...more,
  }) as unknown as Bundle;

/**
 * The host's interface, with what a test changes of it. The host holds the
 * logs of `known`, and serves `hosted`.
 */
function service(
  more: Partial<HostAppOptions> = {},
  made: Partial<HostOptions> & { known?: Mind[]; hosted?: Mind[] } = {},
) {
  const log = new Log({
    service: "host",
    clock,
    sink: (line) => lines.push(JSON.parse(line) as Record<string, unknown>),
  });
  metrics = new Metrics();
  shutdown = new Shutdown({ log });
  archive = new LogArchive({ db, clock });
  const { known = [ada, bob], hosted = [bob], ...options } = made;
  for (const mind of known) archive.publish(idOf(mind), bundleOf(mind));
  host = new Host({ db, archive, ...options });
  for (const mind of hosted) host.adopt(mind.address);
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
    shutdown,
    ready: { database: () => true },
    ...more,
  });
  const ask = (path: string, init: RequestInit = {}, address = "203.0.113.7"): Promise<Response> =>
    Promise.resolve(app.fetch(new Request(`http://10.0.0.7:8080${path}`, init), { address }));
  return { app, ask };
}

const wellKnown = (mind: Mind, rest = ""): string => `/.well-known/oip/mind/${idOf(mind)}${rest}`;
const endpoint = (mind: Mind, rest = ""): string => `/oip/v1/minds/${idOf(mind)}${rest}`;

const sending = (record: unknown, method = "POST", type = MEDIA_TYPE): RequestInit => ({
  method,
  body: typeof record === "string" ? record : JSON.stringify(record),
  headers: { "content-type": type },
});

/** A request signed by a mind for the host's own origin (Layer 1, 13.3). */
async function signed(
  by: Mind,
  method: string,
  path: string,
  record?: unknown,
): Promise<RequestInit> {
  const body = record === undefined ? undefined : utf8(JSON.stringify(record));
  const headers: [string, string][] = body === undefined ? [] : [["Content-Type", MEDIA_TYPE]];
  const added = await signRequest(
    { method, url: `${ORIGIN}${path}`, headers, ...(body === undefined ? {} : { body }) },
    {
      keyRef: formatKeyRef(by.address, by.versionId(), by.operational().publicKey),
      // A signature is made at a whole second.
      created: clock.at - (clock.at % 1_000_000_000n),
      nonce: `nonce-${String(++nonce).padStart(4, "0")}`,
    },
    by.operational(),
  );
  return {
    method,
    ...(body === undefined ? {} : { body }),
    headers: [...headers, ...added] as [string, string][],
  };
}

/** A packet from one mind to others, made at 100 and good for an hour. */
function packet(
  from: Mind,
  to: readonly Mind[],
  more: JsonObject = {},
  by: Mind = from,
): OipRecord {
  return by.sign({
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

const sealed = (to: Mind, enc = "AAAA"): JsonObject => ({
  oip: "1",
  type: "Sealed",
  to: to.address,
  key: "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
  suite: "hpke-base-x25519-sha256-chacha20poly1305",
  enc,
  ciphertext: "AAAA",
});

async function problemOf(response: Response): Promise<{ status: number; type: string }> {
  expect(response.headers.get("content-type")).toBe(PROBLEM_MEDIA_TYPE);
  const body = (await response.json()) as { type: string };
  return { status: response.status, type: body.type };
}

const count = (table: string): number =>
  (db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get() as { n: number }).n;

describe(`${clause("L1 13.1")} what a host serves of a mind`, () => {
  it("is the mind's bundle, with its location record and when each was first seen", async () => {
    const { ask } = service();
    const location = bob.sign(locationBy(bob, 100));
    archive.publish(idOf(bob), bundleOf(bob, { location } as never));
    const served = await ask(wellKnown(bob));
    expect(served.status).toBe(200);
    expect(served.headers.get("content-type")).toBe(MEDIA_TYPE);
    expect(served.headers.get("access-control-allow-origin")).toBe("*");
    expect(served.headers.get("cache-control")).toBe("no-cache");
    // What is served is a record a client's reader takes.
    const bundle = parseRecord(await served.text());
    expect(bundle.ok && bundle.value).toMatchObject({
      type: "Bundle",
      mind: bob.address,
      log: bob.events,
      location,
    });
    const firstSeen = bundle.ok ? (bundle.value as { firstSeen?: object }).firstSeen : undefined;
    expect(Object.keys(firstSeen ?? {})).toHaveLength(2);
  });

  it("is nothing of a mind it does not serve, though it holds its log", async () => {
    const { ask } = service();
    const paths = [wellKnown(ada), wellKnown(eve), "/.well-known/oip/mind/not-a-content-id"];
    for (const path of paths) {
      for (const rest of ["", "/log"]) {
        expect(await problemOf(await ask(path + rest)), path + rest).toStrictEqual({
          status: 404,
          type: "urn:oip:error:not-found",
        });
      }
    }
    expect((await ask("/.well-known/oip/other")).status).toBe(404);
  });

  it("is nothing where the host is said to serve a mind and holds no log of it", async () => {
    const { ask } = service();
    // Not as the host writes its database: a mind is taken on with its log.
    db.prepare("INSERT INTO hosted (mind, since) VALUES (?, ?)").run(eve.address, 1);
    for (const rest of ["", "/log"]) {
      expect(await problemOf(await ask(wellKnown(eve, rest)))).toStrictEqual({
        status: 404,
        type: "urn:oip:error:not-found",
      });
    }
  });

  it("is the mind's log a page at a time, from after a position on", async () => {
    const long = new KeyMind("long");
    for (let n = 1; n <= 4; n++) long.update(10 * n);
    const { ask } = service({ maxPage: 3 }, { known: [long], hosted: [long] });
    const page = async (query: string) => {
      const response = await ask(wellKnown(long, `/log${query}`));
      expect(response.status, query).toBe(200);
      const parsed = parseRecord(await response.text());
      if (!parsed.ok) throw new Error(JSON.stringify(parsed.issues));
      const { type, mind, events, next, firstSeen } = parsed.value as unknown as {
        type: string;
        mind: string;
        events: OipRecord[];
        next?: number;
        firstSeen: Record<string, string>;
      };
      expect([type, mind]).toStrictEqual(["LogPage", long.address]);
      // The times given are those of the events in the page, and of no others.
      expect(Object.keys(firstSeen).sort()).toStrictEqual(events.map((e) => contentId(e)).sort());
      const ids = long.events.map((own) => contentId(own as unknown as OipRecord));
      return { at: events.map((event) => ids.indexOf(contentId(event))), next };
    };
    // A page starts at the genesis, and holds as many as the host serves at once.
    expect(await page("")).toStrictEqual({ at: [0, 1, 2], next: 2 });
    expect(await page("?limit=100")).toStrictEqual({ at: [0, 1, 2], next: 2 });
    expect(await page("?limit=2")).toStrictEqual({ at: [0, 1], next: 1 });
    // `after` is exclusive, and `next` is what to pass as it.
    expect(await page("?after=1&limit=2")).toStrictEqual({ at: [2, 3], next: 3 });
    expect(await page("?after=0&limit=1")).toStrictEqual({ at: [1], next: 1 });
    // The last page says there is no more, and so does one after the end.
    expect(await page("?after=3")).toStrictEqual({ at: [4], next: undefined });
    expect(await page("?after=2&limit=2")).toStrictEqual({ at: [3, 4], next: undefined });
    expect(await page("?after=4")).toStrictEqual({ at: [], next: undefined });
    expect(await page("?after=900")).toStrictEqual({ at: [], next: undefined });
    for (const query of [
      "?after=-1",
      "?after=x",
      "?after=1.5",
      "?after=",
      "?limit=0",
      "?limit=01",
      "?limit=many",
    ]) {
      expect((await ask(wellKnown(long, `/log${query}`))).status, query).toBe(400);
    }
  });
});

describe(`${clause("L1 13.2")} a mind's inbox`, () => {
  it("answers 202 with that the packet is stored, and with the mind's Ack where the host signs for it", async () => {
    const { ask } = service();
    const sent = packet(ada, [bob]);
    const stored = await ask(endpoint(bob, "/inbox"), sending(sent));
    expect(stored.status).toBe(202);
    expect(stored.headers.get("content-type")).toBe("application/json");
    expect(await stored.json()).toStrictEqual({ stored: true });
    // The same packet again is answered the same, and kept once.
    const again = await ask(endpoint(bob, "/inbox"), sending(sent));
    expect([again.status, await again.json()]).toStrictEqual([202, { stored: true }]);
    expect(count("mailbox")).toBe(1);

    db.close();
    rmSync(join(directory, "host.db"));
    db = Database.open(
      { path: join(directory, "host.db"), durable: false },
      HOST_MIGRATIONS,
      clock,
    );
    const custodial = service({}, { signer: () => bob.operational() });
    const acknowledged = await custodial.ask(endpoint(bob, "/inbox"), sending(sent));
    expect(acknowledged.status).toBe(202);
    expect(acknowledged.headers.get("content-type")).toBe(MEDIA_TYPE);
    const ack = parseRecord(await acknowledged.text());
    expect(ack.ok && ack.value).toMatchObject({
      type: "Ack",
      author: bob.address,
      packet: contentId(sent),
    });
    const repeated = await custodial.ask(endpoint(bob, "/inbox"), sending(sent));
    expect(repeated.status).toBe(202);
    expect(await repeated.json()).toStrictEqual(ack.ok ? ack.value : undefined);
    expect(metrics.render()).toContain('oip_host_records_kept_total{at="inbox",answer="ack"} 2');
  });

  it(`${clause("L1 18.5")} takes a packet a broker forwarded to the mind, and a mailbox does not`, async () => {
    const { ask } = service({}, { known: [ada, bob, eve] });
    const asked = packet(ada, [], { to: { query: { want: "A translator." } } });
    const wrapped = eve.sign({
      oip: "1",
      type: "Forwarded",
      broker: eve.address,
      to: bob.address,
      packet: asked,
      created: T(105),
    });
    const taken = await ask(endpoint(bob, "/inbox"), sending(wrapped));
    expect([taken.status, await taken.json()]).toStrictEqual([202, { stored: true }]);
    expect(await problemOf(await ask(endpoint(bob, "/mailbox"), sending(wrapped)))).toStrictEqual({
      status: 400,
      type: "urn:oip:error:invalid-record",
    });
    expect(count("mailbox")).toBe(1);
  });

  it("takes a sealed record for the mind as it is", async () => {
    const { ask } = service();
    const response = await ask(endpoint(bob, "/inbox"), sending(sealed(bob)));
    expect([response.status, await response.json()]).toStrictEqual([202, { stored: true }]);
  });

  it("refuses what it may not take, each with its problem (core 10.2)", async () => {
    const { ask } = service({ maxRecordBytes: 4096 });
    const inbox = endpoint(bob, "/inbox");
    const cases: [string, string, RequestInit, number, string][] = [
      [
        "a mind the host does not serve",
        endpoint(ada, "/inbox"),
        sending(packet(bob, [ada])),
        404,
        "not-found",
      ],
      [
        "what names no mind",
        "/oip/v1/minds/nobody/inbox",
        sending(packet(ada, [bob])),
        404,
        "not-found",
      ],
      ["another record", inbox, sending(ada.sign(intentBy(ada, 100))), 400, "invalid-record"],
      ["no record", inbox, sending("{"), 400, "invalid-record"],
      ["addressed to another", inbox, sending(packet(ada, [eve])), 403, "forbidden"],
      [
        "signed by another than its sender",
        inbox,
        sending(packet(ada, [bob], {}, bob)),
        400,
        "invalid-proof",
      ],
      [
        "from a mind the host holds no log of",
        inbox,
        sending(packet(eve, [bob])),
        409,
        "stale-version",
      ],
      [
        "expired",
        inbox,
        sending(packet(ada, [bob], { created: T(-9000), expires: T(-8000) })),
        400,
        "expired",
      ],
      ["a sealed record for another", inbox, sending(sealed(ada)), 403, "forbidden"],
      [
        "a sealed record that is not well formed",
        inbox,
        sending({ ...sealed(bob), suite: 7 }),
        400,
        "invalid-record",
      ],
      [
        "too long a record",
        inbox,
        sending(
          packet(ada, [bob], { content: { mediaType: "text/plain", body: "x".repeat(5000) } }),
        ),
        413,
        "too-large",
      ],
    ];
    for (const [name, path, init, status, type] of cases) {
      expect(await problemOf(await ask(path, init)), name).toStrictEqual({
        status,
        type: `urn:oip:error:${type}`,
      });
    }
    const other = await ask(inbox, sending(packet(ada, [bob]), "POST", "application/json"));
    expect(other.status).toBe(415);
    expect(other.headers.get("accept")).toBe(MEDIA_TYPE);
    expect((await ask(inbox)).status).toBe(404);
    for (const table of ["mailbox", "accepted", "seen_proofs"]) expect(count(table), table).toBe(0);
  });
});

describe(`${clause("L1 13.5", "L1 13.3")} a mind's mailbox`, () => {
  it("takes what is posted to it, and gives it to the mind alone, which removes what it has", async () => {
    const { ask } = service();
    const mailbox = endpoint(bob, "/mailbox");
    const forged = packet(ada, [bob], {}, eve);
    for (const record of [forged, sealed(bob, "AAA1"), sealed(bob, "AAA2")]) {
      const posted = await ask(mailbox, sending(record));
      expect([posted.status, await posted.json()]).toStrictEqual([202, { stored: true }]);
    }
    // Not signed, signed by another mind, and signed for another mailbox.
    expect(await problemOf(await ask(mailbox))).toStrictEqual({
      status: 401,
      type: "urn:oip:error:unauthorised",
    });
    expect(await problemOf(await ask(mailbox, await signed(ada, "GET", mailbox)))).toStrictEqual({
      status: 403,
      type: "urn:oip:error:forbidden",
    });
    const elsewhere = await signed(bob, "GET", `${mailbox}?after=0`);
    expect((await problemOf(await ask(mailbox, elsewhere))).status).toBe(401);

    const drained = await ask(mailbox, await signed(bob, "GET", mailbox));
    expect(drained.status).toBe(200);
    expect(drained.headers.get("cache-control")).toBe("no-store");
    expect(await drained.json()).toStrictEqual({
      items: [
        { cursor: "1", record: forged },
        { cursor: "2", record: sealed(bob, "AAA1") },
        { cursor: "3", record: sealed(bob, "AAA2") },
      ],
    });
    // A page at a time, from a cursor on.
    const paged = `${mailbox}?after=1&limit=1`;
    expect(await (await ask(paged, await signed(bob, "GET", paged))).json()).toStrictEqual({
      items: [{ cursor: "2", record: sealed(bob, "AAA1") }],
      next: "2",
    });
    for (const query of ["?after=x", "?limit=0", "?after=-1"]) {
      const path = mailbox + query;
      expect((await ask(path, await signed(bob, "GET", path))).status, query).toBe(400);
    }
    // A request that was signed is good once.
    const once = await signed(bob, "GET", mailbox);
    expect((await ask(mailbox, once)).status).toBe(200);
    expect((await problemOf(await ask(mailbox, once))).status).toBe(401);

    const second = `${mailbox}/2`;
    expect((await problemOf(await ask(second, { method: "DELETE" }))).status).toBe(401);
    expect((await problemOf(await ask(second, await signed(ada, "DELETE", second)))).status).toBe(
      403,
    );
    expect(count("mailbox")).toBe(3);
    const removed = await ask(second, await signed(bob, "DELETE", second));
    expect([removed.status, await removed.text()]).toStrictEqual([204, ""]);
    for (const path of [second, `${mailbox}/x`, `${mailbox}/-1`, `${mailbox}/900`]) {
      expect(
        await problemOf(await ask(path, await signed(bob, "DELETE", path))),
        path,
      ).toStrictEqual({
        status: 404,
        type: "urn:oip:error:not-found",
      });
    }
    const left = await ask(mailbox, await signed(bob, "GET", mailbox));
    expect(
      ((await left.json()) as { items: { cursor: string }[] }).items.map((item) => item.cursor),
    ).toStrictEqual(["1", "3"]);
  });

  it("refuses what is no record for the mind, and answers 507 when it is full", async () => {
    const { ask } = service({}, { limits: { mailboxItems: 1 } });
    const mailbox = endpoint(bob, "/mailbox");
    const cases: [string, string, RequestInit, number, string][] = [
      [
        "a mind the host does not serve",
        endpoint(ada, "/mailbox"),
        sending(sealed(ada)),
        404,
        "not-found",
      ],
      ["another record", mailbox, sending(ada.sign(intentBy(ada, 100))), 400, "invalid-record"],
      ["a record for another", mailbox, sending(sealed(ada)), 403, "forbidden"],
    ];
    for (const [name, path, init, status, type] of cases) {
      expect(await problemOf(await ask(path, init)), name).toStrictEqual({
        status,
        type: `urn:oip:error:${type}`,
      });
    }
    expect(
      (await ask(endpoint(ada, "/mailbox"), await signed(ada, "GET", endpoint(ada, "/mailbox"))))
        .status,
    ).toBe(404);
    expect((await ask(mailbox, sending(sealed(bob, "AAA1")))).status).toBe(202);
    const full = await ask(mailbox, sending(sealed(bob, "AAA2")));
    expect(full.status).toBe(507);
    expect(full.headers.get("content-type")).toBe(PROBLEM_MEDIA_TYPE);
    expect((await ask(endpoint(bob, "/inbox"), sending(packet(ada, [bob])))).status).toBe(507);
  });
});

describe(`${clause("L1 13.1", "L1 13.3")} a mind that brings its bundle to a host`, () => {
  it("is taken on if the host admits it and the mind itself signed the request", async () => {
    const { ask } = service({ admits: (mind) => mind === eve.address });
    const path = endpoint(eve);
    // Not signed; signed by a mind the host holds, for another's bundle.
    expect(await problemOf(await ask(path, sending(bundleOf(eve), "PUT")))).toStrictEqual({
      status: 401,
      type: "urn:oip:error:unauthorised",
    });
    expect(
      await problemOf(await ask(path, await signed(ada, "PUT", path, bundleOf(eve)))),
    ).toStrictEqual({
      status: 403,
      type: "urn:oip:error:forbidden",
    });
    expect(host.hosts(eve.address)).toBe(false);
    expect((await ask(wellKnown(eve))).status).toBe(404);
    expect(count("events")).toBe(2);
    // Signed by the mind itself, which the host has never seen: judged against its own log.
    const location = eve.sign(locationBy(eve, 100));
    const first = await ask(
      path,
      await signed(eve, "PUT", path, bundleOf(eve, { location } as never)),
    );
    expect([first.status, await first.json()]).toStrictEqual([201, { added: 1 }]);
    expect(host.hosts(eve.address)).toBe(true);
    const served = (await (await ask(wellKnown(eve))).json()) as {
      log: unknown[];
      location: unknown;
    };
    expect(served).toMatchObject({ log: eve.events, location });
    // It brings what is new the same way.
    const grown = new KeyMind("eve").update(50);
    clock.at = at(120);
    const second = await ask(path, await signed(grown, "PUT", path, bundleOf(grown)));
    expect([second.status, await second.json()]).toStrictEqual([200, { added: 1 }]);
    expect(((await (await ask(wellKnown(eve))).json()) as { log: unknown[] }).log).toHaveLength(2);
    // And packets for it are taken from then on.
    expect((await ask(endpoint(eve, "/inbox"), sending(packet(ada, [eve])))).status).toBe(202);
  });

  it("is judged at one reading of the clock, as every signed request is, though the clock moves", async () => {
    const { ask } = service({ admits: () => true });
    // A millisecond passes each time the clock is read, as on a machine.
    clock.now = () => (clock.at += 1_000_000n);
    const path = endpoint(eve);
    expect((await ask(path, await signed(eve, "PUT", path, bundleOf(eve)))).status).toBe(201);
    expect((await ask(path, await signed(eve, "PUT", path, bundleOf(eve)))).status).toBe(200);
    const mailbox = endpoint(eve, "/mailbox");
    expect((await ask(mailbox, sending(sealed(eve)))).status).toBe(202);
    expect((await ask(mailbox, await signed(eve, "GET", mailbox))).status).toBe(200);
    expect((await ask(`${mailbox}/1`, await signed(eve, "DELETE", `${mailbox}/1`))).status).toBe(
      204,
    );
    const intent = eve.sign(intentBy(eve, 100));
    const object = endpoint(eve, `/obj/${contentId(intent)}`);
    expect((await ask(object, await signed(eve, "PUT", object, intent))).status).toBe(201);
    const entry = eve.sign({
      oip: "1",
      type: "Entry",
      author: eve.address,
      seq: 0,
      created: T(100),
      object: contentId(intent),
      objectType: "Intent",
    });
    const feed = endpoint(eve, "/feed");
    const page = { oip: "1", type: "FeedPage", mind: eve.address, entries: [entry] };
    expect((await ask(feed, await signed(eve, "POST", feed, page))).status).toBe(200);
    expect((await ask(endpoint(eve, "/inbox"), sending(packet(ada, [eve])))).status).toBe(202);
  });

  it("is refused if the host does not admit it, before anything of the request is read", async () => {
    const { ask } = service();
    const path = endpoint(eve);
    const refused = await ask(path, await signed(eve, "PUT", path, bundleOf(eve)));
    expect(await problemOf(refused)).toStrictEqual({
      status: 403,
      type: "urn:oip:error:forbidden",
    });
    expect(count("request_nonces")).toBe(0);
    expect(
      await problemOf(await ask("/oip/v1/minds/nobody", sending(bundleOf(eve), "PUT"))),
    ).toStrictEqual({
      status: 404,
      type: "urn:oip:error:not-found",
    });
    // A mind the host serves already needs no admitting.
    const own = endpoint(bob);
    expect((await ask(own, await signed(bob, "PUT", own, bundleOf(bob)))).status).toBe(200);
  });

  it("is refused what is no bundle of its own that verifies", async () => {
    const { ask } = service({ admits: () => true, maxRecordBytes: 8192 });
    const path = endpoint(eve);
    const cases: [string, RequestInit, number, string][] = [
      [
        "another record",
        await signed(eve, "PUT", path, eve.sign(intentBy(eve, 100))),
        400,
        "invalid-record",
      ],
      [
        "another mind's bundle",
        await signed(eve, "PUT", path, bundleOf(ada)),
        400,
        "invalid-record",
      ],
      ["no record", sending("[]", "PUT"), 400, "invalid-record"],
      [
        "too long a bundle",
        sending(JSON.stringify(bundleOf(eve, { pad: "x".repeat(9000) })), "PUT"),
        413,
        "too-large",
      ],
    ];
    for (const [name, init, status, type] of cases) {
      expect(await problemOf(await ask(path, init)), name).toStrictEqual({
        status,
        type: `urn:oip:error:${type}`,
      });
    }
    expect((await ask(path, sending(bundleOf(eve), "PUT", "text/plain"))).status).toBe(415);
    // A location record another mind signed: the log is the mind's, and the record is not.
    const others = { ...bundleOf(eve), location: ada.sign(locationBy(eve, 100)) };
    expect(await problemOf(await ask(path, await signed(eve, "PUT", path, others)))).toStrictEqual({
      status: 400,
      type: "urn:oip:error:invalid-proof",
    });
    // A log whose second event does not verify: the mind signed, and the bundle is refused.
    const broken = new KeyMind("eve").update(50);
    const events = [broken.events[0], { ...broken.events[1], created: T(51) }];
    const refused = await ask(
      path,
      await signed(eve, "PUT", path, { ...bundleOf(eve), log: events }),
    );
    expect(await problemOf(refused)).toStrictEqual({
      status: 400,
      type: "urn:oip:error:invalid-proof",
    });
    expect(host.hosts(eve.address)).toBe(false);
  });
});

describe(`${clause("L1 10.2", "L1 13.1")} the feed and the records a mind brings to its host`, () => {
  type Signed = JsonObject & { proof: JsonObject[] };
  const published = [1, 2].map(
    (n) => bob.sign(intentBy(bob, n, { want: `Thing ${n}.` })) as Signed,
  );
  const entry = (
    seq: number,
    prev: object | undefined,
    object: Signed,
    seconds = 100 + seq,
  ): Signed =>
    bob.sign({
      oip: "1",
      type: "Entry",
      author: bob.address,
      seq,
      ...(prev === undefined ? {} : { prev: contentId(prev) }),
      created: T(seconds),
      object: contentId(object),
      objectType: "Intent",
    }) as Signed;
  const first = entry(0, undefined, published[0]!);
  const second = entry(1, first, published[1]!);
  const pageOf = (entries: unknown[], mind: Mind = bob): JsonObject => ({
    oip: "1",
    type: "FeedPage",
    mind: mind.address,
    entries: entries as JsonObject[],
  });
  const object = (record: object, mind: Mind = bob): string =>
    endpoint(mind, `/obj/${contentId(record)}`);

  it("are served once the mind itself has brought them", async () => {
    const { ask } = service();
    const feed = endpoint(bob, "/feed");
    // A record: not signed for, signed for by another, and under another name.
    const path = object(published[0]!);
    expect((await problemOf(await ask(path, sending(published[0], "PUT")))).status).toBe(401);
    expect(
      (await problemOf(await ask(path, await signed(ada, "PUT", path, published[0])))).status,
    ).toBe(403);
    const misnamed = object(published[1]!);
    expect(
      await problemOf(await ask(misnamed, await signed(bob, "PUT", misnamed, published[0]))),
    ).toStrictEqual({
      status: 400,
      type: "urn:oip:error:invalid-record",
    });
    expect((await ask(wellKnown(bob, `/obj/${contentId(published[0]!)}`))).status).toBe(404);
    for (const [record, status] of [
      [published[0]!, 201],
      [published[1]!, 201],
      [published[0]!, 200],
    ] as const) {
      const kept = await ask(object(record), await signed(bob, "PUT", object(record), record));
      expect([kept.status, await kept.json()]).toStrictEqual([status, { stored: true }]);
    }
    const served = await ask(wellKnown(bob, `/obj/${contentId(published[0]!)}`));
    expect(served.status).toBe(200);
    expect(served.headers.get("content-type")).toBe(MEDIA_TYPE);
    expect(await served.json()).toStrictEqual(published[0]);
    expect((await ask(wellKnown(bob, "/obj/nothing"))).status).toBe(404);
    expect((await ask(wellKnown(ada, `/obj/${contentId(published[0]!)}`))).status).toBe(404);

    // The entries that list them: not signed for, signed for by another, then brought.
    expect((await problemOf(await ask(feed, sending(pageOf([first]))))).status).toBe(401);
    expect(
      (await problemOf(await ask(feed, await signed(ada, "POST", feed, pageOf([first]))))).status,
    ).toBe(403);
    const added = await ask(feed, await signed(bob, "POST", feed, pageOf([first, second])));
    expect([added.status, await added.json()]).toStrictEqual([200, { added: 2 }]);
    const again = await ask(feed, await signed(bob, "POST", feed, pageOf([first, second])));
    expect(await again.json()).toStrictEqual({ added: 0 });

    const page = async (query: string) => {
      const response = await ask(wellKnown(bob, `/feed${query}`));
      expect(response.status, query).toBe(200);
      expect(response.headers.get("content-type")).toBe(MEDIA_TYPE);
      // What is served is a record a client's reader takes.
      const parsed = parseRecord(await response.text());
      if (!parsed.ok) throw new Error(JSON.stringify(parsed.issues));
      const { type, mind, entries, next } = parsed.value as unknown as {
        type: string;
        mind: string;
        entries: unknown[];
        next?: number;
      };
      expect([type, mind]).toStrictEqual(["FeedPage", bob.address]);
      return { entries, next };
    };
    expect(await page("")).toStrictEqual({ entries: [first, second], next: undefined });
    expect(await page("?limit=1")).toStrictEqual({ entries: [first], next: 0 });
    expect(await page("?after=0")).toStrictEqual({ entries: [second], next: undefined });
    expect(await page("?after=1")).toStrictEqual({ entries: [], next: undefined });
    for (const query of ["?after=x", "?limit=0", "?after=-1"]) {
      expect((await ask(wellKnown(bob, `/feed${query}`))).status, query).toBe(400);
    }
    expect((await ask(wellKnown(ada, "/feed"))).status).toBe(404);
  });

  it("are refused when they are not the mind's to bring so, each with its problem", async () => {
    const { ask } = service();
    const feed = endpoint(bob, "/feed");
    const bring = async (record: unknown, path = feed) =>
      problemOf(await ask(path, await signed(bob, "POST", path, record)));
    const invalid = { status: 400, type: "urn:oip:error:invalid-record" };
    // No page of entries, a page of another mind's, and an entry whose record is not held.
    expect(await bring(first)).toStrictEqual(invalid);
    expect(await bring(pageOf([first], ada))).toStrictEqual(invalid);
    expect(await bring({ ...pageOf([first]), entries: "all" })).toStrictEqual(invalid);
    expect(await bring(pageOf([first]))).toStrictEqual(invalid);
    const kept = object(published[0]!);
    await ask(kept, await signed(bob, "PUT", kept, published[0]));
    expect((await ask(feed, await signed(bob, "POST", feed, pageOf([first])))).status).toBe(200);
    // Another entry where the host holds one (10.3).
    const conflicting = entry(0, undefined, published[0]!, 200);
    expect(await bring(pageOf([conflicting]))).toStrictEqual({
      status: 409,
      type: "urn:oip:error:duplicity",
    });
    // A mind the host does not serve has no feed here, and nothing to bring it to.
    const elsewhere = endpoint(ada, "/feed");
    expect(
      (await ask(elsewhere, await signed(ada, "POST", elsewhere, pageOf([], ada)))).status,
    ).toBe(404);
    const another = object(published[0]!, ada);
    expect((await ask(another, await signed(ada, "PUT", another, published[0]))).status).toBe(404);
    expect((await ask(feed, sending(pageOf([first]), "POST", "text/plain"))).status).toBe(415);
  });
});

describe("what a host asks of its clients", () => {
  it("limits what one address delivers, reads and signs for, each apart", async () => {
    const tight = (): RateLimiter => new RateLimiter({ burst: 2, perMinute: 6 }, clock);
    const { ask } = service({ limits: { read: tight(), deliver: tight(), owner: tight() } });
    const mailbox = endpoint(bob, "/mailbox");
    for (let n = 0; n < 2; n++) {
      expect((await ask(mailbox, sending(sealed(bob, `AAA${String(n)}`)))).status).toBe(202);
    }
    const limited = await ask(endpoint(bob, "/inbox"), sending(packet(ada, [bob])));
    expect(await problemOf(limited)).toStrictEqual({
      status: 429,
      type: "urn:oip:error:rate-limited",
    });
    expect(limited.headers.get("retry-after")).toBe("10");
    expect(count("mailbox")).toBe(2);
    // Another address is another client, and reading and signing have limits of their own.
    expect((await ask(mailbox, sending(sealed(bob, "AAA3")), "198.51.100.9")).status).toBe(202);
    for (let n = 0; n < 2; n++)
      expect((await ask(wellKnown(bob, n === 0 ? "" : "/log"))).status).toBe(200);
    expect((await ask(wellKnown(bob))).status).toBe(429);
    expect((await ask(mailbox, await signed(bob, "GET", mailbox))).status).toBe(200);
    expect((await ask(`${mailbox}/1`, await signed(bob, "DELETE", `${mailbox}/1`))).status).toBe(
      204,
    );
    expect(
      (await ask(endpoint(bob), await signed(bob, "PUT", endpoint(bob), bundleOf(bob)))).status,
    ).toBe(429);
  });

  it("answers a browser that asks before it sends a record or a signed request", async () => {
    const { ask } = service();
    for (const path of [endpoint(bob, "/inbox"), wellKnown(bob)]) {
      const response = await ask(path, { method: "OPTIONS" });
      expect(response.status).toBe(204);
      expect(response.headers.get("access-control-allow-origin")).toBe("*");
      expect(response.headers.get("access-control-allow-methods")).toBe("GET, POST, PUT, DELETE");
      expect(response.headers.get("access-control-allow-headers")).toContain("signature-input");
      expect(response.headers.get("access-control-max-age")).toBe("86400");
    }
  });
});

describe("a host's own endpoints", () => {
  it("says it is alive, and ready until it stops or a check fails", async () => {
    let database = true;
    const { ask } = service({ ready: { database: () => database } });
    expect((await ask("/healthz")).status).toBe(200);
    expect((await ask("/readyz")).status).toBe(200);
    database = false;
    expect((await ask("/readyz")).status).toBe(503);
    database = true;
    void shutdown.run("test");
    expect((await ask("/readyz")).status).toBe(503);
    expect((await ask("/healthz")).status).toBe(200);
  });

  it("counts what it answered by route and status, and names no mind", async () => {
    const { ask } = service();
    await ask(endpoint(bob, "/inbox"), sending(packet(ada, [bob])));
    await ask(endpoint(bob, "/mailbox"), sending(sealed(bob)));
    await ask(wellKnown(ada));
    const text = await (await ask("/metrics")).text();
    expect(text).toContain('oip_host_requests_total{route="inbox",status="202"} 1');
    expect(text).toContain('oip_host_requests_total{route="bundle",status="404"} 1');
    expect(text).toContain('oip_host_records_kept_total{at="inbox",answer="stored"} 1');
    expect(text).toContain('oip_host_records_kept_total{at="mailbox",answer="stored"} 1');
    expect(text).toContain("oip_host_request_seconds_bucket");
    expect(text).not.toContain(idOf(bob));
    expect(text).not.toContain(idOf(ada));
  });

  it("tells a client nothing of a failure nobody expected, and logs it", async () => {
    const { ask } = service();
    db.close();
    const response = await ask(wellKnown(bob));
    expect(response.status).toBe(500);
    expect(await response.json()).toStrictEqual({
      type: "about:blank",
      title: "Internal Server Error",
      status: 500,
    });
    expect(lines.at(-1)).toMatchObject({
      level: "error",
      event: "request failed",
      route: "bundle",
    });
    expect((await ask("/nowhere")).status).toBe(404);
  });

  it("answers the same for a failure where no request passes the gate", async () => {
    const { ask } = service();
    vi.spyOn(metrics, "render").mockImplementation(() => {
      throw new Error("the registry holds hunter2");
    });
    const response = await ask("/metrics");
    expect(response.status).toBe(500);
    expect(await response.text()).not.toContain("hunter2");
    expect(lines.at(-1)).toMatchObject({
      level: "error",
      event: "request failed",
      route: "(none)",
    });
    expect(JSON.stringify(lines)).not.toContain("hunter2");
  });
});
