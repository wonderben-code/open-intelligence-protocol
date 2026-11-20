// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The host as a running service, asked over sockets on this machine. */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  contentId,
  type Ed25519Engine,
  formatKeyRef,
  type JsonObject,
  MEDIA_TYPE,
  mindId,
  type OipRecord,
  useEd25519Engine,
  utf8,
} from "@oip/core";
import { signRequest } from "@oip/net";
import { ConfigError, nativeEd25519 } from "@oip/server";
import { clause } from "@oip/testkit";
import { at, KeyMind, type Mind, T } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { usePortableEd25519 } from "../../core/src/ed25519.ts";
import { WebSocket } from "ws";

import { type Running, start } from "../src/index.ts";

const ORIGIN = "https://host.example";
const RESOLVER = "https://resolver.example";

let directory: string;
let lines: Record<string, unknown>[];
let running: Running[];
let clock: { at: bigint; now: () => bigint };
let nonce = 0;
/** The minds the resolver knows, by the URL their bundle is at. */
let resolved: Map<string, Mind>;

const ada = new KeyMind("ada");
const bob = new KeyMind("bob");
const eve = new KeyMind("eve");

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "oip-host-main-"));
  lines = [];
  running = [];
  clock = { at: at(110), now: () => clock.at };
  resolved = new Map([[`${RESOLVER}/oip/v1/resolve/${mindId(ada.address) ?? ""}`, ada]]);
});
afterEach(async () => {
  for (const service of running) await service.stop("test over");
  rmSync(directory, { recursive: true, force: true });
});

const bundleOf = (mind: Mind): JsonObject =>
  ({ oip: "1", type: "Bundle", mind: mind.address, log: mind.events }) as unknown as JsonObject;

/** Starts a host on a port of its own, with what a test sets besides. */
async function started(more: Record<string, string> = {}) {
  const service = await start(
    {
      OIP_HOST_ORIGIN: ORIGIN,
      OIP_HOST_HOST: "127.0.0.1",
      OIP_HOST_PORT: "0",
      OIP_HOST_DATABASE: join(directory, "host.db"),
      OIP_HOST_MINDS: bob.address,
      OIP_HOST_RESOLVERS: RESOLVER,
      // Nothing of the machine's own environment is a setting of the host.
      PATH: "/usr/bin",
      ...more,
    },
    {
      clock,
      sink: (line) => lines.push(JSON.parse(line) as Record<string, unknown>),
      get: (url) => {
        const mind = resolved.get(url);
        return Promise.resolve(
          mind === undefined
            ? { status: 404, body: new Uint8Array(0) }
            : { status: 200, body: utf8(JSON.stringify(bundleOf(mind))) },
        );
      },
    },
  );
  running.push(service);
  return {
    service,
    http: `http://127.0.0.1:${service.port}`,
    ws: `ws://127.0.0.1:${service.port}`,
  };
}

const endpoint = (mind: Mind, rest = ""): string =>
  `/oip/v1/minds/${mindId(mind.address) ?? ""}${rest}`;

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
      created: clock.at,
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

/** Brings a mind's bundle to the host, as the mind itself. */
const bring = async (base: string, mind: Mind): Promise<Response> =>
  fetch(`${base}${endpoint(mind)}`, await signed(mind, "PUT", endpoint(mind), bundleOf(mind)));

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

const deliver = (base: string, to: Mind, record: unknown): Promise<Response> =>
  fetch(`${base}${endpoint(to, "/inbox")}`, {
    method: "POST",
    headers: { "content-type": MEDIA_TYPE },
    body: JSON.stringify(record),
  });

/** A WebSocket to a mind's socket, with what it was sent and how it ended. */
function socket(base: string, mind: Mind | string, protocols: string[] = ["oip.v1"]) {
  const path = typeof mind === "string" ? mind : endpoint(mind, "/ws");
  const ws = new WebSocket(`${base}${path}`, protocols);
  const messages: JsonObject[] = [];
  const waiting: (() => void)[] = [];
  const wake = (): void => {
    for (const waiter of waiting.splice(0)) waiter();
  };
  let closed: { code: number; reason: string } | undefined;
  let refused: number | undefined;
  ws.on("message", (data: Buffer) => {
    messages.push(JSON.parse(data.toString("utf8")) as JsonObject);
    wake();
  });
  ws.on("close", (code: number, reason: Buffer) => {
    closed = { code, reason: reason.toString("utf8") };
    wake();
  });
  ws.on("unexpected-response", (_request, response) => {
    refused = response.statusCode;
    response.resume();
    wake();
  });
  ws.on("error", wake);
  const until = async (done: () => boolean): Promise<void> => {
    const deadline = Date.now() + 5000;
    while (!done()) {
      if (Date.now() > deadline) throw new Error("the socket did not get there in time");
      await new Promise<void>((resolve) => {
        waiting.push(resolve);
        setTimeout(resolve, 50);
      });
    }
  };
  return {
    ws,
    messages,
    /** Waits for the `n`th message and gives it. */
    message: async (n: number): Promise<JsonObject> => {
      await until(() => messages.length > n || closed !== undefined);
      const message = messages[n];
      if (message === undefined)
        throw new Error(`closed before message ${n}: ${JSON.stringify(closed)}`);
      return message;
    },
    closed: async () => {
      await until(() => closed !== undefined);
      return closed;
    },
    refused: async () => {
      await until(() => refused !== undefined || closed !== undefined);
      return refused;
    },
  };
}

/** Opens a socket and authenticates a mind on it. */
async function welcomed(base: string, as: Mind, to: Mind) {
  const opened = socket(base, to);
  const challenge = await opened.message(0);
  expect(challenge).toMatchObject({ type: "Challenge", domain: ORIGIN });
  opened.ws.send(
    JSON.stringify(
      as.sign(
        { oip: "1", type: "Hello", author: as.address, created: T(110) },
        { more: { challenge: challenge["nonce"] as string, domain: ORIGIN } },
      ),
    ),
  );
  expect(await opened.message(1)).toStrictEqual({ type: "Welcome", mind: as.address });
  return opened;
}

describe(`${clause("L1 13.1", "L1 13.2", "L1 13.5")} a host that is running`, () => {
  it("takes on a mind it is to serve, takes its mail from a stranger, and gives it to the mind", async () => {
    const { http } = await started();
    expect((await fetch(`${http}/healthz`)).status).toBe(200);
    expect((await fetch(`${http}/readyz`)).status).toBe(200);
    // A mind the host is not to serve is not taken on, and one it is, is.
    expect((await bring(http, eve)).status).toBe(403);
    expect((await bring(http, bob)).status).toBe(201);
    const served = await fetch(`${http}/.well-known/oip/mind/${mindId(bob.address) ?? ""}`);
    expect(served.status).toBe(200);
    expect(((await served.json()) as { log: unknown[] }).log).toStrictEqual(bob.events);
    // Ada's log is not held here: the resolver is asked for it, and the packet is taken.
    const sent = packet(ada, [bob]);
    const delivered = await deliver(http, bob, sent);
    expect([delivered.status, await delivered.json()]).toStrictEqual([202, { stored: true }]);
    // Eve's log is nowhere to be had.
    expect((await deliver(http, bob, packet(eve, [bob]))).status).toBe(409);
    const mailbox = endpoint(bob, "/mailbox");
    const drained = await fetch(`${http}${mailbox}`, await signed(bob, "GET", mailbox));
    expect(await drained.json()).toStrictEqual({ items: [{ cursor: "1", record: sent }] });
    const removed = await fetch(`${http}${mailbox}/1`, await signed(bob, "DELETE", `${mailbox}/1`));
    expect(removed.status).toBe(204);
    // It said what it started with, and where it listens.
    expect(lines.map((line) => line["event"])).toStrictEqual(["starting", "listening"]);
    expect(lines[0]).toMatchObject({
      origin: `"${ORIGIN}"`,
      open: "false",
      maxSockets: "1024",
      retentionDays: "30",
      trustedProxies: "0",
    });
    const metrics = await (await fetch(`${http}/metrics`)).text();
    expect(metrics).toContain('oip_host_lookups_total{outcome="learned"} 1');
    expect(metrics).toContain('oip_host_requests_total{route="inbox",status="202"} 1');
  });

  it("takes on any mind that asks, up to a number, when it is open", async () => {
    const { http } = await started({
      OIP_HOST_MINDS: "",
      OIP_HOST_OPEN: "true",
      OIP_HOST_MAX_MINDS: "2",
    });
    expect((await bring(http, eve)).status).toBe(201);
    expect((await bring(http, bob)).status).toBe(201);
    expect((await bring(http, ada)).status).toBe(403);
    // One it serves brings what is new as before.
    expect((await bring(http, eve)).status).toBe(200);
  });

  it("holds what it took in after it has stopped and started again", async () => {
    const first = await started();
    await bring(first.http, bob);
    const sent = packet(ada, [bob]);
    await deliver(first.http, bob, sent);
    expect(await first.service.stop("SIGTERM")).toBe(true);
    await expect(fetch(`${first.http}/healthz`)).rejects.toThrow();
    const second = await started();
    const mailbox = endpoint(bob, "/mailbox");
    const drained = await fetch(`${second.http}${mailbox}`, await signed(bob, "GET", mailbox));
    expect(await drained.json()).toStrictEqual({ items: [{ cursor: "1", record: sent }] });
    // The same packet again is answered as before, and not kept twice.
    expect((await deliver(second.http, bob, sent)).status).toBe(202);
    expect(lines.map((line) => line["event"])).toStrictEqual([
      "starting",
      "listening",
      "stopping",
      "stopped",
      "starting",
      "listening",
    ]);
    expect(lines[3]).toMatchObject({ clean: true });
  });

  it("does not start with a configuration that is wrong, and says all of what is", async () => {
    const wrong = async (environment: Record<string, string>): Promise<readonly string[]> => {
      try {
        await start({ OIP_HOST_DATABASE: join(directory, "x.db"), ...environment });
      } catch (error) {
        if (error instanceof ConfigError) return error.problems;
        throw error;
      }
      throw new Error("it started");
    };
    expect(
      await wrong({ OIP_HOST_PORT: "http", OIP_HOST_RESOLVERS: "resolver.example" }),
    ).toStrictEqual([
      "OIP_HOST_ORIGIN is not set: the origin clients reach the host at, which a Hello and a signed request name",
      'OIP_HOST_PORT: "http" is not a whole number from 0 to 65535',
      'OIP_HOST_RESOLVERS: "resolver.example" is not a list separated by commas, each an HTTPS origin, such as https://host.example',
    ]);
    expect(
      await wrong({ OIP_HOST_ORIGIN: ORIGIN, OIP_HOST_MINDS: `${bob.address},bob` }),
    ).toStrictEqual(["OIP_HOST_MINDS: each is the address of a mind, which starts with did:oip:"]);
    expect(await wrong({ OIP_HOST_ORIGIN: ORIGIN, OIP_HOST_LOG_LEVEL: "loud" })).toStrictEqual([
      'OIP_HOST_LOG_LEVEL: "loud" is not one of debug, info, warn, error',
    ]);
    expect(await wrong({ OIP_HOST_ORIGIN: ORIGIN, OIP_HOST_RETENTION_DAYS: "7" })).toStrictEqual([
      'OIP_HOST_RETENTION_DAYS: "7" is not a whole number from 30 to 3650',
    ]);
  });
});

describe("a host with the machine's own edges", () => {
  it("runs on the machine's clock, and asks resolvers through the guarded fetcher", async () => {
    const service = await start({
      OIP_HOST_ORIGIN: ORIGIN,
      OIP_HOST_HOST: "127.0.0.1",
      OIP_HOST_PORT: "0",
      OIP_HOST_DATABASE: join(directory, "host.db"),
      OIP_HOST_OPEN: "true",
      // No public address: the fetcher refuses it before anything is sent.
      OIP_HOST_RESOLVERS: "https://10.0.0.1",
      OIP_HOST_LOG_LEVEL: "error",
    });
    running.push(service);
    const http = `http://127.0.0.1:${service.port}`;
    expect((await fetch(`${http}/readyz`)).status).toBe(200);
    // Signed at the present, as the machine has it: a signature is made at a whole second.
    clock.at = BigInt(Math.floor(Date.now() / 1000)) * 1_000_000_000n;
    expect((await bring(http, bob)).status).toBe(201);
    // Every signed request is judged at one reading of a clock that moves.
    const mailbox = endpoint(bob, "/mailbox");
    expect((await fetch(`${http}${mailbox}`, await signed(bob, "GET", mailbox))).status).toBe(200);
    // A mind the host has not met says Hello: the resolver is asked, and cannot be.
    const stranger = socket(`ws://127.0.0.1:${service.port}`, bob);
    const challenge = await stranger.message(0);
    stranger.ws.send(
      JSON.stringify(
        eve.sign(
          { oip: "1", type: "Hello", author: eve.address, created: T(110) },
          { more: { challenge: challenge["nonce"] as string, domain: ORIGIN } },
        ),
      ),
    );
    expect(await stranger.closed()).toMatchObject({ code: 4401 });
    const metrics = await (await fetch(`${http}/metrics`)).text();
    expect(metrics).toContain('oip_host_lookups_total{outcome="nothing"} 1');
  });

  it("serves nobody new and asks no resolver unless it is told to", async () => {
    const { http } = await started({ OIP_HOST_MINDS: "", OIP_HOST_RESOLVERS: "" });
    expect((await bring(http, bob)).status).toBe(403);
    expect(await (await fetch(`${http}/metrics`)).text()).not.toContain("oip_host_lookups_total");
  });
});

describe("what a host keeps only for a time", () => {
  it("is let go of every minute, and a failure to do so stops nothing", async () => {
    let tidy: (() => void) | undefined;
    let stopped = false;
    const service = await start(
      {
        OIP_HOST_ORIGIN: ORIGIN,
        OIP_HOST_HOST: "127.0.0.1",
        OIP_HOST_PORT: "0",
        OIP_HOST_DATABASE: join(directory, "host.db"),
        OIP_HOST_MINDS: bob.address,
        OIP_HOST_RESOLVERS: RESOLVER,
      },
      {
        clock,
        sink: (line) => lines.push(JSON.parse(line) as Record<string, unknown>),
        get: () => Promise.resolve({ status: 200, body: utf8(JSON.stringify(bundleOf(ada))) }),
        every: (work, ms) => {
          expect(ms).toBe(60_000);
          tidy = work;
          return () => {
            stopped = true;
          };
        },
      },
    );
    running.push(service);
    const http = `http://127.0.0.1:${service.port}`;
    await bring(http, bob);
    expect((await deliver(http, bob, packet(ada, [bob]))).status).toBe(202);
    const mailbox = endpoint(bob, "/mailbox");
    const held = async (): Promise<number> => {
      const drained = await fetch(`${http}${mailbox}`, await signed(bob, "GET", mailbox));
      return ((await drained.json()) as { items: unknown[] }).items.length;
    };
    // Thirty days less a second: it is still there.
    clock.at = at(110 + 30 * 86_400 - 1);
    tidy?.();
    expect(await held()).toBe(1);
    clock.at = at(110 + 30 * 86_400 + 1);
    tidy?.();
    expect(await held()).toBe(0);
    await service.stop("test");
    expect(stopped).toBe(true);
    // The database is closed: tidying fails, says so, and throws nothing.
    tidy?.();
    expect(lines.at(-1)).toMatchObject({ level: "error", event: "not tidied" });
  });
});

describe(`${clause("L1 13.4")} the socket of a host that is running`, () => {
  it("challenges, welcomes, takes a record, and gives the mind its mail until it says it has it", async () => {
    const { http, ws } = await started();
    await bring(http, bob);
    const first = packet(ada, [bob]);
    await deliver(http, bob, first);
    // The mind's own instance is sent what waits.
    const own = await welcomed(ws, bob, bob);
    expect(own.ws.protocol).toBe("oip.v1");
    expect(await own.message(2)).toStrictEqual(first);
    // A sender delivers over a socket of its own, and the mind's is sent it.
    const sender = await welcomed(ws, ada, bob);
    const second = packet(ada, [bob], { nonce: "nonce-0002" });
    sender.ws.send(JSON.stringify(second));
    expect(await own.message(3)).toStrictEqual(second);
    // The mind says it has the first, with a record: its own Ack.
    own.ws.send(
      JSON.stringify(
        bob.sign({
          oip: "1",
          type: "Ack",
          author: bob.address,
          packet: contentId(first),
          received: T(110),
          created: T(110),
        }),
      ),
    );
    const mailbox = endpoint(bob, "/mailbox");
    const left = async (): Promise<unknown[]> => {
      const drained = await fetch(`${http}${mailbox}`, await signed(bob, "GET", mailbox));
      return ((await drained.json()) as { items: { record: unknown }[] }).items.map(
        (item) => item.record,
      );
    };
    for (let tries = 0; tries < 100 && (await left()).length > 1; tries++) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    expect(await left()).toStrictEqual([second]);
    const metrics = await (await fetch(`${http}/metrics`)).text();
    expect(metrics).toContain("oip_host_sockets_open 2");
    expect(metrics).toContain('oip_host_socket_messages_total{outcome="acknowledged"} 1');
  });

  it("refuses a connection before the handshake where it can", async () => {
    const { http, ws } = await started({
      OIP_HOST_OWNER_BURST: "4",
      OIP_HOST_OWNER_PER_MINUTE: "1",
    });
    await bring(http, bob);
    // A mind it does not serve, what names no mind, and another path.
    expect(await socket(ws, ada).refused()).toBe(404);
    expect(await socket(ws, "/oip/v1/minds/nobody/ws").refused()).toBe(404);
    expect(await socket(ws, endpoint(bob, "/ws/more")).refused()).toBe(404);
    expect(await socket(ws, endpoint(bob, "/inbox")).refused()).toBe(404);
    // Without the subprotocol.
    expect(await socket(ws, bob, ["chat"]).refused()).toBe(400);
    expect(await socket(ws, bob, []).refused()).toBe(400);
    // Beyond what an address may open: the bundle and three sockets were four.
    const opened = [socket(ws, bob), socket(ws, bob), socket(ws, bob)];
    for (const one of opened) await one.message(0);
    expect(await socket(ws, bob).refused()).toBe(429);
    for (const one of opened) one.ws.close();
  });

  it("closes a connection that authenticates nobody, sends no text, or sends too much", async () => {
    const { http, ws } = await started({ OIP_HOST_MAX_RECORD_BYTES: "4096" });
    await bring(http, bob);
    const silent = socket(ws, bob);
    await silent.message(0);
    silent.ws.send("{}");
    expect(await silent.closed()).toMatchObject({ code: 4401 });
    const binary = await welcomed(ws, ada, bob);
    binary.ws.send(new Uint8Array([1, 2, 3]));
    expect(await binary.closed()).toMatchObject({ code: 1003 });
    const long = await welcomed(ws, ada, bob);
    long.ws.send(
      JSON.stringify(
        packet(ada, [bob], { content: { mediaType: "text/plain", body: "x".repeat(5000) } }),
      ),
    );
    expect(await long.closed()).toMatchObject({ code: 1009 });
    const refused = await welcomed(ws, ada, bob);
    refused.ws.send(JSON.stringify(packet(ada, [eve])));
    expect(await refused.closed()).toStrictEqual({ code: 1008, reason: "forbidden" });
  });

  it("closes its connections when it stops, and stops in time", async () => {
    const { service, http, ws } = await started();
    await bring(http, bob);
    const own = await welcomed(ws, bob, bob);
    const stopped = service.stop("SIGTERM");
    expect(await own.closed()).toStrictEqual({ code: 1001, reason: "the host is stopping" });
    expect(await stopped).toBe(true);
    expect(lines.at(-1)).toMatchObject({ event: "stopped", clean: true });
  });
});

describe("what does the arithmetic of a signature", () => {
  /** An engine of the test's own: OpenSSL, under another name. */
  const other: Ed25519Engine = (signature, message, publicKey) =>
    nativeEd25519(signature, message, publicKey);
  beforeEach(() => {
    usePortableEd25519();
  });
  afterEach(() => {
    usePortableEd25519();
  });

  it("is OpenSSL, unless the host is told otherwise", async () => {
    await started();
    expect(lines[0]).toMatchObject({ event: "starting", ed25519: '"native"' });
    expect(lines.map((line) => line["event"])).not.toContain("OpenSSL is not in use");
    // OpenSSL has the place: another engine is refused.
    expect(() => {
      useEd25519Engine(other);
    }).toThrow(new TypeError("another Ed25519 engine is in use"));
  });

  it("is the library where the host is told so", async () => {
    await started({ OIP_HOST_ED25519: "portable" });
    expect(lines[0]).toMatchObject({ event: "starting", ed25519: '"portable"' });
    // No engine was taken: one can be.
    expect(() => {
      useEd25519Engine(other);
    }).not.toThrow();
  });

  it("says so, and runs, where OpenSSL cannot have the place", async () => {
    useEd25519Engine(other);
    const { http } = await started();
    const said = lines.find((line) => line["event"] === "OpenSSL is not in use");
    expect(said).toMatchObject({ level: "warn" });
    expect((await fetch(`${http}/healthz`)).status).toBe(200);
  });
});
