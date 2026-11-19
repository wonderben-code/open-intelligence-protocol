// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The binding on a real server, where `main.test.ts` does not reach. */

import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { mindId } from "@oip/core";
import type { Bundle } from "@oip/schema";
import { Database, Log, LogArchive, Metrics, RateLimiter } from "@oip/server";
import { clause } from "@oip/testkit";
import { at, KeyMind } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { WebSocket } from "ws";

import {
  attachSockets,
  Host,
  HOST_MIGRATIONS,
  Sockets,
  type UpgradeOptions,
} from "../src/index.ts";
import { wireFor } from "../src/upgrade.ts";

const bob = new KeyMind("bob");
const path = `/oip/v1/minds/${mindId(bob.address) ?? ""}/ws`;

let directory: string;
let db: Database;
let server: Server;
let stop: ((graceMs: number) => Promise<void>) | undefined;
let lines: Record<string, unknown>[];
let sockets: Sockets;

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "oip-host-upgrade-"));
  lines = [];
});
afterEach(async () => {
  await stop?.(100);
  stop = undefined;
  await new Promise((resolve) => server.close(resolve));
  try {
    db.close();
  } catch {
    // A test closed it.
  }
  rmSync(directory, { recursive: true, force: true });
});

/** A server whose upgrades go to the binding of a host that serves Bob. */
async function listening(more: Partial<UpgradeOptions> = {}, maxSockets = 8): Promise<string> {
  const clock = { now: () => at(110) };
  db = Database.open({ path: join(directory, "host.db"), durable: false }, HOST_MIGRATIONS, clock);
  const archive = new LogArchive({ db, clock });
  archive.publish(mindId(bob.address) ?? "", {
    oip: "1",
    type: "Bundle",
    mind: bob.address,
    log: bob.events,
  } as unknown as Bundle);
  const host = new Host({ db, archive });
  host.adopt(bob.address);
  const log = new Log({
    service: "host",
    clock,
    sink: (line) => lines.push(JSON.parse(line) as Record<string, unknown>),
  });
  const limiter = new RateLimiter({ burst: 100, perMinute: 6000 }, clock);
  sockets = new Sockets({
    host,
    archive,
    clock,
    randomness: { bytes: (length) => crypto.getRandomValues(new Uint8Array(length)) },
    log,
    metrics: new Metrics(),
    origin: "https://host.example",
    deliver: limiter,
    maxSockets,
  });
  server = createServer((_request, response) => response.writeHead(404).end());
  stop = attachSockets(server, {
    host,
    sockets,
    log,
    limiter,
    address: (request) => request.socket.remoteAddress,
    stopping: () => false,
    maxRecordBytes: 65_536,
    ...more,
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return `ws://127.0.0.1:${(server.address() as AddressInfo).port}${path}`;
}

/** How an attempt to connect ended: the status that refused it, or the code that closed it. */
function outcome(ws: WebSocket): Promise<{ refused?: number; closed?: number; retry?: string }> {
  return new Promise((resolve) => {
    ws.on("unexpected-response", (_request, response) => {
      response.resume();
      const retry = response.headers["retry-after"];
      resolve({ refused: response.statusCode ?? 0, ...(retry === undefined ? {} : { retry }) });
    });
    ws.on("close", (code) => {
      resolve({ closed: code });
    });
    ws.on("error", () => undefined);
  });
}

const opened = (ws: WebSocket): Promise<void> =>
  new Promise((resolve, reject) => {
    ws.once("message", () => {
      resolve();
    });
    ws.once("error", reject);
  });

describe(`${clause("L1 13.4")} a connection the host has no room or no way to take`, () => {
  it("is refused with 503 when as many are open as it serves, or when it is stopping", async () => {
    let stopping = false;
    const url = await listening({ stopping: () => stopping }, 1);
    const first = new WebSocket(url, "oip.v1");
    await opened(first);
    expect(await outcome(new WebSocket(url, "oip.v1"))).toStrictEqual({
      refused: 503,
      retry: "30",
    });
    first.close();
    await outcome(first);
    stopping = true;
    expect(await outcome(new WebSocket(url, "oip.v1"))).toStrictEqual({
      refused: 503,
      retry: "30",
    });
    stopping = false;
    const again = new WebSocket(url, "oip.v1");
    await opened(again);
    again.close();
  });

  it("is refused with 500, and nothing said of why, when the host fails", async () => {
    const url = await listening();
    db.close();
    expect(await outcome(new WebSocket(url, "oip.v1"))).toStrictEqual({ refused: 500 });
    expect(lines.at(-1)).toMatchObject({ level: "error", event: "upgrade failed" });
  });
});

describe("a connection that is open", () => {
  it("is asked whether it is there, and cut if it does not answer", async () => {
    const url = await listening({ pingMs: 40 });
    const alive = new WebSocket(url, "oip.v1");
    const silent = new WebSocket(url, "oip.v1");
    await Promise.all([opened(alive), opened(silent)]);
    let pings = 0;
    alive.on("ping", () => pings++);
    // One that reads nothing answers nothing.
    (silent as unknown as { _socket: { pause(): void; resume(): void } })._socket.pause();
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(pings).toBeGreaterThanOrEqual(2);
    expect(alive.readyState).toBe(WebSocket.OPEN);
    expect(sockets.open).toBe(1);
    const ended = outcome(silent);
    (silent as unknown as { _socket: { resume(): void } })._socket.resume();
    expect((await ended).closed).toBe(1006);
    alive.close();
  });

  it("is closed, and cut if it does not go, when the host stops", async () => {
    const url = await listening();
    const polite = new WebSocket(url, "oip.v1");
    const stuck = new WebSocket(url, "oip.v1");
    await Promise.all([opened(polite), opened(stuck)]);
    (stuck as unknown as { _socket: { pause(): void } })._socket.pause();
    const [gone] = [outcome(polite)];
    const started = Date.now();
    await stop?.(150);
    stop = undefined;
    expect((await gone).closed).toBe(1001);
    // The one that did not answer the close was waited for, and no longer.
    expect(Date.now() - started).toBeGreaterThanOrEqual(140);
    expect(Date.now() - started).toBeLessThan(2000);
    expect(sockets.open).toBe(0);
  });
});

describe("a connection as the binding uses one", () => {
  it("says once that it has room again, when half of what waited has gone", () => {
    const sent: (() => void)[] = [];
    const ws = {
      bufferedAmount: 0,
      closed: undefined as [number, string] | undefined,
      send(_text: string, done: () => void) {
        sent.push(done);
      },
      close(code: number, reason: string) {
        this.closed = [code, reason];
      },
    };
    let drained = 0;
    const wire = wireFor(ws, 100, () => drained++);
    // Not full: nothing is said when what was sent has gone.
    ws.bufferedAmount = 99;
    wire.send("a");
    expect(wire.buffered).toBe(99);
    ws.bufferedAmount = 0;
    sent.shift()?.();
    expect(drained).toBe(0);
    // Full: nothing is said until less than half waits.
    ws.bufferedAmount = 100;
    wire.send("b");
    wire.send("c");
    ws.bufferedAmount = 50;
    sent.shift()?.();
    expect(drained).toBe(0);
    ws.bufferedAmount = 49;
    sent.shift()?.();
    expect(drained).toBe(1);
    // And once: it is not full any more.
    wire.send("d");
    sent.shift()?.();
    expect(drained).toBe(1);
    wire.close(1001, "going");
    expect(ws.closed).toStrictEqual([1001, "going"]);
  });
});
