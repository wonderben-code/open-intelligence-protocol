// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The indexer as a running service, asked over a socket on this machine. */

import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  bytesToBase64url,
  type Ed25519Engine,
  type JsonObject,
  MEDIA_TYPE,
  mindId,
  useEd25519Engine,
  utf8,
} from "@oip/core";
import { judgeRecord } from "@oip/identity";
import { ConfigError, nativeEd25519 } from "@oip/server";
import { clause } from "@oip/testkit";
import { at, KeyMind, locationBy, type Mind, T } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { usePortableEd25519 } from "../../core/src/ed25519.ts";
import { readKey, type Running, start } from "../src/index.ts";

let directory: string;
let lines: Record<string, unknown>[];
let running: Running[];
let clock: { at: bigint; now: () => bigint };
let posted: { url: string; record: JsonObject }[];

const ian = new KeyMind("ian");
const ada = new KeyMind("ada");
const bob = new KeyMind("bob");
const zed = new KeyMind("zed");

/** The private key a test mind signs with, as the test kit makes it from a name: a fixture, and no secret. */
const keyOf = (mind: Mind, n = 0): string =>
  bytesToBase64url(createHash("sha256").update(`${mind.name}/operational/${n}`).digest());

const bundleOf = (mind: Mind, more: JsonObject = {}): JsonObject =>
  ({
    oip: "1",
    type: "Bundle",
    mind: mind.address,
    log: mind.events,
    ...more,
  }) as unknown as JsonObject;

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "oip-indexer-main-"));
  lines = [];
  running = [];
  posted = [];
  clock = { at: at(110), now: () => clock.at };
});
afterEach(async () => {
  for (const service of running) await service.stop("test over");
  rmSync(directory, { recursive: true, force: true });
});

/** Writes a file that only its owner can read, and gives its path. */
function secret(name: string, content: string, mode = 0o600): string {
  const path = join(directory, name);
  writeFileSync(path, content, { mode });
  chmodSync(path, mode);
  return path;
}

const settings = (more: Record<string, string> = {}): Record<string, string> => ({
  OIP_INDEXER_ORIGIN: "https://indexer.example",
  OIP_INDEXER_HOST: "127.0.0.1",
  OIP_INDEXER_PORT: "0",
  OIP_INDEXER_DATABASE: join(directory, "indexer.db"),
  OIP_INDEXER_BUNDLE_FILE: secret("bundle.json", JSON.stringify(bundleOf(ian)), 0o644),
  OIP_INDEXER_KEY_FILE: secret("key", `${keyOf(ian)}\n`),
  OIP_INDEXER_RESOLVERS: "https://resolver.example",
  // Nothing of the machine's own environment is a setting of the indexer.
  PATH: "/usr/bin",
  ...more,
});

/** Starts an indexer on a port of its own, with what a test sets besides. */
async function started(more: Record<string, string> = {}, tidy?: (work: () => void) => void) {
  const service = await start(settings(more), {
    clock,
    sink: (line) => lines.push(JSON.parse(line) as Record<string, unknown>),
    get: (url) =>
      Promise.resolve(
        url === `https://resolver.example/oip/v1/resolve/${mindId(zed.address) ?? ""}`
          ? { status: 200, body: utf8(JSON.stringify(bundleOf(zed))) }
          : { status: 404, body: new Uint8Array(0) },
      ),
    post: (url, body) => {
      posted.push({ url, record: JSON.parse(new TextDecoder().decode(body)) as JsonObject });
      return Promise.resolve({ status: 202 });
    },
    ...(tidy === undefined
      ? {}
      : {
          every: (work) => {
            tidy(work);
            return () => undefined;
          },
        }),
  });
  running.push(service);
  return { service, http: `http://127.0.0.1:${service.port}` };
}

const post = (url: string, body: unknown, type = "application/json"): Promise<Response> =>
  fetch(url, { method: "POST", headers: { "content-type": type }, body: JSON.stringify(body) });

const translator = (mind: Mind, more: JsonObject = {}) =>
  mind.sign({
    oip: "1",
    type: "Participant",
    author: mind.address,
    created: T(100),
    name: mind.name,
    kind: "agent",
    capabilities: [{ id: "translate", summary: "Translates leases", tags: ["domain:legal"] }],
    ...more,
  });

async function wrong(more: Record<string, string>): Promise<readonly string[]> {
  try {
    await start(settings(more), { sink: () => undefined });
  } catch (error) {
    if (error instanceof ConfigError) return error.problems;
    throw error;
  }
  throw new Error("it started");
}

describe(`${clause("L1 18.1", "L1 18.2", "L1 18.5")} an indexer that is running`, () => {
  it("lists what is submitted, answers a query with its own signature, and forwards a packet", async () => {
    const { service, http } = await started();
    expect(service.address).toBe(ian.address);
    expect((await fetch(`${http}/healthz`)).status).toBe(200);
    expect((await fetch(`${http}/readyz`)).status).toBe(200);
    const located = bundleOf(bob, {
      location: bob.sign({
        ...locationBy(bob, 100),
        endpoints: [{ binding: "https", url: "https://bob.example/oip", priority: 1 }],
      }),
    } as never);
    const submitted = await post(`${http}/oip/v1/submit`, { records: [located, translator(bob)] });
    expect([submitted.status, await submitted.json()]).toStrictEqual([
      202,
      { taken: 2, refused: [] },
    ]);

    const answered = await post(`${http}/oip/v1/query`, { want: "leases" });
    expect(answered.status).toBe(200);
    const result = (await answered.json()) as JsonObject;
    expect(result).toMatchObject({ type: "QueryResult", author: ian.address });
    expect(result["results"]).toMatchObject([{ mind: bob.address, capability: "translate" }]);
    // Its signature verifies, and the log it is judged by is served by the indexer itself.
    expect(judgeRecord(result).ok && judgeRecord(result)).toMatchObject({
      value: { proofs: [{}] },
    });
    const own = await fetch(`${http}/.well-known/oip/mind/${mindId(ian.address) ?? ""}`);
    expect(((await own.json()) as { log: unknown[] }).log).toStrictEqual(ian.events);

    // A packet from a mind the indexer has not met: its log is asked of the resolver.
    const packet = zed.sign({
      oip: "1",
      type: "Packet",
      from: zed.address,
      to: { query: { want: "leases" } },
      created: T(100),
      expires: T(3700),
      nonce: "nonce-0001",
      purpose: { verb: "request" },
      content: { mediaType: "text/plain", body: "Who translates a lease?" },
    });
    const taken = await post(`${http}/oip/v1/inbox`, packet, MEDIA_TYPE);
    expect([taken.status, await taken.json()]).toStrictEqual([
      202,
      { stored: true, forwarding: 1 },
    ]);
    // It stops when what it took to forward has been sent.
    expect(await service.stop("SIGTERM")).toBe(true);
    expect(posted.map((sent) => sent.url)).toStrictEqual(["https://bob.example/oip/inbox"]);
    expect(posted[0]?.record).toMatchObject({
      type: "Forwarded",
      broker: ian.address,
      to: bob.address,
      packet,
    });
    expect(lines.map((line) => line["event"])).toStrictEqual([
      "starting",
      "listening",
      "stopping",
      "stopped",
    ]);
    expect(lines[0]).toMatchObject({
      origin: '"https://indexer.example"',
      fanout: "10",
      maxRecords: "100",
    });
    expect(lines.at(-1)).toMatchObject({ clean: true });
  });

  it("holds what it listed after it has stopped and started again", async () => {
    const first = await started();
    await post(`${first.http}/oip/v1/submit`, { records: [bundleOf(bob), translator(bob)] });
    expect(await first.service.stop("SIGTERM")).toBe(true);
    const second = await started();
    const answered = await post(`${second.http}/oip/v1/query`, { want: "leases" });
    expect(((await answered.json()) as { results: unknown[] }).results).toHaveLength(1);
  });

  it("takes out what has expired every minute, and a failure to do so stops nothing", async () => {
    let tidy: (() => void) | undefined;
    const { service, http } = await started({}, (work) => {
      tidy = work;
    });
    await post(`${http}/oip/v1/submit`, {
      records: [bundleOf(bob), translator(bob, { expires: T(500) })],
    });
    const found = async (): Promise<number> =>
      (
        (await (await post(`${http}/oip/v1/query`, { want: "leases" })).json()) as {
          results: unknown[];
        }
      ).results.length;
    expect(await found()).toBe(1);
    clock.at = at(501);
    tidy?.();
    expect(await found()).toBe(0);
    await service.stop("test");
    tidy?.();
    expect(lines.at(-1)).toMatchObject({ level: "error", event: "not tidied" });
  });
});

describe("an indexer with the machine's own edges", () => {
  it("runs on the machine's clock, and reaches resolvers and inboxes through the guarded fetcher", async () => {
    const service = await start(
      settings({
        OIP_INDEXER_LOG_LEVEL: "error",
        // No public address: the fetcher refuses it before anything is sent.
        OIP_INDEXER_RESOLVERS: "https://10.0.0.1",
      }),
    );
    running.push(service);
    const http = `http://127.0.0.1:${service.port}`;
    const hidden = bundleOf(bob, {
      location: bob.sign({
        ...locationBy(bob, 100),
        endpoints: [{ binding: "https", url: "https://10.0.0.2/oip", priority: 1 }],
      }),
    } as never);
    const submitted = await post(`${http}/oip/v1/submit`, {
      records: [bundleOf(ada), hidden, translator(bob)],
    });
    expect(((await submitted.json()) as { taken: number }).taken).toBe(3);
    // Packets made now, as the machine has it.
    const now = Math.floor(Date.now() / 1000);
    const stamp = (seconds: number): string =>
      new Date(seconds * 1000).toISOString().replace(".000Z", "Z");
    const asking = (from: Mind) =>
      from.sign({
        oip: "1",
        type: "Packet",
        from: from.address,
        to: { query: { want: "leases" } },
        created: stamp(now),
        expires: stamp(now + 600),
        nonce: "nonce-0001",
        purpose: { verb: "request" },
        content: { mediaType: "text/plain", body: "Who translates a lease?" },
      });
    // A sender it has not met: the resolver cannot be asked, and the packet is refused as it was.
    expect((await post(`${http}/oip/v1/inbox`, asking(zed), MEDIA_TYPE)).status).toBe(409);
    // A sender it knows: the packet is taken, and the inbox it would go to is not reached.
    const taken = await post(`${http}/oip/v1/inbox`, asking(ada), MEDIA_TYPE);
    expect(await taken.json()).toStrictEqual({ stored: true, forwarding: 1 });
    expect(await service.stop("SIGTERM")).toBe(true);
    expect(posted).toStrictEqual([]);
  });
});

describe("the mind and the key an indexer is started with", () => {
  it("are the Bundle of a mind and an operational key of that mind, or it does not start", async () => {
    expect(await wrong({ OIP_INDEXER_KEY_FILE: join(directory, "none") })).toStrictEqual([
      "OIP_INDEXER_KEY_FILE cannot be read",
    ]);
    expect(await wrong({ OIP_INDEXER_KEY_FILE: secret("short", "AAAA") })).toStrictEqual([
      "OIP_INDEXER_KEY_FILE does not hold the 32 bytes of an Ed25519 private key as base64url",
    ]);
    expect(await wrong({ OIP_INDEXER_KEY_FILE: secret("text", "not a key at all!") })).toHaveLength(
      1,
    );
    // The key of another mind: nothing it signed would count for this one.
    expect(await wrong({ OIP_INDEXER_KEY_FILE: secret("other", keyOf(ada)) })).toStrictEqual([
      "OIP_INDEXER_KEY_FILE: the indexer's key is no operational key of its own mind now",
    ]);
    expect(await wrong({ OIP_INDEXER_BUNDLE_FILE: join(directory, "none") })).toStrictEqual([
      "OIP_INDEXER_BUNDLE_FILE cannot be read",
    ]);
    expect(await wrong({ OIP_INDEXER_BUNDLE_FILE: secret("no.json", "{") })).toHaveLength(1);
    expect(
      await wrong({
        OIP_INDEXER_BUNDLE_FILE: secret("other.json", JSON.stringify(translator(ian))),
      }),
    ).toStrictEqual(["OIP_INDEXER_BUNDLE_FILE: it holds no Bundle"]);
    const broken = { ...bundleOf(ian), log: [{ ...ian.events[0], created: T(9) }] };
    expect(
      (await wrong({ OIP_INDEXER_BUNDLE_FILE: secret("broken.json", JSON.stringify(broken)) }))[0],
    ).toMatch(/^OIP_INDEXER_BUNDLE_FILE: event 0 of the log: /u);
    // A setting that is set to nothing is wrong, and both are said at once.
    expect(await wrong({ OIP_INDEXER_KEY_FILE: "", OIP_INDEXER_BUNDLE_FILE: "" })).toStrictEqual([
      'OIP_INDEXER_BUNDLE_FILE: "" is not text that is not empty',
      'OIP_INDEXER_KEY_FILE: "" is not text that is not empty',
    ]);
  });

  it("keeps the key to itself: a file others can read is refused, and the key is said nowhere", async () => {
    for (const mode of [0o644, 0o640, 0o604]) {
      expect(
        await wrong({ OIP_INDEXER_KEY_FILE: secret(`open-${mode}`, keyOf(ian), mode) }),
      ).toStrictEqual([
        "OIP_INDEXER_KEY_FILE can be read by others than its owner: give it mode 600",
      ]);
    }
    expect(readKey(secret("mine", keyOf(ian), 0o400)).publicKey).toBe(ian.operational().publicKey);
    const { http } = await started();
    await post(`${http}/oip/v1/query`, {});
    const said = JSON.stringify(lines) + (await (await fetch(`${http}/metrics`)).text());
    expect(said).not.toContain(keyOf(ian));
    // What is wrong with a key is said without the key.
    let message = "";
    try {
      readKey(secret("bad", `${keyOf(ian)}x`));
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toContain("does not hold the 32 bytes");
    expect(message).not.toContain(keyOf(ian));
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

  it("is OpenSSL, unless the indexer is told otherwise", async () => {
    await started();
    expect(lines[0]).toMatchObject({ event: "starting", ed25519: '"native"' });
    expect(lines.map((line) => line["event"])).not.toContain("OpenSSL is not in use");
    // OpenSSL has the place: another engine is refused.
    expect(() => {
      useEd25519Engine(other);
    }).toThrow(new TypeError("another Ed25519 engine is in use"));
  });

  it("is the library where the indexer is told so", async () => {
    await started({ OIP_INDEXER_ED25519: "portable" });
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
