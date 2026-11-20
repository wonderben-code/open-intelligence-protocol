// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Faults planted under a running host: the process killed after it has
 * answered a delivery, a mind's connection severed while its mail is being
 * sent, and the database locked by another process. Each time the question
 * is what became of a packet the host said it had: is it there, once, with
 * the time its proofs were first seen?
 */

import { type ChildProcess, spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import {
  contentId,
  formatKeyRef,
  formatTimestamp,
  type JsonObject,
  MEDIA_TYPE,
  mindId,
  proofDigest,
  utf8,
} from "@oip/core";
import { signRequest } from "@oip/net";
import { clause, repoRoot } from "@oip/testkit";
import { KeyMind, type Mind } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { WebSocket } from "ws";

const ORIGIN = "https://host.example";
const bin = join(repoRoot, "packages", "host", "src", "bin.ts");

let directory: string;
let children: ChildProcess[];
let nonce = 0;

const ada = new KeyMind("ada");
const bob = new KeyMind("bob");

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "oip-host-faults-"));
  children = [];
});
afterEach(async () => {
  await Promise.all(children.map((child) => ended(child, "SIGKILL")));
  rmSync(directory, { recursive: true, force: true });
});

/** Ends a process, if it has not ended, and waits until it has. */
function ended(child: ChildProcess, signal: NodeJS.Signals): Promise<void> {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolve();
      return;
    }
    child.once("close", () => {
      resolve();
    });
    child.kill(signal);
  });
}

/** Starts a host as a process of its own on the test's database, and gives where it listens. */
function started(): Promise<{ child: ChildProcess; http: string; ws: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--conditions=@oip/source", bin], {
      env: {
        PATH: process.env["PATH"] ?? "",
        OIP_HOST_ORIGIN: ORIGIN,
        OIP_HOST_HOST: "127.0.0.1",
        OIP_HOST_PORT: "0",
        OIP_HOST_DATABASE: join(directory, "host.db"),
        OIP_HOST_OPEN: "true",
        OIP_HOST_DELIVER_BURST: "100000",
        OIP_HOST_OWNER_BURST: "100000",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    children.push(child);
    let out = "";
    child.stdout?.on("data", (chunk: Buffer) => {
      out += chunk.toString("utf8");
      const port = /"event":"listening".*?"port":(\d+)/u.exec(out)?.[1];
      if (port !== undefined) {
        resolve({ child, http: `http://127.0.0.1:${port}`, ws: `ws://127.0.0.1:${port}` });
      }
    });
    child.once("error", reject);
    child.once("close", () => {
      reject(new Error(`the host ended before it listened: ${out}`));
    });
  });
}

/** The present, to the second: what a record made now is dated. */
const now = (seconds = 0): string =>
  formatTimestamp(BigInt(Math.floor(Date.now() / 1000) + seconds) * 1_000_000_000n);

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
  const headers: [string, string][] = body === undefined ? [] : [["content-type", MEDIA_TYPE]];
  const added = await signRequest(
    { method, url: `${ORIGIN}${path}`, headers, ...(body === undefined ? {} : { body }) },
    {
      keyRef: formatKeyRef(by.address, by.versionId(), by.operational().publicKey),
      created: BigInt(Math.floor(Date.now() / 1000)) * 1_000_000_000n,
      nonce: `fault-nonce-${++nonce}`,
    },
    by.operational(),
  );
  return {
    method,
    ...(body === undefined ? {} : { body }),
    headers: [...headers, ...added] as [string, string][],
  };
}

/** Has the host take both minds on: Bob to serve, Ada so that her packets can be judged. */
async function adopted(http: string): Promise<void> {
  for (const mind of [ada, bob]) {
    const bundle = { oip: "1", type: "Bundle", mind: mind.address, log: mind.events };
    const response = await fetch(
      `${http}${endpoint(mind)}`,
      await signed(mind, "PUT", endpoint(mind), bundle),
    );
    expect(response.status).toBeLessThan(300);
  }
}

/** A packet from Ada to Bob, made now and good for an hour. */
const packet = (n: number) =>
  ada.sign({
    oip: "1",
    type: "Packet",
    from: ada.address,
    to: [bob.address],
    created: now(),
    expires: now(3600),
    nonce: `fault-${String(n).padStart(4, "0")}`,
    purpose: { verb: "inform" },
    content: { mediaType: "text/plain", body: `Packet ${n}.` },
  });

const deliver = (http: string, record: unknown, at = "/inbox"): Promise<Response> =>
  fetch(`${http}${endpoint(bob, at)}`, {
    method: "POST",
    headers: { "content-type": MEDIA_TYPE },
    body: JSON.stringify(record),
  });

/** What is in Bob's mailbox, drained by Bob. */
async function mail(http: string): Promise<{ cursor: string; record: JsonObject }[]> {
  const path = `${endpoint(bob, "/mailbox")}?limit=1000`;
  const response = await fetch(`${http}${path}`, await signed(bob, "GET", path));
  expect(response.status).toBe(200);
  return ((await response.json()) as { items: { cursor: string; record: JsonObject }[] }).items;
}

/** The time the host recorded for the first sight of a proof, read from its database. */
function firstSeen(digest: string): bigint | undefined {
  const db = new DatabaseSync(join(directory, "host.db"), { readOnly: true });
  try {
    const statement = db.prepare("SELECT * FROM seen_proofs WHERE digest = ?");
    // A time is in nanoseconds: more than a number holds.
    statement.setReadBigInts(true);
    const row = statement.get(digest) as Record<string, unknown> | undefined;
    const time = Object.values(row ?? {}).find((value) => typeof value === "bigint");
    return typeof time === "bigint" ? time : undefined;
  } finally {
    db.close();
  }
}

/** Bob's own instance on a socket: authenticated, with what the host sends it. */
async function instance(ws: string) {
  const socket = new WebSocket(`${ws}${endpoint(bob, "/ws")}`, ["oip.v1"]);
  const messages: JsonObject[] = [];
  const waiting: (() => void)[] = [];
  socket.on("message", (data: Buffer) => {
    messages.push(JSON.parse(data.toString("utf8")) as JsonObject);
    for (const waiter of waiting.splice(0)) waiter();
  });
  socket.on("error", () => undefined);
  /** Waits until the socket has been sent `count` messages. */
  const received = async (count: number): Promise<void> => {
    const deadline = Date.now() + 5000;
    while (messages.length < count) {
      if (Date.now() > deadline) throw new Error(`${messages.length} of ${count} messages came`);
      await new Promise<void>((resolve) => {
        waiting.push(resolve);
        setTimeout(resolve, 50);
      });
    }
  };
  await received(1);
  const challenge = messages[0] as { nonce: string };
  socket.send(
    JSON.stringify(
      bob.sign(
        { oip: "1", type: "Hello", author: bob.address, created: now() },
        { more: { challenge: challenge.nonce, domain: ORIGIN } },
      ),
    ),
  );
  await received(2);
  expect(messages[1]).toEqual({ type: "Welcome", mind: bob.address });
  return {
    socket,
    /** The records the host has sent, after the challenge and the welcome. */
    records: (): JsonObject[] => messages.slice(2),
    received: (count: number) => received(count + 2),
    /** Says that the mind has a packet, with its own `Ack`. */
    acknowledge: (record: JsonObject): void => {
      const at = now();
      socket.send(
        JSON.stringify(
          bob.sign({
            oip: "1",
            type: "Ack",
            author: bob.address,
            packet: contentId(record),
            received: at,
            created: at,
          }),
        ),
      );
    },
  };
}

describe(`${clause("L1 13.2", "L1 12.4")} a host whose process is killed`, () => {
  it("keeps a packet it answered for, the answer it gave, and when it first saw the proof", async () => {
    const first = await started();
    let { http } = first;
    await adopted(http);
    const sent = [1, 2, 3].map(packet);
    const answers: unknown[] = [];
    for (const record of sent) {
      const response = await deliver(http, record);
      expect(response.status).toBe(202);
      answers.push(await response.json());
    }
    const digests = sent.map((record) => proofDigest(record.proof[0]));
    const seen = digests.map(firstSeen);
    expect(seen.every((row) => row !== undefined)).toBe(true);
    // More arrives, and the process is killed before it has answered for all of it.
    const more = [4, 5, 6, 7, 8, 9].map(packet);
    const pending = more.map((record) =>
      deliver(http, record).then(
        (response) => response.status,
        () => undefined,
      ),
    );
    await pending[0];
    await ended(first.child, "SIGKILL");
    const statuses = await Promise.all(pending);

    ({ http } = await started());
    const held = await mail(http);
    const ids = held.map((item) => contentId(item.record));
    // What was answered 202 is in the mailbox, once. What was not answered is there once or not at all.
    for (const record of sent) expect(ids.filter((id) => id === contentId(record))).toHaveLength(1);
    for (const [at, record] of more.entries()) {
      const copies = ids.filter((id) => id === contentId(record)).length;
      expect(copies, `packet ${at + 4}`).toBe(statuses[at] === 202 ? 1 : Math.min(copies, 1));
    }
    // The proofs were first seen when they were first seen: the restart moved nothing.
    expect(digests.map(firstSeen)).toEqual(seen);
    // The same packets again are duplicates, answered as they were, and kept once.
    for (const [at, record] of sent.entries()) {
      const response = await deliver(http, record);
      expect(response.status).toBe(202);
      expect(await response.json()).toEqual(answers[at]);
    }
    expect((await mail(http)).map((item) => contentId(item.record))).toEqual(ids);
    expect(digests.map(firstSeen)).toEqual(seen);
  }, 60_000);
});

describe(`${clause("L1 13.4", "L1 13.5")} a mind whose connection to its host is severed`, () => {
  it("is sent again what it had not acknowledged, and not what it had", async () => {
    const { http, ws } = await started();
    await adopted(http);
    const sent = [1, 2, 3, 4, 5, 6].map(packet);
    for (const record of sent) expect((await deliver(http, record)).status).toBe(202);
    const ids = sent.map((record) => contentId(record));
    const idsOf = (records: JsonObject[]): string[] => records.map((record) => contentId(record));

    // The mind reads two records, says it has the first, and the connection is cut: no close, no goodbye.
    const first = await instance(ws);
    await first.received(2);
    const [had] = first.records();
    if (had === undefined) throw new Error("the mind was sent nothing");
    first.acknowledge(had);
    // The acknowledgement is on its way before the cut: the host answers nothing to one.
    await new Promise((resolve) => setTimeout(resolve, 200));
    first.socket.terminate();

    // Nothing was lost: every record the mind did not acknowledge is still in the mailbox.
    const kept = (await mail(http)).map((item) => contentId(item.record));
    expect(kept).toEqual(ids.slice(1));

    // On a new connection the mind is sent them all, in order, and the first no more.
    const second = await instance(ws);
    await second.received(5);
    expect(idsOf(second.records())).toEqual(ids.slice(1));
    for (const record of second.records()) second.acknowledge(record);
    await new Promise((resolve) => setTimeout(resolve, 300));
    second.socket.terminate();
    expect(await mail(http)).toEqual([]);

    // A sender whose connection is cut as soon as it has sent: the packet is kept once, or not at all.
    const late = packet(7);
    const cut = new AbortController();
    const going = deliver(http, late).catch(() => undefined);
    cut.abort();
    await going;
    expect((await deliver(http, late)).status).toBe(202);
    expect((await mail(http)).map((item) => contentId(item.record))).toEqual([contentId(late)]);
  }, 60_000);
});

describe(`${clause("L1 13.2")} a host whose database another process has locked`, () => {
  it("answers a delivery 503, keeps nothing of it, and takes it when the lock is gone", async () => {
    const { http } = await started();
    await adopted(http);
    const [before, during] = [packet(1), packet(2)];
    expect((await deliver(http, before)).status).toBe(202);
    const other = new DatabaseSync(join(directory, "host.db"));
    other.exec("BEGIN IMMEDIATE");
    try {
      const response = await deliver(http, during);
      expect(response.status).toBe(503);
      expect(response.headers.get("content-type")).toBe("application/problem+json");
      expect(response.headers.get("retry-after")).not.toBeNull();
      // What the host serves without writing, it serves.
      const bundle = await fetch(`${http}/.well-known/oip/mind/${mindId(bob.address) ?? ""}`);
      expect(bundle.status).toBe(200);
    } finally {
      other.exec("ROLLBACK");
      other.close();
    }
    expect(firstSeen(proofDigest(during.proof[0]))).toBeUndefined();
    expect((await mail(http)).map((item) => contentId(item.record))).toEqual([contentId(before)]);
    expect((await deliver(http, during)).status).toBe(202);
    expect((await mail(http)).map((item) => contentId(item.record))).toEqual([
      contentId(before),
      contentId(during),
    ]);
    expect(firstSeen(proofDigest(during.proof[0]))).toBeDefined();
  }, 60_000);
});
