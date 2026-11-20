// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Faults planted under a running resolver: the process killed while it
 * publishes and while a client reads its stream, and its database locked
 * by another process. A resolver is a witness (Layer 1, 17.2), so the
 * question each time is the same: of what it said it had taken, is
 * anything lost, or first seen at another time than it said?
 */

import { type ChildProcess, spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { contentId, MEDIA_TYPE, mindId } from "@oip/core";
import { clause, repoRoot } from "@oip/testkit";
import { KeyMind, type Mind } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const bin = join(repoRoot, "packages", "resolver", "src", "bin.ts");

let directory: string;
let children: ChildProcess[];

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "oip-resolver-faults-"));
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

/** Starts a resolver as a process of its own on the test's database, and gives where it listens. */
function started(): Promise<{ child: ChildProcess; http: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--conditions=@oip/source", bin], {
      env: {
        PATH: process.env["PATH"] ?? "",
        OIP_RESOLVER_ORIGIN: "https://resolver.example",
        OIP_RESOLVER_HOST: "127.0.0.1",
        OIP_RESOLVER_PORT: "0",
        OIP_RESOLVER_DATABASE: join(directory, "resolver.db"),
        OIP_RESOLVER_READ_BURST: "100000",
        OIP_RESOLVER_PUBLISH_BURST: "100000",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    children.push(child);
    let out = "";
    child.stdout?.on("data", (chunk: Buffer) => {
      out += chunk.toString("utf8");
      const listening = /"event":"listening".*?"port":(\d+)/u.exec(out);
      if (listening !== null) resolve({ child, http: `http://127.0.0.1:${listening[1] ?? ""}` });
    });
    child.once("error", reject);
    child.once("close", () => {
      reject(new Error(`the resolver ended before it listened: ${out}`));
    });
  });
}

const idOf = (mind: Mind): string => mindId(mind.address) ?? "";

/** Publishes a mind's bundle. The status, or `undefined` if the resolver went away before it answered. */
async function publish(http: string, mind: Mind): Promise<number | undefined> {
  try {
    const response = await fetch(`${http}/oip/v1/resolve/${idOf(mind)}`, {
      method: "PUT",
      headers: { "content-type": MEDIA_TYPE },
      body: JSON.stringify({ oip: "1", type: "Bundle", mind: mind.address, log: mind.events }),
    });
    await response.arrayBuffer();
    return response.status;
  } catch {
    return undefined;
  }
}

/** What the resolver serves for a mind: its log and first-seen times, or `undefined` if it knows none. */
async function resolved(
  http: string,
  mind: Mind,
): Promise<{ log: unknown[]; firstSeen: Record<string, string> } | undefined> {
  const response = await fetch(`${http}/oip/v1/resolve/${idOf(mind)}`);
  if (response.status === 404) return undefined;
  expect(response.status).toBe(200);
  return (await response.json()) as { log: unknown[]; firstSeen: Record<string, string> };
}

/** Reads the stream from a cursor until it is cut or nothing has come for a moment. */
async function streamed(
  http: string,
  since?: string,
): Promise<{ cursor: string; record: string }[]> {
  const told: { cursor: string; record: string }[] = [];
  const abort = new AbortController();
  let text = "";
  try {
    const response = await fetch(
      `${http}/oip/v1/stream${since === undefined ? "" : `?since=${since}`}`,
      { signal: abort.signal },
    );
    const reader = response.body?.getReader();
    const decoder = new TextDecoder();
    for (;;) {
      const quiet = setTimeout(() => {
        abort.abort();
      }, 700);
      const chunk = (await reader?.read()) as { done: boolean; value?: Uint8Array } | undefined;
      clearTimeout(quiet);
      if (chunk === undefined || chunk.done) break;
      text += decoder.decode(chunk.value ?? new Uint8Array(0), { stream: true });
    }
  } catch {
    // The resolver went away, or nothing more came: what was read is what there is.
  }
  for (const block of text.split("\n\n")) {
    const data = /^data: (.*)$/mu.exec(block)?.[1];
    if (data === undefined) continue;
    const event = JSON.parse(data) as { cursor: string; record: object };
    told.push({ cursor: event.cursor, record: contentId(event.record) });
  }
  return told;
}

describe(`${clause("L1 17.2", "L1 7.2")} a resolver whose process is killed`, () => {
  it("keeps what it answered for, with the times it gave, and its stream goes on from a cursor", async () => {
    const first = Array.from({ length: 6 }, (_, n) => new KeyMind(`first-${n}`).update(10));
    const later = Array.from({ length: 24 }, (_, n) => new KeyMind(`later-${n}`).update(10));
    const one = await started();
    let { http } = one;
    for (const mind of first) expect(await publish(http, mind)).toBe(202);
    const before = new Map<string, Record<string, string>>();
    for (const mind of first) before.set(idOf(mind), (await resolved(http, mind))?.firstSeen ?? {});

    // A client reads the stream while more is published, and the process is killed in the middle.
    const reading = streamed(http);
    const answers = later.map((mind) => publish(http, mind));
    await Promise.race(answers.slice(0, 4));
    await ended(one.child, "SIGKILL");
    const statuses = await Promise.all(answers);
    const read = await reading;
    expect(statuses.filter((status) => status === 202).length).toBeGreaterThan(0);
    expect(statuses.every((status) => status === 202 || status === undefined)).toBe(true);
    // The kill came in the middle: some of what was sent was never answered.
    expect(statuses.filter((status) => status === undefined).length).toBeGreaterThan(0);

    ({ http } = await started());
    // What was first seen before the kill has the time it had: to the nanosecond.
    for (const mind of first) {
      const served = await resolved(http, mind);
      expect(served?.log).toEqual(mind.events);
      expect(served?.firstSeen).toEqual(before.get(idOf(mind)));
    }
    // Whatever was answered 202 is there, whole. What was not answered is whole or absent.
    const kept: Mind[] = [...first];
    for (const [at, mind] of later.entries()) {
      const served = await resolved(http, mind);
      if (statuses[at] === 202) expect(served, `mind ${at} was answered 202`).toBeDefined();
      if (served === undefined) continue;
      kept.push(mind);
      expect(served.log).toEqual(mind.events);
      expect(Object.keys(served.firstSeen).toSorted()).toEqual(
        mind.events.map((event) => contentId(event)).toSorted(),
      );
    }

    // The stream, read again from the last cursor the client had: nothing twice, nothing missing.
    const last = read.at(-1)?.cursor;
    const rest = await streamed(http, last);
    const all = [...read, ...rest];
    const cursors = all.map((event) => BigInt(event.cursor));
    expect(cursors.every((cursor, at) => at === 0 || cursor > (cursors[at - 1] ?? 0n))).toBe(true);
    const wanted = kept.flatMap((mind) => mind.events.map((event) => contentId(event)));
    expect(all.map((event) => event.record).toSorted()).toEqual(wanted.toSorted());

    // A mind the kill left out is published again, and taken.
    for (const mind of later) {
      if (!kept.includes(mind)) expect(await publish(http, mind)).toBe(202);
    }
  }, 60_000);
});

describe(`${clause("L1 17.2")} a resolver whose database another process has locked`, () => {
  it("serves what it holds, answers a publication 503, and loses nothing", async () => {
    const [ada, bob] = [new KeyMind("ada").update(10), new KeyMind("bob")];
    const { http } = await started();
    expect(await publish(http, ada)).toBe(202);
    const before = await resolved(http, ada);

    // Another process takes the database's write lock, and holds it.
    const other = new DatabaseSync(join(directory, "resolver.db"));
    other.exec("BEGIN IMMEDIATE");
    try {
      // Reading goes on: a reader is not held up by a writer.
      expect(await resolved(http, ada)).toEqual(before);
      const response = await fetch(`${http}/oip/v1/resolve/${idOf(bob)}`, {
        method: "PUT",
        headers: { "content-type": MEDIA_TYPE },
        body: JSON.stringify({ oip: "1", type: "Bundle", mind: bob.address, log: bob.events }),
      });
      expect(response.status).toBe(503);
      expect(response.headers.get("retry-after")).toBe("1");
      expect(response.headers.get("content-type")).toBe("application/problem+json");
      // Nothing of the bundle was taken: not into the store, and not into the resolver's memory.
      expect(await resolved(http, bob)).toBeUndefined();
    } finally {
      other.exec("ROLLBACK");
      other.close();
    }
    // The lock is gone. The same bundle is taken, first seen now and not when it was refused.
    const from = Date.now();
    expect(await publish(http, bob)).toBe(202);
    const served = await resolved(http, bob);
    expect(served?.log).toEqual(bob.events);
    expect(Date.parse(served?.firstSeen[idOf(bob)] ?? "")).toBeGreaterThanOrEqual(from - 1);
    expect(await resolved(http, ada)).toEqual(before);
  }, 60_000);
});
