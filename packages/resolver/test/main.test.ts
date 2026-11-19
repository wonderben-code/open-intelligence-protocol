// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The resolver as a running service, asked over a socket on this machine. */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { MEDIA_TYPE, mindId } from "@oip/core";
import { ConfigError } from "@oip/server";
import { clause } from "@oip/testkit";
import { KeyMind, type Mind } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { clientAddress, type Running, start } from "../src/index.ts";

let directory: string;
let lines: Record<string, unknown>[];
let running: Running[];

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "oip-resolver-main-"));
  lines = [];
  running = [];
});
afterEach(async () => {
  for (const service of running) await service.stop("test over");
  rmSync(directory, { recursive: true, force: true });
});

/** Starts a resolver on a port of its own, with what a test sets besides. */
async function started(
  more: Record<string, string> = {},
): Promise<{ service: Running; at: string }> {
  const service = await start(
    {
      OIP_RESOLVER_ORIGIN: "https://resolver.example",
      OIP_RESOLVER_HOST: "127.0.0.1",
      OIP_RESOLVER_PORT: "0",
      OIP_RESOLVER_DATABASE: join(directory, "resolver.db"),
      // Nothing of the machine's own environment is a setting of the resolver.
      PATH: "/usr/bin",
      ...more,
    },
    { sink: (line) => lines.push(JSON.parse(line) as Record<string, unknown>) },
  );
  running.push(service);
  return { service, at: `http://127.0.0.1:${service.port}` };
}

const pathOf = (mind: Mind): string => `/oip/v1/resolve/${mindId(mind.address) ?? ""}`;
const publish = (base: string, mind: Mind): Promise<Response> =>
  fetch(`${base}${pathOf(mind)}`, {
    method: "PUT",
    headers: { "content-type": MEDIA_TYPE },
    body: JSON.stringify({ oip: "1", type: "Bundle", mind: mind.address, log: mind.events }),
  });

describe(`${clause("L1 17.1")} a resolver that is running`, () => {
  it("answers over a socket: it takes a bundle in and serves it", async () => {
    const ada = new KeyMind("ada").update(10);
    const { at } = await started();
    expect((await fetch(`${at}/healthz`)).status).toBe(200);
    expect((await fetch(`${at}/readyz`)).status).toBe(200);
    expect((await publish(at, ada)).status).toBe(202);
    const served = await fetch(`${at}${pathOf(ada)}`);
    expect(served.status).toBe(200);
    expect(((await served.json()) as { log: unknown[] }).log).toStrictEqual(ada.events);
    // It said what it started with, and where it listens.
    expect(lines.map((line) => line["event"])).toStrictEqual(["starting", "listening"]);
    expect(lines[0]).toMatchObject({
      origin: '"https://resolver.example"',
      host: '"127.0.0.1"',
      authenticatedPublication: "false",
      maxStreams: "256",
      trustedProxies: "0",
    });
  });

  it("holds what it took in after it has stopped and started again", async () => {
    const ada = new KeyMind("ada");
    const first = await started();
    await publish(first.at, ada);
    const before = await (await fetch(`${first.at}${pathOf(ada)}`)).text();
    expect(await first.service.stop("SIGTERM")).toBe(true);
    await expect(fetch(`${first.at}/healthz`)).rejects.toThrow();
    const second = await started();
    expect(await (await fetch(`${second.at}${pathOf(ada)}`)).text()).toBe(before);
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

  it("ends an open stream when it stops, and stops in time", async () => {
    const ada = new KeyMind("ada");
    const { service, at } = await started();
    await publish(at, ada);
    const response = await fetch(`${at}/oip/v1/stream`);
    const reader = (response.body as ReadableStream<Uint8Array>).getReader();
    const first = new TextDecoder().decode((await reader.read()).value);
    expect(first).toMatch(/^id: 1\ndata: \{"cursor":"1"/u);
    const stopped = service.stop("SIGTERM");
    // The stream ends: nothing more comes.
    for (;;) {
      const { done } = await reader.read().catch(() => ({ done: true }));
      if (done) break;
    }
    expect(await stopped).toBe(true);
  });

  it("limits each address by itself, as the socket gives it", async () => {
    const ada = new KeyMind("ada");
    const { at } = await started({
      OIP_RESOLVER_PUBLISH_BURST: "1",
      OIP_RESOLVER_PUBLISH_PER_MINUTE: "1",
    });
    expect((await publish(at, ada)).status).toBe(202);
    const limited = await publish(at, ada);
    expect(limited.status).toBe(429);
    expect(limited.headers.get("retry-after")).toBe("60");
    // Reading has a limit of its own.
    expect((await fetch(`${at}${pathOf(ada)}`)).status).toBe(200);
  });

  it("does not start with a configuration that is wrong, and says all of what is", async () => {
    let thrown: unknown;
    try {
      await start({
        OIP_RESOLVER_PORT: "http",
        OIP_RESOLVER_PROT: "1",
        OIP_RESOLVER_DATABASE: join(directory, "x.db"),
      });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(ConfigError);
    expect((thrown as ConfigError).problems).toStrictEqual([
      "OIP_RESOLVER_ORIGIN is not set: the origin clients reach the resolver at, which a signed request names",
      'OIP_RESOLVER_PORT: "http" is not a whole number from 0 to 65535',
      "OIP_RESOLVER_PROT is no setting of this service",
    ]);
  });
});

describe("what a resolver keeps only for a time", () => {
  it("is forgotten every minute, and a failure to do so stops nothing", async () => {
    let tidy: (() => void) | undefined;
    let stopped = false;
    const service = await start(
      {
        OIP_RESOLVER_ORIGIN: "https://resolver.example",
        OIP_RESOLVER_HOST: "127.0.0.1",
        OIP_RESOLVER_PORT: "0",
        OIP_RESOLVER_DATABASE: join(directory, "resolver.db"),
      },
      {
        sink: (line) => lines.push(JSON.parse(line) as Record<string, unknown>),
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
    tidy?.();
    expect(lines.map((line) => line["event"])).toStrictEqual(["starting", "listening"]);
    await service.stop("test");
    expect(stopped).toBe(true);
    // The database is closed: forgetting fails, says so, and throws nothing.
    tidy?.();
    expect(lines.at(-1)).toMatchObject({ level: "error", event: "nonces not forgotten" });
  });

  it("writes its log to the process's own output where it is given nowhere else", async () => {
    const written: string[] = [];
    const write = vi.spyOn(process.stdout, "write").mockImplementation((chunk) => {
      written.push(String(chunk));
      return true;
    });
    const service = await start({
      OIP_RESOLVER_ORIGIN: "https://resolver.example",
      OIP_RESOLVER_HOST: "127.0.0.1",
      OIP_RESOLVER_PORT: "0",
      OIP_RESOLVER_DATABASE: join(directory, "resolver.db"),
      OIP_RESOLVER_LOG_LEVEL: "warn",
    });
    await service.stop("test");
    write.mockRestore();
    // Nothing at `info` is written at `warn`.
    expect(written.join("")).toBe("");
    await expect(
      start({ OIP_RESOLVER_ORIGIN: "https://resolver.example", OIP_RESOLVER_LOG_LEVEL: "loud" }),
    ).rejects.toThrow('OIP_RESOLVER_LOG_LEVEL: "loud" is not one of debug, info, warn, error');
  });
});

describe("the address a request came from", () => {
  const arrived = (forwarded?: string | string[]) => ({
    socket: { remoteAddress: "10.0.0.2" },
    headers: forwarded === undefined ? {} : { "x-forwarded-for": forwarded },
  });

  it("is the socket's where no proxy stands in front, whatever the request says", () => {
    expect(clientAddress(arrived(), 0)).toBe("10.0.0.2");
    expect(clientAddress(arrived("203.0.113.7"), 0)).toBe("10.0.0.2");
    expect(clientAddress({ socket: {}, headers: {} }, 0)).toBeUndefined();
  });

  it("is what the outermost trusted proxy was asked from, and nothing the sender wrote before it", () => {
    // The sender wrote the first; each proxy added one.
    const header = "198.51.100.1, 203.0.113.7, 10.0.0.1";
    expect(clientAddress(arrived(header), 1)).toBe("10.0.0.1");
    expect(clientAddress(arrived(header), 2)).toBe("203.0.113.7");
    expect(clientAddress(arrived(["198.51.100.1", "203.0.113.7 ,10.0.0.1"]), 2)).toBe(
      "203.0.113.7",
    );
    // Fewer than the proxies that are said to be there: the socket's.
    expect(clientAddress(arrived("203.0.113.7"), 2)).toBe("10.0.0.2");
    expect(clientAddress(arrived(), 1)).toBe("10.0.0.2");
    expect(clientAddress(arrived(" , "), 1)).toBe("10.0.0.2");
  });
});
