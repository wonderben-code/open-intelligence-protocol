// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { request } from "node:http";

import { afterEach, describe, expect, it } from "vitest";

import {
  type A2aServer,
  type Answer,
  type Asking,
  type Front,
  listen,
  MAX_REQUEST_BYTES,
  type ServedInterface,
} from "../src/index.ts";

const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);
const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** What was asked of the server that stands in for the gateway's. */
const asked: Asking[] = [];
let answering: (asking: Asking) => Promise<Answer>;
const server = {
  handle: (asking: Asking) => {
    asked.push(asking);
    return answering(asking);
  },
} as unknown as A2aServer;

/** A front whose mailbox is read as often as it is asked, and fails where a test says. */
let pumped = 0;
let pumping: () => Promise<number>;
const front = { pump: () => pumping() } as unknown as Front;

let served: ServedInterface | undefined;
afterEach(async () => {
  await served?.close();
  served = undefined;
  asked.length = 0;
});

const start = async (
  more: { everyMs?: number; failed?: (error: unknown) => void } = {},
  reading: () => Promise<number> = () => Promise.resolve(++pumped),
) => {
  pumped = 0;
  pumping = reading;
  answering = () =>
    Promise.resolve({
      status: 200,
      headers: { "content-type": "application/json", etag: '"tag"' },
      body: utf8('{"ok":true}'),
    });
  served = await listen(server, front, { port: 0, ...more });
  return served;
};

/** Asks over HTTP, as a client on this machine. */
function ask(
  port: number,
  method: string,
  path: string,
  headers: Record<string, string | string[]> = {},
  body: Uint8Array = new Uint8Array(),
): Promise<{ status: number; headers: Record<string, unknown>; body: string }> {
  return new Promise((resolve, reject) => {
    const asking = request({ host: "127.0.0.1", port, method, path, headers }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.on("end", () => {
        resolve({
          status: response.statusCode ?? 0,
          headers: response.headers,
          body: Buffer.concat(chunks).toString("utf8"),
        });
      });
    });
    asking.on("error", reject);
    asking.end(body);
  });
}

describe("the A2A interface on a port of this machine", () => {
  it("gives the server each request as it arrived, and the client what the server answers", async () => {
    const { port } = await start();
    expect(port).toBeGreaterThan(0);
    const answer = await ask(
      port,
      "POST",
      "/a2a/bciqmind?A2A-Version=1.0",
      { "A2A-Version": "1.0", "Content-Type": "application/json", "X-Twice": ["one", "two"] },
      utf8('{"jsonrpc":"2.0"}'),
    );
    expect(answer).toMatchObject({
      status: 200,
      headers: { "content-type": "application/json", etag: '"tag"', "content-length": "11" },
      body: '{"ok":true}',
    });
    expect(asked).toHaveLength(1);
    expect(asked[0]).toMatchObject({
      method: "POST",
      path: "/a2a/bciqmind?A2A-Version=1.0",
      // Names in lower case, and a header that came twice as one.
      headers: { "a2a-version": "1.0", "content-type": "application/json", "x-twice": "one, two" },
    });
    expect(new TextDecoder().decode(asked[0]?.body)).toBe('{"jsonrpc":"2.0"}');
    // A request with no body.
    await ask(port, "GET", "/a2a/bciqmind/.well-known/agent-card.json");
    expect(asked[1]).toMatchObject({ method: "GET", body: new Uint8Array() });
  });

  it("reads of a request no more than one may have, and one byte to tell that it has more", async () => {
    const { port } = await start();
    await ask(port, "POST", "/a2a/x", {}, new Uint8Array(MAX_REQUEST_BYTES + 70_000));
    expect(asked[0]?.body).toHaveLength(MAX_REQUEST_BYTES + 1);
    await ask(port, "POST", "/a2a/x", {}, new Uint8Array(MAX_REQUEST_BYTES));
    expect(asked[1]?.body).toHaveLength(MAX_REQUEST_BYTES);
  });

  it("lets go of a request that is far too large, and of its connection", async () => {
    const failures: unknown[] = [];
    const { port } = await start({ failed: (error) => failures.push(error) });
    await expect(
      ask(port, "POST", "/a2a/x", {}, new Uint8Array(17 * MAX_REQUEST_BYTES)),
    ).rejects.toThrow();
    expect(asked).toHaveLength(0);
    expect(failures).toMatchObject([{ message: "a request was far too large" }]);
  });

  it("ends a connection that cannot be answered, and says so to who logs", async () => {
    const failures: unknown[] = [];
    const { port } = await start({ failed: (error) => failures.push(error) });
    answering = () => Promise.reject(new Error("no answer"));
    await expect(ask(port, "GET", "/a2a/x")).rejects.toThrow();
    expect(failures).toMatchObject([{ message: "no answer" }]);
    // The next request is answered.
    answering = () => Promise.resolve({ status: 204, headers: {}, body: new Uint8Array() });
    expect((await ask(port, "GET", "/a2a/x")).status).toBe(204);
  });

  it("listens on this machine alone unless it is told otherwise, and on no port that is taken", async () => {
    const { port } = await start();
    await expect(listen(server, front, { port })).rejects.toMatchObject({ code: "EADDRINUSE" });
    const everywhere = await listen(server, front, { port: 0, host: "0.0.0.0" });
    expect((await ask(everywhere.port, "GET", "/")).status).toBe(200);
    await everywhere.close();
  });
});

describe("the reading of the gateway's mailbox", () => {
  it("is made again and again while the interface is served, and no more once it is closed", async () => {
    const { close } = await start({ everyMs: 5 });
    await sleep(80);
    expect(pumped).toBeGreaterThan(3);
    await close();
    served = undefined;
    const then = pumped;
    await sleep(40);
    expect(pumped).toBe(then);
  });

  it("goes on after a reading that failed, which is told to who logs", async () => {
    const failures: unknown[] = [];
    await start({ everyMs: 5, failed: (error) => failures.push(error) });
    pumping = () =>
      ++pumped === 2 ? Promise.reject(new Error("the host is away")) : Promise.resolve(0);
    await sleep(80);
    expect(pumped).toBeGreaterThan(3);
    expect(failures).toMatchObject([{ message: "the host is away" }]);
  });

  it("rests half a second between two readings where no rest is named, and is silent where nobody logs", async () => {
    await start({}, () => {
      pumped += 1;
      return Promise.reject(new Error("unheard"));
    });
    await sleep(60);
    // The reading made at the start, and no other yet.
    expect(pumped).toBe(1);
  });

  it("waits for a reading that is under way before it is closed", async () => {
    const { close } = await start({ everyMs: 5 });
    let ended = 0;
    pumping = async () => {
      await sleep(40);
      ended += 1;
      return 0;
    };
    // A reading is under way now, and has not ended.
    await sleep(20);
    expect(ended).toBe(0);
    await close();
    served = undefined;
    expect(ended).toBe(1);
  });
});
