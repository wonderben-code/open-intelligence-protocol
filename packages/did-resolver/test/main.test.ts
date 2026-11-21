// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** `oip-did-resolver`, run as a program is. */

import { request } from "node:http";

import { LOCAL } from "@oip/cli";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { DID_JSON, type Host, main, type Serving } from "../src/index.ts";
import { Place } from "./harness.ts";

let place: Place;
let ada: string;

beforeAll(async () => {
  place = await new Place().start();
  ada = await place.make("ada");
});
afterAll(async () => {
  await place.close();
});

/** A process for the program to run in: what it wrote, and how it is asked to stop. */
function host(env: Record<string, string> = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const stops: (() => void)[] = [];
  const process: Host = {
    env,
    stdout: { write: (text) => out.push(text) },
    stderr: { write: (text) => err.push(text) },
    once: (_, heard) => stops.push(heard),
  };
  return {
    process,
    out: () => out.join(""),
    err: () => err.join(""),
    stop: () => {
      for (const heard of stops) heard();
    },
  };
}

/** Asks over HTTP, as a client on this machine. */
function get(port: number, path: string, accept?: string) {
  return new Promise<{ status: number; type: string; body: string }>((resolve, reject) => {
    request(
      { host: "127.0.0.1", port, path, headers: accept === undefined ? {} : { accept } },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () => {
          resolve({
            status: response.statusCode ?? 0,
            type: response.headers["content-type"] ?? "",
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });
      },
    )
      .on("error", reject)
      .end();
  });
}

const ENV = { OIP_DID_RESOLVERS: LOCAL.resolver, OIP_DID_PORT: "0" };

/** Starts the program serving on a port the system gives it. */
async function serving(env: Record<string, string> = ENV, fetch = place.options().fetch) {
  const ran = host(env);
  const done = await main([], ran.process, fetch === undefined ? {} : { fetch });
  if (typeof done === "number") throw new Error(`the program ended with ${String(done)}`);
  return { ...ran, ...(done satisfies Serving) };
}

describe("oip-did-resolver", () => {
  it("says what it serves and how it is set up", async () => {
    const ran = host();
    expect(await main(["--help"], ran.process)).toBe(0);
    expect(ran.out()).toMatch(/^oip-did-resolver: resolves did:oip over HTTP/u);
    for (const word of ["/1.0/identifiers/", "OIP_DID_RESOLVERS", "OIP_DID_HOST", "OIP_DID_PORT"]) {
      expect(ran.out()).toContain(word);
    }
    expect(ran.err()).toBe("");
  });

  it.each([
    [["serve"], ENV, "it takes no arguments but --help: it is set up by its environment"],
    [
      [],
      {},
      "OIP_DID_RESOLVERS names the resolvers to ask, as HTTPS origins: https://resolver.example,https://other.example",
    ],
    [
      [],
      { OIP_DID_RESOLVERS: " , " },
      "OIP_DID_RESOLVERS names the resolvers to ask, as HTTPS origins: https://resolver.example,https://other.example",
    ],
    [
      [],
      { OIP_DID_RESOLVERS: "https://resolver.example,http://plain.example" },
      "OIP_DID_RESOLVERS names the resolvers to ask, as HTTPS origins: https://resolver.example,https://other.example",
    ],
    [
      [],
      { OIP_DID_RESOLVERS: "https://resolver.example/path" },
      "OIP_DID_RESOLVERS names the resolvers to ask, as HTTPS origins: https://resolver.example,https://other.example",
    ],
    [
      [],
      { ...ENV, OIP_DID_PORT: "http" },
      "OIP_DID_PORT is a port: a whole number from 0 to 65535",
    ],
    [
      [],
      { ...ENV, OIP_DID_PORT: "70000" },
      "OIP_DID_PORT is a port: a whole number from 0 to 65535",
    ],
    [[], { ...ENV, OIP_DID_PORT: "-1" }, "OIP_DID_PORT is a port: a whole number from 0 to 65535"],
    [[], { ...ENV, OIP_DID_PORT: "8e3" }, "OIP_DID_PORT is a port: a whole number from 0 to 65535"],
  ])("does not start where it is set up wrongly: %j %j", async (argv, env, why) => {
    const ran = host(env);
    expect(await main(argv, ran.process)).toBe(2);
    expect(ran.err()).toBe(`oip-did-resolver: ${why}\n`);
    expect(ran.out()).toBe("");
  });

  it("resolves did:oip for whoever asks it over HTTP, until it is asked to stop", async () => {
    const program = await serving({ ...ENV, OIP_DID_RESOLVERS: ` ${LOCAL.resolver} , ` });
    expect(program.err()).toBe(
      `oip-did-resolver: resolving did:oip on port ${String(program.port)}, by asking ${LOCAL.resolver}\n`,
    );
    const result = await get(program.port, `/1.0/identifiers/${ada}`);
    expect(result.status).toBe(200);
    expect(JSON.parse(result.body)).toMatchObject({ didDocument: { id: ada } });
    const document = await get(program.port, `/1.0/identifiers/${ada}`, DID_JSON);
    expect(document).toMatchObject({ status: 200, type: DID_JSON });
    expect(JSON.parse(document.body)).toMatchObject({ id: ada });
    expect(await get(program.port, "/healthz")).toMatchObject({ status: 200, body: "ok\n" });
    program.stop();
    await program.ended;
    await expect(get(program.port, "/healthz")).rejects.toThrow();
  });

  it("listens where it is told, and says so where it cannot", async () => {
    const first = await serving({ ...ENV, OIP_DID_HOST: "127.0.0.1" });
    try {
      const ran = host({ ...ENV, OIP_DID_PORT: String(first.port) });
      expect(await main([], ran.process)).toBe(2);
      expect(ran.err()).toBe(
        `oip-did-resolver: the port ${String(first.port)} cannot be listened on: EADDRINUSE\n`,
      );
    } finally {
      first.stop();
      await first.ended;
    }
    // With no port named, it is 8080: taken or not, the program says which it tried.
    const ran = host({ OIP_DID_RESOLVERS: LOCAL.resolver, OIP_DID_HOST: "192.0.2.1" });
    expect(await main([], ran.process)).toBe(2);
    expect(ran.err()).toMatch(
      /^oip-did-resolver: the port 8080 cannot be listened on: E[A-Z]+\n$/u,
    );
  });

  it("answers with 500, and logs, where what goes wrong is nobody's answer", async () => {
    // A machine whose clock cannot be read: a fault of the program's own, and none of the caller's.
    const ran = host(ENV);
    const done = await main([], ran.process, {
      ...place.options(),
      clock: {
        now: () => {
          throw new Error("the clock of this machine cannot be read");
        },
      },
    });
    if (typeof done === "number") throw new Error("the program did not start");
    try {
      const answer = await get(done.port, `/1.0/identifiers/${ada}`);
      // The caller is told that it failed, and nothing of the inside.
      expect(answer).toMatchObject({ status: 500, body: "The resolver could not answer.\n" });
      expect(ran.err()).toContain("oip-did-resolver: the clock of this machine cannot be read\n");
    } finally {
      ran.stop();
      await done.ended;
    }
  });
});
