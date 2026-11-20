// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** `oip-bridge-a2a`, run as a program is, on a real resolver, host and indexer. */

import { writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { join } from "node:path";

import { canonicalBytes } from "@oip/core";
import { clause } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { type Host, main, type Reach, type Serving } from "../src/index.ts";
import { cardOf, Place, served } from "./harness.ts";

const LEXIS = "https://lexis.example";
const SIGNED = "https://signed.example";
const ELSEWHERE = "https://keys.elsewhere.example";

let place: Place;
let amina: string;
/** What each URL of an agent's answers with, where it answers. */
const pages = new Map<string, { status: number; body: Uint8Array }>();
/** Whether the agents can be reached. */
let reachable = true;

const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);
const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
const b64 = (bytes: Uint8Array | string): string => Buffer.from(bytes).toString("base64url");

/** An agent that completes what it is asked, with a text. */
const reach = (): Reach => ({
  machine: place.machine(),
  get: (url) => {
    const page = pages.get(url);
    return page === undefined || !reachable
      ? Promise.reject(new Error("unreachable"))
      : Promise.resolve(page);
  },
  ask: ({ body }) => {
    if (!reachable) return Promise.reject(new Error("the agent is away"));
    const asked = JSON.parse(new TextDecoder().decode(body)) as { id: string };
    const task = {
      id: "task-1",
      status: { state: "TASK_STATE_COMPLETED" },
      artifacts: [{ artifactId: "a-1", parts: [{ text: "The lease in English." }] }],
    };
    return Promise.resolve({
      status: 200,
      body: utf8(JSON.stringify({ jsonrpc: "2.0", id: asked.id, result: { task } })),
    });
  },
});

/** A process for the program to run in: what it wrote, and how it is asked to stop. */
function host() {
  const out: string[] = [];
  const err: string[] = [];
  const stops: (() => void)[] = [];
  const process: Host = {
    env: {},
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

/** Runs the program in the gateway's directory, to its end. */
async function run(...argv: string[]) {
  const ran = host();
  const code = await main(["--dir", join(place.root, "gateway"), ...argv], ran.process, reach());
  return { code, out: ran.out(), err: ran.err(), stop: ran.stop };
}

beforeAll(async () => {
  place = await new Place().start();
  await place.make("gateway", { kind: "service" });
  amina = await place.make("amina", { kind: "person" });
  pages.set(`${LEXIS}/.well-known/agent-card.json`, { status: 200, body: served(cardOf(LEXIS)) });
});
afterAll(async () => {
  await place.close();
});

describe("oip-bridge-a2a", () => {
  it("says what it takes, and which version it is", async () => {
    const help = await run("--help");
    expect(help).toMatchObject({ code: 0, err: "" });
    expect(help.out).toMatch(
      /^oip-bridge-a2a: a gateway between the Open Intelligence Protocol and A2A\.\n/u,
    );
    for (const word of [
      "bridge <origin>",
      "agents",
      "serve",
      "--base",
      "--keys",
      "OIP_PASSPHRASE",
    ]) {
      expect(help.out).toContain(word);
    }
    expect(await run("--version")).toMatchObject({ code: 0, out: "0.0.0\n", err: "" });
  });

  it.each([
    [[], "say what to do: bridge, agents or serve. `oip-bridge-a2a --help` shows each"],
    [["dance"], "dance is none of bridge, agents and serve, or takes no such argument"],
    [["agents", "all"], "agents is none of bridge, agents and serve, or takes no such argument"],
    [["serve", "now"], "serve is none of bridge, agents and serve, or takes no such argument"],
    [["bridge"], "bridge takes one origin: oip-bridge-a2a bridge https://agent.example"],
    [
      ["bridge", LEXIS, SIGNED],
      "bridge takes one origin: oip-bridge-a2a bridge https://agent.example",
    ],
    [
      ["bridge", "lexis.example"],
      "lexis.example is no HTTPS origin: an agent is named as https://agent.example",
    ],
    [["serve", "--port", "http"], "--port is a whole number from 0 to 65535"],
    [["serve", "--port", "70000"], "--port is a whole number from 0 to 65535"],
    [["serve", "--every", "0"], "--every is a whole number from 1 to 3600"],
    [["serve", "--every", "1.5"], "--every is a whole number from 1 to 3600"],
    [
      ["serve", "--base", "ftp://gateway.example/a2a"],
      "--base is the URL the interface is reached under: https://gateway.example/a2a",
    ],
    [
      ["serve", "--base", "gateway.example"],
      "--base is the URL the interface is reached under: https://gateway.example/a2a",
    ],
  ])("is told what is wrong with what it was given: %j", async (argv, why) => {
    expect(await run(...argv)).toStrictEqual({
      code: 2,
      out: "",
      err: `oip-bridge-a2a: ${why}\n`,
      stop: expect.any(Function) as () => void,
    });
  });

  it("takes no option it does not know, and no key set that is none", async () => {
    const unknown = await run("agents", "--loudly");
    expect(unknown.code).toBe(2);
    expect(unknown.err).toMatch(
      /^oip-bridge-a2a: Unknown option '--loudly'.*`oip-bridge-a2a --help` shows what it takes\n$/u,
    );
    const missing = await run("agents", "--keys", join(place.root, "no-such-file.json"));
    expect(missing.code).toBe(2);
    expect(missing.err).toMatch(
      /no-such-file\.json is no JSON Web Key Set that can be read: ENOENT/u,
    );
    const file = join(place.root, "not-keys.json");
    for (const text of ['{"keys":"none"}', "[]", "{ no json"]) {
      writeFileSync(file, text);
      const refused = await run("agents", "--keys", file);
      expect(refused.code).toBe(2);
      expect(refused.err).toMatch(/not-keys\.json is no JSON Web Key Set that can be read: /u);
    }
  });

  it(`${clause("L0 3.1", "L0 1.2")} bridges an A2A agent, and lists the agents it bridges`, async () => {
    expect(await run("agents")).toMatchObject({
      code: 0,
      out: "The gateway bridges no agent yet: `oip-bridge-a2a bridge <origin>`\n",
    });
    const bridged = await run("bridge", LEXIS);
    expect(bridged).toMatchObject({ code: 0, err: "" });
    const [, mind = ""] =
      /^https:\/\/lexis\.example is bridged as (did:oip:[a-z0-9]+)\n/u.exec(bridged.out) ?? [];
    expect(mind).toMatch(/^did:oip:/u);
    expect(bridged.out).toContain(
      "Its card is not signed: the gateway read it over HTTPS, and says no more of it.\n",
    );
    // What it made is a mind anyone can look up: bridged, and attested by the gateway.
    expect(await place.reader().assurance(mind)).toMatchObject({
      level: "bridged",
      protocol: "a2a",
    });
    expect((await run("agents")).out).toBe(`${LEXIS}  ${mind}\n`);
    // Done again, it is the same mind.
    expect((await run("bridge", LEXIS)).out).toContain(`is bridged as ${mind}\n`);
  });

  it("says why an agent is not bridged, and makes nothing of it", async () => {
    const refused = await run("bridge", "https://nowhere.example");
    expect(refused).toMatchObject({
      code: 1,
      out: "",
      err: "oip-bridge-a2a: the card of https://nowhere.example could not be fetched: unreachable\n",
    });
    expect((await run("agents")).out).not.toContain("nowhere.example");
  });
});

describe("the keys oip-bridge-a2a verifies a signed card with", () => {
  let jwk: Record<string, unknown>;
  /** A card of the signed agent's, signed, with what its signature's header says besides. */
  let signedCard: (header?: Record<string, unknown>) => Promise<Uint8Array>;
  const CARD_URL = `${SIGNED}/.well-known/agent-card.json`;

  beforeAll(async () => {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ]);
    jwk = { ...(await crypto.subtle.exportKey("jwk", pair.publicKey)), kid: "key-1" };
    signedCard = async (header = {}) => {
      const card = cardOf(SIGNED);
      const protectedHeader = b64(
        JSON.stringify({ alg: "ES256", typ: "JOSE", kid: "key-1", ...header }),
      );
      const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        pair.privateKey,
        utf8(`${protectedHeader}.${b64(canonicalBytes(card))}`),
      );
      return served({
        ...card,
        signatures: [{ protected: protectedHeader, signature: b64(new Uint8Array(signature)) }],
      });
    };
  });

  it(`${clause("L0 3.1")} are the operator's own, from a key set it names`, async () => {
    pages.set(CARD_URL, { status: 200, body: await signedCard() });
    // No key is known for the signature: the card is not taken.
    const unknown = await run("bridge", SIGNED);
    expect(unknown.code).toBe(1);
    expect(unknown.err).toMatch(
      /^oip-bridge-a2a: the card of https:\/\/signed\.example is not taken: /u,
    );
    const file = join(place.root, "keys.json");
    // A key set holds what is no key with a name too: it is passed over.
    writeFileSync(
      file,
      JSON.stringify({ keys: [{ kty: "EC" }, "junk", { ...jwk, kid: "another" }, jwk] }),
    );
    const bridged = await run("bridge", SIGNED, "--keys", file);
    expect(bridged).toMatchObject({ code: 0, err: "" });
    expect(bridged.out).toContain("Its card is signed, by a key this gateway takes.\n");
  });

  it("are those an agent serves at its own origin too, which say no more than the card does", async () => {
    const jku = `${SIGNED}/keys.json`;
    pages.set(CARD_URL, { status: 200, body: await signedCard({ jku }) });
    // The key set is not there, is none, or has no such key: no key, and the card is not taken.
    for (const page of [
      undefined,
      { status: 404, body: utf8("Not found") },
      { status: 200, body: utf8("{ no json") },
      { status: 200, body: new Uint8Array([0xff, 0xfe]) },
      { status: 200, body: utf8(JSON.stringify({ keys: [{ ...jwk, kid: "another" }] })) },
    ]) {
      if (page === undefined) pages.delete(jku);
      else pages.set(jku, page);
      expect((await run("bridge", SIGNED)).code, JSON.stringify(page?.status)).toBe(1);
    }
    pages.set(jku, { status: 200, body: utf8(JSON.stringify({ keys: [jwk] })) });
    expect((await run("bridge", SIGNED)).out).toContain(
      "Its card is signed, by a key this gateway takes.\n",
    );
  });

  it("are none that another origin serves, and none at what is no URL", async () => {
    for (const jku of [`${ELSEWHERE}/keys.json`, "no url"]) {
      pages.set(`${ELSEWHERE}/keys.json`, {
        status: 200,
        body: utf8(JSON.stringify({ keys: [jwk] })),
      });
      pages.set(CARD_URL, { status: 200, body: await signedCard({ jku }) });
      const refused = await run("bridge", SIGNED);
      expect(refused.code, jku).toBe(1);
      expect(refused.err).toContain("is not taken");
    }
  });
});

describe("oip-bridge-a2a serve", () => {
  /** Starts the program serving, and gives how to stop it. */
  async function serving(...argv: string[]) {
    const ran = host();
    const code = await main(
      ["--dir", join(place.root, "gateway"), "serve", ...argv],
      ran.process,
      reach(),
    );
    if (typeof code === "number")
      throw new Error(`the program ended with ${String(code)}: ${ran.err()}`);
    return { ...ran, ended: (code satisfies Serving).ended };
  }

  /** Waits until something is so. */
  async function until(so: () => boolean | Promise<boolean>): Promise<void> {
    for (let tries = 0; tries < 400; tries++) {
      if (await so()) return;
      await sleep(25);
    }
    throw new Error("it did not come to be");
  }

  it(`${clause("L0 3.1")} relays between each bridged mind and its agent until it is asked to stop`, async () => {
    const bridged = (await run("agents")).out.split("\n").find((line) => line.startsWith(LEXIS));
    const mind = bridged?.split("  ")[1] ?? "";
    const opened = await place.mind("amina");
    let request: string;
    try {
      const sent = await opened.mind.send({
        to: [mind],
        verb: "request",
        content: { mediaType: "text/plain", body: "Translate the lease." },
      });
      request = sent.id;
    } finally {
      opened.mind.close();
    }
    const program = await serving("--every", "1");
    expect(program.err()).toMatch(
      /oip-bridge-a2a 0\.0\.0: relaying for 2 bridged agents, every 1 s\n/u,
    );
    await until(() => program.err().includes("1 request passed on"));
    expect(program.err()).toContain(
      `oip-bridge-a2a: ${LEXIS}: 1 request passed on, 1 packet sent, 1 Receipt signed, 0 tasks open\n`,
    );
    program.stop();
    // Asked twice, it stops once.
    program.stop();
    await program.ended;
    expect(program.out()).toBe("");
    // The requester has the agent's answer, with the gateway's Receipt.
    const reader = await place.mind("amina");
    try {
      const { received } = await reader.mind.receive();
      expect(received).toMatchObject([
        { from: mind, packet: { purpose: { verb: "deliver" }, replyTo: request } },
      ]);
    } finally {
      reader.mind.close();
    }
  });

  it("goes on relaying where an agent cannot be reached, and says what failed", async () => {
    const bridged = (await run("agents")).out.split("\n").find((line) => line.startsWith(LEXIS));
    const mind = bridged?.split("  ")[1] ?? "";
    const opened = await place.mind("amina");
    let request: string;
    try {
      const sent = await opened.mind.send({
        to: [mind],
        verb: "request",
        content: { mediaType: "text/plain", body: "Translate again." },
      });
      request = sent.id;
    } finally {
      opened.mind.close();
    }
    reachable = false;
    const program = await serving("--every", "1");
    try {
      await until(() => program.err().includes("the agent is away"));
      expect(program.err()).toContain(`oip-bridge-a2a: ${LEXIS}: ${request}: the agent is away\n`);
      reachable = true;
      await until(() => program.err().includes("1 request passed on"));
    } finally {
      reachable = true;
      program.stop();
      await program.ended;
    }
  });

  it(`${clause("L0 3.2")} serves the minds that ask for it as A2A agents under the URL it is given`, async () => {
    const base = "https://gateway.example/a2a";
    const id = amina.slice("did:oip:".length);
    const opened = await place.mind("amina");
    try {
      await opened.mind.publishProfile({
        name: "Amina",
        interfaces: { a2a: `${base}/${id}/.well-known/agent-card.json` },
      });
    } finally {
      opened.mind.close();
    }
    // The URL may end in a slash: it is the same URL.
    const program = await serving("--base", `${base}/`, "--port", "0", "--host", "127.0.0.1");
    try {
      const [, port = ""] =
        /serving minds as A2A agents under https:\/\/gateway\.example\/a2a, on port (\d+)\n/u.exec(
          program.err(),
        ) ?? [];
      expect(Number(port)).toBeGreaterThan(0);
      const card = await new Promise<{ status: number; body: string }>((resolve, reject) => {
        httpRequest(
          { host: "127.0.0.1", port: Number(port), path: `/a2a/${id}/.well-known/agent-card.json` },
          (response) => {
            const chunks: Buffer[] = [];
            response.on("data", (chunk: Buffer) => chunks.push(chunk));
            response.on("end", () => {
              resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks).toString() });
            });
          },
        )
          .on("error", reject)
          .end();
      });
      expect(card.status).toBe(200);
      expect(JSON.parse(card.body)).toMatchObject({
        name: "Amina",
        version: "0.0.0",
        supportedInterfaces: [{ url: `${base}/${id}`, protocolBinding: "JSONRPC" }],
      });
    } finally {
      program.stop();
      await program.ended;
    }
  });

  it("does not start to serve on a port that is taken, and says so", async () => {
    const first = await serving("--base", "https://gateway.example/a2a", "--port", "0");
    try {
      const [, port = ""] = /on port (\d+)\n/u.exec(first.err()) ?? [];
      const second = await run("serve", "--base", "https://gateway.example/a2a", "--port", port);
      expect(second).toMatchObject({
        code: 2,
        out: "",
        err: `oip-bridge-a2a: the port ${port} cannot be listened on: EADDRINUSE\n`,
      });
    } finally {
      first.stop();
      await first.ended;
    }
  });
});
