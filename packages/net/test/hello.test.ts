// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { proofDigest } from "@oip/core";
import { LogBook } from "@oip/identity";
import { clause, type JsonObject, readVectors } from "@oip/testkit";
import { at, KeyMind, LATER, type Mind, T, witness } from "@oip/testkit/minds";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { Challenges, type HelloServer, verifyHello } from "../src/index.ts";

type Signed = JsonObject & { proof: JsonObject[] };

const ORIGIN = "https://host.example";
const NONCE = "q8xG3kZ2pV7mT0wR5nY1aB";

const ada = new KeyMind("ada");
const eve = new KeyMind("eve");

/** A Hello of a mind, signed over a challenge and the origin it connected to. */
const hello = (
  mind: Mind,
  seconds: number,
  more: { challenge?: string; domain?: string } = { challenge: NONCE, domain: ORIGIN },
  key = 0,
): Signed =>
  mind.sign({ oip: "1", type: "Hello", author: mind.address, created: T(seconds) }, { more, key });

/** A server that holds some minds' logs and issued one challenge at `issued`. */
function serverAt(seconds: number, issued = seconds - 5, minds: readonly Mind[] = [ada, eve]) {
  const seen = witness(minds.map((mind) => mind.events));
  const book = new LogBook(seen);
  for (const mind of minds) book.hold(mind.events, LATER);
  const challenges = new Challenges();
  challenges.issue(NONCE, at(issued));
  const server: HelloServer = { origin: ORIGIN, now: at(seconds), challenges, view: book, seen };
  return { server, challenges, seen };
}

function refusal(value: unknown, server: HelloServer) {
  const result = verifyHello(value, server);
  if (result.ok) throw new Error("the Hello was accepted");
  return { clause: result.issues[0].clause, path: result.issues[0].path };
}

describe(`${clause("L1 13.3")} a Hello`, () => {
  it("authenticates the mind that signed the server's challenge for the server's origin", () => {
    const { server, challenges, seen } = serverAt(100);
    const record = hello(ada, 99);
    const result = verifyHello(record, server);
    expect(result).toStrictEqual({
      ok: true,
      value: { mind: ada.address, challenge: NONCE, key: ada.operational().publicKey },
    });
    // The challenge is used up, and the proof was first seen now.
    expect(challenges.size).toBe(0);
    expect(seen.proofSeen(proofDigest(record.proof[0] as never))).toBe(at(100));
  });

  it("is good once: the same Hello again answers no open challenge", () => {
    const { server } = serverAt(100);
    const record = hello(ada, 99);
    expect(verifyHello(record, server).ok).toBe(true);
    expect(refusal(record, server)).toStrictEqual({
      clause: "L1 13.3",
      path: "/proof/0/challenge",
    });
  });

  it(`${clause("L1 19")} answers a challenge this server issued within the last 300 seconds`, () => {
    const record = hello(ada, 99);
    expect(verifyHello(record, serverAt(400, 100).server).ok).toBe(true);
    expect(refusal(record, serverAt(400.000000001, 100).server).path).toBe("/proof/0/challenge");
    // One the server says it issued later than now was not issued yet.
    expect(refusal(record, serverAt(100, 101).server).path).toBe("/proof/0/challenge");
    // One it never issued, and none at all.
    const { server } = serverAt(100);
    expect(
      refusal(hello(ada, 99, { challenge: "another-nonce-0001", domain: ORIGIN }), server),
    ).toStrictEqual({
      clause: "L1 13.3",
      path: "/proof/0/challenge",
    });
    expect(refusal(hello(ada, 99, { domain: ORIGIN }), server).path).toBe("/proof/0/challenge");
  });

  it("is for this server's origin, and no other", () => {
    const { server, challenges } = serverAt(100);
    for (const domain of [
      "https://relay.example",
      "https://host.example/",
      "https://host.example:8443",
      "http://host.example",
      "HTTPS://HOST.EXAMPLE",
    ]) {
      expect(refusal(hello(ada, 99, { challenge: NONCE, domain }), server), domain).toStrictEqual({
        clause: "L1 13.3",
        path: "/proof/0/domain",
      });
    }
    expect(refusal(hello(ada, 99, { challenge: NONCE }), server).path).toBe("/proof/0/domain");
    // A Hello that fails leaves the challenge open for the mind it was sent to.
    expect(challenges.size).toBe(1);
    expect(verifyHello(hello(ada, 99), server).ok).toBe(true);
  });

  it("carries a single proof", () => {
    const { server, challenges } = serverAt(100);
    const twice = eve.sign(hello(ada, 99), { more: { challenge: NONCE, domain: ORIGIN } });
    expect(refusal(twice, server)).toStrictEqual({ clause: "L1 13.3", path: "/proof" });
    expect(challenges.size).toBe(1);
  });

  it("is signed by the mind it names, with an authentication proof that verifies", () => {
    const { server, challenges } = serverAt(100);
    // In Ada's name, by Eve.
    const forged = eve.sign(
      { oip: "1", type: "Hello", author: ada.address, created: T(99) },
      { more: { challenge: NONCE, domain: ORIGIN } },
    );
    expect(refusal(forged, server)).toStrictEqual({ clause: "L1 6.1", path: "/proof/0" });
    // Eve's attempt leaves the challenge open: only the holder of Ada's key can use it up.
    expect(challenges.size).toBe(1);
    // A signature changed on the way.
    const record = hello(ada, 99);
    const [proof] = record.proof as [JsonObject];
    const value = String(proof["proofValue"]);
    const changed = { ...record, proof: [{ ...proof, proofValue: `${value.slice(0, -1)}z` }] };
    expect(refusal(changed, server)).toStrictEqual({ clause: "L1 13.3", path: "/proof/0" });
    // Another record that Ada signed is no Hello.
    const intent = ada.sign({
      oip: "1",
      type: "Intent",
      author: ada.address,
      created: T(99),
      want: "To come in.",
    });
    expect(refusal(intent, server)).toStrictEqual({ clause: "L1 13.3", path: "/type" });
  });

  it(`${clause("L1 6.1")} is signed with a key of the latest state the server knows`, () => {
    const zed = new KeyMind("zed");
    const before = hello(zed, 50);
    // By a key that was valid when the Hello was made, and has been removed since.
    zed.update(60, { keys: [{ key: zed.operational(1).publicKey }] });
    expect(refusal(before, serverAt(100, 95, [zed]).server)).toStrictEqual({
      clause: "L1 6.1",
      path: "/proof/0",
    });
    const current = hello(zed, 99, { challenge: NONCE, domain: ORIGIN }, 1);
    expect(verifyHello(current, serverAt(100, 95, [zed]).server).ok).toBe(true);
    // A mind whose log the server does not hold.
    expect(refusal(hello(ada, 99), serverAt(100, 95, [zed]).server).clause).toBe("L1 6.1");
  });

  it("needs evidence for its proof: the server's own first sight, which `seen` records", () => {
    const { server } = serverAt(100);
    const { seen: _, ...without } = server;
    expect(refusal(hello(ada, 99), without).clause).toBe("L1 6.1");
  });

  it(`${clause("core 8.3")} is accepted with a critical extension only by a server that implements it`, () => {
    const record = ada.sign(
      {
        oip: "1",
        type: "Hello",
        author: ada.address,
        created: T(99),
        ext: { "com.example": { client: "a client" } },
        critical: ["com.example"],
      },
      { more: { challenge: NONCE, domain: ORIGIN } },
    );
    const { server } = serverAt(100);
    expect(refusal(record, server)).toStrictEqual({ clause: "core 8.3", path: "/critical" });
    expect(verifyHello(record, { ...server, understood: ["com.example"] }).ok).toBe(true);
  });

  it("stands for the Hello of the test vectors", () => {
    const cases = (readVectors() as unknown as { cases: Record<string, JsonObject> }).cases;
    const record = cases["hello"] as Signed;
    const log = cases["lexis_agent_log"] as unknown as JsonObject[];
    const seen = witness([log]);
    const book = new LogBook(seen);
    book.hold(log, LATER);
    const [proof] = record.proof as [{ challenge: string; domain: string; created: string }];
    const now = BigInt(Date.parse(proof.created)) * 1_000_000n + 1_000_000_000n;
    const challenges = new Challenges();
    challenges.issue(proof.challenge, now - 2_000_000_000n);
    const result = verifyHello(record, { origin: proof.domain, now, challenges, view: book, seen });
    expect(result.ok && result.value.mind).toBe(record["author"]);
  });

  it("never throws on what arrives, and takes its own arguments as the caller's", () => {
    const { server } = serverAt(100);
    fc.assert(
      fc.property(fc.anything(), (value) => {
        expect(verifyHello(value, server).ok).toBe(false);
      }),
      { numRuns: 200 },
    );
    expect(() => verifyHello(hello(ada, 99), { ...server, now: 100 as never })).toThrow(TypeError);
    expect(() => verifyHello(hello(ada, 99), { ...server, origin: undefined as never })).toThrow(
      TypeError,
    );
  });
});

describe(`${clause("L1 13.3")} the challenges a server has issued`, () => {
  it("are each open from when they are issued until they are used or 300 seconds have passed", () => {
    const challenges = new Challenges();
    challenges.issue("nonce-a", at(10));
    challenges.issue("nonce-b", at(200));
    expect(challenges.issuedAt("nonce-a")).toBe(at(10));
    expect(challenges.issuedAt("nonce-c")).toBeUndefined();
    expect(challenges.size).toBe(2);
    expect(challenges.forget(at(310))).toBe(0);
    expect(challenges.forget(at(310.000000001))).toBe(1);
    expect(challenges.issuedAt("nonce-a")).toBeUndefined();
    challenges.use("nonce-b");
    challenges.use("nonce-b");
    expect(challenges.size).toBe(0);
  });

  it("are issued once each, as strings, at a time", () => {
    const challenges = new Challenges();
    challenges.issue("nonce-a", at(10));
    expect(() => challenges.issue("nonce-a", at(20))).toThrow(TypeError);
    expect(() => challenges.issue("", at(20))).toThrow(TypeError);
    expect(() => challenges.issue(7 as never, at(20))).toThrow(TypeError);
    expect(() => challenges.issue("nonce-b", 20 as never)).toThrow(TypeError);
    expect(() => challenges.forget(20 as never)).toThrow(TypeError);
    expect(challenges.issuedAt("nonce-a")).toBe(at(10));
  });
});
