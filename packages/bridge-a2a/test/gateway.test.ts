// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A gateway bridges A2A agents (Layer 0, 1.2 and 3.1), against a real
 * resolver, host and indexer on ports of this machine. The agents are
 * their cards: what a gateway reads before it speaks to one.
 */

import type { webcrypto } from "node:crypto";
import { existsSync } from "node:fs";

import { canonicalBytes, sha256Digest } from "@oip/core";
import { UsageError } from "@oip/local";
import { clause } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { BridgeError, Gateway, type GatewayEdges, type KeySource } from "../src/index.ts";
import { cardOf, Place, served } from "./harness.ts";

let place: Place;
let gatewayAddress: string;
/** What each origin serves at its card's path: bytes, a status, or nothing at all. */
const cards = new Map<string, Uint8Array | number>();
let keys: KeySource = () => Promise.resolve([]);

const edges: GatewayEdges = {
  get: (url) => {
    const answer = cards.get(new URL(url).origin);
    if (!url.endsWith("/.well-known/agent-card.json") || answer === undefined) {
      return Promise.reject(new Error("the host's name did not resolve"));
    }
    return Promise.resolve(
      typeof answer === "number"
        ? { status: answer, body: new Uint8Array() }
        : { status: 200, body: answer },
    );
  },
  ask: () => Promise.reject(new Error("no request is made of an agent while it is bridged")),
  keys: (wanted) => keys(wanted),
};

beforeAll(async () => {
  place = await new Place().start();
  gatewayAddress = await place.make("gateway", { kind: "service" });
});
afterAll(async () => {
  await place.close();
});

const gateway = (): Gateway => new Gateway(place.where("gateway"), edges);

/** What bridging is refused with. */
async function refusal(origin: string): Promise<string> {
  try {
    await gateway().bridge(origin);
  } catch (error) {
    if (error instanceof BridgeError) return error.code;
    throw error;
  }
  throw new Error("the agent was bridged");
}

describe("a gateway bridging an A2A agent", () => {
  const LEXIS = "https://lexis.example";

  it(`${clause("L0 1.2", "L0 3.1")} makes a bridged mind: a service the gateway names itself in, attests in its own feed, and describes by the card`, async () => {
    const body = served(cardOf(LEXIS));
    cards.set(LEXIS, body);
    const bridged = await gateway().bridge(LEXIS);
    expect(bridged).toMatchObject({
      origin: LEXIS,
      cardDigest: sha256Digest(body),
      signed: false,
      extension: false,
      interface: { url: `${LEXIS}/a2a/v1`, protocolBinding: "JSONRPC", protocolVersion: "1.0" },
    });
    expect(bridged.attestation.startsWith(`${gatewayAddress}/`)).toBe(true);

    // As anyone on the network finds it.
    const reader = place.reader();
    const resolved = await reader.resolve(bridged.mind);
    expect(resolved.state.kind).toBe("service");
    const block = {
      protocol: "a2a",
      endpoint: LEXIS,
      gateway: gatewayAddress,
      assurance: "bridged",
    };
    expect(resolved.log.entries[0].event.ext).toStrictEqual({ "oip.bridge": block });
    expect(resolved.participant?.record).toMatchObject({
      name: "Lexis translation agent",
      summary: "Translates legal texts between Swahili and English.",
      kind: "service",
      capabilities: [
        {
          id: "translate",
          summary: "Translate: Translates a lease.",
          tags: ["a2a:translation", "a2a:legal"],
        },
      ],
      interfaces: { a2a: `${LEXIS}/a2a/v1` },
      ext: {
        "oip.bridge": { ...block, attestation: bridged.attestation },
        // The digest of the exact bytes the agent's origin served.
        "oip.a2a": { cardDigest: sha256Digest(body) },
      },
    });
    expect(resolved.location?.record.status).toBe("active");
  });

  it(`${clause("L0 1.3")} is found \`bridged\` by a client that asks: the gateway's feed attests the mind`, async () => {
    const bridged = gateway().bridged(LEXIS);
    if (bridged === undefined) throw new Error("the agent is not bridged");
    expect(await place.reader().assurance(bridged.mind)).toStrictEqual({
      level: "bridged",
      gateway: gatewayAddress,
      protocol: "a2a",
      endpoint: LEXIS,
    });
  });

  it("makes no second mind and signs nothing new for an agent it bridges already", async () => {
    const before = gateway().bridged(LEXIS);
    const profile = (await place.reader().resolve(before?.mind ?? "")).participant?.id;
    const feed = (await place.reader().feed(gatewayAddress)).feed.entries.length;
    const again = await gateway().bridge(LEXIS);
    expect(again).toStrictEqual(before);
    expect((await place.reader().resolve(again.mind)).participant?.id).toBe(profile);
    expect((await place.reader().feed(gatewayAddress)).feed.entries).toHaveLength(feed);
  });

  it(`${clause("L0 3.1")} brings the profile up to a card that has changed, for the same mind under the same attestation`, async () => {
    const before = gateway().bridged(LEXIS);
    const changed = served(
      cardOf(LEXIS, {
        skills: [
          { id: "translate", name: "Translate", description: "Translates a lease.", tags: [] },
          { id: "review", name: "Review", description: "Reviews a translation.", tags: [] },
        ],
      }),
    );
    cards.set(LEXIS, changed);
    const after = await gateway().bridge(LEXIS);
    expect(after).toMatchObject({
      mind: before?.mind,
      attestation: before?.attestation,
      cardDigest: sha256Digest(changed),
    });
    const profile = (await place.reader().resolve(after.mind)).participant?.record;
    expect(profile?.capabilities?.map(({ id }) => id)).toStrictEqual(["translate", "review"]);
    expect(profile?.ext?.["oip.a2a"]).toStrictEqual({ cardDigest: sha256Digest(changed) });
    expect((await place.reader().assurance(after.mind)).level).toBe("bridged");
  });

  it("makes a mind of its own for each agent", async () => {
    const OTHER = "https://other-agent.example";
    cards.set(OTHER, served(cardOf(OTHER, { name: "Another agent", skills: [] })));
    const other = await gateway().bridge(OTHER);
    expect(other.mind).not.toBe(gateway().bridged(LEXIS)?.mind);
    const profile = (await place.reader().resolve(other.mind)).participant?.record;
    expect(profile?.name).toBe("Another agent");
    expect(profile).not.toHaveProperty("capabilities");
  });

  it(`${clause("L0 3.3")} notes that an agent declares the OIP extension`, async () => {
    const ORIGIN = "https://extended.example";
    const uri =
      "https://github.com/wonderben-code/open-intelligence-protocol/blob/main/spec/layer-0-bridge.md#a2a-extension";
    cards.set(ORIGIN, served(cardOf(ORIGIN, { capabilities: { extensions: [{ uri }] } })));
    expect((await gateway().bridge(ORIGIN)).extension).toBe(true);
  });
});

describe("an agent a gateway does not bridge", () => {
  it("is one whose card cannot be had, is no card, or names no interface the gateway speaks", async () => {
    await expect(gateway().bridge("http://plain.example")).rejects.toThrow(UsageError);
    await expect(gateway().bridge("https://agent.example/path")).rejects.toThrow(UsageError);
    expect(await refusal("https://nowhere.example")).toBe("unreachable");
    cards.set("https://missing.example", 404);
    expect(await refusal("https://missing.example")).toBe("no-card");
    cards.set("https://broken.example", served({ name: "Half a card" }));
    expect(await refusal("https://broken.example")).toBe("invalid-card");
    const GRPC = "https://grpc-only.example";
    cards.set(
      GRPC,
      served(
        cardOf(GRPC, {
          supportedInterfaces: [
            { url: `${GRPC}/grpc`, protocolBinding: "GRPC", protocolVersion: "1.0" },
          ],
        }),
      ),
    );
    expect(await refusal(GRPC)).toBe("no-interface");
    // Nothing was made for any of them.
    for (const origin of [
      "https://nowhere.example",
      "https://missing.example",
      "https://broken.example",
      GRPC,
    ]) {
      expect(gateway().bridged(origin)).toBeUndefined();
    }
  });

  it(`${clause("L0 3.1")} is one whose card is signed and does not verify`, async () => {
    const ORIGIN = "https://signed.example";
    const card = cardOf(ORIGIN);
    const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
      "sign",
      "verify",
    ])) as unknown as webcrypto.CryptoKeyPair;
    const header = Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JOSE", kid: "k1" })).toString(
      "base64url",
    );
    const input = `${header}.${Buffer.from(canonicalBytes(card as never)).toString("base64url")}`;
    const signature = Buffer.from(
      await crypto.subtle.sign(
        { name: "Ed25519" },
        pair.privateKey,
        new TextEncoder().encode(input),
      ),
    ).toString("base64url");
    cards.set(ORIGIN, served({ ...card, signatures: [{ protected: header, signature }] }));
    // The gateway has no key for it: a signature is not taken on trust.
    keys = () => Promise.resolve([]);
    expect(await refusal(ORIGIN)).toBe("unverified-card");
    expect(gateway().bridged(ORIGIN)).toBeUndefined();
    // With the key its operator lets stand for the agent, it is bridged, and said to be signed.
    const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
    keys = () => Promise.resolve([jwk]);
    expect((await gateway().bridge(ORIGIN)).signed).toBe(true);
    // The card with another name, under the same signature.
    cards.set(
      ORIGIN,
      served({ ...card, name: "An impostor", signatures: [{ protected: header, signature }] }),
    );
    expect(await refusal(ORIGIN)).toBe("unverified-card");
    keys = () => Promise.resolve([]);
  });

  it(`${clause("L0 1.2")} is any agent, for a gateway whose mind has no home: it has no feed to attest in`, async () => {
    await place.make("homeless", { kind: "service", homes: [] });
    const ORIGIN = "https://someone.example";
    cards.set(ORIGIN, served(cardOf(ORIGIN)));
    const homeless = new Gateway(place.where("homeless"), edges);
    await expect(homeless.bridge(ORIGIN)).rejects.toThrow("names no home");
    expect(existsSync(`${place.where("homeless").dir}/agents`)).toBe(false);
  });
});
