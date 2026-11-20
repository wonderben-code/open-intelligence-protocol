// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The signatures on an Agent Card (A2A, Section 8.4), which a gateway
 * verifies before it bridges the card's agent (Layer 0, 3.1). The cards
 * here are signed as A2A says, with keys the platform makes.
 */

import type { webcrypto } from "node:crypto";

import { canonicalBytes } from "@oip/core";
import { clause } from "@oip/testkit";
import { beforeAll, describe, expect, it } from "vitest";

import { type KeySource, type PublicJwk, readCard, verifySignatures } from "../src/index.ts";

const CARD = {
  name: "Example Agent",
  description: "An example agent that echoes messages.",
  supportedInterfaces: [
    { url: "https://example.com/a2a/v1", protocolBinding: "JSONRPC", protocolVersion: "1.0" },
  ],
  version: "1.0.0",
  capabilities: { streaming: false, pushNotifications: false },
  defaultInputModes: ["text/plain"],
  defaultOutputModes: ["text/plain"],
  skills: [{ id: "echo", name: "Echo", description: "Echoes the input.", tags: ["echo"] }],
};
type Card = Record<string, unknown>;

const b64 = (bytes: Uint8Array | string): string => Buffer.from(bytes).toString("base64url");

/** A key pair of an algorithm, as the platform makes one. */
const GENERATED: Record<
  string,
  [
    webcrypto.AlgorithmIdentifier | webcrypto.RsaHashedKeyGenParams | webcrypto.EcKeyGenParams,
    object,
  ]
> = {
  ES256: [
    { name: "ECDSA", namedCurve: "P-256" },
    { name: "ECDSA", hash: "SHA-256" },
  ],
  ES384: [
    { name: "ECDSA", namedCurve: "P-384" },
    { name: "ECDSA", hash: "SHA-384" },
  ],
  ES512: [
    { name: "ECDSA", namedCurve: "P-521" },
    { name: "ECDSA", hash: "SHA-512" },
  ],
  RS256: [
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: Uint8Array.of(1, 0, 1),
      hash: "SHA-256",
    },
    { name: "RSASSA-PKCS1-v1_5" },
  ],
  PS256: [
    {
      name: "RSA-PSS",
      modulusLength: 2048,
      publicExponent: Uint8Array.of(1, 0, 1),
      hash: "SHA-256",
    },
    { name: "RSA-PSS", saltLength: 32 },
  ],
  EdDSA: [{ name: "Ed25519" }, { name: "Ed25519" }],
};

interface Signer {
  readonly alg: string;
  readonly kid: string;
  readonly jwk: PublicJwk;
  /** One entry of a card's `signatures`, over the card given. */
  sign(
    card: Card,
    header?: Record<string, unknown>,
  ): Promise<{ protected: string; signature: string }>;
}

async function signer(alg: string, kid: string): Promise<Signer> {
  const [generate, signing] = GENERATED[alg] ?? [];
  if (generate === undefined || signing === undefined) throw new Error(`no such algorithm: ${alg}`);
  const pair = (await crypto.subtle.generateKey(generate, true, [
    "sign",
    "verify",
  ])) as webcrypto.CryptoKeyPair;
  const jwk = { ...(await crypto.subtle.exportKey("jwk", pair.publicKey)), kid } as PublicJwk;
  return {
    alg,
    kid,
    jwk,
    sign: async (card, header = {}) => {
      const { signatures: _, ...payload } = card;
      const protectedHeader = b64(JSON.stringify({ alg, typ: "JOSE", kid, ...header }));
      const input = new TextEncoder().encode(`${protectedHeader}.${b64(canonicalBytes(payload))}`);
      const signature = await crypto.subtle.sign(
        signing as webcrypto.AlgorithmIdentifier,
        pair.privateKey,
        input,
      );
      return { protected: protectedHeader, signature: b64(new Uint8Array(signature)) };
    },
  };
}

/** A source that has these keys, and remembers what it was asked for. */
function source(...keys: PublicJwk[]): KeySource & { asked: { kid: string; jku?: string }[] } {
  const asked: { kid: string; jku?: string }[] = [];
  const give: KeySource = (wanted) => {
    asked.push(wanted);
    return Promise.resolve(keys);
  };
  return Object.assign(give, { asked });
}

/** What verifying a card came to: the keys that verified, or where it was refused and why. */
async function verified(card: Card, keys: KeySource) {
  const read = readCard(new TextEncoder().encode(JSON.stringify(card)));
  if (!read.ok) throw new Error(JSON.stringify(read.issues));
  const result = await verifySignatures(read.value, keys);
  return result.ok
    ? result.value
    : {
        refused: result.issues[0].path,
        why: result.issues[0].message,
        clause: result.issues[0].clause,
      };
}

let es256: Signer;
let other: Signer;
beforeAll(async () => {
  es256 = await signer("ES256", "key-1");
  other = await signer("ES256", "key-1");
});

describe(`${clause("L0 3.1")} the signatures on an Agent Card`, () => {
  it("are none on a card nobody signed, which A2A lets a card be", async () => {
    const keys = source();
    expect(await verified(CARD, keys)).toStrictEqual({ signed: false, verifiedBy: [] });
    expect(keys.asked).toStrictEqual([]);
  });

  it.each(Object.keys(GENERATED))(
    "verify under %s, by the key the source gives for them",
    async (alg) => {
      const by = await signer(alg, `a-key-for-${alg}`);
      const card = { ...CARD, signatures: [await by.sign(CARD)] };
      expect(await verified(card, source(by.jwk))).toStrictEqual({
        signed: true,
        verifiedBy: [`a-key-for-${alg}`],
      });
    },
  );

  it("tell the source which key is named, and where the signer says its keys are", async () => {
    const keys = source(es256.jwk);
    const signature = await es256.sign(CARD, { jku: "https://example.com/agent/jwks.json" });
    await verified({ ...CARD, signatures: [signature] }, keys);
    expect(keys.asked).toStrictEqual([
      { kid: "key-1", jku: "https://example.com/agent/jwks.json" },
    ]);
    const plain = source(es256.jwk);
    await verified({ ...CARD, signatures: [await es256.sign(CARD)] }, plain);
    expect(plain.asked).toStrictEqual([{ kid: "key-1" }]);
  });

  it("do not verify over a card that was changed after it was signed", async () => {
    const signature = await es256.sign(CARD);
    for (const changed of [
      { name: "Another Agent" },
      { skills: [...CARD.skills, { id: "pay", name: "Pay", description: "Pays.", tags: [] }] },
      {
        supportedInterfaces: [{ ...CARD.supportedInterfaces[0], url: "https://evil.example/a2a" }],
      },
    ]) {
      expect(
        await verified({ ...CARD, ...changed, signatures: [signature] }, source(es256.jwk)),
      ).toMatchObject({
        refused: "/signatures/0",
        clause: "L0 3.1",
      });
    }
  });

  it("do not verify under another key, though it bears the same name", async () => {
    const card = { ...CARD, signatures: [await es256.sign(CARD)] };
    expect(await verified(card, source(other.jwk))).toMatchObject({ refused: "/signatures/0" });
    // Of two keys the source gives for a name, one that verifies is enough.
    expect(await verified(card, source(other.jwk, es256.jwk))).toMatchObject({ signed: true });
  });

  it("are not taken on trust: a signed card with no key to verify it by is refused", async () => {
    const card = { ...CARD, signatures: [await es256.sign(CARD)] };
    expect(await verified(card, source())).toStrictEqual({
      refused: "/signatures",
      why: "the card is signed, and there is no key to verify any of its signatures by",
      clause: "L0 3.1",
    });
    // A key that says it is another is not the key that was named.
    expect(await verified(card, source({ ...es256.jwk, kid: "key-2" }))).toMatchObject({
      refused: "/signatures",
    });
    // A key with no name of its own is taken for the one asked for.
    const { kid: _, ...nameless } = es256.jwk;
    expect(await verified(card, source(nameless))).toMatchObject({ signed: true });
  });

  it("may be several: one that verifies is enough where the others have no key, and one that is wrong refuses the card", async () => {
    const old = await signer("ES256", "key-of-last-year");
    const both = { ...CARD, signatures: [await old.sign(CARD), await es256.sign(CARD)] };
    // The agent changed its key, and signs with both for a while: the source has the new one.
    expect(await verified(both, source(es256.jwk))).toStrictEqual({
      signed: true,
      verifiedBy: ["key-1"],
    });
    expect(await verified(both, source(es256.jwk, old.jwk))).toStrictEqual({
      signed: true,
      verifiedBy: ["key-of-last-year", "key-1"],
    });
    // One signature is over another card.
    const forged = {
      ...CARD,
      signatures: [await es256.sign(CARD), await old.sign({ ...CARD, name: "x" })],
    };
    expect(await verified(forged, source(es256.jwk, old.jwk))).toMatchObject({
      refused: "/signatures/1",
    });
  });

  it("are over the card without its defaults, whether or not the server wrote them", async () => {
    // The signer left out what is empty, as A2A 8.4.1 says. The server writes it all the same.
    const signature = await es256.sign(CARD);
    const served = {
      ...CARD,
      supportedInterfaces: [{ ...CARD.supportedInterfaces[0], tenant: "" }],
      capabilities: { ...CARD.capabilities, extensions: [] },
      securitySchemes: {},
      securityRequirements: [],
      skills: [{ ...CARD.skills[0], examples: [], inputModes: [], outputModes: [] }],
      signatures: [signature],
    };
    expect(await verified(served, source(es256.jwk))).toMatchObject({ signed: true });
    // A signer that signed the card as it is served, with what is empty in it, verifies too.
    const literal = { ...served, signatures: [] as unknown[] };
    literal.signatures = [await es256.sign(literal)];
    expect(await verified(literal, source(es256.jwk))).toMatchObject({ signed: true });
    // What is not a default is part of what was signed: an extension that is required, a tenant.
    const required = {
      ...CARD,
      capabilities: {
        extensions: [{ uri: "https://example.com/ext", required: true, description: "" }],
      },
    };
    const signedRequired = { ...required, signatures: [await es256.sign(required)] };
    expect(await verified(signedRequired, source(es256.jwk))).toMatchObject({ signed: true });
    const dropped = {
      ...signedRequired,
      capabilities: { extensions: [{ uri: "https://example.com/ext", required: false }] },
    };
    expect(await verified(dropped, source(es256.jwk))).toMatchObject({ refused: "/signatures/0" });
  });

  it("name an algorithm of a key the reader does not hold: not `none`, and not a shared secret", async () => {
    const real = await es256.sign(CARD);
    for (const alg of ["none", "HS256", "ES256K", "es256", "", 7, undefined]) {
      const header = b64(JSON.stringify({ alg, typ: "JOSE", kid: "key-1" }));
      const card = { ...CARD, signatures: [{ protected: header, signature: real.signature }] };
      expect(await verified(card, source(es256.jwk)), String(alg)).toMatchObject({
        refused: "/signatures/0/protected",
        why: "the signature names no algorithm that is taken",
      });
    }
  });

  it("are refused where they say something that must be understood, name no key, or are not what a signature is", async () => {
    const real = await es256.sign(CARD);
    const withHeader = (header: unknown): Card => ({
      ...CARD,
      signatures: [
        {
          protected: typeof header === "string" ? header : b64(JSON.stringify(header)),
          signature: real.signature,
        },
      ],
    });
    const keys = source(es256.jwk);
    expect(
      await verified(withHeader({ alg: "ES256", kid: "key-1", crit: ["exp"], exp: 1 }), keys),
    ).toMatchObject({
      refused: "/signatures/0/protected",
      why: "the signature marks a header as critical that is not understood",
    });
    for (const header of [{ alg: "ES256" }, { alg: "ES256", kid: "" }, { alg: "ES256", kid: 7 }]) {
      expect(await verified(withHeader(header), keys)).toMatchObject({
        refused: "/signatures/0/protected",
        why: "the signature names no key",
      });
    }
    for (const header of ["not base64url!", b64("not json"), b64("[1]"), b64('"text"'), "a"]) {
      expect(await verified(withHeader(header), keys), header).toMatchObject({
        refused: "/signatures/0/protected",
      });
    }
    for (const signature of [
      "AAAA",
      "not base64url!",
      b64(new Uint8Array(63)),
      b64(new Uint8Array(65)),
    ]) {
      const card = { ...CARD, signatures: [{ protected: real.protected, signature }] };
      expect(await verified(card, keys), signature).toMatchObject({
        refused: "/signatures/0/signature",
      });
    }
  });

  it("are not verified by a key of another kind, or by one too short to trust", async () => {
    const rsa = await signer("RS256", "key-1");
    const card = { ...CARD, signatures: [await es256.sign(CARD)] };
    // An RSA key under the name of the elliptic one: no key for this signature.
    expect(await verified(card, source(rsa.jwk))).toMatchObject({ refused: "/signatures" });
    const weak = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 1024,
        publicExponent: Uint8Array.of(1, 0, 1),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    );
    const header = b64(JSON.stringify({ alg: "RS256", typ: "JOSE", kid: "weak" }));
    const input = new TextEncoder().encode(`${header}.${b64(canonicalBytes(CARD))}`);
    const signature = b64(
      new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", weak.privateKey, input)),
    );
    const weakly = { ...CARD, signatures: [{ protected: header, signature }] };
    const jwk = (await crypto.subtle.exportKey("jwk", weak.publicKey)) as PublicJwk;
    expect(await verified(weakly, source(jwk))).toMatchObject({ refused: "/signatures" });
    // Members that are no key at all.
    for (const broken of [
      { kty: "EC", crv: "P-256", x: 7 },
      { kty: "EC", crv: "P-256", x: "AA" },
      { kty: "EC", crv: "P-256", x: "AA", y: "AA" },
      {},
    ]) {
      expect(await verified(card, source(broken))).toMatchObject({ refused: "/signatures" });
    }
  });

  it("are not verified on a card that holds a number with a fraction: it has no canonical form here", async () => {
    const fractional = {
      ...CARD,
      capabilities: {
        extensions: [{ uri: "https://example.com/ext", params: { threshold: 0.5 } }],
      },
    };
    expect(
      await verified({ ...fractional, signatures: [await es256.sign(CARD)] }, source(es256.jwk)),
    ).toMatchObject({
      refused: "",
      clause: "L0 3.1",
    });
    // Unsigned, the same card is read: nothing needs its canonical form.
    expect(await verified(fractional, source())).toStrictEqual({ signed: false, verifiedBy: [] });
  });
});
