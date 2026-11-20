// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** An Agent Card, read as something a stranger wrote (Layer 0, 3.1). */

import { sha256Digest } from "@oip/core";
import { clause } from "@oip/testkit";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  interfaceOf,
  MAX_CARD_BYTES,
  MAX_CARD_ITEMS,
  MAX_CARD_TEXT,
  readCard,
  supports,
} from "../src/index.ts";

/** The sample card of the A2A specification, Section 8.4.1, with a skill and an extension more. */
const SAMPLE = {
  name: "Example Agent",
  description: "An example agent that echoes messages.",
  supportedInterfaces: [
    { url: "https://example.com/a2a/v1", protocolBinding: "JSONRPC", protocolVersion: "1.0" },
  ],
  version: "1.0.0",
  capabilities: {
    streaming: false,
    pushNotifications: false,
    extensions: [{ uri: "https://example.com/extensions/geolocation/v1", required: false }],
  },
  defaultInputModes: ["text/plain"],
  defaultOutputModes: ["text/plain"],
  skills: [{ id: "echo", name: "Echo", description: "Echoes the input.", tags: ["echo"] }],
};

const bytesOf = (value: unknown): Uint8Array =>
  new TextEncoder().encode(typeof value === "string" ? value : JSON.stringify(value));

/** The card read from a value, or the places it was refused at. */
function read(value: unknown) {
  const result = readCard(bytesOf(value));
  return result.ok
    ? { card: result.value.card }
    : { refused: result.issues.map(({ path, clause: broken }) => `${path} (${broken})`) };
}

describe(`${clause("L0 3.1")} an Agent Card`, () => {
  it("is read as what a gateway uses of it, with the digest of the exact bytes that were served", () => {
    // The same card, served with other spacing, is other bytes.
    const compact = bytesOf(JSON.stringify(SAMPLE));
    const spaced = bytesOf(JSON.stringify(SAMPLE, undefined, 2));
    const first = readCard(compact);
    const second = readCard(spaced);
    if (!first.ok || !second.ok) throw new Error("the sample card was refused");
    expect(first.value.card).toStrictEqual({
      name: "Example Agent",
      description: "An example agent that echoes messages.",
      version: "1.0.0",
      supportedInterfaces: [
        { url: "https://example.com/a2a/v1", protocolBinding: "JSONRPC", protocolVersion: "1.0" },
      ],
      skills: [{ id: "echo", name: "Echo", description: "Echoes the input.", tags: ["echo"] }],
      extensions: [{ uri: "https://example.com/extensions/geolocation/v1", required: false }],
      defaultInputModes: ["text/plain"],
      defaultOutputModes: ["text/plain"],
      signatures: [],
    });
    expect(second.value.card).toStrictEqual(first.value.card);
    expect(first.value.digest).toBe(sha256Digest(compact));
    expect(first.value.digest).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(second.value.digest).toBe(sha256Digest(spaced));
    expect(second.value.digest).not.toBe(first.value.digest);
    // The whole of it is kept as it was read: a signature is over that, and not over the part used.
    expect(first.value.json).toStrictEqual(SAMPLE);
  });

  it("keeps a tenant, the signatures, and whether an extension is required", () => {
    const { card } = read({
      ...SAMPLE,
      supportedInterfaces: [{ ...SAMPLE.supportedInterfaces[0], tenant: "acme" }],
      capabilities: { extensions: [{ uri: "https://example.com/ext", required: true }] },
      signatures: [{ protected: "eyJhbGciOiJFUzI1NiJ9", signature: "QFdk", header: { kid: "1" } }],
    });
    expect(card?.supportedInterfaces[0]?.tenant).toBe("acme");
    expect(card?.extensions).toStrictEqual([{ uri: "https://example.com/ext", required: true }]);
    expect(card?.signatures).toStrictEqual([
      { protected: "eyJhbGciOiJFUzI1NiJ9", signature: "QFdk" },
    ]);
    expect(card === undefined ? false : supports(card, "https://example.com/ext")).toBe(true);
    expect(card === undefined ? true : supports(card, "https://example.com/other")).toBe(false);
  });

  it("is refused where it is not JSON, not an object, or too long to read", () => {
    for (const served of ["", "not json", "[]", "null", "7", '"a card"', "{"]) {
      expect(read(served).refused, served).toStrictEqual([" (L0 3.1)"]);
    }
    expect(readCard(Uint8Array.of(0x7b, 0x22, 0xff, 0x22, 0x7d)).ok).toBe(false);
    const long = { ...SAMPLE, description: "x".repeat(MAX_CARD_BYTES) };
    expect(read(long).refused).toStrictEqual([" (L0 3.1)"]);
  });

  it("is refused where a member a gateway uses is missing, or is something else, with each such place", () => {
    const { name: _, ...nameless } = SAMPLE;
    expect(read(nameless).refused).toStrictEqual(["/name (L0 3.1)"]);
    expect(read({ ...SAMPLE, name: "", version: 2, description: ["x"] }).refused).toStrictEqual([
      "/name (L0 3.1)",
      "/description (L0 3.1)",
      "/version (L0 3.1)",
    ]);
    expect(read({ ...SAMPLE, capabilities: "none" }).refused).toStrictEqual([
      "/capabilities (L0 3.1)",
    ]);
    expect(read({ ...SAMPLE, supportedInterfaces: [] }).refused).toStrictEqual([
      "/supportedInterfaces (L0 3.1)",
    ]);
    expect(read({ ...SAMPLE, supportedInterfaces: "https://example.com" }).refused).toStrictEqual([
      "/supportedInterfaces (L0 3.1)",
    ]);
    expect(
      read({ ...SAMPLE, supportedInterfaces: [{ url: "https://example.com" }, "another"] }).refused,
    ).toStrictEqual([
      "/supportedInterfaces/1 (L0 3.1)",
      "/supportedInterfaces/0/protocolBinding (L0 3.1)",
      "/supportedInterfaces/0/protocolVersion (L0 3.1)",
    ]);
    expect(
      read({
        ...SAMPLE,
        skills: [{ id: "a", name: "A", description: "An a.", tags: ["ok", 7, ""] }],
      }).refused,
    ).toStrictEqual(["/skills/0/tags/1 (L0 3.1)", "/skills/0/tags/2 (L0 3.1)"]);
    expect(read({ ...SAMPLE, signatures: [{ protected: "abc" }] }).refused).toStrictEqual([
      "/signatures/0/signature (L0 3.1)",
    ]);
  });

  it("is refused where a text or a list is longer than is read", () => {
    expect(read({ ...SAMPLE, name: "x".repeat(MAX_CARD_TEXT + 1) }).refused).toStrictEqual([
      "/name (L0 3.1)",
    ]);
    expect(read({ ...SAMPLE, name: "x".repeat(MAX_CARD_TEXT) }).card?.name).toHaveLength(
      MAX_CARD_TEXT,
    );
    const skill = SAMPLE.skills[0];
    const many = Array.from({ length: MAX_CARD_ITEMS + 1 }, (_, n) => ({
      ...skill,
      id: `s${String(n)}`,
    }));
    expect(read({ ...SAMPLE, skills: many }).refused).toStrictEqual(["/skills (L0 3.1)"]);
    expect(read({ ...SAMPLE, skills: many.slice(1) }).card?.skills).toHaveLength(MAX_CARD_ITEMS);
  });

  it("may leave out what A2A lets it leave out", () => {
    const { card } = read({ ...SAMPLE, capabilities: {}, skills: [], defaultInputModes: [] });
    expect(card).toMatchObject({
      extensions: [],
      skills: [],
      signatures: [],
      defaultInputModes: [],
    });
  });

  it("never makes the reader throw, whatever was served", () => {
    fc.assert(
      fc.property(fc.oneof(fc.jsonValue(), fc.string(), fc.uint8Array()), (served) => {
        const bytes = served instanceof Uint8Array ? served : bytesOf(served);
        const result = readCard(bytes);
        if (result.ok) expect(result.value.digest).toBe(sha256Digest(bytes));
        else expect(result.issues.length).toBeGreaterThan(0);
      }),
      { numRuns: 500 },
    );
    // A card built on the sample, with members replaced by anything.
    fc.assert(
      fc.property(
        fc.dictionary(fc.constantFrom(...Object.keys(SAMPLE), "signatures"), fc.jsonValue()),
        (changed) => {
          expect(() => readCard(bytesOf({ ...SAMPLE, ...changed }))).not.toThrow();
        },
      ),
      { numRuns: 500 },
    );
  });
});

describe("the interface a gateway speaks to", () => {
  const card = (supportedInterfaces: unknown) => {
    const result = read({ ...SAMPLE, supportedInterfaces });
    if (result.card === undefined) throw new Error("the card was refused");
    return result.card;
  };

  it("is the first that is JSON-RPC, in A2A 1.0, over HTTPS: a card lists them in the order its agent prefers", () => {
    const grpc = {
      url: "https://example.com/grpc",
      protocolBinding: "GRPC",
      protocolVersion: "1.0",
    };
    const old = {
      url: "https://example.com/v03",
      protocolBinding: "JSONRPC",
      protocolVersion: "0.3",
    };
    const plain = {
      url: "http://example.com/rpc",
      protocolBinding: "JSONRPC",
      protocolVersion: "1.0",
    };
    const first = {
      url: "https://example.com/a",
      protocolBinding: "JSONRPC",
      protocolVersion: "1.0",
    };
    const second = {
      url: "https://example.com/b",
      protocolBinding: "JSONRPC",
      protocolVersion: "1.0",
    };
    expect(interfaceOf(card([grpc, old, plain, first, second]))).toStrictEqual(first);
    expect(interfaceOf(card([grpc, old, plain]))).toBeUndefined();
  });
});
