// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { clause, positiveVectorRecords } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import {
  CONTAINER_RECORD_TYPES,
  IDENTITY_EVENT_TYPES,
  isRecordType,
  jsonSchemas,
  RECORD_TYPES,
  type RecordType,
  SIGNED_RECORD_TYPES,
  UNSIGNED_RECORD_TYPES,
  validateProof,
  validateRecord,
  validateRecordOfType,
} from "../src/index.ts";
import { sample, sampleProof, samples, without } from "./fixtures.ts";

function expectRejected(record: unknown, pathOrMessage?: RegExp): void {
  const result = validateRecord(record);
  // JSON.stringify gives undefined for undefined, whatever its type says.
  const shown = (JSON.stringify(record) as string | undefined)?.slice(0, 200);
  expect(result.ok, shown).toBe(false);
  if (!result.ok && pathOrMessage !== undefined) {
    expect(result.issues.map((issue) => `${issue.path} ${issue.message}`).join("\n")).toMatch(
      pathOrMessage,
    );
  }
}

describe(`${clause("core 11")} the record types`, () => {
  it("has a schema for every record type in the table, and none for Merge", () => {
    expect([...RECORD_TYPES].sort()).toEqual(
      [
        ...["Genesis", "Update", "Fork", "Retire"],
        ...["Delegation", "Revocation", "Lineage", "Collective"],
        ...["Intent", "Offer", "Commitment", "Receipt", "Packet"],
        ...["Entry", "Checkpoint", "Ack", "QueryResult", "Forwarded"],
        ...["Location", "Participant", "Hello", "Session", "Resume", "Branch"],
        ...["Bundle", "LogPage", "FeedPage", "DuplicityEvidence", "Sealed"],
      ].sort(),
    );
    expect(isRecordType("Merge")).toBe(false);
    expect(isRecordType("toString")).toBe(false);
    expect(isRecordType(7)).toBe(false);
  });

  it("splits the types into signed and unsigned, with the containers unsigned", () => {
    expect(SIGNED_RECORD_TYPES.length + UNSIGNED_RECORD_TYPES.length).toBe(RECORD_TYPES.length);
    for (const type of CONTAINER_RECORD_TYPES) expect(UNSIGNED_RECORD_TYPES).toContain(type);
    for (const type of IDENTITY_EVENT_TYPES) expect(SIGNED_RECORD_TYPES).toContain(type);
  });

  it.each(RECORD_TYPES)("accepts a well-formed %s", (type) => {
    const result = validateRecord(samples[type]);
    expect(result.ok ? [] : result.issues).toEqual([]);
    expect(validateRecordOfType(type, samples[type]).ok).toBe(true);
  });

  it.each(RECORD_TYPES)("rejects a %s that lacks any one required member", (type) => {
    const required = jsonSchemas[type]?.["required"] as string[];
    expect(required.length).toBeGreaterThan(0);
    for (const member of required) {
      expectRejected(without(samples[type], member));
    }
  });

  it.each(UNSIGNED_RECORD_TYPES)("rejects a %s that carries proof", (type) => {
    expectRejected(sample(type, { proof: [sampleProof()] }), /proof/);
  });

  it.each(SIGNED_RECORD_TYPES)("rejects a %s without proof, or with an empty proof set", (type) => {
    expectRejected(without(samples[type], "proof"), /proof/);
    expectRejected(sample(type, { proof: [] }), /proof/);
  });

  it.each(CONTAINER_RECORD_TYPES)("accepts a %s without created", (type) => {
    expect(samples[type]).not.toHaveProperty("created");
    expect(validateRecord(samples[type]).ok).toBe(true);
  });

  it("validates a record as the type asked for, not as the type it names", () => {
    expect(validateRecordOfType("Offer", samples.Intent).ok).toBe(false);
  });
});

describe("the positive test vectors", () => {
  const records = positiveVectorRecords();

  it("contain records to check", () => {
    expect(records.length).toBeGreaterThan(40);
  });

  it.each(records)("$name validates", ({ record }) => {
    const result = validateRecord(record);
    expect(result.ok ? [] : result.issues).toEqual([]);
  });

  it(`${clause("core 5.2")} every proof on them is a well-formed proof`, () => {
    let checked = 0;
    for (const { record } of records) {
      for (const proof of (record["proof"] as unknown[] | undefined) ?? []) {
        const result = validateProof(proof);
        expect(result.ok ? [] : result.issues).toEqual([]);
        checked++;
      }
    }
    expect(checked).toBeGreaterThan(40);
  });
});

describe("common members", () => {
  it(`${clause("core 7")} rejects a record whose oip is not the string "1"`, () => {
    for (const oip of ["2", "1.0", 1, null, undefined, ""]) {
      expectRejected({ ...samples.Intent, oip }, /oip/);
    }
  });

  it(`${clause("core 7")} rejects a record without a type, or with a type this revision does not define`, () => {
    expectRejected(without(samples.Intent, "type"), /type/);
    expectRejected(sample("Intent", { type: 5 }), /type/);
    expectRejected(sample("Intent", { type: "Promise" }), /not a record type/);
    expectRejected(sample("Intent", { type: "constructor" }), /not a record type/);
  });

  it(`${clause("L1 3.9")} rejects the reserved type Merge`, () => {
    expectRejected(sample("Update", { type: "Merge" }), /reserved/);
  });

  it(`${clause("core 1.1")} rejects anything that is not a JSON object`, () => {
    for (const value of [null, undefined, "record", 1, true, [samples.Intent]]) {
      expectRejected(value, /JSON object/);
    }
  });

  it(`${clause("core 1.7")} accepts members it does not recognise, and returns them`, () => {
    const record = sample("Intent", { futureMember: { nested: [1, "two", null] } });
    const result = validateRecord(record);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value).toBe(record);
  });

  it(`${clause("core 1.4")} rejects a created that is not a real UTC timestamp`, () => {
    for (const created of [
      "2026-13-01T00:00:00Z",
      "2026-02-30T00:00:00Z",
      "2026-10-30T24:00:00Z",
      "2026-10-30T09:00:60Z",
      "2026-10-30T09:00:00+01:00",
      "2026-10-30T09:00:00",
      "2026-10-30 09:00:00Z",
      "2026-10-30T09:00:00.1234567890Z",
      1793350800,
    ]) {
      expectRejected(sample("Intent", { created }), /created/);
    }
  });

  it(`${clause("core 8.1")} accepts the three kinds of extension namespace`, () => {
    const ext = { "com.example.escrow": { v: "1" }, x402: {}, "oip.bridge": { protocol: "mcp" } };
    expect(validateRecord(sample("Offer", { ext })).ok).toBe(true);
  });

  it(`${clause("core 8.1")} rejects an extension block under any other name, or that is not an object`, () => {
    expectRejected(sample("Offer", { ext: { escrow: {} } }), /ext/);
    expectRejected(sample("Offer", { ext: { "Com.Example": {} } }), /ext/);
    expectRejected(sample("Offer", { ext: { x402: "yes" } }), /ext/);
    expectRejected(sample("Offer", { ext: [] }), /ext/);
  });

  it(`${clause("core 8.3")} rejects a critical namespace that has no extension block`, () => {
    const ext = { "com.example.escrow": {} };
    expect(validateRecord(sample("Offer", { ext, critical: ["com.example.escrow"] })).ok).toBe(
      true,
    );
    expectRejected(sample("Offer", { ext, critical: ["com.example.other"] }), /critical/);
    expectRejected(sample("Offer", { critical: ["com.example.escrow"] }), /critical/);
  });
});

describe(`${clause("core 5.1")} proof sets`, () => {
  it("rejects more than 256 proofs", () => {
    const proofs = (n: number) => Array.from({ length: n }, () => sampleProof());
    expect(validateRecord(sample("Intent", { proof: proofs(256) })).ok).toBe(true);
    expectRejected(sample("Intent", { proof: proofs(257) }), /proof/);
  });

  it("rejects a proof set that is not an array of objects", () => {
    expectRejected(sample("Intent", { proof: sampleProof() }), /proof/);
    expectRejected(sample("Intent", { proof: ["z58..."] }), /proof/);
  });

  it(`${clause("core 5.5")} does not reject a record because one of its proofs is malformed`, () => {
    const junk = { type: "SomethingElse", note: "added by a third party" };
    const record = sample("Intent");
    record["proof"] = [...(record["proof"] as unknown[]), junk];
    expect(validateRecord(record).ok).toBe(true);
    expect(validateProof(junk).ok).toBe(false);
  });
});

describe("validating one record type", () => {
  const cases: [RecordType, string, Record<string, unknown>, RegExp][] = [
    ["Delegation", "L1 11.1", { nonce: "1234567" }, /nonce/],
    ["Delegation", "L1 11.1", { nonce: "n".repeat(65) }, /nonce/],
    ["Delegation", "L1 11.2", { command: "oip/sign/Offer" }, /command/],
    ["Delegation", "L1 11.2", { command: "/oip" }, /command/],
    ["Delegation", "L1 11.2", { command: "/oip/sign" }, /command/],
    ["Delegation", "L1 11.2", { command: "/oip/sign/Delegation" }, /command/],
    ["Delegation", "L1 11.2", { command: "/oip/sign/Offer/extra" }, /command/],
    [
      "Delegation",
      "L1 11.3",
      { policy: Array.from({ length: 65 }, () => ["==", ".a", 1]) },
      /policy/,
    ],
    ["Delegation", "L1 11.3", { policy: [["like", ".a", "x*"]] }, /policy/],
    ["Delegation", "L1 11.3", { policy: [["==", ".a"]] }, /policy/],
    ["Delegation", "L1 11.3", { policy: [["and", []]] }, /policy/],
    ["Delegation", "L1 11.3", { policy: [["not", ["==", ".a", 1], ["==", ".b", 2]]] }, /policy/],
    ["Packet", "L1 12.1", { nonce: "short" }, /nonce/],
    ["Packet", "L1 12.1", { to: [] }, /to/],
    ["Packet", "L1 12.1", { purpose: { goal: "no verb" } }, /purpose/],
    ["Packet", "L1 12.3", { purpose: { verb: "shout" } }, /purpose/],
    ["Packet", "L1 12.2", { content: { mediaType: "text/plain" } }, /content/],
    [
      "Packet",
      "L1 12.2",
      { content: { mediaType: "text/plain", body: "a", ref: "https://x.example/a" } },
      /content/,
    ],
    [
      "Packet",
      "L1 12.2",
      { content: { mediaType: "text/plain", ref: "https://x.example/a" } },
      /content/,
    ],
    ["Packet", "L1 12.2", { content: { parts: [{ parts: [] }] } }, /content/],
    [
      "Packet",
      "L1 12.2",
      {
        content: {
          parts: Array.from({ length: 33 }, () => ({ mediaType: "text/plain", body: "a" })),
        },
      },
      /content/,
    ],
    ["Entry", "L1 10.1", { seq: 2, prev: undefined }, /prev/],
    ["Entry", "L1 10.1", { proofs: ["sha256:ABCD"] }, /proofs/],
    ["Checkpoint", "L1 10.5", { size: 0 }, /size/],
    ["Location", "L1 15.1", { ttl: 59 }, /ttl/],
    ["Location", "L1 15.1", { ttl: 86401 }, /ttl/],
    ["Location", "L1 15.1", { status: "asleep" }, /status/],
    [
      "Location",
      "L1 15.1",
      {
        endpoints: Array.from({ length: 33 }, () => ({
          binding: "https",
          url: "https://h.example",
          priority: 1,
        })),
      },
      /endpoints/,
    ],
    ["Participant", "L1 16.1", { name: "n".repeat(129) }, /name/],
    [
      "Participant",
      "L1 16.2",
      { capabilities: [{ id: "a", summary: "A", tags: ["untagged"] }] },
      /tags/,
    ],
    ["Session", "L1 14.1", { nonce: "short" }, /nonce/],
    ["Sealed", "L1 12.6", { suite: "hpke-base-p256-sha256-aes128gcm" }, /suite/],
    ["Sealed", "L1 12.6", { enc: "has+padding=" }, /enc/],
    ["Intent", "L2 4.1", { want: "w".repeat(4097) }, /want/],
    ["Intent", "L2 4.1", { constraints: { budget: { max: "-5", currency: "USD" } } }, /budget/],
    ["Intent", "L2 2", { status: "withdrawn", supersedes: undefined }, /supersedes/],
    ["Offer", "L2 4.2", { terms: { price: { amount: "400", currency: "USD" } } }, /terms/],
    [
      "Offer",
      "L2 4.2",
      { terms: { summary: "s", price: { amount: 400, currency: "USD" } } },
      /amount/,
    ],
    [
      "Offer",
      "L2 4.2",
      { terms: { summary: "s", price: { amount: "1e2", currency: "USD" } } },
      /amount/,
    ],
    ["Receipt", "L2 6.1", { outcome: "wonderful" }, /outcome/],
    ["Receipt", "L2 6.1", { outcome: "revoked" }, /supersedes/],
    ["Receipt", "L2 6.1", { rating: { score: "1.5" } }, /score/],
    ["Receipt", "L2 9", { evidence: [{ kind: "uri", ref: "https://x.example/file" }] }, /digest/],
    ["Receipt", "L2 9", { evidence: [{ kind: "telepathy", ref: "x" }] }, /kind/],
    ["Collective", "L2 6.2", { name: "n".repeat(129) }, /name/],
  ];

  it.each(cases)("%s [%s] rejects %j", (type, id, changes) => {
    expect(clause(id)).toContain(id);
    const record = sample(type, changes);
    for (const [name, value] of Object.entries(changes)) {
      if (value === undefined) delete record[name];
    }
    expectRejected(record, cases.find((entry) => entry[2] === changes)?.[3]);
  });

  it(`${clause("L1 11.2")} accepts the five /oip commands and commands under another first segment`, () => {
    for (const command of [
      "/oip/sign/Intent",
      "/oip/sign/Offer",
      "/oip/sign/Commitment",
      "/oip/sign/Receipt",
      "/oip/send",
      "/x402/pay",
      "/oipx/anything",
    ]) {
      const result = validateRecord(sample("Delegation", { command }));
      expect(result.ok ? [] : result.issues).toEqual([]);
    }
  });

  it(`${clause("L2 6.2")} accepts a charter whose role names a reserved command, which grants nothing`, () => {
    const roles = { steward: { purpose: "p", powers: [{ command: "/oip/sign", policy: [] }] } };
    expect(validateRecord(sample("Collective", { roles })).ok).toBe(true);
  });

  it(`${clause("L1 12.1")} requires expires outside a session, and session with seq together`, () => {
    const packet = sample("Packet");
    expect(packet).toHaveProperty("session");
    expect(validateRecord(without(packet, "expires")).ok).toBe(true);
    expectRejected(
      without(without(without(packet, "expires"), "session"), "seq"),
      /expires|session/,
    );
    expectRejected(without(packet, "seq"), /seq/);
    expectRejected(without(packet, "session"), /session/);
    expectRejected({ ...packet, seq: 1 }, /prev/);
  });

  it(`${clause("L1 12.1")} accepts a packet addressed to a capability query`, () => {
    const to = { query: { tags: ["lang:ar"] }, brokers: [sample("Packet")["from"]], maxFanout: 50 };
    expect(validateRecord(sample("Packet", { to })).ok).toBe(true);
    expectRejected(sample("Packet", { to: { ...to, maxFanout: 51 } }), /to/);
    expectRejected(sample("Packet", { to: { ...to, brokers: [] } }), /to/);
  });
});
