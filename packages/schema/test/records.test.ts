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
  validateExtensionRecord,
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
    for (const oip of ["2", "1.0", 1, null, ""]) {
      expectRejected({ ...samples.Intent, oip }, /oip/);
    }
    // A member that is undefined is not JSON at all, which is said first.
    expectRejected({ ...samples.Intent, oip: undefined }, /not a JSON value/);
    expectRejected(without(samples.Intent, "oip"), /oip/);
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
    if (result.ok) expect(result.value).toEqual(record);
  });

  it("returns a plain copy of the record, not the value it was given", () => {
    const record = sample("Intent", { futureMember: { nested: [1, "two", null] } });
    const result = validateRecord(record);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value).not.toBe(record);
    expect(result.value).toEqual(record);
    // Changing the original afterwards changes nothing in what was validated.
    (record["futureMember"] as { nested: unknown[] }).nested.push(1.5);
    record["want"] = 42;
    expect(validateRecord(result.value).ok).toBe(true);
    expect(validateRecord(record).ok).toBe(false);
    expect(JSON.stringify(result.value)).not.toContain("1.5");
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

  it(`${clause("core 8.3")} lets critical name a namespace more than once`, () => {
    const ext = { x402: {} };
    expect(validateRecord(sample("Offer", { ext, critical: ["x402", "x402"] })).ok).toBe(true);
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

describe("readings the specification does not state", () => {
  // Where the text gives a type and no further limit, validation adds none:
  // another implementation that follows the text must not be rejected.
  const accepted: [RecordType, string, Record<string, unknown>][] = [
    ["Location", "L1 15.1", { seq: -3 }],
    ["Location", "L1 15.1", { endpoints: [{ binding: "", url: "" }] }],
    ["Offer", "L2 4.2", { terms: { summary: "", quantity: 0 } }],
    ["Offer", "L2 4.2", { terms: { summary: "s", price: { amount: "1", currency: "" } } }],
    ["Intent", "L2 4.1", { constraints: { budget: { max: "5" } } }],
    ["Intent", "L2 4.1", { audience: { query: { limit: 0 } } }],
    ["Entry", "L1 10.1", { objectType: "" }],
    ["Receipt", "L2 6.1", { rating: { score: "-0" } }],
    ["Receipt", "L2 6.1", { rating: { score: "-0.00" } }],
    ["Receipt", "L2 9", { evidence: [{ kind: "oip", ref: "" }] }],
    ["Participant", "L1 16.2", { capabilities: [{ id: "", summary: "" }] }],
    ["Packet", "L1 12.1", { context: { summary: { en: "structured" } } }],
    ["Packet", "L1 12.1", { constraints: { maxHops: -1, jurisdiction: ["GB", "SG"] } }],
    ["Packet", "L1 12.1", { provenance: { generatedBy: { model: 7 } } }],
    ["Packet", "L1 12.2", { content: { mediaType: "", body: null } }],
  ];

  it.each(accepted)("%s [%s] accepts %j", (type, id, changes) => {
    expect(clause(id)).toContain(id);
    const result = validateRecord(sample(type, changes));
    expect(result.ok ? [] : result.issues).toEqual([]);
  });

  it(`${clause("L1 18.3")} sets no maximum on the results of a query`, () => {
    const one = (samples.QueryResult["results"] as unknown[])[0];
    const results = Array.from({ length: 101 }, () => one);
    expect(validateRecord(sample("QueryResult", { results })).ok).toBe(true);
  });

  it(`${clause("L2 6.1")} keeps a score between 0 and 1`, () => {
    for (const score of ["-0.1", "1.01", "2", "-1"]) {
      expectRejected(sample("Receipt", { rating: { score } }), /score/);
    }
  });
});

describe("issues", () => {
  const first = (record: unknown) => {
    const result = validateRecord(record);
    if (result.ok) throw new Error("expected the record to be rejected");
    return result.issues[0];
  };

  it("cite the clause that defines the value at fault, not only the record's", () => {
    expect(first(sample("Intent", { created: "yesterday" }))).toMatchObject({
      path: "/created",
      clause: "core 1.4",
    });
    expect(first(sample("Intent", { ext: { Bad: {} } }))).toMatchObject({
      path: "/ext",
      clause: "core 8.1",
    });
    expect(first(sample("Intent", { proof: [] }))).toMatchObject({
      path: "/proof",
      clause: "core 5.1",
    });
    expect(first(sample("Intent", { author: "did:web:example.com" }))).toMatchObject({
      path: "/author",
      clause: "core 6.1",
    });
    expect(
      first(
        sample("Offer", { terms: { summary: "s", price: { amount: "1e2", currency: "USD" } } }),
      ),
    ).toMatchObject({
      path: "/terms/price/amount",
      clause: "core 1.3",
    });
    expect(first(sample("Checkpoint", { head: "bafy" }))).toMatchObject({
      path: "/head",
      clause: "core 3.2",
    });
    expect(first(sample("Intent", { want: 5 }))).toMatchObject({ path: "/want", clause: "L2 4.1" });
  });

  it("put the most specific fault first when a value could have been one of several shapes", () => {
    const members = ["did:oip:" + "bciqa" + "a".repeat(50) + "a"];
    const controller = { members: [...members, ...members], threshold: 2 };
    const issue = first(sample("Genesis", { kind: "collective", controller }));
    expect(issue.path).toBe("/controller/members");
    expect(issue.message).toMatch(/duplicate/);
  });

  it("leave out the bare complaint that no shape matched, when they say which fault it was", () => {
    const controller = { keys: [], next: [] };
    const result = validateRecord(sample("Genesis", { controller }));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.issues.length).toBeGreaterThan(0);
      for (const issue of result.issues) expect(issue.message).not.toMatch(/anyOf/);
    }
  });

  it("never quote more than a short piece of the input", () => {
    const long = "x".repeat(100_000);
    const cases = [
      sample("Delegation", { policy: [["==", long, 1]] }),
      sample("Offer", { ext: {}, critical: [`com.example.${long}`] }),
      sample("Participant", {
        capabilities: [1, 2].map(() => ({ id: long.slice(0, 128), summary: "" })),
      }),
      { oip: "1", type: long },
    ];
    for (const record of cases) {
      const result = validateRecord(record);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        for (const issue of result.issues) expect(issue.message.length).toBeLessThan(400);
      }
    }
  });
});

describe(`${clause("core 7")} records of a type an extension defines`, () => {
  const escrow = {
    oip: "1",
    type: "com.example.Escrow",
    created: "2026-10-30T09:00:00Z",
    ext: { "com.example.escrow": { v: "1" } },
    critical: ["com.example.escrow"],
    holds: { amount: "400", currency: "USD" },
    proof: [sampleProof()],
  };

  it("are not records this revision defines, and validateRecord says where to take them", () => {
    expect(isRecordType(escrow.type)).toBe(false);
    const result = validateRecord(escrow);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.issues[0].message).toMatch(/validateExtensionRecord/);
  });

  it("are accepted by validateExtensionRecord when their common members are well formed", () => {
    const result = validateExtensionRecord(escrow);
    expect(result.ok ? [] : result.issues).toEqual([]);
    const minimal = {
      oip: "1",
      type: "com.example.Minimal",
      ext: { "com.example.minimal": {} },
      critical: ["com.example.minimal"],
    };
    expect(validateExtensionRecord(minimal).ok).toBe(true);
  });

  it("must list the extension that defines the type in critical", () => {
    const { critical: _critical, ...unlisted } = escrow;
    for (const record of [
      unlisted,
      { ...escrow, critical: [] },
      { oip: "1", type: "com.example.Minimal" },
      { oip: "1", type: "com.example.Minimal", ext: { "com.example.minimal": {} } },
    ]) {
      const result = validateExtensionRecord(record);
      // A missing list is against core 7; an empty one is reported where the list is.
      expect(result.ok ? undefined : result.issues[0]).toMatchObject({
        path: expect.stringMatching(/^(\/critical)?$/) as string,
        clause: expect.stringMatching(/^core (7|8\.3)$/) as string,
      });
    }
  });

  it("are rejected when a common member is malformed", () => {
    const rejected = (changes: Record<string, unknown>) => {
      const result = validateExtensionRecord({ ...escrow, ...changes });
      return result.ok ? undefined : result.issues[0].clause;
    };
    expect(rejected({ oip: "2" })).toBe("core 7");
    expect(rejected({ created: "soon" })).toBe("core 1.4");
    expect(rejected({ expires: 5 })).toBe("core 7");
    expect(rejected({ ext: { Escrow: {} } })).toBe("core 8.1");
    expect(rejected({ critical: ["com.example.other"] })).toBe("core 8.3");
    expect(rejected({ proof: [] })).toBe("core 5.1");
    expect(rejected({ holds: 1.5 })).toBe("core 1.2");
  });

  it(`${clause("L1 3.9")} never accept a reserved type or a type this revision defines`, () => {
    expect(validateExtensionRecord({ ...escrow, type: "Merge" }).ok).toBe(false);
    expect(validateExtensionRecord(samples.Intent).ok).toBe(false);
    expect(validateExtensionRecord("Escrow").ok).toBe(false);
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
