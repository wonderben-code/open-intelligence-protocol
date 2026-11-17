// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Tables written by hand from the specifications, not derived from the
 * schemas: the required members of each record type, every count and length
 * limit at the limit and one beyond it, and every member that has a syntax.
 * A schema that drifts from the specification fails here even if it still
 * agrees with itself.
 */

import { clause, type JsonObject } from "@oip/testkit";
import { Type } from "typebox";
import { describe, expect, it } from "vitest";

import {
  jsonSchemas,
  MAX_DEPTH,
  MAX_ISSUES,
  MAX_POLICY_DEPTH,
  RECORD_TYPES,
  type RecordType,
  validateProof,
  validateRecord,
} from "../src/index.ts";
import { define, ref } from "../src/naming.ts";
import { DEFINING_CLAUSE } from "../src/registry.ts";
import { AMINA, CID, sample, sampleProof, samples, T0, without } from "./fixtures.ts";

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";

function digits(n: number, alphabet: string, width: number): string {
  let out = "";
  for (let i = 0, rest = n; i < width; i++, rest = Math.floor(rest / alphabet.length)) {
    out = (alphabet[rest % alphabet.length] ?? "") + out;
  }
  return out;
}

/** Distinct, well-formed values, so that a limit is the only thing a list can break. */
const cid = (n: number) => `bciqa${digits(n, BASE32, 50)}a`;
const address = (n: number) => `did:oip:${cid(n)}`;
const edKey = (n: number) => `z6Mk${digits(n, BASE58, 44)}`;
const xKey = (n: number) => `z6LS${digits(n, BASE58, 44)}`;
const list = <T>(n: number, item: (i: number) => T): T[] =>
  Array.from({ length: n }, (_x, i) => item(i));

const REF = `${AMINA}/${CID}`;
const DIGEST = `sha256:${"0f".repeat(32)}`;
const accepts = (record: unknown) => {
  const result = validateRecord(record);
  return result.ok ? "accepted" : `rejected: ${result.issues[0].path} ${result.issues[0].message}`;
};

describe("required members", () => {
  const always = ["oip", "type"];
  const signed = [...always, "created", "proof"];
  const later = [...signed, "mind", "seq", "prev"];
  const REQUIRED: Record<RecordType, string[]> = {
    Genesis: [...signed, "kind", "controller"],
    Update: later,
    Fork: [...later, "child"],
    Retire: later,
    Delegation: [...signed, "author", "delegate", "subject", "command", "expires", "nonce"],
    Revocation: [...signed, "author", "revokes"],
    Lineage: [...signed, "author", "child"],
    Collective: [...signed, "author", "name", "purpose"],
    Intent: [...signed, "author", "want"],
    Offer: [...signed, "author", "provides", "terms"],
    Commitment: [...signed, "author", "parties", "promise", "terms"],
    Receipt: [...signed, "author", "about", "outcome"],
    Packet: [...signed, "from", "to", "nonce", "purpose", "content"],
    Entry: [...signed, "author", "seq", "object", "objectType"],
    Checkpoint: [...signed, "author", "size", "head", "root"],
    Ack: [...signed, "author", "packet", "received"],
    QueryResult: [...signed, "author", "query", "results"],
    Forwarded: [...signed, "broker", "to", "packet"],
    Location: [...signed, "author", "seq", "ttl", "status", "endpoints"],
    Participant: [...signed, "author", "name", "kind"],
    Hello: [...signed, "author"],
    Session: [...always, "created", "participants", "nonce"],
    Resume: [...always, "created", "session", "lastReceived"],
    Branch: [...always, "created", "parentSession", "fork"],
    Bundle: [...always, "mind", "log"],
    LogPage: [...always, "mind", "events"],
    FeedPage: [...always, "mind", "entries"],
    DuplicityEvidence: [...always, "mind", "pairs"],
    Sealed: [...always, "to", "key", "suite", "enc", "ciphertext"],
  };

  it.each(RECORD_TYPES)(
    `${clause("core 11")} %s requires exactly the members its definition requires`,
    (type) => {
      expect([...(jsonSchemas[type]?.["required"] as string[])].sort()).toEqual(
        [...REQUIRED[type]].sort(),
      );
      for (const member of REQUIRED[type]) {
        expect(accepts(without(samples[type], member)), member).toMatch(/^rejected/);
      }
    },
  );

  it("cites the clause that defines each record type", () => {
    expect(DEFINING_CLAUSE).toEqual({
      Genesis: "L1 3.6",
      Update: "L1 3.7",
      Fork: "L1 3.8",
      Retire: "L1 3.10",
      Delegation: "L1 11.1",
      Revocation: "L1 11.5",
      Lineage: "L1 8.3",
      Collective: "L2 6.2",
      Intent: "L2 4.1",
      Offer: "L2 4.2",
      Commitment: "L2 5.1",
      Receipt: "L2 6.1",
      Packet: "L1 12.1",
      Entry: "L1 10.1",
      Checkpoint: "L1 10.5",
      Ack: "L1 13.2",
      QueryResult: "L1 18.3",
      Forwarded: "L1 18.5",
      Location: "L1 15.1",
      Participant: "L1 16.1",
      Hello: "L1 13.3",
      Session: "L1 14.1",
      Resume: "L1 14.4",
      Branch: "L1 14.5",
      Bundle: "L1 13.1",
      LogPage: "L1 13.1",
      FeedPage: "L1 13.1",
      DuplicityEvidence: "L1 17.1",
      Sealed: "L1 12.6",
    });
    for (const id of Object.values(DEFINING_CLAUSE)) expect(clause(id)).toBe(`[${id}]`);
  });
});

describe("limits, at the limit and one beyond it", () => {
  const statement = (i: number) => ["==", `.m${i}`, i];
  const party = (i: number, role = "witness") =>
    role === "witness" ? { mind: address(i), role } : { mind: address(i), role, required: true };
  const majority = (n: number) => Math.floor(n / 2) + 1;

  const counts: [
    what: string,
    id: string,
    limit: number,
    type: RecordType,
    build: (n: number) => JsonObject,
  ][] = [
    ["packet recipients", "L1 12.1", 64, "Packet", (n) => ({ to: list(n, address) })],
    ["brokers", "L1 12.1", 8, "Packet", (n) => ({ to: { query: {}, brokers: list(n, address) } })],
    [
      "content parts",
      "L1 12.2",
      32,
      "Packet",
      (n) => ({ content: { parts: list(n, (i) => ({ mediaType: "text/plain", body: i })) } }),
    ],
    [
      "parties",
      "L2 5.1",
      64,
      "Commitment",
      (n) => ({
        terms: {},
        parties: [party(0, "debtor"), party(1, "creditor"), ...list(n - 2, (i) => party(i + 2))],
      }),
    ],
    ["policy statements", "L1 11.3", 64, "Delegation", (n) => ({ policy: list(n, statement) })],
    [
      "statements in a connective",
      "L1 11.3",
      64,
      "Delegation",
      (n) => ({ policy: [["or", list(n, statement)]] }),
    ],
    [
      "control keys",
      "L1 3.4",
      16,
      "Genesis",
      (n) => ({ controller: { keys: list(n, edKey), next: [] } }),
    ],
    [
      "committed keys",
      "L1 3.4",
      16,
      "Genesis",
      (n) => ({
        controller: {
          keys: [edKey(0)],
          next: list(n, cid),
          nextThreshold: Math.min(majority(n), 16),
        },
      }),
    ],
    [
      "members",
      "L1 3.4",
      256,
      "Genesis",
      (n) => ({
        kind: "collective",
        controller: { members: list(n, address), threshold: majority(n) },
      }),
    ],
    [
      "operational keys",
      "L1 3.5",
      64,
      "Update",
      (n) => ({ keys: list(n, (i) => ({ key: edKey(i) })) }),
    ],
    [
      "invocation keys",
      "L1 3.5",
      16,
      "Update",
      (n) => ({ keys: [], invocation: list(n, (i) => ({ key: edKey(i) })) }),
    ],
    [
      "agreement keys",
      "L1 3.5",
      16,
      "Update",
      (n) => ({ agreement: list(n, (i) => ({ key: xKey(i) })) }),
    ],
    ["homes", "L1 3.6", 8, "Genesis", (n) => ({ homes: list(n, (i) => `https://h${i}.example`) })],
    [
      "aliases",
      "L1 3.6",
      16,
      "Genesis",
      (n) => ({ alsoKnownAs: list(n, (i) => `https://a${i}.example`) }),
    ],
    [
      "parents",
      "L1 3.6",
      16,
      "Genesis",
      (n) => ({ parents: list(n, (i) => ({ mind: address(i), at: `${i}-${cid(i)}` })) }),
    ],
    [
      "session participants",
      "L1 14.1",
      256,
      "Session",
      (n) => ({ participants: list(n, address).sort() }),
    ],
    [
      "location endpoints",
      "L1 15.1",
      32,
      "Location",
      (n) => ({
        endpoints: list(n, (i) => ({
          binding: "https",
          url: `https://e${i}.example`,
          priority: i,
        })),
      }),
    ],
    [
      "capabilities",
      "L1 16.1",
      256,
      "Participant",
      (n) => ({ capabilities: list(n, (i) => ({ id: `c${i}`, summary: "" })) }),
    ],
    [
      "capability tags",
      "L1 16.2",
      64,
      "Participant",
      (n) => ({ capabilities: [{ id: "c", summary: "", tags: list(n, (i) => `t:${i}`) }] }),
    ],
    [
      "evidence items",
      "L2 6.1",
      64,
      "Receipt",
      (n) => ({ evidence: list(n, (i) => ({ kind: "oip", ref: `r${i}` })) }),
    ],
  ];

  it.each(counts)("%s [%s]: %i accepted, one more rejected", (_what, id, limit, type, build) => {
    expect(clause(id)).toBe(`[${id}]`);
    expect(accepts(sample(type, build(limit)))).toBe("accepted");
    expect(accepts(sample(type, build(limit + 1)))).toMatch(/^rejected/);
  });

  const minima: [
    what: string,
    id: string,
    minimum: number,
    type: RecordType,
    build: (n: number) => JsonObject,
  ][] = [
    ["packet recipients", "L1 12.1", 1, "Packet", (n) => ({ to: list(n, address) })],
    ["brokers", "L1 12.1", 1, "Packet", (n) => ({ to: { query: {}, brokers: list(n, address) } })],
    [
      "control keys",
      "L1 3.4",
      1,
      "Genesis",
      (n) => ({ controller: { keys: list(n, edKey), next: [] } }),
    ],
    [
      "members",
      "L1 3.4",
      1,
      "Genesis",
      (n) => ({ kind: "collective", controller: { members: list(n, address), threshold: 1 } }),
    ],
    [
      "session participants",
      "L1 14.1",
      2,
      "Session",
      (n) => ({ participants: list(n, address).sort() }),
    ],
    [
      "statements in a connective",
      "L1 11.3",
      1,
      "Delegation",
      (n) => ({ policy: [["and", list(n, statement)]] }),
    ],
  ];

  it.each(minima)("%s [%s]: %i accepted, one fewer rejected", (_what, id, minimum, type, build) => {
    expect(clause(id)).toBe(`[${id}]`);
    expect(accepts(sample(type, build(minimum)))).toBe("accepted");
    expect(accepts(sample(type, build(minimum - 1)))).toMatch(/^rejected/);
  });

  // Lengths are in code points, so the filler is a character of two UTF-16 units (core 1.8).
  const text = (n: number) => "𝛑".repeat(n);
  const lengths: [
    what: string,
    id: string,
    limit: number,
    type: RecordType,
    build: (n: number) => JsonObject,
  ][] = [
    ["packet nonce", "L1 12.1", 64, "Packet", (n) => ({ nonce: text(n) })],
    ["delegation nonce", "L1 11.1", 64, "Delegation", (n) => ({ nonce: text(n) })],
    ["session nonce", "L1 14.1", 64, "Session", (n) => ({ nonce: text(n) })],
    ["packet instance", "L1 12.1", 64, "Packet", (n) => ({ instance: text(n) })],
    ["packet thread", "L1 12.1", 128, "Packet", (n) => ({ thread: text(n) })],
    ["packet parentThread", "L1 12.1", 128, "Packet", (n) => ({ parentThread: text(n) })],
    ["packet replyTo", "L1 12.1", 128, "Packet", (n) => ({ replyTo: text(n) })],
    [
      "purpose goal",
      "L1 12.1",
      256,
      "Packet",
      (n) => ({ purpose: { verb: "inform", goal: text(n) } }),
    ],
    ["genesis kind", "L1 3.6", 64, "Genesis", (n) => ({ kind: text(n) })],
    ["key label", "L1 3.5", 64, "Update", (n) => ({ keys: [{ key: edKey(1), label: text(n) }] })],
    [
      "endpoint instance",
      "L1 15.1",
      64,
      "Location",
      (n) => ({ endpoints: [{ binding: "https", url: "https://e.example", instance: text(n) }] }),
    ],
    ["profile name", "L1 16.1", 128, "Participant", (n) => ({ name: text(n) })],
    ["profile kind", "L1 16.1", 64, "Participant", (n) => ({ kind: text(n) })],
    ["profile summary", "L1 16.1", 1024, "Participant", (n) => ({ summary: text(n) })],
    [
      "capability id",
      "L1 16.2",
      128,
      "Participant",
      (n) => ({ capabilities: [{ id: text(n), summary: "" }] }),
    ],
    ["query want", "L1 18.2", 1024, "Intent", (n) => ({ audience: { query: { want: text(n) } } })],
    ["intent want", "L2 4.1", 4096, "Intent", (n) => ({ want: text(n) })],
    ["offer provides", "L2 4.2", 4096, "Offer", (n) => ({ provides: text(n) })],
    ["offer capability", "L2 4.2", 128, "Offer", (n) => ({ capability: text(n) })],
    ["commitment promise", "L2 5.1", 8192, "Commitment", (n) => ({ promise: text(n) })],
    ["receipt statement", "L2 6.1", 8192, "Receipt", (n) => ({ statement: text(n) })],
    ["charter name", "L2 6.2", 128, "Collective", (n) => ({ name: text(n) })],
    [
      "amount",
      "core 1.3",
      64,
      "Offer",
      (n) => ({ terms: { summary: "", price: { amount: "1".repeat(n), currency: "USD" } } }),
    ],
    [
      "budget",
      "core 1.3",
      64,
      "Intent",
      (n) => ({ constraints: { budget: { max: "1".repeat(n) } } }),
    ],
    ["score", "core 1.3", 64, "Receipt", (n) => ({ rating: { score: `0.${"1".repeat(n - 2)}` } })],
  ];

  it.each(lengths)(
    "%s [%s]: %i characters accepted, one more rejected",
    (_what, id, limit, type, build) => {
      expect(clause(id)).toBe(`[${id}]`);
      expect(accepts(sample(type, build(limit)))).toBe("accepted");
      expect(accepts(sample(type, build(limit + 1)))).toMatch(/^rejected/);
    },
  );

  it(`${clause("L1 12.1", "L1 11.1", "L1 14.1")} a nonce has at least 8 characters`, () => {
    for (const type of ["Packet", "Delegation", "Session"] as const) {
      expect(accepts(sample(type, { nonce: text(8) }))).toBe("accepted");
      expect(accepts(sample(type, { nonce: text(7) }))).toMatch(/^rejected/);
    }
  });

  const ranges: [
    what: string,
    id: string,
    low: number,
    high: number,
    type: RecordType,
    build: (n: number) => JsonObject,
  ][] = [
    ["maxFanout", "L1 12.1", 1, 50, "Packet", (n) => ({ to: { query: {}, maxFanout: n } })],
    ["ttl", "L1 15.1", 60, 86400, "Location", (n) => ({ ttl: n })],
    [
      "height",
      "L1 3.6",
      1,
      4,
      "Genesis",
      (n) => ({
        kind: "collective",
        controller: { members: [address(1)], threshold: 1 },
        height: n,
      }),
    ],
    [
      "nextThreshold",
      "L1 3.4",
      9,
      16,
      "Genesis",
      (n) => ({ controller: { keys: [edKey(0)], next: list(16, cid), nextThreshold: n } }),
    ],
  ];

  it.each(ranges)("%s [%s]: from %i to %i", (_what, id, low, high, type, build) => {
    expect(clause(id)).toBe(`[${id}]`);
    for (const inside of [low, high]) expect(accepts(sample(type, build(inside)))).toBe("accepted");
    for (const outside of [low - 1, high + 1])
      expect(accepts(sample(type, build(outside)))).toMatch(/^rejected/);
  });

  it(`${clause("L1 18.2", "L1 10.5", "L1 10.1", "L1 3.2")} other bounds on integers`, () => {
    expect(accepts(sample("Intent", { audience: { query: { limit: 100 } } }))).toBe("accepted");
    expect(accepts(sample("Intent", { audience: { query: { limit: 101 } } }))).toMatch(/^rejected/);
    expect(accepts(sample("Checkpoint", { size: 1 }))).toBe("accepted");
    expect(accepts(sample("Checkpoint", { size: 0 }))).toMatch(/^rejected/);
    expect(accepts(sample("Entry", { seq: -1 }))).toMatch(/^rejected/);
    expect(accepts(sample("Update", { seq: 1 }))).toBe("accepted");
    expect(accepts(sample("Update", { seq: 0 }))).toMatch(/^rejected/);
    expect(accepts(sample("Update", { seq: 1.5 }))).toMatch(/^rejected/);
  });
});

describe("members that have a syntax", () => {
  const [debtor, creditor] = (samples.Commitment["parties"] as { mind: string }[]).map(
    (entry) => entry.mind,
  ) as [string, string];
  const versioned = `${AMINA}?versionId=2-${CID}`;
  const low = `did:oip:bciqa${"a".repeat(50)}a`;
  const high = `did:oip:bciqp${"z".repeat(50)}y`;

  const typed: [
    type: RecordType,
    what: string,
    build: (value: unknown) => JsonObject,
    good: unknown,
  ][] = [
    ["Session", "created", (v) => ({ created: v }), T0],
    ["Resume", "created", (v) => ({ created: v }), T0],
    ["Branch", "created", (v) => ({ created: v }), T0],
    ["Intent", "created", (v) => ({ created: v }), T0],
    ["Genesis", "created", (v) => ({ created: v }), T0],
    ["Sealed", "expires", (v) => ({ expires: v }), T0],
    ["Bundle", "expires", (v) => ({ expires: v }), T0],
    ["Ack", "received", (v) => ({ received: v }), T0],
    ["Ack", "packet", (v) => ({ packet: v }), CID],
    ["Ack", "sealed", (v) => ({ sealed: v }), CID],
    ["Ack", "author", (v) => ({ author: v }), AMINA],
    ["Ack", "expires", (v) => ({ expires: v }), T0],
    ["Bundle", "mind", (v) => ({ mind: v }), AMINA],
    ["Bundle", "a firstSeen time", (v) => ({ firstSeen: { [CID]: v } }), T0],
    ["Bundle", "a firstSeen key", (v) => ({ firstSeen: { [String(v)]: T0 } }), CID],
    ["Bundle", "a firstSeen proof digest", (v) => ({ firstSeen: { [String(v)]: T0 } }), DIGEST],
    ["LogPage", "a firstSeen time", (v) => ({ firstSeen: { [CID]: v } }), T0],
    ["LogPage", "mind", (v) => ({ mind: v }), AMINA],
    ["FeedPage", "mind", (v) => ({ mind: v }), AMINA],
    ["DuplicityEvidence", "mind", (v) => ({ mind: v }), AMINA],
    ["Update", "mind", (v) => ({ mind: v }), AMINA],
    ["Update", "prev", (v) => ({ prev: v }), CID],
    ["Update", "a revoked key", (v) => ({ revoked: [{ key: v }] }), edKey(999)],
    [
      "Update",
      "compromisedSince",
      (v) => ({ revoked: [{ key: edKey(999), compromisedSince: v }] }),
      T0,
    ],
    ["Update", "an operational key", (v) => ({ keys: [{ key: v }] }), edKey(2)],
    ["Update", "an invocation key", (v) => ({ invocation: [{ key: v }] }), edKey(3)],
    ["Update", "an agreement key", (v) => ({ agreement: [{ key: v }] }), xKey(2)],
    ["Update", "a home", (v) => ({ homes: [v] }), "https://home.example:8443"],
    ["Fork", "child", (v) => ({ child: v }), AMINA],
    ["Retire", "successor", (v) => ({ successor: v }), AMINA],
    ["Genesis", "a control key", (v) => ({ controller: { keys: [v], next: [] } }), edKey(1)],
    [
      "Genesis",
      "a committed key hash",
      (v) => ({ controller: { keys: [edKey(1)], next: [v] } }),
      CID,
    ],
    [
      "Genesis",
      "a member",
      (v) => ({ kind: "collective", controller: { members: [v], threshold: 1 } }),
      AMINA,
    ],
    ["Genesis", "a parent", (v) => ({ parents: [{ mind: v, at: `0-${CID}` }] }), AMINA],
    ["Genesis", "a parent's version", (v) => ({ parents: [{ mind: AMINA, at: v }] }), `0-${CID}`],
    ["Delegation", "author", (v) => ({ author: v }), address(8)],
    ["Delegation", "delegate", (v) => ({ delegate: v }), address(7)],
    ["Delegation", "subject", (v) => ({ subject: v }), AMINA],
    ["Delegation", "notBefore", (v) => ({ notBefore: v }), T0],
    ["Delegation", "expires", (v) => ({ expires: v }), T0],
    ["Revocation", "revokes", (v) => ({ revokes: v }), REF],
    ["Lineage", "child", (v) => ({ child: v }), AMINA],
    ["Entry", "object", (v) => ({ object: v }), CID],
    ["Entry", "prev", (v) => ({ prev: v }), CID],
    ["Entry", "a proof digest", (v) => ({ proofs: [v] }), DIGEST],
    ["Checkpoint", "head", (v) => ({ head: v }), CID],
    ["Checkpoint", "root", (v) => ({ root: v }), CID],
    ["Packet", "from", (v) => ({ from: v }), AMINA],
    ["Packet", "a recipient", (v) => ({ to: [v] }), AMINA],
    ["Packet", "a broker", (v) => ({ to: { query: {}, brokers: [v] } }), AMINA],
    ["Packet", "session", (v) => ({ session: v }), CID],
    ["Packet", "prev", (v) => ({ seq: 1, prev: v }), CID],
    ["Packet", "expires", (v) => ({ expires: v }), T0],
    ["Packet", "onBehalfOf", (v) => ({ provenance: { onBehalfOf: v } }), AMINA],
    ["Packet", "retention", (v) => ({ constraints: { retention: v } }), "P30D"],
    [
      "Packet",
      "a content digest",
      (v) => ({ content: { mediaType: "text/plain", ref: "https://x.example/a", digest: v } }),
      DIGEST,
    ],
    [
      "Packet",
      "a hint's mind",
      (v) => ({ hints: { [String(v)]: ["https://x.example/a"] } }),
      AMINA,
    ],
    ["Packet", "a hint's URL", (v) => ({ hints: { [AMINA]: [v] } }), "https://x.example/a"],
    ["Sealed", "to", (v) => ({ to: v }), AMINA],
    ["Sealed", "key", (v) => ({ key: v }), xKey(1)],
    ["Sealed", "enc", (v) => ({ enc: v }), "AAEC_-"],
    ["Sealed", "ciphertext", (v) => ({ ciphertext: v }), "AAEC_-"],
    ["Session", "a participant", (v) => ({ participants: [v, high] }), low],
    ["Resume", "session", (v) => ({ session: v }), CID],
    ["Resume", "lastSent.packet", (v) => ({ lastSent: { seq: 0, packet: v } }), CID],
    [
      "Resume",
      "a lastReceived mind",
      (v) => ({ lastReceived: [{ mind: v, seq: 0, packet: CID }] }),
      AMINA,
    ],
    [
      "Resume",
      "a lastReceived packet",
      (v) => ({ lastReceived: [{ mind: AMINA, seq: 0, packet: v }] }),
      CID,
    ],
    ["Branch", "parentSession", (v) => ({ parentSession: v }), CID],
    ["Branch", "fork", (v) => ({ fork: v }), versioned],
    ["Location", "author", (v) => ({ author: v }), AMINA],
    ["Location", "resumeAfter", (v) => ({ resumeAfter: v }), T0],
    ["Location", "participant", (v) => ({ participant: v }), CID],
    ["Location", "feed.head", (v) => ({ feed: { seq: 1, head: v } }), CID],
    ["Location", "a home", (v) => ({ homes: [v] }), "https://home.example"],
    ["Participant", "supersedes", (v) => ({ supersedes: v }), REF],
    ["Participant", "an actsFor mind", (v) => ({ actsFor: [{ mind: v, authority: REF }] }), AMINA],
    [
      "Participant",
      "an actsFor authority",
      (v) => ({ actsFor: [{ mind: AMINA, authority: v }] }),
      REF,
    ],
    [
      "Participant",
      "a capability subject",
      (v) => ({ capabilities: [{ id: "c", summary: "", subject: v }] }),
      "legal.translation",
    ],
    [
      "QueryResult",
      "a result's mind",
      (v) => ({ results: [{ mind: v, record: CID, score: "1" }] }),
      AMINA,
    ],
    [
      "QueryResult",
      "a result's record",
      (v) => ({ results: [{ mind: AMINA, record: v, score: "1" }] }),
      CID,
    ],
    [
      "QueryResult",
      "a result's score",
      (v) => ({ results: [{ mind: AMINA, record: CID, score: v }] }),
      "0.5",
    ],
    ["Forwarded", "broker", (v) => ({ broker: v }), AMINA],
    ["Forwarded", "to", (v) => ({ to: v }), AMINA],
    ["Intent", "supersedes", (v) => ({ supersedes: v }), REF],
    ["Intent", "deadline", (v) => ({ constraints: { deadline: v } }), T0],
    ["Intent", "an audience member", (v) => ({ audience: [v] }), AMINA],
    ["Offer", "answers", (v) => ({ answers: v }), REF],
    ["Offer", "deliveryBy", (v) => ({ terms: { summary: "", deliveryBy: v } }), T0],
    [
      "Commitment",
      "a party",
      (v) => ({
        terms: {},
        parties: [
          { mind: v, role: "debtor", required: true },
          { mind: high, role: "creditor", required: true },
        ],
      }),
      low,
    ],
    ["Commitment", "deadline", (v) => ({ terms: { deadline: v } }), T0],
    [
      "Commitment",
      "a price's amount",
      (v) => ({ terms: { price: { amount: v, currency: "USD", payer: debtor, payee: creditor } } }),
      "400.00",
    ],
    [
      "Offer",
      "a price's amount",
      (v) => ({ terms: { summary: "", price: { amount: v, currency: "USD" } } }),
      "400.00",
    ],
    [
      "Intent",
      "a budget's maximum",
      (v) => ({ constraints: { budget: { max: v, currency: "USD" } } }),
      "400.00",
    ],
    [
      "Commitment",
      "payer",
      (v) => ({ terms: { price: { amount: "1", currency: "USD", payer: v, payee: creditor } } }),
      debtor,
    ],
    [
      "Commitment",
      "payee",
      (v) => ({ terms: { price: { amount: "1", currency: "USD", payer: creditor, payee: v } } }),
      debtor,
    ],
    ["Commitment", "a resolved record", (v) => ({ resolves: [v] }), REF],
    ["Commitment", "onBehalfOf", (v) => ({ onBehalfOf: v }), AMINA],
    ["Receipt", "about", (v) => ({ about: v }), REF],
    [
      "Receipt",
      "an evidence digest",
      (v) => ({ evidence: [{ kind: "hash", ref: "r", digest: v }] }),
      DIGEST,
    ],
    [
      "Collective",
      "an assigned mind",
      (v) => ({ assignments: [{ mind: v, role: "steward" }] }),
      AMINA,
    ],
    [
      "Collective",
      "a power's command",
      (v) => ({ roles: { steward: { powers: [{ command: v }] } } }),
      "/oip/sign/Offer",
    ],
  ];

  it.each(typed)("%s: %s must have its syntax", (type, _what, build, good) => {
    expect(accepts(sample(type, build(good)))).toBe("accepted");
    const wellFormed = JSON.stringify(build(good));
    for (const bad of [
      "not valid",
      `${String(good)} `,
      ` ${String(good)}`,
      7,
      null,
      [good],
      { value: good },
    ]) {
      // Where the value is a member name, an array of the good name spells it again.
      if (JSON.stringify(build(bad)) === wellFormed) continue;
      expect(accepts(sample(type, build(bad))), JSON.stringify(bad)).toMatch(/^rejected/);
    }
  });
});

describe("members that depend on another", () => {
  it.each(["Intent", "Offer", "Commitment", "Receipt", "Collective"] as const)(
    `${clause("L2 2")} %s: status appears only in a superseding record`,
    (type) => {
      const plain = without(without(samples[type], "status"), "supersedes");
      expect(accepts(plain)).toBe("accepted");
      expect(accepts({ ...plain, supersedes: REF })).toBe("accepted");
      expect(accepts({ ...plain, supersedes: REF, status: "withdrawn" })).toBe("accepted");
      expect(accepts({ ...plain, status: "withdrawn" })).toMatch(/^rejected/);
    },
  );

  it(`${clause("L2 5.1")} a Commitment's price names its payer and its payee`, () => {
    const [debtor, creditor] = (samples.Commitment["parties"] as { mind: string }[]).map(
      (entry) => entry.mind,
    );
    const price = { amount: "1", currency: "USD", payer: debtor, payee: creditor };
    expect(accepts(sample("Commitment", { terms: { price } }))).toBe("accepted");
    for (const member of ["amount", "currency", "payer", "payee"] as const) {
      const { [member]: _removed, ...partial } = price;
      expect(accepts(sample("Commitment", { terms: { price: partial } })), member).toMatch(
        /^rejected/,
      );
    }
  });

  it(`${clause("L2 4.2")} an Offer's price has an amount and a currency, and its terms a summary`, () => {
    expect(
      accepts(sample("Offer", { terms: { summary: "", price: { amount: "1", currency: "USD" } } })),
    ).toBe("accepted");
    expect(
      accepts(sample("Offer", { terms: { summary: "", price: { currency: "USD" } } })),
    ).toMatch(/^rejected/);
    expect(accepts(sample("Offer", { terms: { summary: "", price: { amount: "1" } } }))).toMatch(
      /^rejected/,
    );
    expect(
      accepts(sample("Offer", { terms: { price: { amount: "1", currency: "USD" } } })),
    ).toMatch(/^rejected/);
  });
});

describe("proofs, value by value", () => {
  const verdict = (changes: JsonObject) => validateProof(sampleProof(changes)).ok;
  const key = edKey(5);

  it(`${clause("core 5.2")} a proofValue is z and the base58btc form of 64 bytes`, () => {
    for (const length of [64, 87, 88])
      expect(verdict({ proofValue: `z${"2".repeat(length)}` })).toBe(true);
    for (const length of [0, 63, 89])
      expect(verdict({ proofValue: `z${"2".repeat(length)}` })).toBe(false);
    expect(verdict({ proofValue: `u${"2".repeat(87)}` })).toBe(false);
    expect(verdict({ proofValue: `z${"0".repeat(87)}` })).toBe(false);
  });

  it(`${clause("core 6.1")} a control-key-ref is did:key, a Multikey, "#" and a Multikey`, () => {
    expect(verdict({ verificationMethod: `did:key:${key}#${key}` })).toBe(true);
    for (const method of [
      `did:key:${key}`,
      `did:key:#${key}`,
      "did:key:abc#abc",
      `did:key:z0#z0`,
      `did:key:${key}#${key}#x`,
      `did:key:${key} #${key}`,
    ]) {
      expect(verdict({ verificationMethod: method }), method).toBe(false);
    }
  });

  it(`${clause("core 5.2")} challenge alone, or domain alone, belongs only in an authentication proof`, () => {
    for (const member of ["challenge", "domain"]) {
      expect(verdict({ proofPurpose: "authentication", [member]: "x" })).toBe(true);
      for (const purpose of ["assertionMethod", "capabilityInvocation", "capabilityDelegation"]) {
        expect(verdict({ proofPurpose: purpose, [member]: "x" }), `${member} with ${purpose}`).toBe(
          false,
        );
      }
    }
  });

  it(`${clause("core 5.6")} accepts each of the four purposes`, () => {
    for (const purpose of [
      "capabilityInvocation",
      "capabilityDelegation",
      "authentication",
      "assertionMethod",
    ]) {
      expect(verdict({ proofPurpose: purpose })).toBe(true);
    }
  });

  it(`${clause("core 5.2")} created is a timestamp`, () => {
    expect(verdict({ created: T0 })).toBe(true);
    expect(verdict({ created: "2026-02-30T00:00:00Z" })).toBe(false);
  });
});

describe("rules, case by case", () => {
  const rejectedAt = (record: unknown) => {
    const result = validateRecord(record);
    return result.ok ? "accepted" : `${result.issues[0].clause} ${result.issues[0].path}`;
  };

  it(`${clause("L1 3.4", "L1 3.5")} applies the identity rules to every kind of event`, () => {
    const minority = { members: [address(1), address(2), address(3)], threshold: 1 };
    const twice = [{ key: edKey(1) }, { key: edKey(1) }];
    for (const type of ["Update", "Fork", "Retire"] as const) {
      expect(rejectedAt(sample(type, { controller: minority }))).toBe(
        "L1 3.4 /controller/threshold",
      );
      expect(rejectedAt(sample(type, { keys: twice }))).toBe("L1 3.5 /keys/1/key");
    }
    expect(rejectedAt(sample("Genesis", { kind: "collective", controller: minority }))).toBe(
      "L1 3.4 /controller/threshold",
    );
    expect(rejectedAt(sample("Genesis", { keys: twice }))).toBe("L1 3.5 /keys/1/key");
    expect(rejectedAt(sample("Update", { agreement: [{ key: xKey(1) }, { key: xKey(1) }] }))).toBe(
      "L1 3.5 /agreement/1/key",
    );
  });

  it("applies the rules to both events of a pair of conflicting events", () => {
    const good = samples.Update;
    const bad = sample("Update", { keys: [{ key: edKey(1) }, { key: edKey(1) }] });
    expect(rejectedAt(sample("DuplicityEvidence", { pairs: [[bad, good]] }))).toBe(
      "L1 3.5 /pairs/0/0/keys/1/key",
    );
    expect(rejectedAt(sample("DuplicityEvidence", { pairs: [[good, bad]] }))).toBe(
      "L1 3.5 /pairs/0/1/keys/1/key",
    );
    expect(
      rejectedAt(
        sample("DuplicityEvidence", {
          pairs: [
            [good, good],
            [good, bad],
          ],
        }),
      ),
    ).toBe("L1 3.5 /pairs/1/1/keys/1/key");
    for (const pairs of [[[good]], [[good, good, good]], [good], [[good, samples.Intent]]]) {
      expect(accepts(sample("DuplicityEvidence", { pairs }))).toMatch(/^rejected/);
    }
  });

  it(`${clause("L1 3.9")} names the reserved type when a container holds a Merge event`, () => {
    const merge = { ...samples.Update, type: "Merge" };
    expect(rejectedAt(sample("LogPage", { events: [samples.Genesis, merge] }))).toMatch(
      /\/events\/1\/type$/,
    );
    expect(rejectedAt(sample("Bundle", { log: [merge] }))).toMatch(/\/log\/0\/type$/);
    expect(rejectedAt(sample("LogPage", { events: [samples.Intent] }))).toMatch(
      /\/events\/0\/type$/,
    );
  });

  it(`${clause("L1 3.7")} revoked is a list of keys, each with an optional compromise time`, () => {
    expect(accepts(sample("Update", { revoked: [] }))).toBe("accepted");
    for (const revoked of ["all", [{}], [edKey(1)], [{ key: "x" }], { key: edKey(1) }]) {
      expect(accepts(sample("Update", { revoked })), JSON.stringify(revoked)).toMatch(/^rejected/);
    }
  });

  it(`${clause("core 8.3")} looks for a critical namespace among the record's own extension blocks only`, () => {
    for (const namespace of ["toString", "constructor", "hasOwnProperty", "__proto__"]) {
      expect(rejectedAt(sample("Offer", { ext: {}, critical: [namespace] }))).toBe(
        "core 8.3 /critical/0",
      );
    }
  });

  const nestThrough = (depth: number, wrap: (inner: unknown) => unknown): unknown => {
    let statement: unknown = ["==", ".a", 1];
    for (let i = 0; i < depth; i++) statement = wrap(statement);
    return statement;
  };
  const connectives: [string, (inner: unknown) => unknown][] = [
    ["not", (inner) => ["not", inner]],
    ["and", (inner) => ["and", [inner]]],
    ["or", (inner) => ["or", [["==", ".b", 2], inner]]],
    ["all", (inner) => ["all", ".list", inner]],
    ["any", (inner) => ["any", ".list", inner]],
  ];

  it.each(connectives)(`${clause("L1 11.3")} counts nesting through %s`, (_name, wrap) => {
    expect(MAX_POLICY_DEPTH).toBe(8);
    expect(accepts(sample("Delegation", { policy: [nestThrough(8, wrap)] }))).toBe("accepted");
    expect(rejectedAt(sample("Delegation", { policy: [nestThrough(9, wrap)] }))).toMatch(
      /^L1 11\.3 \/policy\/0/,
    );
  });

  it("limits nesting whether it is of arrays, of objects or of both", () => {
    expect(MAX_DEPTH).toBe(64);
    expect(MAX_ISSUES).toBe(32);
    const nest = (depth: number, wrap: (inner: unknown) => unknown) => nestThrough(depth, wrap);
    const shapes: ((inner: unknown) => unknown)[] = [(inner) => [inner], (inner) => ({ inner })];
    for (const wrap of shapes) {
      // The record is level 1, the member's value level 2, and the innermost statement one more.
      expect(accepts(sample("Intent", { futureMember: nest(MAX_DEPTH - 2, wrap) }))).toBe(
        "accepted",
      );
      expect(accepts(sample("Intent", { futureMember: nest(MAX_DEPTH - 1, wrap) }))).toMatch(
        /^rejected/,
      );
    }
  });

  it(`${clause("core 1.1")} rejects two low surrogates, a low before a high, and a high at the end`, () => {
    for (const bad of ["\udc00\udc00", "\udc00\ud800", "\ud800\ud800", "x\ud800"]) {
      expect(rejectedAt(sample("Intent", { want: bad }))).toBe("core 1.1 ");
    }
    expect(accepts(sample("Intent", { want: "𐀀􏿿" }))).toBe("accepted");
  });
});

describe("how schemas are named", () => {
  it("refuses a reference to a schema with no $id, and a definition named twice", () => {
    expect(() => ref(Type.String())).toThrow(/needs a schema with an \$id/);
    expect(() => define("timestamp", Type.String())).toThrow(/already exists/);
  });
});
