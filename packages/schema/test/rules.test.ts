// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { clause, copy, type JsonObject } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import { MAX_POLICY_DEPTH, validateProof, validateRecord } from "../src/index.ts";
import {
  AMINA,
  CID,
  delegatedProof,
  LEXIS_AGENT,
  sample,
  sampleProof,
  samples,
} from "./fixtures.ts";

function issuesOf(record: unknown): string[] {
  const result = validateRecord(record);
  return result.ok
    ? []
    : result.issues.map((issue) => `${issue.clause} ${issue.path}: ${issue.message}`);
}

const KEY_A = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
const KEY_B = "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
const HASH = (n: number) => `bciq${"abcdefghijklmnop"[n] ?? "a"}${"a".repeat(50)}a`;

describe("thresholds are majorities", () => {
  const keyGenesis = (controller: JsonObject) => sample("Genesis", { controller });
  const memberGenesis = (controller: JsonObject) =>
    sample("Genesis", { kind: "collective", controller });
  const members = (n: number) => Array.from({ length: n }, (_unused, i) => `did:oip:${HASH(i)}`);

  it(`${clause("L1 3.4")} accepts nextThreshold from a majority up to the number of committed keys`, () => {
    const next = [HASH(0), HASH(1), HASH(2)];
    for (const nextThreshold of [2, 3]) {
      expect(issuesOf(keyGenesis({ keys: [KEY_A], next, nextThreshold }))).toEqual([]);
    }
    expect(issuesOf(keyGenesis({ keys: [KEY_A], next: [HASH(0)] }))).toEqual([]);
  });

  it(`${clause("L1 3.4")} rejects a nextThreshold that is not a majority, including the default of 1`, () => {
    const next = [HASH(0), HASH(1), HASH(2)];
    expect(issuesOf(keyGenesis({ keys: [KEY_A], next, nextThreshold: 1 }))[0]).toMatch(/majority/);
    expect(issuesOf(keyGenesis({ keys: [KEY_A], next }))[0]).toMatch(/majority/);
    expect(issuesOf(keyGenesis({ keys: [KEY_A], next: [HASH(0), HASH(1)] }))[0]).toMatch(
      /majority/,
    );
    expect(issuesOf(keyGenesis({ keys: [KEY_A], next, nextThreshold: 4 }))[0]).toMatch(/majority/);
    expect(issuesOf(keyGenesis({ keys: [KEY_A], next, nextThreshold: 0 }))).not.toEqual([]);
  });

  it(`${clause("L1 3.4")} rejects nextThreshold when next is empty`, () => {
    expect(issuesOf(keyGenesis({ keys: [KEY_A], next: [] }))).toEqual([]);
    expect(issuesOf(keyGenesis({ keys: [KEY_A], next: [], nextThreshold: 1 }))[0]).toMatch(
      /absent/,
    );
  });

  it(`${clause("L1 3.4")} rejects duplicate control keys, duplicate commitments and more than 16 of either`, () => {
    expect(issuesOf(keyGenesis({ keys: [KEY_A, KEY_A], next: [] }))).not.toEqual([]);
    expect(
      issuesOf(keyGenesis({ keys: [KEY_A], next: [HASH(0), HASH(0)], nextThreshold: 2 })),
    ).not.toEqual([]);
    expect(issuesOf(keyGenesis({ keys: [], next: [] }))).not.toEqual([]);
    const seventeen = Array.from(
      { length: 17 },
      (_unused, i) => `bciqa${"a".repeat(49)}${"abcdefghijklmnopq"[i] ?? ""}a`,
    );
    expect(issuesOf(keyGenesis({ keys: [KEY_A], next: seventeen, nextThreshold: 9 }))).not.toEqual(
      [],
    );
  });

  it(`${clause("L1 3.4")} accepts a member threshold that is a majority and rejects one that is not`, () => {
    expect(issuesOf(memberGenesis({ members: members(3), threshold: 2 }))).toEqual([]);
    expect(issuesOf(memberGenesis({ members: members(3), threshold: 3 }))).toEqual([]);
    expect(issuesOf(memberGenesis({ members: members(1), threshold: 1 }))).toEqual([]);
    expect(issuesOf(memberGenesis({ members: members(3), threshold: 1 }))[0]).toMatch(/majority/);
    expect(issuesOf(memberGenesis({ members: members(4), threshold: 2 }))[0]).toMatch(/majority/);
    expect(issuesOf(memberGenesis({ members: members(2), threshold: 3 }))[0]).toMatch(/majority/);
    expect(issuesOf(memberGenesis({ members: members(3), threshold: 0 }))).not.toEqual([]);
  });

  it(`${clause("L1 3.4")} rejects a controller that mixes the two kinds or has members it does not define`, () => {
    expect(
      issuesOf(keyGenesis({ keys: [KEY_A], next: [], members: members(1), threshold: 1 })),
    ).not.toEqual([]);
    expect(issuesOf(keyGenesis({ keys: [KEY_A], next: [], note: "extra" }))).not.toEqual([]);
    const duplicated = [...members(2), ...members(1)];
    expect(issuesOf(memberGenesis({ members: duplicated, threshold: 2 }))).not.toEqual([]);
  });

  it(`${clause("L1 3.6")} requires a collective to be member-controlled, and allows height only there`, () => {
    expect(issuesOf(sample("Genesis", { kind: "collective" }))).not.toEqual([]);
    expect(issuesOf(sample("Genesis", { height: 1 }))).not.toEqual([]);
    expect(issuesOf(memberGenesis({ members: members(3), threshold: 2 }))).toEqual([]);
    const tall = { ...memberGenesis({ members: members(3), threshold: 2 }), height: 4 };
    expect(issuesOf(tall)).toEqual([]);
    expect(issuesOf({ ...tall, height: 5 })).not.toEqual([]);
    expect(issuesOf({ ...tall, height: 0 })).not.toEqual([]);
  });
});

describe("identity events", () => {
  it(`${clause("L1 3.2")} rejects a Genesis with mind, seq or prev`, () => {
    expect(issuesOf(sample("Genesis", { mind: AMINA }))).not.toEqual([]);
    expect(issuesOf(sample("Genesis", { seq: 0 }))).not.toEqual([]);
    expect(issuesOf(sample("Genesis", { prev: CID }))).not.toEqual([]);
  });

  it(`${clause("L1 3.2")} rejects a later event with seq 0`, () => {
    expect(issuesOf(sample("Update", { seq: 0 }))).not.toEqual([]);
  });

  it(`${clause("L1 3.6")} rejects height in an event after the genesis`, () => {
    for (const type of ["Update", "Fork", "Retire"] as const) {
      expect(issuesOf(sample(type, { height: 1 }))).not.toEqual([]);
    }
  });

  it(`${clause("L1 3.12")} rejects any identity event that contains recovery`, () => {
    for (const type of ["Genesis", "Update", "Fork", "Retire"] as const) {
      expect(issuesOf(sample(type, { recovery: { keys: [] } }))).not.toEqual([]);
    }
  });

  it(`${clause("L1 3.10")} rejects a key-controlled Retire that commits to further keys`, () => {
    expect(issuesOf(samples.Retire)).toEqual([]);
    const controller = { keys: [KEY_A], next: [HASH(0)] };
    expect(issuesOf(sample("Retire", { controller }))).not.toEqual([]);
  });

  it(`${clause("L1 3.5")} rejects a key that appears twice in a set, or in both keys and invocation`, () => {
    const entry = (key: string, label?: string) => (label === undefined ? { key } : { key, label });
    expect(issuesOf(sample("Update", { keys: [entry(KEY_A), entry(KEY_B)] }))).toEqual([]);
    expect(issuesOf(sample("Update", { keys: [entry(KEY_A), entry(KEY_A, "again")] }))[0]).toMatch(
      /twice/,
    );
    expect(
      issuesOf(sample("Update", { keys: [entry(KEY_A)], invocation: [entry(KEY_A)] }))[0],
    ).toMatch(/both keys and invocation/);
  });

  it(`${clause("L1 3.5")} rejects key entries of the wrong type, with unknown members or with long labels`, () => {
    const agreement = (samples.Genesis["agreement"] as JsonObject[])[0]!;
    expect(issuesOf(sample("Update", { keys: [agreement] }))).not.toEqual([]);
    expect(issuesOf(sample("Update", { agreement: [{ key: KEY_A }] }))).not.toEqual([]);
    expect(issuesOf(sample("Update", { keys: [{ key: KEY_A, note: "x" }] }))).not.toEqual([]);
    expect(
      issuesOf(sample("Update", { keys: [{ key: KEY_A, label: "l".repeat(65) }] })),
    ).not.toEqual([]);
    expect(issuesOf(sample("Update", { keys: [{ key: KEY_A, label: "é".repeat(64) }] }))).toEqual(
      [],
    );
    const many = (n: number) => Array.from({ length: n }, () => ({ key: KEY_A }));
    expect(issuesOf(sample("Update", { invocation: many(17) }))).not.toEqual([]);
    expect(issuesOf(sample("Update", { keys: many(65) }))).not.toEqual([]);
  });

  it(`${clause("L1 3.4")} rejects a later event whose member controller lists the mind itself`, () => {
    const collective = `did:oip:${HASH(9)}`;
    const others = [`did:oip:${HASH(1)}`, `did:oip:${HASH(2)}`];
    const update = (members: string[]) =>
      sample("Update", { mind: collective, controller: { members, threshold: 2 } });
    expect(issuesOf(update(others))).toEqual([]);
    expect(issuesOf(update([...others, collective]))[0]).toMatch(
      /^L1 3\.4 \/controller\/members\/2: .*member of itself/,
    );
  });

  it(`${clause("L1 4.5")} rejects an event that revokes a key and also lists it in keys or invocation`, () => {
    const revoked = [{ key: KEY_A, compromisedSince: "2026-10-30T09:00:00Z" }];
    expect(issuesOf(sample("Update", { revoked, keys: [{ key: KEY_B }] }))).toEqual([]);
    expect(issuesOf(sample("Update", { revoked, keys: [{ key: KEY_A }] }))[0]).toMatch(
      /^L1 4\.5 \/keys\/0\/key: .*revoked by this event/,
    );
    expect(issuesOf(sample("Fork", { revoked, invocation: [{ key: KEY_A }] }))[0]).toMatch(
      /^L1 4\.5 \/invocation\/0\/key/,
    );
    // Without a new key set, the check needs the state, which is @oip/identity's work.
    expect(issuesOf(sample("Update", { revoked }))).toEqual([]);
  });

  it(`${clause("L1 3.6")} bounds homes, aliases and parents`, () => {
    const origins = (n: number) =>
      Array.from({ length: n }, (_unused, i) => `https://h${i}.example`);
    expect(issuesOf(sample("Genesis", { homes: origins(8) }))).toEqual([]);
    expect(issuesOf(sample("Genesis", { homes: origins(9) }))).not.toEqual([]);
    expect(issuesOf(sample("Genesis", { homes: ["http://plain.example"] }))).not.toEqual([]);
    expect(issuesOf(sample("Genesis", { homes: ["https://h.example/path"] }))).not.toEqual([]);
    expect(issuesOf(sample("Genesis", { alsoKnownAs: origins(17) }))).not.toEqual([]);
    expect(issuesOf(sample("Genesis", { parents: [{ mind: AMINA, at: `3-${CID}` }] }))).toEqual([]);
    expect(issuesOf(sample("Genesis", { parents: [{ mind: AMINA, at: CID }] }))).not.toEqual([]);
  });
});

describe("delegation", () => {
  it(`${clause("L1 11.1")} rejects a delegation whose delegate is its author`, () => {
    const delegation = sample("Delegation");
    expect(issuesOf({ ...delegation, delegate: delegation["author"] })[0]).toMatch(
      /^L1 11\.1 \/delegate: .*differ/,
    );
  });

  const nested = (depth: number): unknown =>
    depth === 0 ? ["==", ".a", 1] : ["not", nested(depth - 1)];

  it(`${clause("L1 11.3")} accepts statements nested up to the limit and rejects deeper ones`, () => {
    expect(issuesOf(sample("Delegation", { policy: [nested(MAX_POLICY_DEPTH)] }))).toEqual([]);
    expect(issuesOf(sample("Delegation", { policy: [nested(MAX_POLICY_DEPTH + 1)] }))[0]).toMatch(
      /nests/,
    );
  });

  it(`${clause("L1 11.3")} checks selectors in comparisons, quantifiers and connectives`, () => {
    const good = [
      [
        "all",
        ".parties",
        [
          "or",
          [
            ["==", ".mind", AMINA],
            ["!=", '["a b"]', null],
          ],
        ],
      ],
      [
        "and",
        [
          ["<=", ".terms.price.amount", "500"],
          ["any", ".x[0]", ["==", ".", 1]],
        ],
      ],
    ];
    expect(issuesOf(sample("Delegation", { policy: good }))).toEqual([]);
    for (const policy of [
      [["==", "terms.price", 1]],
      [["any", "parties", ["==", ".", 1]]],
      [["all", ".parties", ["==", "mind", 1]]],
      [["not", ["==", ".a[01]", 1]]],
      [
        [
          "or",
          [
            ["==", ".a", 1],
            ["==", ".b..c", 1],
          ],
        ],
      ],
    ]) {
      expect(issuesOf(sample("Delegation", { policy }))[0]).toMatch(/not a selector/);
    }
  });

  it(`${clause("L2 6.2")} applies the policy rules to the powers of a charter's roles`, () => {
    const charter = (policy: unknown) =>
      sample("Collective", {
        roles: { "the steward": { powers: [{ command: "/oip/sign/Offer", policy }] } },
      });
    expect(issuesOf(charter([["==", ".a", 1]]))).toEqual([]);
    expect(issuesOf(charter([["==", "a", 1]]))[0]).toMatch(/roles\/the steward\/powers\/0\/policy/);
    expect(issuesOf(sample("Collective", { roles: { r: {} } }))).toEqual([]);
  });
});

describe("commitments", () => {
  const parties = samples.Commitment["parties"] as {
    mind: string;
    role: string;
    required?: boolean;
  }[];
  const [first, second] = parties as [(typeof parties)[0], (typeof parties)[0]];
  const terms = samples.Commitment["terms"] as JsonObject;

  it(`${clause("L2 5.1")} rejects a mind that is a party more than once`, () => {
    const twice = [first, second, { ...first, role: "witness", required: false }];
    expect(issuesOf(sample("Commitment", { parties: twice }))[0]).toMatch(/more than once/);
  });

  it(`${clause("L2 5.1")} requires a debtor and a creditor, both required, among 2 to 64 parties`, () => {
    const role = (r: string) => parties.map((party) => ({ ...party, role: r }));
    expect(issuesOf(sample("Commitment", { parties: role("debtor") }))).not.toEqual([]);
    expect(issuesOf(sample("Commitment", { parties: role("creditor") }))).not.toEqual([]);
    expect(issuesOf(sample("Commitment", { parties: [first] }))).not.toEqual([]);
    const optional = [{ mind: first.mind, role: first.role }, second];
    expect(issuesOf(sample("Commitment", { parties: optional }))).not.toEqual([]);
    const notRequired = [{ ...first, required: false }, second];
    expect(issuesOf(sample("Commitment", { parties: notRequired }))).not.toEqual([]);
    const witness = [first, second, { mind: LEXIS_AGENT, role: "witness" }];
    const namespaced = [first, second, { mind: LEXIS_AGENT, role: "com.example:arbiter" }];
    const unknownRole = [first, second, { mind: LEXIS_AGENT, role: "bystander" }];
    expect(issuesOf(sample("Commitment", { parties: witness, terms: {} }))).toEqual([]);
    expect(issuesOf(sample("Commitment", { parties: namespaced, terms: {} }))).toEqual([]);
    expect(issuesOf(sample("Commitment", { parties: unknownRole, terms: {} }))).not.toEqual([]);
  });

  it(`${clause("L2 5.1")} requires a price to name two different parties as payer and payee`, () => {
    const price = terms["price"] as JsonObject;
    const withPrice = (changes: JsonObject) =>
      sample("Commitment", { terms: { ...terms, price: { ...price, ...changes } } });
    expect(issuesOf(withPrice({}))).toEqual([]);
    expect(issuesOf(withPrice({ payer: LEXIS_AGENT }))[0]).toMatch(
      /payer must be one of the parties/,
    );
    expect(issuesOf(withPrice({ payee: LEXIS_AGENT }))[0]).toMatch(
      /payee must be one of the parties/,
    );
    expect(issuesOf(withPrice({ payee: price["payer"] }))[0]).toMatch(/two different parties/);
    const { payer: _payer, ...noPayer } = price;
    expect(issuesOf(sample("Commitment", { terms: { ...terms, price: noPayer } }))).not.toEqual([]);
  });
});

describe("other rules", () => {
  it(`${clause("L1 14.1")} requires session participants to be distinct and sorted by code point`, () => {
    const participants = [...(samples.Session["participants"] as string[])];
    expect(participants.length).toBeGreaterThanOrEqual(2);
    expect(issuesOf(sample("Session", { participants: participants.toReversed() }))[0]).toMatch(
      /sorted/,
    );
    expect(
      issuesOf(sample("Session", { participants: [participants[0], participants[0]] })),
    ).not.toEqual([]);
    expect(issuesOf(sample("Session", { participants: [participants[0]] }))).not.toEqual([]);
  });

  it(`${clause("L1 16.2")} rejects a capability id used twice in one profile`, () => {
    const capabilities = [
      { id: "translate", summary: "Translation" },
      { id: "translate", summary: "More translation" },
    ];
    expect(issuesOf(sample("Participant", { capabilities }))[0]).toMatch(/more than once/);
  });

  it("applies the rules to the records inside containers and wrappers", () => {
    const bad = sample("Update", { keys: [{ key: KEY_A }, { key: KEY_A }] });
    const good = samples.Update;
    expect(issuesOf(sample("Bundle", { log: [good, bad] }))[0]).toMatch(/\/log\/1\/keys\/1\/key/);
    expect(issuesOf(sample("LogPage", { events: [bad] }))[0]).toMatch(/\/events\/0\//);
    expect(issuesOf(sample("DuplicityEvidence", { pairs: [[good, bad]] }))[0]).toMatch(
      /\/pairs\/0\/1\//,
    );
    const packet = sample("Packet", { critical: ["com.example.x"] });
    expect(issuesOf(sample("Forwarded", { packet }))[0]).toMatch(/core 8\.3 \/packet\/critical\/0/);
    const profile = sample("Participant", {
      capabilities: [
        { id: "a", summary: "A" },
        { id: "a", summary: "B" },
      ],
    });
    expect(issuesOf(sample("Bundle", { participant: profile }))[0]).toMatch(
      /\/participant\/capabilities\/1/,
    );
    const location = sample("Location", { critical: ["com.example.x"] });
    expect(issuesOf(sample("Bundle", { location }))[0]).toMatch(/\/location\/critical\/0/);
    const entry = sample("Entry", { critical: ["com.example.x"] });
    expect(issuesOf(sample("FeedPage", { entries: [entry] }))[0]).toMatch(
      /\/entries\/0\/critical\/0/,
    );
  });
});

describe("proofs", () => {
  const rejected = (proof: unknown) => {
    const result = validateProof(proof);
    return result.ok
      ? []
      : result.issues.map((issue) => `${issue.clause} ${issue.path}: ${issue.message}`);
  };

  it(`${clause("core 5.2")} accepts a proof with exactly the members allowed`, () => {
    expect(rejected(sampleProof())).toEqual([]);
    expect(rejected(delegatedProof())).toEqual([]);
  });

  it(`${clause("core 5.2")} rejects a proof with id, previousProof or any other member`, () => {
    for (const member of ["id", "previousProof", "nonce", "expires"]) {
      expect(rejected(sampleProof({ [member]: "x" }))).not.toEqual([]);
    }
  });

  it(`${clause("core 5.2")} rejects a proof that lacks a required member or has the wrong type or cryptosuite`, () => {
    for (const member of [
      "type",
      "cryptosuite",
      "verificationMethod",
      "proofPurpose",
      "created",
      "proofValue",
    ]) {
      const { [member]: _removed, ...rest } = sampleProof();
      expect(rejected(rest)).not.toEqual([]);
    }
    expect(rejected(sampleProof({ type: "Ed25519Signature2020" }))).not.toEqual([]);
    expect(rejected(sampleProof({ cryptosuite: "eddsa-rdfc-2022" }))).not.toEqual([]);
    expect(rejected(sampleProof({ proofValue: "u3q2-7w" }))).not.toEqual([]);
    expect(rejected(sampleProof({ created: "yesterday" }))).not.toEqual([]);
  });

  it(`${clause("core 5.6")} rejects a proof purpose the specification does not define`, () => {
    expect(rejected(sampleProof({ proofPurpose: "keyAgreement" }))).not.toEqual([]);
  });

  it(`${clause("core 5.2")} allows challenge and domain only in authentication proofs`, () => {
    const hello = (samples.Hello["proof"] as JsonObject[])[0]!;
    expect(hello["proofPurpose"]).toBe("authentication");
    expect(rejected(hello)).toEqual([]);
    expect(rejected({ ...hello, proofPurpose: "assertionMethod" })).not.toEqual([]);
    const { challenge: _challenge, ...domainOnly } = hello;
    expect(rejected({ ...domainOnly, proofPurpose: "assertionMethod" })).not.toEqual([]);
  });

  it(`${clause("core 6.2")} requires both keys of a control-key-ref to be identical`, () => {
    expect(rejected(sampleProof({ verificationMethod: `did:key:${KEY_A}#${KEY_A}` }))).toEqual([]);
    expect(rejected(sampleProof({ verificationMethod: `did:key:${KEY_A}#${KEY_B}` }))[0]).toMatch(
      /identical/,
    );
  });

  it(`${clause("core 6.1")} rejects a verification method that is neither a key-ref nor a control-key-ref`, () => {
    for (const verificationMethod of [
      `${AMINA}#${KEY_A}`,
      `${AMINA}?versionId=01-${CID}#${KEY_A}`,
      `${AMINA}?versionId=1-${CID}`,
      `did:web:example.com#${KEY_A}`,
      KEY_A,
    ]) {
      expect(rejected(sampleProof({ verificationMethod }))).not.toEqual([]);
    }
    expect(
      rejected(sampleProof({ verificationMethod: `${AMINA}?versionId=0-${CID}#${KEY_A}` })),
    ).toEqual([]);
  });

  it(`${clause("core 5.2", "L1 11.6")} accepts 1 to 8 authority entries, each a record-ref or an inline record`, () => {
    const refs = (n: number) => Array.from({ length: n }, () => `${AMINA}/${CID}`);
    expect(rejected(sampleProof({ authority: refs(1) }))).toEqual([]);
    expect(rejected(sampleProof({ authority: refs(8) }))).toEqual([]);
    expect(rejected(sampleProof({ authority: [`${AMINA}/${CID}`, samples.Delegation] }))).toEqual(
      [],
    );
    expect(rejected(sampleProof({ authority: [samples.Collective] }))).toEqual([]);
    expect(rejected(sampleProof({ authority: refs(9) }))).not.toEqual([]);
    expect(rejected(sampleProof({ authority: [] }))).not.toEqual([]);
    expect(rejected(sampleProof({ authority: `${AMINA}/${CID}` }))).not.toEqual([]);
    for (const entry of [7, null, true, [samples.Delegation]]) {
      expect(rejected(sampleProof({ authority: [entry] }))).not.toEqual([]);
    }
  });

  it(`${clause("L2 7.1")} keeps a proof a proof when its chain or charter would not hold up`, () => {
    // Such a proof still counts for its signer's own mind, so validation must
    // not reject it. The chain is judged when it is evaluated (Layer 1, 11.4).
    const toSelf = copy(samples.Delegation);
    toSelf["delegate"] = toSelf["author"];
    expect(validateRecord(toSelf).ok).toBe(false);
    expect(rejected(sampleProof({ authority: [toSelf] }))).toEqual([]);
    expect(rejected(sampleProof({ authority: [{ not: "a delegation" }] }))).toEqual([]);
    expect(rejected(sampleProof({ authority: ["not a record-ref"] }))).toEqual([]);
    expect(rejected(sampleProof({ authority: [samples.Delegation, samples.Collective] }))).toEqual(
      [],
    );
  });
});
