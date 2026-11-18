// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What a verifier is handed by strangers: records built to cost it work, to
 * confuse it, or to make it throw. Each is answered, in bounded time, and
 * none counts.
 */

import { contentId, formatRecordRef, proofDigest } from "@oip/core";
import { FirstSeen, type JudgedRecord, judgeRecord, LogBook } from "@oip/identity";
import { clause, type JsonObject } from "@oip/testkit";
import { at, intentBy, KeyMind, LATER, type Mind, rawSign, T } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import {
  delegatedProofTime,
  delegatedTime,
  type DelegationContext,
  evaluatePolicy,
  MAX_CHAIN,
  MAX_POLICY_WORK,
  policyHolds,
  RecordSet,
  type RecordView,
  revokedTime,
} from "../src/index.ts";

type Signed = JsonObject & { proof: JsonObject[] };

const amina = new KeyMind("amina");
const agents = Array.from({ length: 9 }, (_, n) => new KeyMind(`agent-${n}`));
const minds: Mind[] = [amina, ...agents];

let nonce = 0;
function delegation(author: Mind, delegate: Mind, more: JsonObject = {}): Signed {
  return author.sign({
    oip: "1",
    type: "Delegation",
    author: author.address,
    delegate: delegate.address,
    subject: amina.address,
    command: "/oip/sign/Intent",
    expires: T(100_000),
    nonce: `nonce-${String(nonce++).padStart(4, "0")}`,
    created: T(10),
    ...more,
  });
}

/** A record signed raw, as an attacker with the key could sign it, whatever its `authority`. */
function signedWith(by: Mind, authority: unknown, record: object = intentBy(amina, 100)): Signed {
  return rawSign(
    record,
    [{ member: by.address, versionId: by.versionId(0), invocation: by.operational() }],
    { purpose: "assertionMethod", authority: authority as string[] },
  );
}

/** What a verifier holds: every log, and every proof seen when it was made. */
function holding(records: readonly object[], view?: RecordView): DelegationContext {
  const evidence = new FirstSeen();
  for (const mind of minds) {
    for (const event of mind.events) evidence.sawEvent(contentId(event), at(0));
  }
  const see = (record: unknown): void => {
    if (typeof record !== "object" || record === null) return;
    const proofs = (record as { proof?: unknown }).proof;
    for (const proof of Array.isArray(proofs) ? (proofs as JsonObject[]) : []) {
      try {
        evidence.sawProof(
          proofDigest(proof),
          BigInt(Date.parse(String(proof["created"]))) * 1_000_000n,
        );
      } catch {
        // What has no digest has no evidence either.
      }
      const carried = proof["authority"];
      for (const entry of Array.isArray(carried) ? (carried as unknown[]) : []) see(entry);
    }
  };
  const set = new RecordSet();
  for (const record of records) {
    see(record);
    set.add(record);
  }
  const identity = new LogBook(evidence);
  for (const mind of minds) identity.hold(mind.events, LATER);
  return { identity, records: view ?? set };
}

const judged = (record: object): JudgedRecord | undefined => {
  const result = judgeRecord(record);
  return result.ok ? result.value : undefined;
};

/** Whether a record counts for Amina through a chain, for a verifier that also holds `held`. */
function counts(record: Signed, held: readonly object[] = []): boolean {
  const value = judged(record);
  if (value === undefined) return false;
  return delegatedTime(value, amina.address, holding([...held, record])) !== undefined;
}

describe(`${clause("L1 11.6")} an authority built to confuse`, () => {
  const grant = delegation(amina, agents[0]!);
  const signer = agents[0]!;

  it("counts for nobody when an entry is not a delegation or a reference to one", () => {
    const intent = amina.sign(intentBy(amina, 5)) as Signed;
    for (const entry of [
      5,
      null,
      true,
      [],
      [grant],
      {},
      { type: "Delegation" },
      intent,
      "",
      "not a reference",
      formatRecordRef(amina.address, contentId(intent)),
      `${amina.address}/`,
    ]) {
      expect(counts(signedWith(signer, [entry]), [grant, intent]), JSON.stringify(entry)).toBe(
        false,
      );
      // Nor beside the delegation that would otherwise do.
      expect(counts(signedWith(signer, [grant, entry]), [intent]), JSON.stringify(entry)).toBe(
        false,
      );
    }
    expect(counts(signedWith(signer, [grant]))).toBe(true);
  });

  it("counts for nobody when the authority is no list, is empty or is too long", () => {
    for (const authority of [grant, "x", 5, null, {}, [], Array.from({ length: 9 }, () => grant)]) {
      expect(counts(signedWith(signer, authority)), JSON.stringify(authority).slice(0, 40)).toBe(
        false,
      );
    }
  });

  it("is not led round a ring of delegations", () => {
    // Two agents delegate to each other, and the principal to neither.
    const [one, two] = [agents[1]!, agents[2]!];
    const forth = delegation(one, two);
    const back = delegation(two, one);
    for (const authority of [
      [forth, back],
      [back, forth],
      [forth, back, forth, back, forth, back, forth, back],
    ]) {
      expect(counts(signedWith(one, authority))).toBe(false);
      expect(counts(signedWith(two, authority))).toBe(false);
    }
    // A ring that starts at the principal ends where it started: nobody else signs by it.
    const out = delegation(amina, one);
    const home = delegation(one, amina);
    expect(counts(signedWith(one, [out, home]))).toBe(false);
    expect(counts(signedWith(amina, [out, home]))).toBe(false);
    // Round and out again, the chain grants what its first delegation grants, and no more:
    // each step keeps every statement of the one before it.
    expect(counts(signedWith(one, [out, home, out]))).toBe(true);
    const limited = delegation(amina, one, { policy: [["==", ".want", "Nothing at all."]] });
    expect(counts(signedWith(one, [limited]))).toBe(false);
    expect(counts(signedWith(one, [limited, home, out]))).toBe(false);
    const kept = { policy: [["==", ".want", "Nothing at all."]] };
    expect(
      counts(
        signedWith(one, [limited, delegation(one, amina, kept), delegation(amina, one, kept)]),
      ),
    ).toBe(false);
  });

  it("is not misled by a reference to the record itself, or to a revocation", () => {
    const record = signedWith(signer, ["placeholder"]);
    const self = formatRecordRef(amina.address, contentId(record));
    const again = signedWith(signer, [self]);
    expect(contentId(again)).toBe(contentId(record));
    expect(counts(again, [record])).toBe(false);
    const revocation = amina.sign({
      oip: "1",
      type: "Revocation",
      author: amina.address,
      revokes: formatRecordRef(amina.address, contentId(grant)),
      created: T(5000),
    }) as Signed;
    const named = formatRecordRef(amina.address, contentId(revocation));
    expect(counts(signedWith(signer, [named]), [revocation])).toBe(false);
  });

  it("answers for a chain of the greatest length, and for a record with many proofs", () => {
    const chain: Signed[] = [];
    for (let i = 0; i < MAX_CHAIN; i++) {
      chain.push(delegation(i === 0 ? amina : agents[i - 1]!, agents[i]!));
    }
    const last = agents[MAX_CHAIN - 1]!;
    expect(counts(signedWith(last, chain))).toBe(true);
    // Thirty-two proofs, each carrying eight delegations whole, and only the last a chain.
    const junk = chain.map((link) =>
      delegation(agents[8]!, agents[8 - 1]!, { nonce: String(link["nonce"]) + "x" }),
    );
    const content = intentBy(amina, 100);
    const proofs = Array.from({ length: 31 }, () => signedWith(last, junk, content).proof[0]!);
    const heavy = { ...content, proof: [...proofs, signedWith(last, chain, content).proof[0]!] };
    const started = performance.now();
    expect(counts(heavy as Signed)).toBe(true);
    expect(performance.now() - started).toBeLessThan(30_000);
  });
});

describe("a view that fails", () => {
  it("is the caller's, and its failure is not taken for an answer", () => {
    const grant = delegation(amina, agents[0]!);
    const record = signedWith(agents[0]!, [formatRecordRef(amina.address, contentId(grant))]);
    const failing: RecordView = {
      record: () => {
        throw new Error("the store is closed");
      },
      revocationsOf: () => {
        throw new Error("the store is closed");
      },
      chartersOf: () => [],
    };
    const value = judged(record);
    if (value === undefined) throw new Error("the record is well formed");
    const context = holding([grant], failing);
    expect(() => delegatedTime(value, amina.address, context)).toThrow("the store is closed");
    expect(() => revokedTime(contentId(grant), amina.address, failing, context.identity)).toThrow(
      "the store is closed",
    );
    // With the delegation given whole, it is the revocations that are asked for.
    const carrying = signedWith(agents[0]!, [grant]);
    const inline = judged(carrying);
    if (inline === undefined) throw new Error("the record is well formed");
    const seeing = holding([carrying], failing);
    expect(() => delegatedProofTime(inline, inline.proofs[0]!, amina.address, seeing)).toThrow(
      "the store is closed",
    );
  });
});

describe(`${clause("L1 11.3")} a policy built to cost work`, () => {
  it("stops at the work allowed, and does not hold", () => {
    // A quantifier inside a quantifier, over 600 arrays of 600.
    const record = {
      rows: Array.from({ length: 600 }, () => Array.from({ length: 600 }, () => 1)),
    };
    const policy = [["all", ".rows", ["all", ".", ["==", ".", 1]]]];
    const started = performance.now();
    expect(evaluatePolicy(policy, record)).toMatchObject({
      ok: false,
      issues: [{ clause: "L1 11.3" }],
    });
    expect(performance.now() - started).toBeLessThan(5000);
    // Within the work allowed, the same policy holds.
    const small = { rows: Array.from({ length: 100 }, () => Array.from({ length: 100 }, () => 1)) };
    expect(100 * 100 + 101).toBeLessThan(MAX_POLICY_WORK);
    expect(policyHolds(policy, small)).toBe(true);
  });

  it("does no more work than it counts, where every statement compares the whole record", () => {
    // A record of some 440 KB, and 256 statements that each compare all of it with a
    // number. Written out for each, its canonical form took seconds for one proof.
    const record = { blob: "x".repeat(440_000), n: 1 };
    const policy = Array.from({ length: 64 }, () => [
      "and",
      Array.from({ length: 4 }, () => ["!=", ".", 0]),
    ]);
    const started = performance.now();
    // The first comparison counts more than all the work there is.
    expect(evaluatePolicy(policy, record)).toMatchObject({
      ok: false,
      issues: [{ clause: "L1 11.3" }],
    });
    expect(performance.now() - started).toBeLessThan(500);
    // A record of a fifth of the work allowed: four comparisons of it hold, a fifth does not.
    const fifth = { blob: "x".repeat(52_000) };
    const compare = (times: number) => Array.from({ length: times }, () => ["!=", ".", 0]);
    expect(policyHolds(compare(4), fifth)).toBe(true);
    expect(policyHolds(compare(5), fifth)).toBe(true);
    expect(policyHolds(compare(6), fifth)).toBe(false);
  });

  it("reads a selector once, however many values its statement is tried on", () => {
    // A selector of 180 KB that resolves on nothing, tried on 4,000 elements.
    const selector = `.a${'["a"]'.repeat(30_000)}`;
    const record = { xs: Array.from({ length: 4000 }, () => ({ a: 1 })) };
    const started = performance.now();
    const refused = evaluatePolicy([["all", ".xs", ["==", selector, 1]]], record);
    expect(performance.now() - started).toBeLessThan(1000);
    expect(refused.ok).toBe(false);
    // What it says of the selector is no longer than a line.
    const issues = refused.ok ? [] : refused.issues;
    expect(issues.length).toBeGreaterThan(0);
    for (const issue of issues) {
      expect(issue.clause).toBe("L1 11.3");
      expect(issue.message.length).toBeLessThan(200);
    }
  });

  it("is read no further than the work allowed, where one statement stands in many places", () => {
    // Eight levels of `and`, each holding the level below 64 times: one small value in
    // memory, and 64 to the power of 8 statements to whoever walks it.
    let statement: unknown = ["==", ".a", 1];
    for (let level = 0; level < 8; level++)
      statement = ["and", Array.from({ length: 64 }, () => statement)];
    const started = performance.now();
    expect(evaluatePolicy([statement], { a: 1 })).toMatchObject({
      ok: false,
      issues: [{ clause: "implementation limit" }],
    });
    expect(performance.now() - started).toBeLessThan(5000);
  });

  it("holds at the limits of its form: 64 statements of 64, and a long selector", () => {
    const wide = Array.from({ length: 64 }, () => [
      "and",
      Array.from({ length: 64 }, () => ["==", ".a", 1]),
    ]);
    expect(policyHolds(wide, { a: 1 })).toBe(true);
    expect(policyHolds([...wide, ["==", ".a", 1]], { a: 1 })).toBe(false);
    const deep = `.a${".a".repeat(5000)}`;
    expect(policyHolds([["==", deep, 1]], { a: { a: 1 } })).toBe(false);
    expect(policyHolds([["not", ["==", deep, 1]]], { a: { a: 1 } })).toBe(false);
    // A name every object has is no member of the record.
    for (const name of ["constructor", "__proto__", "toString", "hasOwnProperty"]) {
      expect(policyHolds([["!=", `.${name}`, 1]], { a: 1 }), name).toBe(false);
      expect(policyHolds([["!=", `.a.${name}`, 1]], { a: {} }), name).toBe(false);
    }
  });
});
