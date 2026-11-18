// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A check that was cut short, in this package (ADR-0010).
 *
 * Whether a delegation is revoked is found by looking for a revocation that
 * counts. A look that could not be finished has found none, and "not
 * revoked" is the answer that lets a delegate act: so no function here
 * gives it, or anything built on it, for a look that was cut short.
 */

import { contentId, formatRecordRef, type Instant, proofDigest } from "@oip/core";
import {
  FirstSeen,
  type IdentityView,
  type JudgedRecord,
  judgeRecord,
  LogBook,
} from "@oip/identity";
import { CUT_SHORT, cutShortCount, noteCutShort } from "@oip/schema";
import { clause, type JsonObject } from "@oip/testkit";
import { at, intentBy, KeyMind, LATER, type Mind, T } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import {
  delegatedProofTime,
  delegatedTime,
  type DelegationContext,
  evaluatePolicy,
  policyHolds,
  RecordSet,
  revokedTime,
  sentFor,
  witnessProofs,
} from "../src/index.ts";

type Signed = JsonObject & { proof: JsonObject[] };

const SPENT = {
  ok: false,
  issues: [{ path: "", message: CUT_SHORT, clause: "implementation limit" }],
};

const overflow = (): RangeError => new RangeError("Maximum call stack size exceeded");

/** A value that throws `error` as soon as anything is asked of it. */
function failing(error: unknown): object {
  const refuse = (): never => {
    throw error;
  };
  return new Proxy(
    {},
    { ownKeys: refuse, get: refuse, has: refuse, getOwnPropertyDescriptor: refuse },
  );
}

const amina = new KeyMind("amina");
const agent = new KeyMind("agent");
const minds = [amina, agent];

/** Amina's delegation to her agent, made at 10, and her revocation of it, made at 30. */
const grant = amina.sign({
  oip: "1",
  type: "Delegation",
  author: amina.address,
  delegate: agent.address,
  subject: amina.address,
  command: "/oip/sign/Intent",
  expires: T(10_000),
  nonce: "nonce-0001",
  created: T(10),
}) as Signed;
const revocation = amina.sign({
  oip: "1",
  type: "Revocation",
  author: amina.address,
  revokes: formatRecordRef(amina.address, contentId(grant)),
  created: T(30),
}) as Signed;
/** An Intent of Amina's that her agent signed at 50, after the revocation. */
const late = agent.sign(intentBy(amina, 50), {
  more: { authority: [formatRecordRef(amina.address, contentId(grant))] },
}) as Signed;

function judged(record: object): JudgedRecord {
  const result = judgeRecord(record);
  if (!result.ok) throw new Error(JSON.stringify(result.issues));
  return result.value;
}

/**
 * What a verifier holds, with logs that note a check cut short while
 * `cut.now` is set, each time the log of `about` is asked for.
 */
function holding(records: readonly Signed[], about: Mind) {
  const evidence = new FirstSeen();
  for (const mind of minds) {
    for (const event of mind.events) evidence.sawEvent(contentId(event), at(0));
  }
  const set = new RecordSet();
  for (const record of records) {
    for (const proof of record.proof) {
      evidence.sawProof(
        proofDigest(proof),
        BigInt(Date.parse(String(proof["created"]))) * 1_000_000n,
      );
    }
    set.add(record);
  }
  const book = new LogBook(evidence);
  for (const mind of minds) book.hold(mind.events, LATER);
  const cut = { now: false };
  const identity: IdentityView = {
    evidence: book.evidence,
    log: (mind) => {
      if (cut.now && mind === about.address) noteCutShort(overflow());
      return book.log(mind);
    },
  };
  const context: DelegationContext = { identity, records: set };
  return { context, set, cut };
}

describe(`${clause("L1 11.5")} a look for a revocation that was cut short`, () => {
  it("is not the answer that the delegation is not revoked", () => {
    const { context, set, cut } = holding([grant, revocation, late], amina);
    const asked = () => revokedTime(contentId(grant), amina.address, set, context.identity);
    expect(asked()).toStrictEqual({ ok: true, value: at(30) });
    cut.now = true;
    expect(asked()).toStrictEqual(SPENT);
    cut.now = false;
    expect(asked()).toStrictEqual({ ok: true, value: at(30) });
    // A delegation that nobody revoked is not revoked, and that is an answer.
    expect(revokedTime(contentId(late), amina.address, set, context.identity)).toStrictEqual({
      ok: true,
      value: undefined,
    });
  });

  it("lets nothing count through the delegation: not the proof, and not the record", () => {
    const { context, cut } = holding([grant, revocation, late], amina);
    const record = judged(late);
    const [proof] = record.proofs;
    if (proof === undefined) throw new Error("no proof");
    const proofTime = () => delegatedProofTime(record, proof, amina.address, context);
    const time = (): Instant | undefined => delegatedTime(record, amina.address, context);
    // The delegation was revoked at 30, and the proof was made at 50.
    expect(proofTime()).toMatchObject({ ok: false, issues: [{ clause: "L1 11.5" }] });
    expect(time()).toBeUndefined();
    cut.now = true;
    // With the look for the revocation cut short, the answer is not that the proof counts.
    expect(proofTime()).toStrictEqual(SPENT);
    expect(time()).toBeUndefined();
    cut.now = false;
    expect(proofTime()).toMatchObject({ ok: false, issues: [{ clause: "L1 11.5" }] });
  });

  it("gives no time for a record one of whose proofs could not be judged", () => {
    // Two proofs by the agent under the delegation, before it was revoked. The second is
    // judged with a check cut short: the first is not given as the earliest of them.
    const early = agent.sign(intentBy(amina, 15), {
      more: { authority: [formatRecordRef(amina.address, contentId(grant))] },
    }) as Signed;
    const twice = agent.sign(early, {
      created: T(16),
      more: { authority: [formatRecordRef(amina.address, contentId(grant))] },
    }) as Signed;
    const { context } = holding([grant, twice], agent);
    const record = judged(twice);
    expect(delegatedTime(record, amina.address, context)).toBe(at(15));
    let asked = 0;
    const second: DelegationContext = {
      ...context,
      identity: {
        evidence: context.identity.evidence,
        log: (mind) => {
          // The agent's log is asked for once for each proof, first.
          if (mind === agent.address && ++asked === 2) noteCutShort(overflow());
          return context.identity.log(mind);
        },
      },
    };
    expect(delegatedTime(record, amina.address, second)).toBeUndefined();
  });
});

describe(`${clause("L1 11.2")} the other judges of this package, where a check is cut short`, () => {
  it("say of no packet that it was sent for its subject", () => {
    const send = amina.sign({
      oip: "1",
      type: "Delegation",
      author: amina.address,
      delegate: agent.address,
      subject: amina.address,
      command: "/oip/send",
      expires: T(10_000),
      nonce: "nonce-0002",
      created: T(10),
    }) as Signed;
    const packet = agent.sign(
      {
        oip: "1",
        type: "Packet",
        from: agent.address,
        to: [amina.address],
        created: T(20),
        expires: T(3620),
        nonce: "nonce-0003",
        purpose: { verb: "inform" },
        content: { mediaType: "text/plain", body: "For Amina." },
        provenance: { onBehalfOf: amina.address },
      },
      { more: { authority: [formatRecordRef(amina.address, contentId(send))] } },
    ) as Signed;
    const { context, cut } = holding([send, packet], agent);
    expect(sentFor(judged(packet), amina.address, context)).toBe(at(20));
    cut.now = true;
    expect(sentFor(judged(packet), amina.address, context)).toBeUndefined();
  });

  it("refuse for a policy that could not be read for want of room", () => {
    const record = { type: "Intent", budget: "100" };
    const spent = new Proxy([], {
      get: () => {
        throw overflow();
      },
    });
    expect(evaluatePolicy(spent, record)).toStrictEqual(SPENT);
    expect(policyHolds(spent, record)).toBe(false);
    expect(evaluatePolicy([["==", ".type", "Intent"]], record)).toStrictEqual({
      ok: true,
      value: true,
    });
  });

  it("take in no record that could not be judged, and hold nothing of it", () => {
    const set = new RecordSet(failing(overflow()));
    expect(set.add(revocation)).toStrictEqual(SPENT);
    expect(set.record(contentId(revocation))).toBeUndefined();
    expect(set.revocationsOf(contentId(grant))).toStrictEqual([]);
  });
});

describe(`${clause("core 9.4")} a look at the proofs a record carries that was cut short`, () => {
  it("says so, so that the delegation it carries is not first seen too late", () => {
    // The agent's record carries the delegation whole. A verifier that keeps its own first
    // sight records the delegation's proof with the record's, at the same reading.
    const carrying = agent.sign(intentBy(amina, 20), {
      more: { authority: [grant] as never },
    }) as Signed;
    const record = judged(carrying);
    const seen = new FirstSeen();
    const before = cutShortCount();
    expect(witnessProofs(record, at(25), seen, failing(overflow()) as never)).toStrictEqual(SPENT);
    expect(cutShortCount()).toBeGreaterThan(before);
    // The record's own proof is recorded, and the delegation's is not: looked at again
    // with the same reading, it is, and at that reading.
    const [own] = record.proofs;
    const [carried] = grant.proof;
    if (own === undefined || carried === undefined) throw new Error("no proof");
    expect(seen.proofSeen(own.digest)).toBe(at(25));
    expect(seen.proofSeen(proofDigest(carried))).toBeUndefined();
    expect(witnessProofs(record, at(25), seen)).toStrictEqual({ ok: true, value: true });
    expect(seen.proofSeen(proofDigest(carried))).toBe(at(25));
  });
});
