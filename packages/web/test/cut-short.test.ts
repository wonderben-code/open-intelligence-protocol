// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A check that was cut short, in this package (ADR-0010).
 *
 * A status is worked out from the records that count: a withdrawal, a
 * Receipt, a charter that supersedes another. A record whose check could
 * not be finished has not been found not to count. Leaving it out gives the
 * status it was there to change, so no function here answers for a check
 * that was cut short as if the record were not there.
 */

import { contentId, formatRecordRef, proofDigest } from "@oip/core";
import {
  FirstSeen,
  type IdentityView,
  type JudgedRecord,
  judgeRecord,
  LogBook,
} from "@oip/identity";
import { CUT_SHORT, noteCutShort } from "@oip/schema";
import { clause, type JsonObject } from "@oip/testkit";
import { at, Collective, intentBy, KeyMind, LATER, type Mind, T } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import {
  actsFor,
  charterInForce,
  charterStatus,
  commitmentAccepted,
  commitmentStatus,
  countsFor,
  intentStatus,
  offerStatus,
  roleProofTime,
  roleTime,
  signedTime,
  status,
  type WebContext,
  WebRecordSet,
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

const ann = new KeyMind("ann");
const bo = new KeyMind("bo");
const club = new Collective("club", [ann, bo], 2, 5);
const minds: Mind[] = [ann, bo, club];

const ref = (record: object) =>
  formatRecordRef((record as { author: string }).author, contentId(record));

function judged(record: object): JudgedRecord {
  const result = judgeRecord(record);
  if (!result.ok) throw new Error(JSON.stringify(result.issues));
  return result.value;
}

/**
 * What a verifier holds, each proof seen when it was made. While `cut.now`
 * is set, the check of each proof on `unjudged` is cut short: the evidence
 * notes it when it is asked when that proof was seen.
 */
function holding(records: readonly Signed[], unjudged: Signed) {
  const evidence = new FirstSeen();
  const instant = (created: unknown) => BigInt(Date.parse(String(created))) * 1_000_000n;
  for (const mind of minds) {
    for (const event of mind.events) evidence.sawEvent(contentId(event), instant(event.created));
  }
  const set = new WebRecordSet();
  for (const record of records) {
    for (const proof of record.proof) {
      evidence.sawProof(proofDigest(proof), instant(proof["created"]));
    }
    const added = set.add(record);
    if (!added.ok) throw new Error(JSON.stringify(added.issues));
  }
  const book = new LogBook(evidence);
  for (const mind of minds) book.hold(mind.events, LATER);
  const cut = { now: false };
  const digests = new Set(unjudged.proof.map((proof) => proofDigest(proof)));
  const identity: IdentityView = {
    evidence: {
      proofSeen: (digest) => {
        if (cut.now && digests.has(digest)) noteCutShort(overflow());
        return evidence.proofSeen(digest);
      },
      eventSeen: (id) => evidence.eventSeen(id),
    },
    log: (mind) => book.log(mind),
  };
  const context: WebContext = { identity, records: set };
  return { context, cut };
}

describe(`${clause("L2 8")} a status, where the check of a record that changes it was cut short`, () => {
  it("is not `open` for an Intent whose withdrawal could not be judged", () => {
    const intent = ann.sign(intentBy(ann, 10)) as Signed;
    const withdrawal = ann.sign(
      intentBy(ann, 20, { supersedes: ref(intent), status: "withdrawn" }),
    ) as Signed;
    const { context, cut } = holding([intent, withdrawal], withdrawal);
    const asked = () => status(judged(intent), at(50), context);
    expect(asked()).toStrictEqual({ ok: true, value: "withdrawn" });
    cut.now = true;
    expect(asked()).toStrictEqual(SPENT);
    expect(intentStatus(judged(intent), at(50), context)).toStrictEqual(SPENT);
    cut.now = false;
    expect(intentStatus(judged(intent), at(50), context)).toStrictEqual({
      ok: true,
      value: "withdrawn",
    });
  });

  it("is not `open` for an Offer whose withdrawal could not be judged", () => {
    const offer = bo.sign({
      oip: "1",
      type: "Offer",
      author: bo.address,
      created: T(10),
      provides: "Translation of leases.",
      terms: { summary: "One lease, three days." },
    }) as Signed;
    const { proof: _, ...content } = offer;
    const withdrawal = bo.sign({
      ...content,
      created: T(20),
      supersedes: ref(offer),
      status: "withdrawn",
    }) as Signed;
    const { context, cut } = holding([offer, withdrawal], withdrawal);
    expect(offerStatus(judged(offer), at(50), context)).toStrictEqual({
      ok: true,
      value: "withdrawn",
    });
    cut.now = true;
    expect(offerStatus(judged(offer), at(50), context)).toStrictEqual(SPENT);
    expect(status(judged(offer), at(50), context)).toStrictEqual(SPENT);
  });

  it("is not `accepted` for a Commitment whose `broken` Receipt could not be judged", () => {
    const commitment = ann.sign(
      bo.sign({
        oip: "1",
        type: "Commitment",
        author: bo.address,
        created: T(10),
        parties: [
          { mind: bo.address, role: "debtor", required: true },
          { mind: ann.address, role: "creditor", required: true },
        ],
        promise: "Translate the lease.",
        terms: {},
      }),
    ) as Signed;
    const broken = ann.sign({
      oip: "1",
      type: "Receipt",
      author: ann.address,
      created: T(30),
      about: ref(commitment),
      outcome: "broken",
    }) as Signed;
    const { context, cut } = holding([commitment, broken], broken);
    const asked = () => commitmentStatus(judged(commitment), at(50), context);
    expect(asked()).toStrictEqual({ ok: true, value: "broken" });
    cut.now = true;
    expect(asked()).toStrictEqual(SPENT);
    expect(status(judged(commitment), at(50), context)).toStrictEqual(SPENT);
    // Whether it is accepted says nothing of the Receipt, and is answered.
    expect(commitmentAccepted(judged(commitment), context)).toBe(true);
  });

  it("is no acceptance of a Commitment one of whose parties' proofs could not be judged", () => {
    const commitment = ann.sign(
      bo.sign({
        oip: "1",
        type: "Commitment",
        author: bo.address,
        created: T(10),
        parties: [
          { mind: bo.address, role: "debtor", required: true },
          { mind: ann.address, role: "creditor", required: true },
        ],
        promise: "Translate the lease.",
        terms: {},
      }),
    ) as Signed;
    const { context, cut } = holding([commitment], commitment);
    expect(commitmentAccepted(judged(commitment), context)).toBe(true);
    cut.now = true;
    expect(commitmentAccepted(judged(commitment), context)).toBe(false);
    expect(countsFor(judged(commitment), bo.address, context)).toBe(false);
    // And it is not called proposed, or disputed, on the strength of that.
    expect(commitmentStatus(judged(commitment), at(50), context)).toStrictEqual(SPENT);
  });

  it("is not the status of a charter whose collective's log could not be read", () => {
    const { context } = holding([], ann.sign(intentBy(ann, 10)));
    const cut = { now: true };
    const noting: WebContext = {
      ...context,
      identity: {
        evidence: context.identity.evidence,
        log: (mind) => {
          if (cut.now) noteCutShort(overflow());
          return context.identity.log(mind);
        },
      },
    };
    expect(charterStatus(club.address, noting)).toStrictEqual(SPENT);
    cut.now = false;
    expect(charterStatus(club.address, noting)).toStrictEqual({ ok: true, value: "active" });
  });
});

describe(`${clause("L2 6.2")} the charter in force, where the check of a later charter was cut short`, () => {
  /** A charter of the club, made at `seconds`, which the club's own key signs. */
  const charter = (seconds: number, more: JsonObject = {}): Signed =>
    club.sign(
      {
        oip: "1",
        type: "Collective",
        author: club.address,
        name: "The club",
        purpose: "To translate leases.",
        roles: { clerk: { purpose: "Posts requests.", powers: [{ command: "/oip/sign/Intent" }] } },
        assignments: [{ mind: ann.address, role: "clerk" }],
        created: T(seconds),
        ...more,
      },
      { position: 0 },
    );
  const first = charter(10);
  /** The charter that replaces it at 30, under which Ann has no role. */
  const second = charter(30, { supersedes: ref(first), assignments: [] });
  /** An Intent of the club's that Ann signed at 50 as its clerk, under the first charter. */
  const posted = ann.sign(intentBy(club, 50), { more: { authority: [ref(first)] } }) as Signed;

  it("is not the charter that the later one replaced", () => {
    const { context, cut } = holding([first, second, posted], second);
    const asked = (seconds: number) => charterInForce(club.address, at(seconds), context);
    expect(asked(20)).toStrictEqual({ ok: true, value: contentId(first) });
    expect(asked(50)).toStrictEqual({ ok: true, value: contentId(second) });
    cut.now = true;
    expect(asked(50)).toStrictEqual(SPENT);
  });

  it("gives nobody a role under the charter that was replaced", () => {
    const { context, cut } = holding([first, second, posted], second);
    const record = judged(posted);
    const log = context.identity.log(club.address);
    if (!log.ok) throw new Error(JSON.stringify(log.issues));
    const asked = () => ({
      role: roleTime(record, club.address, log.value, context),
      signed: signedTime(record, club.address, context),
      counts: countsFor(record, club.address, context),
      acts: actsFor(record, ann.address, club.address, context),
    });
    const nothing = { role: undefined, signed: undefined, counts: false, acts: false };
    // Ann signed at 50, and the charter that made her a clerk was replaced at 30.
    expect(asked()).toStrictEqual(nothing);
    const [proof] = record.proofs;
    if (proof === undefined) throw new Error("no proof");
    const byRole = () => roleProofTime(record, proof, club.address, log.value, context);
    expect(byRole()).toMatchObject({ ok: false, issues: [{ clause: "L2 6.2" }] });
    cut.now = true;
    // With the check of the later charter cut short, the earlier one is not in force again.
    expect(asked()).toStrictEqual(nothing);
    expect(byRole()).toStrictEqual(SPENT);
    cut.now = false;
    // Under the first charter alone she is a clerk, and the record counts: the rule is at work.
    const before = holding([first, posted], second);
    expect(countsFor(record, club.address, before.context)).toBe(true);
  });
});

describe(`${clause("L2 7.1")} the earliest time a record counts, where one route was cut short`, () => {
  it("is not the time by another route", () => {
    // Bo's own proof is of 30. His agent's, under a delegation, is of 20, which is when the
    // record first counts for him. With the agent's proof unjudged, 30 is not the answer.
    const grant = bo.sign({
      oip: "1",
      type: "Delegation",
      author: bo.address,
      delegate: ann.address,
      subject: bo.address,
      command: "/oip/sign/Intent",
      expires: T(10_000),
      nonce: "nonce-0001",
      created: T(10),
    }) as Signed;
    const byAgent = ann.sign(intentBy(bo, 20), { more: { authority: [ref(grant)] } }) as Signed;
    const both = bo.sign(byAgent, { created: T(30) }) as Signed;
    const agents = { ...both, proof: both.proof.slice(0, 1) };
    const { context, cut } = holding([grant, both], agents);
    expect(signedTime(judged(both), bo.address, context)).toBe(at(20));
    cut.now = true;
    expect(signedTime(judged(both), bo.address, context)).toBeUndefined();
    expect(countsFor(judged(both), bo.address, context)).toBe(false);
  });
});

describe("the records a verifier holds, where one could not be judged", () => {
  it("take in nothing of it, and list nothing by it", () => {
    const intent = ann.sign(intentBy(ann, 10)) as Signed;
    const withdrawal = ann.sign(
      intentBy(ann, 20, { supersedes: ref(intent), status: "withdrawn" }),
    ) as Signed;
    const set = new WebRecordSet(failing(overflow()));
    expect(set.add(withdrawal)).toStrictEqual(SPENT);
    expect(set.record(contentId(withdrawal))).toBeUndefined();
    expect(set.supersedersOf(contentId(intent))).toStrictEqual([]);
  });
});
