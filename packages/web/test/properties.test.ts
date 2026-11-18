// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, formatRecordRef, proofDigest } from "@oip/core";
import { FirstSeen, type JudgedRecord, judgeRecord, LogBook } from "@oip/identity";
import { clause, type JsonObject } from "@oip/testkit";
import { at, KeyMind, LATER, type Mind, T } from "@oip/testkit/minds";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  commitmentAccepted,
  countsFor,
  signedTime,
  status,
  type WebContext,
  WebRecordSet,
} from "../src/index.ts";

type Signed = JsonObject & { proof: JsonObject[] };

/** Bo owes, Ann is owed; Ann's agent signs for her under a delegation; Cy and Dee look on. */
const [ann, bo, cy, dee, agent] = ["ann", "bo", "cy", "dee", "agent"].map(
  (name) => new KeyMind(name),
) as [KeyMind, KeyMind, KeyMind, KeyMind, KeyMind];
const minds: Mind[] = [ann, bo, cy, dee, agent];

const grant = ann.sign({
  oip: "1",
  type: "Delegation",
  author: ann.address,
  delegate: agent.address,
  subject: ann.address,
  command: "/oip/sign/Commitment",
  policy: [["<=", ".terms.price.amount", "500"]],
  expires: T(100_000),
  nonce: "nonce-0001",
  created: T(5),
}) as Signed;

const commitment = (amount: string): JsonObject => ({
  oip: "1",
  type: "Commitment",
  author: bo.address,
  created: T(10),
  parties: [
    { mind: bo.address, role: "debtor", required: true },
    { mind: ann.address, role: "creditor", required: true },
  ],
  promise: "Translate the lease.",
  terms: { price: { amount, currency: "USD", payer: ann.address, payee: bo.address } },
});

/** The ways a mind can sign the Commitment: by its own key, or for Ann under her delegation. */
const WAYS = ["bo", "ann", "agent for ann", "cy", "dee"] as const;
type Way = (typeof WAYS)[number];

function proofBy(record: JsonObject, way: Way): JsonObject {
  const signer = { bo, ann, "agent for ann": agent, cy, dee }[way];
  const signed = signer.sign(
    record,
    way === "agent for ann"
      ? { position: 0, more: { authority: [grant] as never } }
      : { position: 0 },
  ) as Signed;
  return signed.proof.at(-1)!;
}

function holding(records: readonly Signed[]): WebContext {
  const evidence = new FirstSeen();
  const instant = (created: unknown) => BigInt(Date.parse(String(created))) * 1_000_000n;
  for (const mind of minds) {
    for (const event of mind.events) evidence.sawEvent(contentId(event), instant(event.created));
  }
  const set = new WebRecordSet();
  for (const record of [grant, ...records]) {
    for (const proof of record.proof)
      evidence.sawProof(proofDigest(proof), instant(proof["created"]));
    set.add(record);
  }
  const identity = new LogBook(evidence);
  for (const mind of minds) identity.hold(mind.events, LATER);
  return { identity, records: set };
}

function judged(record: object): JudgedRecord {
  const result = judgeRecord(record);
  if (!result.ok) throw new Error(JSON.stringify(result.issues));
  return result.value;
}

const ways = fc.uniqueArray(fc.constantFrom(...WAYS), { minLength: 1 });
const amounts = fc.constantFrom("120", "500", "500.01", "900");

describe(`${clause("L2 5.3", "core 3.1")} co-signing`, () => {
  it("never changes a content ID, whoever signs and in whatever order", () => {
    fc.assert(
      fc.property(amounts, ways, (amount, signers) => {
        const record = commitment(amount);
        const proofs = signers.map((way) => proofBy(record, way));
        const signed = { ...record, proof: proofs };
        expect(contentId(signed)).toBe(contentId(record));
        expect(contentId({ ...record, proof: [...proofs].reverse() })).toBe(contentId(record));
      }),
      { numRuns: 30 },
    );
  });

  it("never makes a record count for fewer minds, and the order of proofs changes nothing", () => {
    fc.assert(
      fc.property(amounts, ways, fc.constantFrom(...WAYS), (amount, signers, more) => {
        const record = commitment(amount);
        const proofs = signers.map((way) => proofBy(record, way));
        const before = { ...record, proof: proofs } as Signed;
        const after = { ...record, proof: [...proofs, proofBy(record, more)] } as Signed;
        const turned = { ...record, proof: [...proofs].reverse() } as Signed;
        for (const mind of minds) {
          const [was, is, other] = [before, after, turned].map((signed) =>
            signedTime(judged(signed), mind.address, holding([signed])),
          );
          // A proof more can only make a record count, or count from earlier.
          if (was !== undefined) expect(is).toBe(was);
          expect(other).toBe(was);
        }
        if (commitmentAccepted(judged(before), holding([before]))) {
          expect(commitmentAccepted(judged(after), holding([after]))).toBe(true);
        }
      }),
      { numRuns: 30 },
    );
  });

  it("is merged by a verifier that holds the copies: each proof once, from whichever copy", () => {
    fc.assert(
      fc.property(amounts, ways, ways, (amount, first, second) => {
        const record = commitment(amount);
        const copy = (signers: readonly Way[]) =>
          ({ ...record, proof: signers.map((way) => proofBy(record, way)) }) as Signed;
        const [one, two] = [copy(first), copy(second)];
        const all = copy([...new Set([...first, ...second])]);
        // Held as two copies, in either order, the Commitment is the one with every proof.
        for (const copies of [
          [one, two],
          [two, one],
        ]) {
          const context = holding(copies);
          const held = context.records.record(contentId(record));
          expect(held?.proofs.map((proof) => proof.digest).sort()).toStrictEqual(
            all.proof.map((proof) => proofDigest(proof)).sort(),
          );
          const whole = holding([all]);
          for (const mind of minds) {
            expect(held === undefined ? undefined : signedTime(held, mind.address, context)).toBe(
              signedTime(judged(all), mind.address, whole),
            );
          }
        }
      }),
      { numRuns: 20 },
    );
  });
});

describe(`${clause("L1 11.6", "L2 7.1")} a proof`, () => {
  it("counts for its signer and for at most one other mind", () => {
    fc.assert(
      fc.property(amounts, fc.constantFrom(...WAYS), (amount, way) => {
        const record = commitment(amount);
        const signed = { ...record, proof: [proofBy(record, way)] } as Signed;
        const context = holding([signed]);
        const counted = minds.filter((mind) => countsFor(judged(signed), mind.address, context));
        const signer = { bo, ann, "agent for ann": agent, cy, dee }[way];
        // Always for its signer, by the signer's own key.
        expect(counted).toContain(signer);
        const others = counted.filter((mind) => mind !== signer);
        // For Ann too, when her agent signs within what she delegated, and for nobody else.
        expect(others).toStrictEqual(
          way === "agent for ann" && (amount === "120" || amount === "500") ? [ann] : [],
        );
      }),
      { numRuns: 20 },
    );
  });
});

describe(`${clause("L2 8")} a status`, () => {
  it("is defined for any set of signers, at any time", () => {
    fc.assert(
      fc.property(amounts, ways, fc.constantFrom(0, 50, 10 ** 6), (amount, signers, seconds) => {
        const record = commitment(amount);
        const signed = { ...record, proof: signers.map((way) => proofBy(record, way)) } as Signed;
        const answer = status(judged(signed), at(seconds), holding([signed]));
        expect(answer.ok).toBe(true);
        const accepted =
          signers.includes("bo") &&
          (signers.includes("ann") ||
            (signers.includes("agent for ann") && (amount === "120" || amount === "500")));
        expect(answer.ok ? answer.value : undefined).toBe(accepted ? "accepted" : "proposed");
      }),
      { numRuns: 30 },
    );
  });

  it("does not depend on the order in which the records were held", () => {
    const agreed = bo.sign(ann.sign(commitment("120"), { position: 0 }), { position: 0 }) as Signed;
    const about = (author: KeyMind, seconds: number, outcome: string) =>
      author.sign(
        {
          oip: "1",
          type: "Receipt",
          author: author.address,
          created: T(seconds),
          about: formatRecordRef(bo.address, contentId(agreed)),
          outcome,
        },
        { position: 0 },
      ) as Signed;
    const receipts = [
      about(bo, 20, "fulfilled"),
      about(ann, 21, "fulfilled"),
      about(ann, 22, "broken"),
      about(bo, 23, "cancelled"),
      about(ann, 24, "cancelled"),
      about(cy, 25, "disputed"),
    ];
    fc.assert(
      fc.property(fc.subarray(receipts), fc.nat(1000), (chosen, seed) => {
        const shuffled = [...chosen].sort(
          (a, b) =>
            ((contentId(a).charCodeAt(seed % 40) + seed) % 7) -
            ((contentId(b).charCodeAt(seed % 40) + seed) % 7),
        );
        const one = status(judged(agreed), at(50), holding([agreed, ...chosen]));
        const other = status(judged(agreed), at(50), holding([...shuffled, agreed]));
        expect(other).toStrictEqual(one);
      }),
      { numRuns: 40 },
    );
  });
});
