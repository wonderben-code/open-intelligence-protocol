// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The hot paths of Layer 2: whether a record counts for a collective through
 * a charter role (Section 7), and the status of a record among those a
 * verifier holds (Section 8).
 *
 * BUILD.md 3.8 has no row for them, so there is no ceiling in milliseconds.
 * The checks are ratios against judging one record with one proof, which is
 * a signature and the reading around it (ADR-0006). Status checks no
 * signature: the records it reads were judged when they were taken in.
 */

import { contentId, formatRecordRef, proofDigest } from "@oip/core";
import { FirstSeen, judgeRecord, LogBook } from "@oip/identity";
import type { JsonObject } from "@oip/testkit";
import { at, Collective, intentBy, KeyMind, LATER, type Mind, T } from "@oip/testkit/minds";
import { describe, expect, test } from "vitest";

import { signedTime, status, type WebContext, WebRecordSet } from "../src/index.ts";

export const BUDGETS = {
  /**
   * A record signed for a collective by a member, through a role of the
   * charter it names, judged and counted, against judging one record with
   * one proof. It is one signature, and the charter's rules. It measures at
   * about 1.1.
   */
  role: 1.3,
  /**
   * The status of a Commitment with two parties and four Receipts about it,
   * against judging one record with one proof. It measures at about
   * 0.075.
   */
  commitment: 0.1,
  /**
   * The status of an Intent that an accepted Commitment closes, against
   * judging one record with one proof. It measures at about 0.015.
   */
  intent: 0.02,
} as const;

/** How many times each ratio is measured. Odd, so that one of them is the middle. */
const ROUNDS = 3;

/** The middle of an odd number of values. */
function middle(values: readonly number[]): number {
  const sorted = values.toSorted((a, b) => a - b);
  return sorted[(sorted.length - 1) / 2] ?? Number.NaN;
}

type Signed = JsonObject & { proof: JsonObject[] };

const ref = (record: object) =>
  formatRecordRef((record as { author: string }).author, contentId(record));

/** Ann asks, Bo provides, and the two are a club with a charter. */
function deal() {
  const [ann, bo] = [new KeyMind("ann"), new KeyMind("bo")];
  const club = new Collective("club", [ann, bo], 2, 5);
  const minds: Mind[] = [ann, bo, club];
  const signedBy = (record: object, ...signers: Mind[]): Signed => {
    let signed = record;
    for (const signer of signers) signed = signer.sign(signed, { position: 0 });
    return signed as Signed;
  };
  const asked = signedBy(intentBy(ann, 10), ann);
  const agreed = signedBy(
    {
      oip: "1",
      type: "Commitment",
      author: bo.address,
      created: T(20),
      parties: [
        { mind: bo.address, role: "debtor", required: true },
        { mind: ann.address, role: "creditor", required: true },
      ],
      promise: "Translate the lease.",
      terms: { deadline: T(1000) },
      resolves: [ref(asked)],
      closesIntent: true,
    },
    bo,
    ann,
  );
  const receipt = (author: Mind, seconds: number, outcome: string, more: JsonObject = {}) =>
    signedBy(
      {
        oip: "1",
        type: "Receipt",
        author: author.address,
        created: T(seconds),
        about: ref(agreed),
        outcome,
        ...more,
      },
      author,
    );
  const started = receipt(bo, 30, "progress");
  const receipts = [
    started,
    receipt(bo, 40, "fulfilled", { supersedes: ref(started) }),
    receipt(ann, 45, "progress"),
    receipt(ann, 50, "fulfilled"),
  ];
  const charter = club.sign(
    {
      oip: "1",
      type: "Collective",
      author: club.address,
      name: "The club",
      purpose: "To translate leases.",
      roles: {
        buyer: {
          purpose: "Buys, up to a limit.",
          powers: [{ command: "/oip/sign/Intent", policy: [["<=", ".budget", "100"]] }],
        },
      },
      assignments: [{ mind: ann.address, role: "buyer" }],
      created: T(10),
    },
    { position: 0 },
  ) as Signed;
  const forTheClub = ann.sign(intentBy(club, 60, { budget: "80" }), {
    more: { authority: [formatRecordRef(club.address, contentId(charter))] },
  }) as Signed;

  const evidence = new FirstSeen();
  const instant = (created: unknown) => BigInt(Date.parse(String(created))) * 1_000_000n;
  for (const mind of minds) {
    for (const event of mind.events) evidence.sawEvent(contentId(event), instant(event.created));
  }
  const records = new WebRecordSet();
  for (const record of [asked, agreed, ...receipts, charter, forTheClub]) {
    for (const proof of record.proof)
      evidence.sawProof(proofDigest(proof), instant(proof["created"]));
    if (record !== forTheClub) records.add(record);
  }
  const identity = new LogBook(evidence);
  for (const mind of minds) identity.hold(mind.events, LATER);
  const context: WebContext = { identity, records };
  return { club: club.address, asked, agreed, forTheClub, context };
}

describe("a record among those a verifier holds", () => {
  const { club, asked, agreed, forTheClub, context } = deal();
  const judged = (record: object) => {
    const result = judgeRecord(record);
    if (!result.ok) throw new Error(JSON.stringify(result.issues));
    return result.value;
  };
  const [intent, commitment] = [judged(asked), judged(agreed)];
  const byRole = () => signedTime(judged(forTheClub), club, context);

  test("stays close to one signature for a role, and well under one for a status", async ({
    bench,
  }) => {
    expect(byRole()).toBe(at(60));
    expect(status(commitment, at(100), context)).toStrictEqual({ ok: true, value: "fulfilled" });
    expect(status(intent, at(100), context)).toStrictEqual({ ok: true, value: "satisfied" });
    const ratios = { role: [] as number[], commitment: [] as number[], intent: [] as number[] };
    for (let round = 1; round <= ROUNDS; round++) {
      const measure = async (name: string, run: () => unknown): Promise<number> =>
        (await bench(`${name} (round ${round})`, run).run()).latency.p50;
      const one = await measure("judgeRecord: one Intent, one proof", () => judgeRecord(asked));
      ratios.role.push(
        (await measure("judgeRecord + signedTime: for a collective, through a role", byRole)) / one,
      );
      ratios.commitment.push(
        (await measure("status: a Commitment with four Receipts", () =>
          status(commitment, at(100), context),
        )) / one,
      );
      ratios.intent.push(
        (await measure("status: an Intent that a Commitment closes", () =>
          status(intent, at(100), context),
        )) / one,
      );
    }
    expect(middle(ratios.role)).toBeLessThan(BUDGETS.role);
    expect(middle(ratios.commitment)).toBeLessThan(BUDGETS.commitment);
    expect(middle(ratios.intent)).toBeLessThan(BUDGETS.intent);
  });
});
