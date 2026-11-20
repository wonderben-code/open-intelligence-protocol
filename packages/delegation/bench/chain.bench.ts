// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The hot path of Layer 1, Section 11: whether a record signed through a
 * delegation chain counts for its principal.
 *
 * BUILD.md 3.8 has no row for it, so there is no ceiling in milliseconds.
 * The checks are ratios against judging one record with one proof, which is
 * a signature and the reading around it: they hold on any machine, and say
 * what the chain adds to the signatures a verifier must check in any case
 * (ADR-0006).
 */

import { contentId, forgetVerifiedSignatures, formatRecordRef, proofDigest } from "@oip/core";
import { FirstSeen, judgeRecord, LogBook } from "@oip/identity";
import type { JsonObject } from "@oip/testkit";
import { at, intentBy, KeyMind, LATER, T } from "@oip/testkit/minds";
import { ratiosOver, reportMeasured } from "@oip/testkit/ratio";
import { describe, expect, test } from "vitest";

import {
  delegatedTime,
  type DelegationContext,
  evaluatePolicy,
  MAX_CHAIN,
  RecordSet,
} from "../src/index.ts";

export const BUDGETS = {
  /**
   * A record whose proof carries the longest chain whole, eight delegations,
   * judged and counted for its principal, against judging one record with
   * one proof. It is nine signatures: the record's and each delegation's.
   * It measures at about 10.
   */
  chainGivenWhole: 11.5,
  /**
   * The same with the chain named by reference, the delegations held and
   * judged before: one signature, and the chain's rules for eight links. It
   * measures at about 1.2.
   */
  chainNamed: 1.5,
  /**
   * The policy of the specification's example (Layer 1, 11.3), five
   * statements with a connective and a quantifier, for one record, against judging one
   * record with one proof. It measures at about 0.005.
   */
  policy: 0.007,
} as const;

type Signed = JsonObject & { proof: JsonObject[] };

/** Amina, and eight agents each of which delegates to the next. */
function chainOfEight() {
  const amina = new KeyMind("amina");
  const agents = Array.from({ length: MAX_CHAIN }, (_, n) => new KeyMind(`agent-${n}`));
  const policy = [
    ["==", ".type", "Intent"],
    ["<=", ".budget", "500"],
    [
      "or",
      [
        ["==", ".currency", "USD"],
        ["==", ".currency", "EUR"],
      ],
    ],
    ["not", ["==", ".want", ""]],
    ["all", ".tags", ["!=", ".", "private"]],
  ];
  const chain = agents.map(
    (agent, n) =>
      (n === 0 ? amina : agents[n - 1]!).sign({
        oip: "1",
        type: "Delegation",
        author: (n === 0 ? amina : agents[n - 1]!).address,
        delegate: agent.address,
        subject: amina.address,
        command: "/oip/sign/Intent",
        policy,
        expires: T(100_000),
        nonce: `nonce-${String(n).padStart(4, "0")}`,
        created: T(10 + n),
      }) as Signed,
  );
  const last = agents.at(-1)!;
  const content = intentBy(amina, 100, { budget: "120", currency: "USD", tags: ["lease", "pt"] });
  const whole = last.sign(content, { more: { authority: chain as never } }) as Signed;
  const named = last.sign(content, {
    more: { authority: chain.map((link) => formatRecordRef(amina.address, contentId(link))) },
  }) as Signed;

  const evidence = new FirstSeen();
  const records = new RecordSet();
  for (const mind of [amina, ...agents]) {
    for (const event of mind.events) evidence.sawEvent(contentId(event), at(0));
  }
  for (const record of [...chain, whole, named]) {
    for (const proof of record.proof) {
      evidence.sawProof(
        proofDigest(proof),
        BigInt(Date.parse(String(proof["created"]))) * 1_000_000n,
      );
    }
  }
  for (const link of chain) records.add(link);
  const identity = new LogBook(evidence);
  for (const mind of [amina, ...agents]) identity.hold(mind.events, LATER);
  const context: DelegationContext = { identity, records };
  return { principal: amina.address, chain, whole, named, content, policy, context };
}

describe("a record signed through a delegation chain", () => {
  const { principal, chain, whole, named, content, policy, context } = chainOfEight();
  const counts = (record: Signed) => {
    const judged = judgeRecord(record);
    return judged.ok ? delegatedTime(judged.value, principal, context) : undefined;
  };

  test("stays close to the signatures it must check", async () => {
    expect(chain).toHaveLength(8);
    expect(counts(whole)).toBe(at(100));
    expect(counts(named)).toBe(at(100));
    expect(evaluatePolicy(policy, content as never).ok).toBe(true);
    const [first] = chain;
    // What is timed is the checking of signatures: none is remembered from the call before.
    const afresh =
      (run: () => unknown): (() => unknown) =>
      () => {
        forgetVerifiedSignatures();
        return run();
      };
    const measured = await ratiosOver(
      afresh(() => judgeRecord(first)),
      {
        "judgeRecord + delegatedTime: a chain of eight, given whole": afresh(() => counts(whole)),
        "judgeRecord + delegatedTime: a chain of eight, named": afresh(() => counts(named)),
        "evaluatePolicy: five statements, one record": afresh(() =>
          evaluatePolicy(policy, content),
        ),
      },
    );
    reportMeasured("@oip/delegation", "judgeRecord: one delegation, one proof", measured);
    const { ratios } = measured;
    expect(ratios["judgeRecord + delegatedTime: a chain of eight, given whole"]).toBeLessThan(
      BUDGETS.chainGivenWhole,
    );
    expect(ratios["judgeRecord + delegatedTime: a chain of eight, named"]).toBeLessThan(
      BUDGETS.chainNamed,
    );
    expect(ratios["evaluatePolicy: five statements, one record"]).toBeLessThan(BUDGETS.policy);
  });
});
