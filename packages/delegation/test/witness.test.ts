// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, formatRecordRef, proofDigest } from "@oip/core";
import { FirstSeen, judgeRecord, LogBook, witnessRecord } from "@oip/identity";
import { clause, type JsonObject } from "@oip/testkit";
import { at, intentBy, KeyMind, rawSign, T } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import { delegatedTime, RecordSet, witnessProofs } from "../src/index.ts";

type Signed = JsonObject & { proof: JsonObject[] };

const [amina, agent, helper] = ["amina", "agent", "helper"].map((name) => new KeyMind(name)) as [
  KeyMind,
  KeyMind,
  KeyMind,
];

const delegation = (author: KeyMind, delegate: KeyMind, seconds: number, nonce: string) =>
  author.sign({
    oip: "1",
    type: "Delegation",
    author: author.address,
    delegate: delegate.address,
    subject: amina.address,
    command: "/oip/sign/Intent",
    expires: T(100_000),
    nonce,
    created: T(seconds),
  }) as Signed;

const grant = delegation(amina, agent, 10, "nonce-0001");
const passedOn = delegation(agent, helper, 20, "nonce-0002");

/** A verifier whose only evidence is what it saw itself, and that follows the three logs. */
function verifier(now: number) {
  const seen = new FirstSeen();
  const identity = new LogBook(seen);
  for (const mind of [amina, agent, helper]) identity.witness(mind.events, at(now), seen);
  return { seen, identity, records: new RecordSet() };
}

const judged = (record: object) => {
  const result = judgeRecord(record);
  if (!result.ok) throw new Error(JSON.stringify(result.issues));
  return result.value;
};

describe(`${clause("core 9.4", "L1 11.4")} a record that arrives with its chain`, () => {
  const record = helper.sign(intentBy(amina, 30), {
    more: { authority: [grant, passedOn] as never },
  }) as Signed;

  it("is seen with the delegations its proof carries, each proof that verifies", () => {
    const { seen, identity, records } = verifier(50);
    witnessProofs(judged(record), at(50), seen);
    for (const proof of [...record.proof, ...grant.proof, ...passedOn.proof]) {
      expect(seen.proofSeen(proofDigest(proof))).toBe(at(50));
    }
    expect(delegatedTime(judged(record), amina.address, { identity, records })).toBe(at(50));
  });

  it("would not count if the record's own proofs alone were seen", () => {
    const { seen, identity, records } = verifier(50);
    witnessRecord(judged(record), at(50), seen);
    expect(seen.proofSeen(proofDigest(grant.proof[0]!))).toBeUndefined();
    expect(delegatedTime(judged(record), amina.address, { identity, records })).toBeUndefined();
  });

  it("keeps an earlier time it holds for a delegation it saw before", () => {
    const { seen, identity, records } = verifier(50);
    witnessProofs(judged(grant), at(40), seen);
    witnessProofs(judged(record), at(50), seen);
    expect(seen.proofSeen(proofDigest(grant.proof[0]!))).toBe(at(40));
    expect(seen.proofSeen(proofDigest(passedOn.proof[0]!))).toBe(at(50));
    expect(delegatedTime(judged(record), amina.address, { identity, records })).toBe(at(50));
  });

  it("sees nothing in what is carried that is no record, or whose proof does not verify", () => {
    const forged = { ...grant, proof: [{ ...grant.proof[0], proofValue: "z1111" }] };
    const odd = helper.sign(intentBy(amina, 31), {
      more: { authority: [forged, passedOn] as never },
    }) as Signed;
    const { seen } = verifier(50);
    witnessProofs(judged(odd), at(50), seen);
    expect(seen.proofSeen(proofDigest(forged.proof[0]!))).toBeUndefined();
    expect(seen.proofSeen(proofDigest(passedOn.proof[0]!))).toBe(at(50));
    expect(seen.proofSeen(proofDigest(odd.proof[0]!))).toBe(at(50));
  });

  it("passes over an entry that is no record at all, and sees the rest", () => {
    const odd = rawSign(
      intentBy(amina, 33),
      [
        {
          member: helper.address,
          versionId: helper.versionId(0),
          invocation: helper.operational(),
        },
      ],
      { purpose: "assertionMethod", authority: [{}, { type: "Delegation" }, grant] as never },
    ) as unknown as Signed;
    const { seen } = verifier(50);
    witnessProofs(judged(odd), at(50), seen);
    expect(seen.proofSeen(proofDigest(odd.proof[0]!))).toBe(at(50));
    expect(seen.proofSeen(proofDigest(grant.proof[0]!))).toBe(at(50));
  });

  it("has nothing more to see where the chain is named by reference", () => {
    const refs = [grant, passedOn].map((link) =>
      formatRecordRef(String(link["author"]), contentId(link)),
    );
    const named = helper.sign(intentBy(amina, 32), { more: { authority: refs } }) as Signed;
    const { seen, identity, records } = verifier(50);
    witnessProofs(judged(named), at(50), seen);
    expect(seen.proofSeen(proofDigest(grant.proof[0]!))).toBeUndefined();
    // The verifier holds the delegations, and saw each when it took it in.
    for (const link of [grant, passedOn]) {
      records.add(link);
      witnessProofs(judged(link), at(45), seen);
    }
    expect(delegatedTime(judged(named), amina.address, { identity, records })).toBe(at(50));
  });
});
