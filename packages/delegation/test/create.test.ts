// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, formatRecordRef, proofDigest } from "@oip/core";
import { FirstSeen, judgeRecord, LogBook } from "@oip/identity";
import type { Delegation } from "@oip/schema";
import { clause } from "@oip/testkit";
import { at, intentBy, KeyMind, LATER, type Mind, T } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import {
  authorityOf,
  delegatedTime,
  type DelegationContext,
  draftDelegation,
  draftRevocation,
  draftSubDelegation,
  RecordSet,
} from "../src/index.ts";

/** Amina delegates to her agent, which passes it on to a helper. */
const [amina, agent, helper] = ["amina", "agent", "helper"].map((name) => new KeyMind(name)) as [
  KeyMind,
  KeyMind,
  KeyMind,
];
const minds: Mind[] = [amina, agent, helper];

const grant = (more: Partial<Delegation> = {}) =>
  draftDelegation(T(10), {
    author: amina.address,
    delegate: agent.address,
    subject: amina.address,
    command: "/oip/sign/Intent",
    policy: [["<=", ".constraints.budget.max", "500"]],
    expires: T(10_000),
    nonce: "nonce-0001",
    ...more,
  });

/** What a verifier holds, each proof seen when it was made. */
function holding(records: readonly object[]): DelegationContext {
  const evidence = new FirstSeen();
  for (const mind of minds) {
    for (const event of mind.events) evidence.sawEvent(contentId(event), at(0));
  }
  const see = (record: object): void => {
    for (const proof of (record as { proof: Record<string, unknown>[] }).proof) {
      evidence.sawProof(
        proofDigest(proof),
        BigInt(Date.parse(String(proof["created"]))) * 1_000_000n,
      );
      const carried = proof["authority"];
      for (const entry of Array.isArray(carried) ? (carried as unknown[]) : []) {
        if (typeof entry === "object" && entry !== null) see(entry);
      }
    }
  };
  const set = new RecordSet();
  for (const record of records) {
    see(record);
    set.add(record);
  }
  const identity = new LogBook(evidence);
  for (const mind of minds) identity.hold(mind.events, LATER);
  return { identity, records: set };
}

/** When an Intent of Amina's for `max`, signed by `by` under a chain, counts for her. */
function countsAt(by: Mind, authority: readonly unknown[], held: readonly object[], max = "120") {
  const record = by.sign(intentBy(amina, 100, { constraints: { budget: { max } } }), {
    more: { authority: authority as string[] },
  });
  const judged = judgeRecord(record);
  if (!judged.ok) throw new Error(JSON.stringify(judged.issues));
  return delegatedTime(judged.value, amina.address, holding([...held, record]));
}

describe(`${clause("L1 11.1")} a delegation that is drafted`, () => {
  it("is the record its author signs, and a proof that carries it counts for the author", () => {
    const draft = grant();
    expect(draft).toMatchObject({ oip: "1", type: "Delegation", created: T(10) });
    const signed = amina.sign(draft);
    expect(judgeRecord(signed).ok).toBe(true);
    expect(countsAt(agent, authorityOf([signed]), [])).toBe(at(100));
    expect(countsAt(agent, authorityOf([signed]), [], "500.01")).toBeUndefined();
  });

  it("is refused at signing when it is not one", () => {
    expect(() => amina.sign(grant({ delegate: amina.address }))).toThrow(/delegate/);
    expect(() => amina.sign(grant({ command: "/oip/sign" }))).toThrow();
  });
});

describe(`${clause("L1 11.4")} a delegation that passes one on`, () => {
  const root = amina.sign(grant());

  it("keeps the subject, every statement and the expiry of the one it was given", () => {
    const next = draftSubDelegation(root, T(20), { delegate: helper.address, nonce: "nonce-0002" });
    expect(next).toStrictEqual({
      oip: "1",
      type: "Delegation",
      author: agent.address,
      delegate: helper.address,
      subject: amina.address,
      command: "/oip/sign/Intent",
      policy: [["<=", ".constraints.budget.max", "500"]],
      expires: T(10_000),
      nonce: "nonce-0002",
      created: T(20),
    });
    const link = agent.sign(next);
    expect(countsAt(helper, authorityOf([root, link]), [])).toBe(at(100));
  });

  it("may grant less: statements added, an earlier expiry, a later start", () => {
    const next = draftSubDelegation(root, T(20), {
      delegate: helper.address,
      nonce: "nonce-0003",
      policy: [["<=", ".constraints.budget.max", "200"]],
      expires: T(5000),
      notBefore: T(50),
    });
    expect(next.policy).toStrictEqual([
      ["<=", ".constraints.budget.max", "500"],
      ["<=", ".constraints.budget.max", "200"],
    ]);
    expect(next).toMatchObject({ expires: T(5000), notBefore: T(50) });
    const link = agent.sign(next);
    expect(countsAt(helper, authorityOf([root, link]), [], "200")).toBe(at(100));
    expect(countsAt(helper, authorityOf([root, link]), [], "300")).toBeUndefined();
  });

  it("has no policy where neither has one", () => {
    const open = amina.sign(grant({ policy: [], nonce: "nonce-0004" }));
    const { policy: _policy, ...bare } = grant({ nonce: "nonce-0005" });
    for (const parent of [open, amina.sign(bare)]) {
      const next = draftSubDelegation(parent, T(20), {
        delegate: helper.address,
        nonce: "n-000006",
      });
      expect("policy" in next).toBe(false);
      expect(judgeRecord(agent.sign(next)).ok).toBe(true);
    }
  });

  it("is a mistake to ask for more than was given", () => {
    const wider = { delegate: helper.address, nonce: "nonce-0007", command: "/oip/sign/Offer" };
    expect(() => draftSubDelegation(root, T(20), wider)).toThrow(TypeError);
    const longer = { delegate: helper.address, nonce: "nonce-0008", expires: T(10_001) };
    expect(() => draftSubDelegation(root, T(20), longer)).toThrow(TypeError);
    const never = { delegate: helper.address, nonce: "nonce-0009", expires: "soon" };
    expect(() => draftSubDelegation(root, T(20), never)).toThrow(TypeError);
    // A command the parent's covers is no more than was given.
    const pay = amina.sign(grant({ command: "/x402/pay", policy: [], nonce: "nonce-0010" }));
    const narrower = { delegate: helper.address, nonce: "nonce-0011", command: "/x402/pay/usd" };
    expect(draftSubDelegation(pay, T(20), narrower).command).toBe("/x402/pay/usd");
    expect(() =>
      draftSubDelegation(pay, T(20), { ...narrower, command: "/x402/payments" }),
    ).toThrow(TypeError);
  });
});

describe(`${clause("L1 11.5")} a revocation that is drafted`, () => {
  it("names the delegation, signed or not, and ends it once its author signs", () => {
    const root = amina.sign(grant());
    const draft = draftRevocation(T(50), root);
    expect(draft).toStrictEqual({
      oip: "1",
      type: "Revocation",
      author: amina.address,
      revokes: formatRecordRef(amina.address, contentId(root)),
      created: T(50),
    });
    expect(draftRevocation(T(50), grant())).toStrictEqual(draft);
    expect(countsAt(agent, authorityOf([root]), [])).toBe(at(100));
    expect(countsAt(agent, authorityOf([root]), [amina.sign(draft)])).toBeUndefined();
  });
});

describe(`${clause("L1 11.6")} the authority a proof lists`, () => {
  it("gives the chain whole or by reference, root first", () => {
    const root = amina.sign(grant());
    const link = agent.sign(
      draftSubDelegation(root, T(20), { delegate: helper.address, nonce: "nonce-0012" }),
    );
    expect(authorityOf([root, link])).toStrictEqual([root, link]);
    const refs = authorityOf([root, link], "references");
    expect(refs).toStrictEqual([
      formatRecordRef(amina.address, contentId(root)),
      formatRecordRef(agent.address, contentId(link)),
    ]);
    expect(authorityOf([])).toStrictEqual([]);
    // By reference, the verifier must hold them.
    expect(countsAt(helper, refs, [root, link])).toBe(at(100));
    expect(countsAt(helper, refs, [root])).toBeUndefined();
  });
});
