// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The principles of Layer 2 (Section 1), and its records as the Mind Web reads them. */

import { contentId, formatRecordRef, proofDigest } from "@oip/core";
import { FirstSeen, type JudgedRecord, judgeRecord, LogBook } from "@oip/identity";
import { clause, type JsonObject } from "@oip/testkit";
import { at, Collective, intentBy, KeyMind, LATER, type Mind, T } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import {
  commitmentAccepted,
  countsFor,
  status,
  type WebContext,
  WebRecordSet,
} from "../src/index.ts";

type Signed = JsonObject & { proof: JsonObject[] };

/** Ann is owed, Bo owes, Bo's agent signs for him under a delegation; the club is a collective of Ann and Bo. */
const [ann, bo, agent, cy] = ["ann", "bo", "agent", "cy"].map((name) => new KeyMind(name)) as [
  KeyMind,
  KeyMind,
  KeyMind,
  KeyMind,
];
const club = new Collective("club", [ann, bo], 2, 5);
const minds: Mind[] = [ann, bo, agent, cy, club];

/** Bo lets his agent sign Commitments in which he is paid, up to 500 dollars. */
const grant = bo.sign({
  oip: "1",
  type: "Delegation",
  author: bo.address,
  delegate: agent.address,
  subject: bo.address,
  command: "/oip/sign/Commitment",
  policy: [
    ["<=", ".terms.price.amount", "500"],
    ["==", ".terms.price.payee", bo.address],
  ],
  expires: T(100_000),
  nonce: "nonce-0001",
  created: T(5),
}) as Signed;

const commitment = (more: JsonObject = {}, author: Mind = bo): JsonObject => ({
  oip: "1",
  type: "Commitment",
  author: author.address,
  created: T(10),
  parties: [
    { mind: bo.address, role: "debtor", required: true },
    { mind: ann.address, role: "creditor", required: true },
  ],
  promise: "Bo will translate the lease; Ann will pay 120 dollars.",
  terms: { price: { amount: "120", currency: "USD", payer: ann.address, payee: bo.address } },
  ...more,
});

const ref = (record: object) =>
  formatRecordRef((record as { author: string }).author, contentId(record));

function holding(records: readonly object[]): WebContext {
  const evidence = new FirstSeen();
  const instant = (created: unknown) => BigInt(Date.parse(String(created))) * 1_000_000n;
  for (const mind of minds) {
    for (const event of mind.events) evidence.sawEvent(contentId(event), instant(event.created));
  }
  const see = (record: object): void => {
    for (const proof of (record as Signed).proof) {
      evidence.sawProof(proofDigest(proof), instant(proof["created"]));
      const carried: unknown = proof["authority"];
      for (const entry of Array.isArray(carried) ? (carried as unknown[]) : []) {
        if (typeof entry === "object" && entry !== null && "proof" in entry) see(entry);
      }
    }
  };
  const set = new WebRecordSet();
  for (const record of records) {
    see(record);
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

const counts = (record: object, mind: Mind, held: readonly object[] = []) =>
  countsFor(judged(record), mind.address, holding([...held, record]));

const statusOf = (record: object, others: readonly object[], seconds = 50) => {
  const answer = status(judged(record), at(seconds), holding([record, ...others]));
  return answer.ok ? answer.value : undefined;
};

/** The agent's proof on a record, carrying Bo's delegation. */
const byAgent = (record: JsonObject) =>
  agent.sign(record, { position: 0, more: { authority: [grant] as never } }) as Signed;

describe(`${clause("L2 1.1")} obligations come from signed records, and from nothing else`, () => {
  it("binds nobody a record names without their signature", () => {
    // Ann is named as a party, and has not signed.
    const proposed = bo.sign(commitment(), { position: 0 });
    expect(counts(proposed, bo)).toBe(true);
    expect(counts(proposed, ann)).toBe(false);
    expect(commitmentAccepted(judged(proposed), holding([proposed]))).toBe(false);
  });

  it(`${clause("L2 5.1")} does not bind a collective that a Commitment says it is made on behalf of`, () => {
    // Both members of the club sign as themselves, and the record names the club.
    const named = ann.sign(bo.sign(commitment({ onBehalfOf: club.address }), { position: 0 }), {
      position: 0,
    });
    expect(commitmentAccepted(judged(named), holding([named]))).toBe(true);
    // They signed without `authority`, so under the club's threshold the record is the
    // club's too, as any record its members sign together is. What names it adds nothing:
    const plain = ann.sign(bo.sign(commitment(), { position: 0 }), { position: 0 });
    expect(counts(named, club)).toBe(counts(plain, club));
    // And one member's signature does not bind it, whatever the record says.
    const alone = bo.sign(commitment({ onBehalfOf: club.address }), { position: 0 });
    expect(counts(alone, club)).toBe(false);
  });

  it("gives no authority to a delegation the record carries outside its proof", () => {
    // The agent signs with no `authority` in its proof; the delegation sits in the record.
    const outside = agent.sign(commitment({ authority: [grant] }), { position: 0 });
    expect(counts(outside, agent)).toBe(true);
    expect(counts(outside, bo)).toBe(false);
    expect(counts(byAgent(commitment()), bo)).toBe(true);
  });
});

describe(`${clause("L2 1.2")} records are immutable`, () => {
  it("leaves a record as it was when another supersedes it", () => {
    const asked = ann.sign(intentBy(ann, 10), { position: 0 }) as Signed;
    const withdrawal = ann.sign(
      intentBy(ann, 20, { supersedes: ref(asked), status: "withdrawn" }),
      { position: 0 },
    ) as Signed;
    const context = holding([asked, withdrawal]);
    // The change of state is the new record. The old one is the record it was.
    const held = context.records.record(contentId(asked));
    expect(held?.record).toStrictEqual(judged(asked).record);
    expect(contentId(withdrawal)).not.toBe(contentId(asked));
    expect(statusOf(asked, [withdrawal])).toBe("withdrawn");
    expect(statusOf(asked, [])).toBe("open");
  });
});

describe(`${clause("L2 1.3")} status is computed, from the records known and the time`, () => {
  it("differs between verifiers that hold other records, and for one verifier later", () => {
    const agreed = ann.sign(bo.sign(commitment({ terms: { deadline: T(100) } }), { position: 0 }), {
      position: 0,
    }) as Signed;
    const done = ann.sign(
      {
        oip: "1",
        type: "Receipt",
        author: ann.address,
        created: T(60),
        about: ref(agreed),
        outcome: "fulfilled",
      },
      { position: 0 },
    );
    expect(statusOf(agreed, [], 70)).toBe("accepted");
    expect(statusOf(agreed, [done], 70)).toBe("fulfilled");
    expect(statusOf(agreed, [], 200)).toBe("overdue");
    // No record holds its own status: the same bytes answer three ways.
    expect("status" in agreed).toBe(false);
  });
});

describe(`${clause("L2 2")} the common members`, () => {
  const asked = ann.sign(intentBy(ann, 10), { position: 0 }) as Signed;

  it("counts a record for its author only by a proof that is the author's", () => {
    const forged = cy.sign(intentBy(ann, 10), { position: 0 });
    expect(counts(asked, ann)).toBe(true);
    expect(counts(forged, ann)).toBe(false);
    expect(counts(forged, cy)).toBe(true);
  });

  it(`${clause("L2 4.3")} supersedes a record of the same type by the same author, and no other`, () => {
    const edit = ann.sign(intentBy(ann, 20, { supersedes: ref(asked), want: "Two leases." }), {
      position: 0,
    });
    const withdrawal = ann.sign(
      intentBy(ann, 21, { supersedes: ref(asked), status: "withdrawn" }),
      { position: 0 },
    );
    expect(statusOf(asked, [edit])).toBe("superseded");
    expect(statusOf(asked, [withdrawal])).toBe("withdrawn");
    // A stranger's record that names it, and the author's record of another type.
    const stranger = cy.sign(
      { ...intentBy(cy, 20, { supersedes: ref(asked), status: "withdrawn" }) },
      { position: 0 },
    );
    expect(statusOf(asked, [stranger])).toBe("open");
    // `status` belongs to a superseding record: one without `supersedes` is not a record.
    expect(() => ann.sign(intentBy(ann, 22, { status: "withdrawn" }), { position: 0 })).toThrow(
      /status/,
    );
  });

  it("takes `links` for what the author says they are: they change no status", () => {
    const linked = ann.sign(intentBy(ann, 20, { links: [{ rel: "replaces", ref: ref(asked) }] }), {
      position: 0,
    });
    expect(statusOf(asked, [linked])).toBe("open");
    expect(() =>
      ann.sign(intentBy(ann, 21, { links: [{ rel: "replaces" }] }), { position: 0 }),
    ).toThrow(/links/);
  });
});

describe(`${clause("L2 4.1", "L2 4.2")} an Intent and an Offer`, () => {
  it("are what their authors sign: a want with its constraints, a provision with its terms", () => {
    const asked = ann.sign(
      intentBy(ann, 10, {
        constraints: {
          deadline: T(500),
          budget: { max: "500", currency: "USD" },
          requires: ["sw"],
        },
        audience: [bo.address],
        expires: T(100),
      }),
      { position: 0 },
    );
    expect(counts(asked, ann)).toBe(true);
    expect(statusOf(asked, [], 100)).toBe("open");
    expect(statusOf(asked, [], 101)).toBe("expired");
    const offered = bo.sign(
      {
        oip: "1",
        type: "Offer",
        author: bo.address,
        created: T(11),
        provides: "Translation of leases.",
        terms: { summary: "One lease.", price: { amount: "120", currency: "USD" }, quantity: 1 },
        answers: ref(asked),
      },
      { position: 0 },
    );
    expect(counts(offered, bo)).toBe(true);
    expect(statusOf(offered, [asked])).toBe("open");
    // An Offer that answers an Intent does not satisfy it: only a Commitment does.
    expect(statusOf(asked, [offered])).toBe("open");
    // A budget is an amount, and a quantity at least one.
    expect(() =>
      ann.sign(intentBy(ann, 12, { constraints: { budget: { max: "-5" } } }), { position: 0 }),
    ).toThrow(/budget/);
  });
});

describe(`${clause("L2 5.1")} a Commitment's parties and price`, () => {
  it("needs a debtor and a creditor, each required, and a payer and a payee among the parties", () => {
    const sign = (more: JsonObject) => bo.sign(commitment(more), { position: 0 });
    expect(judgeRecord(sign({})).ok).toBe(true);
    const price = (commitment()["terms"] as { price: JsonObject }).price;
    for (const more of [
      { parties: [{ mind: bo.address, role: "debtor", required: true }] },
      {
        parties: [
          { mind: bo.address, role: "debtor", required: true },
          { mind: ann.address, role: "witness" },
        ],
      },
      {
        parties: [
          { mind: bo.address, role: "debtor", required: true },
          { mind: ann.address, role: "creditor" },
        ],
      },
      {
        parties: [
          { mind: bo.address, role: "debtor", required: true },
          { mind: bo.address, role: "creditor", required: true },
        ],
      },
      { terms: { price: { ...price, payee: cy.address } } },
      { terms: { price: { ...price, payer: bo.address } } },
      { terms: { price: { amount: "120", currency: "USD" } } },
    ] as JsonObject[]) {
      expect(() => sign(more), JSON.stringify(more).slice(0, 80)).toThrow();
    }
  });
});

describe(`${clause("L2 5.4")} a party bound through a delegate`, () => {
  it("is bound by the terms, which the policy could check, whatever the promise says", () => {
    // The promise speaks of 900 dollars. The terms say 120, and the policy allows up to 500.
    const modest = byAgent(commitment({ promise: "Bo will translate; Ann will pay 900 dollars." }));
    expect(counts(modest, bo)).toBe(true);
    // The promise speaks of 120. The terms say 900: the agent's proof does not bind Bo.
    const dear = byAgent(
      commitment({
        terms: { price: { amount: "900", currency: "USD", payer: ann.address, payee: bo.address } },
      }),
    );
    expect(counts(dear, bo)).toBe(false);
    expect(counts(dear, agent)).toBe(true);
  });
});

describe(`${clause("L2 6.1", "L2 11.2")} a Receipt's outcome`, () => {
  const agreed = ann.sign(bo.sign(commitment(), { position: 0 }), { position: 0 }) as Signed;
  const receipt = (outcome: string, more: JsonObject = {}) => ({
    oip: "1",
    type: "Receipt",
    author: ann.address,
    created: T(60),
    about: ref(agreed),
    outcome,
    ...more,
  });

  it("is one of the seven, or a namespaced one, which changes no status", () => {
    for (const outcome of [
      "accepted",
      "progress",
      "fulfilled",
      "broken",
      "cancelled",
      "disputed",
    ]) {
      expect(judgeRecord(ann.sign(receipt(outcome), { position: 0 })).ok, outcome).toBe(true);
    }
    const own = ann.sign(receipt("com.example:paused"), { position: 0 });
    expect(statusOf(agreed, [own])).toBe("accepted");
    // A new outcome with no namespace is no outcome.
    expect(() => ann.sign(receipt("paused"), { position: 0 })).toThrow(/outcome/);
    // And so for a role, and for a kind of evidence.
    const audited = commitment({
      parties: [
        ...(commitment()["parties"] as JsonObject[]),
        { mind: cy.address, role: "com.example:auditor" },
      ],
    });
    expect(judgeRecord(bo.sign(audited, { position: 0 })).ok).toBe(true);
    const unnamed = commitment({
      parties: [
        ...(commitment()["parties"] as JsonObject[]),
        { mind: cy.address, role: "auditor" },
      ],
    });
    expect(() => bo.sign(unnamed, { position: 0 })).toThrow(/role/);
    const shown = (kind: string) =>
      receipt("fulfilled", { evidence: [{ kind, ref: "https://files.example/lease" }] });
    expect(judgeRecord(ann.sign(shown("com.example:scan"), { position: 0 })).ok).toBe(true);
    expect(() => ann.sign(shown("scan"), { position: 0 })).toThrow(/kind/);
  });

  it("is `revoked` only in a Receipt that supersedes an earlier one", () => {
    expect(() => ann.sign(receipt("revoked"), { position: 0 })).toThrow(/supersedes/);
    const broken = ann.sign(receipt("broken"), { position: 0 }) as Signed;
    const takenBack = ann.sign(
      { ...receipt("revoked", { supersedes: ref(broken) }), created: T(70) },
      { position: 0 },
    );
    expect(statusOf(agreed, [broken], 80)).toBe("broken");
    expect(statusOf(agreed, [broken, takenBack], 80)).toBe("accepted");
  });
});
