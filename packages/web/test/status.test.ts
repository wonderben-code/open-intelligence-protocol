// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, formatRecordRef, proofDigest } from "@oip/core";
import { FirstSeen, type JudgedRecord, judgeRecord, LogBook } from "@oip/identity";
import { clause, type JsonObject } from "@oip/testkit";
import { at, Collective, intentBy, KeyMind, LATER, type Mind, T } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import {
  charterStatus,
  commitmentAccepted,
  commitmentStatus,
  intentStatus,
  offerStatus,
  status,
  type WebContext,
  WebRecordSet,
} from "../src/index.ts";

type Signed = JsonObject & { proof: JsonObject[] };

/**
 * Ann asks, Bo provides, Cy is an outsider and Dee an onlooker. At 300 Eve
 * declares the key she signed with compromised since 20. The guild retires
 * at 400.
 */
const [ann, bo, cy, dee, eve, fay] = ["ann", "bo", "cy", "dee", "eve", "fay"].map(
  (name) => new KeyMind(name),
) as [KeyMind, KeyMind, KeyMind, KeyMind, KeyMind, KeyMind];
eve.update(300, { revoked: [{ key: eve.operational().publicKey, compromisedSince: T(20) }] });
// Fay removes her key at 300, and declares nothing.
fay.update(300, { revoked: [{ key: fay.operational().publicKey }] });
const club = new Collective("club", [ann, bo], 2, 5);
const guild = new Collective("guild", [ann, bo], 2, 5).retire(400, [ann, bo]);
const minds: Mind[] = [ann, bo, cy, dee, eve, fay, club, guild];

const ref = (record: object) =>
  formatRecordRef((record as { author: string }).author, contentId(record));

/** Signs a record with each mind's first operational key, one proof after another. */
function signedBy(record: object, ...signers: Mind[]): Signed {
  let signed = record;
  for (const signer of signers) signed = signer.sign(signed, { position: 0 });
  return signed as Signed;
}

const intent = (seconds: number, more: JsonObject = {}) => intentBy(ann, seconds, more);

const offer = (seconds: number, more: JsonObject = {}) => ({
  oip: "1",
  type: "Offer",
  author: bo.address,
  created: T(seconds),
  provides: "Translation of leases.",
  terms: { summary: "One lease, three days." },
  ...more,
});

/** A Commitment Bo authors: Bo owes, Ann is owed. */
const commitment = (seconds: number, more: JsonObject = {}, debtor: Mind = bo) => ({
  oip: "1",
  type: "Commitment",
  author: debtor.address,
  created: T(seconds),
  parties: [
    { mind: debtor.address, role: "debtor", required: true },
    { mind: ann.address, role: "creditor", required: true },
  ],
  promise: "Translate the lease.",
  terms: {},
  ...more,
});

const receipt = (author: Mind, seconds: number, about: object, outcome: string, more = {}) => ({
  oip: "1",
  type: "Receipt",
  author: author.address,
  created: T(seconds),
  about: ref(about),
  outcome,
  ...more,
});

/** What a verifier holds, each proof seen when it was made. */
function holding(records: readonly object[]): WebContext {
  const evidence = new FirstSeen();
  const instant = (created: unknown) => BigInt(Date.parse(String(created))) * 1_000_000n;
  for (const mind of minds) {
    for (const event of mind.events) evidence.sawEvent(contentId(event), instant(event.created));
  }
  const set = new WebRecordSet();
  for (const record of records) {
    for (const proof of (record as Signed).proof) {
      evidence.sawProof(proofDigest(proof), instant(proof["created"]));
    }
    const added = set.add(record);
    if (!added.ok) throw new Error(JSON.stringify(added.issues));
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

/** The status of a record at a time, given the other records held. */
const statusOf = (record: object, others: readonly object[], seconds = 50) => {
  const answer = status(judged(record), at(seconds), holding([record, ...others]));
  if (!answer.ok) throw new Error(JSON.stringify(answer.issues));
  return answer.value;
};

describe(`${clause("L2 7.3", "L2 5.2")} an accepted Commitment`, () => {
  const accepted = (record: object) => commitmentAccepted(judged(record), holding([record]));

  it("counts for its author and for every required party", () => {
    const draft = commitment(10);
    expect(accepted(signedBy(draft, bo, ann))).toBe(true);
    expect(accepted(signedBy(draft, ann, bo))).toBe(true);
    expect(accepted(signedBy(draft, bo))).toBe(false);
    expect(accepted(signedBy(draft, ann))).toBe(false);
    // A party that is not required need not sign.
    const watched = commitment(10, {
      parties: [...commitment(10).parties, { mind: dee.address, role: "witness" }],
    });
    expect(accepted(signedBy(watched, bo, ann))).toBe(true);
    // One that is required must.
    const needed = commitment(10, {
      parties: [...commitment(10).parties, { mind: dee.address, role: "witness", required: true }],
    });
    expect(accepted(signedBy(needed, bo, ann))).toBe(false);
    expect(accepted(signedBy(needed, bo, ann, dee))).toBe(true);
  });

  it("has an author that is a party, or signs for one", () => {
    // Cy writes a Commitment between Bo and Ann, and all three sign it.
    const theirs = { ...commitment(10), author: cy.address };
    expect(accepted(signedBy(theirs, cy, bo, ann))).toBe(false);
    // Without the author's own signature it is not accepted either.
    expect(accepted(signedBy(theirs, bo, ann))).toBe(false);
  });

  it("is a Commitment", () => {
    const asked = signedBy(intent(10), ann);
    expect(commitmentAccepted(judged(asked), holding([asked]))).toBe(false);
  });
});

describe(`${clause("L2 8.1")} the status of an Intent`, () => {
  const asked = signedBy(intent(10), ann);
  const superseding = (seconds: number, more: JsonObject = {}, by: Mind = ann) =>
    signedBy(intent(seconds, { supersedes: ref(asked), ...more }), by);
  const withdrawal = superseding(20, { status: "withdrawn" });
  const fulfilment = superseding(21, { status: "satisfied" });
  const edit = superseding(22, { want: "Translate two leases." });
  /** A Commitment that lists the Intent in `resolves`. */
  const resolving = (more: JsonObject = {}, ...signers: Mind[]) =>
    signedBy(commitment(30, { resolves: [ref(asked)], closesIntent: true, ...more }), ...signers);

  it("is open when nothing else is known", () => {
    expect(statusOf(asked, [])).toBe("open");
  });

  it.each([
    ["withdrawn", [withdrawal]],
    ["satisfied", [fulfilment]],
    ["superseded", [edit]],
    // `satisfied` before `withdrawn`, and `withdrawn` before an edit.
    ["satisfied", [edit, withdrawal, fulfilment]],
    ["withdrawn", [edit, withdrawal]],
  ] as const)("is %s by what its author supersedes it with", (expected, others) => {
    expect(statusOf(asked, others)).toBe(expected);
    expect(statusOf(asked, [...others].reverse())).toBe(expected);
  });

  it("is not changed by a superseding record that is not its author's, or not signed", () => {
    // Another mind's Intent that names it.
    const stranger = signedBy(
      { ...intent(20, { supersedes: ref(asked), status: "withdrawn" }), author: cy.address },
      cy,
    );
    expect(statusOf(asked, [stranger])).toBe("open");
    // In the author's name, signed by another.
    expect(statusOf(asked, [superseding(20, { status: "withdrawn" }, cy)])).toBe("open");
    // A record of another type by the same author.
    const other = signedBy({ ...offer(20, { supersedes: ref(asked) }), author: ann.address }, ann);
    expect(statusOf(asked, [other])).toBe("open");
    // A `status` that means nothing on an Intent is no status, and no edit.
    expect(statusOf(asked, [superseding(20, { status: "exhausted" })])).toBe("open");
  });

  it("has, for a superseding record that carries a status, that status itself", () => {
    expect(statusOf(withdrawal, [asked])).toBe("withdrawn");
    expect(statusOf(fulfilment, [asked])).toBe("satisfied");
    // An edit is an Intent like any other.
    expect(statusOf(edit, [asked])).toBe("open");
    // A `status` that means nothing on an Intent gives none.
    expect(statusOf(superseding(20, { status: "exhausted" }), [asked])).toBe("open");
  });

  it("is satisfied by an accepted Commitment that closes it and counts for its author", () => {
    expect(statusOf(asked, [resolving({}, bo, ann)])).toBe("satisfied");
    // Not accepted: Ann has not signed.
    expect(statusOf(asked, [resolving({}, bo)])).toBe("open");
    // It does not say that it closes the Intent.
    expect(statusOf(asked, [resolving({ closesIntent: false }, bo, ann)])).toBe("open");
    const silent = commitment(30, { resolves: [ref(asked)] });
    expect(statusOf(asked, [signedBy(silent, bo, ann)])).toBe("open");
    // It resolves something else.
    const elsewhere = signedBy(intent(11, { want: "Something else." }), ann);
    expect(
      statusOf(asked, [signedBy(commitment(30, { resolves: [ref(elsewhere)] }), bo, ann)]),
    ).toBe("open");
  });

  it("is not closed by other minds that commit among themselves", () => {
    const between = commitment(30, {
      parties: [
        { mind: bo.address, role: "debtor", required: true },
        { mind: cy.address, role: "creditor", required: true },
      ],
      resolves: [ref(asked)],
      closesIntent: true,
    });
    const theirs = signedBy(between, bo, cy);
    expect(commitmentAccepted(judged(theirs), holding([theirs]))).toBe(true);
    expect(statusOf(asked, [theirs])).toBe("open");
    // Ann's signature on it, though she is no party, makes it count for her.
    expect(statusOf(asked, [signedBy(between, bo, cy, ann)])).toBe("satisfied");
  });

  it("expires after its `expires`, and not at it", () => {
    const brief = signedBy(intent(10, { expires: T(100) }), ann);
    expect(statusOf(brief, [], 100)).toBe("open");
    expect(statusOf(brief, [], 100.000000001)).toBe("expired");
    // No `expires`, no expiry.
    expect(statusOf(asked, [], 10 ** 8)).toBe("open");
  });

  it("takes each rule in the order of 8.1", () => {
    const brief = signedBy(intent(10, { expires: T(100) }), ann);
    const closes = signedBy(
      commitment(30, { resolves: [ref(brief)], closesIntent: true }),
      bo,
      ann,
    );
    const edited = signedBy(intent(20, { supersedes: ref(brief), expires: T(100) }), ann);
    // An edit before a Commitment that closes it; either before expiry.
    expect(statusOf(brief, [closes, edited], 200)).toBe("superseded");
    expect(statusOf(brief, [closes], 200)).toBe("satisfied");
    expect(statusOf(brief, [], 200)).toBe("expired");
  });
});

describe(`${clause("L2 8.2")} the status of an Offer`, () => {
  const made = signedBy(offer(10), bo);
  const superseding = (seconds: number, more: JsonObject = {}, by: Mind = bo) =>
    signedBy(offer(seconds, { supersedes: ref(made), ...more }), by);
  /** An accepted Commitment by Bo that takes up an Offer. */
  const taking = (of: object, seconds: number, ...signers: Mind[]) =>
    signedBy(commitment(seconds, { resolves: [ref(of)] }), ...signers);

  it("is open when nothing else is known", () => {
    expect(statusOf(made, [])).toBe("open");
  });

  it("is withdrawn or superseded by what its author supersedes it with", () => {
    const withdrawal = superseding(20, { status: "withdrawn" });
    const edit = superseding(21, { provides: "Translation of leases and deeds." });
    expect(statusOf(made, [withdrawal])).toBe("withdrawn");
    expect(statusOf(made, [edit])).toBe("superseded");
    expect(statusOf(made, [edit, withdrawal])).toBe("withdrawn");
    expect(statusOf(withdrawal, [made])).toBe("withdrawn");
    // In the author's name, signed by another.
    expect(statusOf(made, [superseding(20, { status: "withdrawn" }, cy)])).toBe("open");
  });

  it("is never satisfied: that status means nothing on an Offer", () => {
    expect(statusOf(made, [superseding(20, { status: "satisfied" })])).toBe("open");
    expect(statusOf(superseding(20, { status: "satisfied" }), [made])).toBe("open");
  });

  it("expires after its `expires`, and not at it", () => {
    const brief = signedBy(offer(10, { expires: T(100) }), bo);
    expect(statusOf(brief, [], 100)).toBe("open");
    expect(statusOf(brief, [], 101)).toBe("expired");
  });

  it("is exhausted when as many accepted Commitments take it up as it has to give", () => {
    const two = signedBy(offer(10, { terms: { summary: "Two leases.", quantity: 2 } }), bo);
    const first = taking(two, 30, bo, ann);
    const second = taking(two, 31, bo, ann);
    expect(statusOf(two, [first])).toBe("open");
    expect(statusOf(two, [first, second])).toBe("exhausted");
    // One that is not accepted is not counted.
    expect(statusOf(two, [first, taking(two, 31, bo)])).toBe("open");
    // The same Commitment held twice is one.
    expect(statusOf(two, [first, first])).toBe("open");
    // No quantity, no end.
    expect(statusOf(made, [taking(made, 30, bo, ann), taking(made, 31, bo, ann)])).toBe("open");
    // An Offer of nothing is no Offer (4.2).
    expect(() => signedBy(offer(10, { terms: { summary: "Nothing.", quantity: 0 } }), bo)).toThrow(
      /quantity/,
    );
  });

  it("counts only Commitments that also count for its author", () => {
    const one = signedBy(offer(10, { terms: { summary: "One lease.", quantity: 1 } }), bo);
    // Cy and Ann commit between themselves, naming Bo's Offer.
    const between = signedBy(commitment(30, { resolves: [ref(one)] }, cy), cy, ann);
    expect(commitmentAccepted(judged(between), holding([between]))).toBe(true);
    expect(statusOf(one, [between])).toBe("open");
    expect(statusOf(one, [taking(one, 30, bo, ann)])).toBe("exhausted");
  });

  it("takes each rule in the order of 8.2", () => {
    const one = signedBy(
      offer(10, { expires: T(100), terms: { summary: "One lease.", quantity: 1 } }),
      bo,
    );
    const taken = taking(one, 30, bo, ann);
    const edit = signedBy(offer(20, { supersedes: ref(one) }), bo);
    expect(statusOf(one, [taken, edit], 200)).toBe("superseded");
    expect(statusOf(one, [taken], 200)).toBe("expired");
    expect(statusOf(one, [taken], 50)).toBe("exhausted");
  });
});

describe(`${clause("L2 8.3")} the status of a Commitment`, () => {
  const draft = commitment(10, { terms: { deadline: T(100) } });
  const agreed = signedBy(draft, bo, ann);
  /** A Receipt about the agreed Commitment. */
  const about = (author: Mind, seconds: number, outcome: string, more = {}, ...also: Mind[]) =>
    signedBy(receipt(author, seconds, agreed, outcome, more), author, ...also);

  it("item 1: is proposed until it is accepted", () => {
    expect(statusOf(signedBy(draft, bo), [])).toBe("proposed");
    expect(statusOf(agreed, [])).toBe("accepted");
    // Receipts about a Commitment that is not accepted change nothing.
    const early = signedBy(receipt(bo, 20, draft, "fulfilled"), bo);
    expect(statusOf(signedBy(draft, bo), [early])).toBe("proposed");
  });

  it("item 1: is disputed when a party has withdrawn its signature by declaring its key compromised", () => {
    // Eve signed at 30 with a key she later declared compromised since 20.
    const withEve = signedBy(commitment(30, {}, eve), eve, ann);
    expect(commitmentAccepted(judged(withEve), holding([withEve]))).toBe(false);
    expect(statusOf(withEve, [], 350)).toBe("disputed");
    // Before the time she named, her signature stands.
    expect(statusOf(signedBy(commitment(15, {}, eve), eve, ann), [], 350)).toBe("accepted");
    // A key that was removed and not declared compromised withdraws nothing made before.
    expect(statusOf(signedBy(commitment(30, {}, fay), fay, ann), [], 350)).toBe("accepted");
    // Never signed by Ann at all: proposed, compromise or no.
    expect(statusOf(signedBy(commitment(30, {}, eve), eve), [], 350)).toBe("proposed");
  });

  it.each([
    // Item 3.
    ["claimed-fulfilled", "the debtor says it is done", [about(bo, 60, "fulfilled")]],
    ["fulfilled", "a creditor says it is done", [about(ann, 60, "fulfilled")]],
    ["fulfilled", "both say so", [about(bo, 60, "fulfilled"), about(ann, 61, "fulfilled")]],
    [
      "fulfilled",
      "the debtor says so in a Receipt the creditor has signed too",
      [about(bo, 60, "fulfilled", {}, ann)],
    ],
    // Items 4 to 6.
    ["broken", "a party says it is broken", [about(ann, 60, "broken")]],
    ["disputed", "a party disputes it", [about(ann, 60, "disputed")]],
    [
      "broken",
      "one says broken and another disputes",
      [about(ann, 60, "broken"), about(bo, 61, "disputed")],
    ],
    [
      "disputed",
      "the debtor says done and the creditor says broken",
      [about(bo, 60, "fulfilled"), about(ann, 61, "broken")],
    ],
    [
      "disputed",
      "the creditor says done and the debtor disputes",
      [about(ann, 60, "fulfilled"), about(bo, 61, "disputed")],
    ],
    // Receipts that say nothing of the outcome.
    ["accepted", "a party reports progress", [about(bo, 60, "progress")]],
    ["accepted", "a party acknowledges it", [about(ann, 60, "accepted")]],
    ["accepted", "a party uses an outcome of its own", [about(ann, 60, "com.example:paused")]],
  ] as const)("items 3 to 6: is %s when %s", (expected, _when, receipts) => {
    expect(statusOf(agreed, receipts, 70)).toBe(expected);
    expect(statusOf(agreed, [...receipts].reverse(), 70)).toBe(expected);
  });

  it("item 3: takes the debtor's word where the terms say so", () => {
    const trusting = signedBy(commitment(10, { terms: { selfReport: true } }), bo, ann);
    const done = signedBy(receipt(bo, 60, trusting, "fulfilled"), bo);
    expect(statusOf(trusting, [done])).toBe("fulfilled");
    expect(statusOf(trusting, [])).toBe("accepted");
    const wary = signedBy(commitment(10, { terms: { selfReport: false } }), bo, ann);
    expect(statusOf(wary, [signedBy(receipt(bo, 60, wary, "fulfilled"), bo)])).toBe(
      "claimed-fulfilled",
    );
  });

  it("item 2: is cancelled when Receipts that say so count for every required party", () => {
    expect(statusOf(agreed, [about(bo, 60, "cancelled")])).toBe("accepted");
    expect(statusOf(agreed, [about(bo, 60, "cancelled"), about(ann, 61, "cancelled")])).toBe(
      "cancelled",
    );
    // One Receipt that both have signed.
    expect(statusOf(agreed, [about(bo, 60, "cancelled", {}, ann)])).toBe("cancelled");
    // Before anything the Receipts of fulfilment say.
    expect(
      statusOf(agreed, [
        about(ann, 59, "fulfilled"),
        about(bo, 60, "cancelled"),
        about(ann, 61, "cancelled"),
      ]),
    ).toBe("cancelled");
    // A party that is not required need not agree.
    const watched = signedBy(
      commitment(10, {
        parties: [...commitment(10).parties, { mind: dee.address, role: "witness" }],
      }),
      bo,
      ann,
    );
    const cancels = (author: Mind, seconds: number) =>
      signedBy(receipt(author, seconds, watched, "cancelled"), author);
    expect(statusOf(watched, [cancels(bo, 60), cancels(ann, 61)])).toBe("cancelled");
    expect(statusOf(watched, [cancels(bo, 60), cancels(dee, 61)])).toBe("accepted");
  });

  it("items 7 and 8: is overdue after its deadline, if nothing says how it went", () => {
    expect(statusOf(agreed, [], 100)).toBe("accepted");
    expect(statusOf(agreed, [], 100.000000001)).toBe("overdue");
    expect(statusOf(agreed, [about(bo, 60, "fulfilled")], 200)).toBe("claimed-fulfilled");
    expect(statusOf(agreed, [about(ann, 60, "fulfilled")], 200)).toBe("fulfilled");
    expect(statusOf(agreed, [about(ann, 60, "broken")], 200)).toBe("broken");
    expect(statusOf(agreed, [about(bo, 60, "progress")], 200)).toBe("overdue");
    // No deadline, never overdue.
    expect(statusOf(signedBy(commitment(10), bo, ann), [], 10 ** 8)).toBe("accepted");
  });

  it("hears only Receipts by a party that count for their author", () => {
    // An outsider's.
    expect(statusOf(agreed, [about(cy, 60, "broken")])).toBe("accepted");
    // In a party's name, signed by another.
    expect(statusOf(agreed, [signedBy(receipt(ann, 60, agreed, "broken"), cy)])).toBe("accepted");
    // About another Commitment.
    const other = signedBy(commitment(11), bo, ann);
    expect(statusOf(agreed, [signedBy(receipt(ann, 60, other, "broken"), ann)])).toBe("accepted");
    // A creditor's signature on an outsider's Receipt does not make it a party's.
    expect(statusOf(agreed, [about(cy, 60, "fulfilled", {}, ann)])).toBe("accepted");
  });

  it("hears only a Receipt, whatever the view answers with", () => {
    // Ann's Receipt says the Commitment is broken. An Intent of hers supersedes that
    // Receipt, as only another Receipt of hers could, and a view hands it over as one.
    const broken = about(ann, 60, "broken");
    const posing = signedBy(intent(70, { supersedes: ref(broken) }), ann);
    const context = holding([agreed, broken, posing]);
    const answering = (records: readonly object[]): WebContext => ({
      ...context,
      records: {
        record: (id) => context.records.record(id),
        revocationsOf: (id) => context.records.revocationsOf(id),
        chartersOf: (mind) => context.records.chartersOf(mind),
        supersedersOf: (id) => context.records.supersedersOf(id),
        resolversOf: (id) => context.records.resolversOf(id),
        receiptsAbout: () => records.map((record) => judged(record)),
      },
    });
    const told = (records: readonly object[]) =>
      commitmentStatus(judged(agreed), at(80), answering(records));
    expect(told([posing])).toBe("accepted");
    expect(told([posing, agreed])).toBe("accepted");
    expect(told([broken])).toBe("broken");
    expect(told([broken, posing])).toBe("broken");
    expect(told([posing, broken])).toBe("broken");
  });

  it("leaves out a Receipt that a Receipt of the same author supersedes, and one that is revoked", () => {
    const broken = about(ann, 60, "broken");
    // Ann takes it back.
    const revoked = about(ann, 70, "revoked", { supersedes: ref(broken) });
    expect(statusOf(agreed, [broken, revoked], 80)).toBe("accepted");
    expect(statusOf(agreed, [revoked, broken], 80)).toBe("accepted");
    // Ann changes her mind.
    const done = about(ann, 70, "fulfilled", { supersedes: ref(broken) });
    expect(statusOf(agreed, [broken, done], 80)).toBe("fulfilled");
    // Bo cannot supersede Ann's Receipt.
    const notMine = about(bo, 70, "progress", { supersedes: ref(broken) });
    expect(statusOf(agreed, [broken, notMine], 80)).toBe("broken");
    // A Receipt that supersedes one the verifier does not hold stands by itself.
    expect(statusOf(agreed, [done], 80)).toBe("fulfilled");
    // One that an outsider's Receipt names is not superseded: that Receipt is not heard.
    const outside = about(cy, 70, "progress", { supersedes: ref(broken) });
    expect(statusOf(agreed, [broken, outside], 80)).toBe("broken");
  });
});

describe(`${clause("L2 8.4")} the status of a charter`, () => {
  const charter = (collective: Collective) =>
    collective.sign(
      {
        oip: "1",
        type: "Collective",
        author: collective.address,
        name: "A collective",
        purpose: "To translate leases.",
        created: T(10),
      },
      { position: 0 },
    );

  it("is active until the collective's log is retired", () => {
    expect(statusOf(charter(club), [], 500)).toBe("active");
    expect(statusOf(charter(guild), [], 500)).toBe("dissolved");
    const context = holding([]);
    expect(charterStatus(club.address, context)).toStrictEqual({ ok: true, value: "active" });
    expect(charterStatus(guild.address, context)).toStrictEqual({ ok: true, value: "dissolved" });
  });

  it("is not known for a collective whose log is not held", () => {
    const unknown = new Collective("unknown", [ann, bo], 2, 5);
    expect(charterStatus(unknown.address, holding([]))).toMatchObject({
      ok: false,
      issues: [{ clause: "L1 6.3" }],
    });
  });
});

describe(`${clause("L2 8")} status, by the type of the record`, () => {
  it("is defined for an Intent, an Offer, a Commitment and a charter, and for no other record", () => {
    const told = signedBy(receipt(ann, 20, signedBy(commitment(10), bo, ann), "fulfilled"), ann);
    expect(status(judged(told), at(50), holding([told]))).toMatchObject({
      ok: false,
      issues: [{ clause: "L2 8" }],
    });
  });

  it("is a mistake in the caller to ask one type's status of another, or at no time", () => {
    const asked = signedBy(intent(10), ann);
    const made = signedBy(offer(10), bo);
    const agreed = signedBy(commitment(10), bo, ann);
    const context = holding([asked, made, agreed]);
    expect(() => intentStatus(judged(made), at(50), context)).toThrow(TypeError);
    expect(() => offerStatus(judged(agreed), at(50), context)).toThrow(TypeError);
    expect(() => commitmentStatus(judged(asked), at(50), context)).toThrow(TypeError);
    expect(() => intentStatus(judged(asked), 50 as never, context)).toThrow(TypeError);
    expect(intentStatus(judged(asked), at(50), context)).toBe("open");
    expect(offerStatus(judged(made), at(50), context)).toBe("open");
    expect(commitmentStatus(judged(agreed), at(50), context)).toBe("accepted");
  });
});

describe("the records a verifier holds, by what they refer to", () => {
  const asked = signedBy(intent(10), ann);
  const edit = signedBy(intent(20, { supersedes: ref(asked) }), ann);
  const agreed = signedBy(commitment(30, { resolves: [ref(asked)] }), bo, ann);
  const told = signedBy(receipt(ann, 60, agreed, "fulfilled"), ann);
  const ids = (found: readonly JudgedRecord[]) => found.map((entry) => contentId(entry.record));

  it("finds what supersedes a record, the Commitments that resolve it and the Receipts about it", () => {
    const set = new WebRecordSet();
    for (const record of [asked, edit, agreed, told]) expect(set.add(record).ok).toBe(true);
    expect(ids(set.supersedersOf(contentId(asked)))).toStrictEqual([contentId(edit)]);
    expect(ids(set.resolversOf(contentId(asked)))).toStrictEqual([contentId(agreed)]);
    expect(ids(set.receiptsAbout(contentId(agreed)))).toStrictEqual([contentId(told)]);
    expect(set.supersedersOf(contentId(edit))).toStrictEqual([]);
    expect(set.resolversOf(contentId(agreed))).toStrictEqual([]);
    expect(set.receiptsAbout(contentId(asked))).toStrictEqual([]);
    expect(set.record(contentId(told))?.record.type).toBe("Receipt");
    expect(set.record(contentId(intent(99)))).toBeUndefined();
  });

  it("keeps a record once, with every proof it has been shown", () => {
    const set = new WebRecordSet();
    const draft = commitment(30, { resolves: [ref(asked)] });
    set.add(signedBy(draft, bo));
    set.add(signedBy(draft, ann));
    expect(set.resolversOf(contentId(asked))).toHaveLength(1);
    expect(set.record(contentId(draft))?.proofs).toHaveLength(2);
  });

  it("holds nothing that is not a record, and says why", () => {
    const set = new WebRecordSet();
    expect(set.add({ ...asked, want: 5 })).toMatchObject({ ok: false });
    expect(set.add(null)).toMatchObject({ ok: false });
    expect(set.supersedersOf(contentId(asked))).toStrictEqual([]);
  });

  it("finds revocations and charters as a record set does", () => {
    const set = new WebRecordSet();
    const rules = club.sign(
      {
        oip: "1",
        type: "Collective",
        author: club.address,
        name: "The club",
        purpose: "To translate leases.",
        created: T(10),
      },
      { position: 0 },
    );
    set.add(rules);
    expect(ids(set.chartersOf(club.address))).toStrictEqual([contentId(rules)]);
    expect(set.revocationsOf(contentId(rules))).toStrictEqual([]);
  });
});
