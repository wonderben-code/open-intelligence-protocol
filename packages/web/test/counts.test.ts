// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, formatRecordRef, proofDigest } from "@oip/core";
import { type DelegationContext, RecordSet, type RecordView } from "@oip/delegation";
import { FirstSeen, type JudgedRecord, judgeRecord, LogBook } from "@oip/identity";
import { clause, type JsonObject } from "@oip/testkit";
import {
  at,
  Collective,
  intentBy,
  KeyMind,
  LATER,
  type Mind,
  rawSign,
  T,
} from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import {
  actsFor,
  charterInForce as charterInForceOf,
  countsFor,
  roleProofTime,
  roleTime,
  signedTime,
} from "../src/index.ts";

/** The charter in force, or `undefined`: the value `charterInForce` answers with. */
function charterInForce(...asked: Parameters<typeof charterInForceOf>): string | undefined {
  const answer = charterInForceOf(...asked);
  if (!answer.ok) throw new Error(JSON.stringify(answer.issues));
  return answer.value;
}

type Signed = JsonObject & { proof: JsonObject[] };

/** A club of three with a threshold of two. From 100 on, Cy is no longer a member. */
const [ann, bo, cy, dee] = ["ann", "bo", "cy", "dee"].map((name) => new KeyMind(name)) as [
  KeyMind,
  KeyMind,
  KeyMind,
  KeyMind,
];
const club = new Collective("club", [ann, bo, cy], 2, 5).update(100, [ann, bo], {
  controller: { members: [ann.address, bo.address], threshold: 2 },
});
const minds: Mind[] = [ann, bo, cy, dee, club];

const refTo = (record: object) => formatRecordRef(club.address, contentId(record));

/**
 * A charter of the club, signed by the club's own key at `seconds`.
 *
 * @param without - Members to leave out of it.
 */
function charter(seconds: number, more: JsonObject = {}, without: readonly string[] = []): Signed {
  const content: JsonObject = {
    oip: "1",
    type: "Collective",
    author: club.address,
    name: "The club",
    purpose: "To translate leases.",
    roles: {
      clerk: { purpose: "Posts requests.", powers: [{ command: "/oip/sign/Intent" }] },
      buyer: {
        purpose: "Buys, up to a limit.",
        powers: [{ command: "/oip/sign/Intent", policy: [["<=", ".budget", "100"]] }],
      },
    },
    assignments: [
      { mind: ann.address, role: "clerk" },
      { mind: cy.address, role: "clerk" },
      { mind: bo.address, role: "buyer" },
    ],
    created: T(seconds),
    ...more,
  };
  for (const member of without) delete content[member];
  return club.sign(content, { position: 0 });
}

/** An Intent of the club's, signed by a member that names an authority. */
function signedBy(
  member: Mind,
  seconds: number,
  authority: readonly unknown[],
  more: JsonObject = {},
) {
  return member.sign(intentBy(club, seconds, more), { more: { authority: authority as string[] } });
}

/** What a verifier holds, each proof seen when made unless `seen` says otherwise. */
function holding(records: readonly object[], seen: ReadonlyMap<object, number> = new Map()) {
  const evidence = new FirstSeen();
  for (const mind of minds) {
    for (const event of mind.events) {
      evidence.sawEvent(contentId(event), BigInt(Date.parse(event.created)) * 1_000_000n);
    }
  }
  const set = new RecordSet();
  const see = (record: object, when: number | undefined): void => {
    for (const proof of (record as Signed).proof) {
      evidence.sawProof(
        proofDigest(proof),
        when === undefined ? BigInt(Date.parse(String(proof["created"]))) * 1_000_000n : at(when),
      );
      const carried: unknown = proof["authority"];
      for (const entry of Array.isArray(carried) ? (carried as unknown[]) : []) {
        if (typeof entry === "object" && entry !== null && "proof" in entry) see(entry, undefined);
      }
    }
  };
  for (const record of records) {
    see(record, seen.get(record));
    set.add(record);
  }
  const identity = new LogBook(evidence);
  for (const mind of minds) identity.hold(mind.events, LATER);
  const context: DelegationContext = { identity, records: set };
  return context;
}

function judged(record: object): JudgedRecord {
  const result = judgeRecord(record);
  if (!result.ok) throw new Error(JSON.stringify(result.issues));
  return result.value;
}

const counts = (record: object, held: readonly object[], seen?: ReadonlyMap<object, number>) =>
  signedTime(judged(record), club.address, holding([...held, record], seen));

/** Why the first proof on a record does not count for the club through a role. */
function refusal(record: object, held: readonly object[]) {
  const context = holding([...held, record]);
  const value = judged(record);
  const log = context.identity.log(club.address);
  if (!log.ok) throw new Error("the club's log does not verify");
  const result = roleProofTime(value, value.proofs[0]!, club.address, log.value, context);
  if (result.ok) throw new Error("the proof counts");
  return { clause: result.issues[0].clause, path: result.issues[0].path };
}

describe(`${clause("L2 7.1")} a collective's role (item 4)`, () => {
  const rules = charter(10);

  it("lets a member sign for the collective what a power of its role covers", () => {
    expect(counts(signedBy(ann, 20, [refTo(rules)]), [rules])).toBe(at(20));
    // With the charter given whole.
    expect(counts(signedBy(ann, 20, [rules]), [])).toBe(at(20));
    // Given whole, it is the same charter as any copy held (Section 2), and is judged
    // with the proofs of them all: a copy without the club's proof names the charter as
    // a reference would. Where no copy held is signed for the club, it is no charter.
    const { proof: _signatures, ...bare } = rules;
    const signedByAnother = dee.sign(bare, { created: T(10) });
    expect(contentId(signedByAnother)).toBe(contentId(rules));
    expect(counts(signedBy(ann, 20, [signedByAnother]), [rules])).toBe(at(20));
    expect(counts(signedBy(ann, 20, [signedByAnother]), [])).toBeUndefined();
    // From the proof's evidence, not its date.
    const late = signedBy(ann, 20, [refTo(rules)]);
    expect(counts(late, [rules], new Map([[late, 60]]))).toBe(at(60));
  });

  it("holds the record to the power's policy", () => {
    expect(counts(signedBy(bo, 20, [refTo(rules)], { budget: "100" }), [rules])).toBe(at(20));
    expect(counts(signedBy(bo, 20, [refTo(rules)], { budget: "100.01" }), [rules])).toBeUndefined();
    // A member the policy constrains and the record lacks is an error, which fails it.
    expect(counts(signedBy(bo, 20, [refTo(rules)]), [rules])).toBeUndefined();
    expect(refusal(signedBy(bo, 20, [refTo(rules)]), [rules])).toStrictEqual({
      clause: "L2 7.1",
      path: "/authority/0",
    });
  });

  it("is of a member of the collective's state at the proof's time", () => {
    // Cy is a member until 100, and a clerk in the charter throughout.
    expect(counts(signedBy(cy, 99, [refTo(rules)]), [rules])).toBe(at(99));
    expect(counts(signedBy(cy, 100, [refTo(rules)]), [rules])).toBeUndefined();
    expect(refusal(signedBy(cy, 100, [refTo(rules)]), [rules])).toStrictEqual({
      clause: "L2 7.1",
      path: "/verificationMethod",
    });
    // Dee was never a member, whatever a charter says of her.
    const generous = charter(12, { assignments: [{ mind: dee.address, role: "clerk" }] });
    expect(counts(signedBy(dee, 20, [refTo(generous)]), [generous])).toBeUndefined();
  });

  it("is a role the charter assigns to the signer, with a power that covers the record", () => {
    // No assignment; a role the charter does not define; a power for another type.
    const unassigned = charter(10, { assignments: [] });
    expect(counts(signedBy(ann, 20, [refTo(unassigned)]), [unassigned])).toBeUndefined();
    const undefinedRole = charter(10, { assignments: [{ mind: ann.address, role: "treasurer" }] });
    expect(counts(signedBy(ann, 20, [refTo(undefinedRole)]), [undefinedRole])).toBeUndefined();
    const offers = charter(10, {
      roles: { clerk: { powers: [{ command: "/oip/sign/Offer" }] } },
    });
    expect(counts(signedBy(ann, 20, [refTo(offers)]), [offers])).toBeUndefined();
    // A role named like a member every object has gives nothing.
    const inherited = charter(10, { assignments: [{ mind: ann.address, role: "constructor" }] });
    expect(counts(signedBy(ann, 20, [refTo(inherited)]), [inherited])).toBeUndefined();
  });

  it("gives nothing where the charter leaves the assignments, the roles or the powers out", () => {
    const refused = { clause: "L2 7.1", path: "/authority/0" };
    for (const silent of [
      // Roles, and nobody assigned to one.
      charter(10, {}, ["assignments"]),
      // Assignments to roles the charter does not have.
      charter(10, {}, ["roles"]),
      charter(10, {}, ["roles", "assignments"]),
      // A role with a purpose and no power.
      charter(10, { roles: { clerk: { purpose: "Posts requests." } } }),
    ]) {
      expect(judgeRecord(silent).ok).toBe(true);
      const record = signedBy(ann, 20, [refTo(silent)]);
      expect(counts(record, [silent])).toBeUndefined();
      expect(refusal(record, [silent])).toStrictEqual(refused);
      expect(refusal(signedBy(ann, 20, [silent]), [])).toStrictEqual(refused);
    }
  });

  it("is the earliest of the proofs that count, in whatever order they stand", () => {
    // Ann signs at 30 and Cy at 20, each by the role of clerk.
    const content = intentBy(club, 20);
    const proofOf = (member: Mind, seconds: number) =>
      (
        member.sign(content, {
          created: T(seconds),
          more: { authority: [refTo(rules)] },
        }) as Signed
      ).proof[0]!;
    const [late, early] = [proofOf(ann, 30), proofOf(cy, 20)];
    for (const proof of [
      [late, early],
      [early, late],
    ]) {
      const record = { ...content, proof };
      const context = holding([rules, record]);
      expect(signedTime(judged(record), club.address, context)).toBe(at(20));
      const log = context.identity.log(club.address);
      if (!log.ok) throw new Error("the club's log does not verify");
      const of = (signer?: string) =>
        roleTime(judged(record), club.address, log.value, context, signer);
      expect(of()).toBe(at(20));
      expect(of(ann.address)).toBe(at(30));
      expect(of(cy.address)).toBe(at(20));
      expect(of(bo.address)).toBeUndefined();
    }
  });

  it(`${clause("L1 11.2")} grants nothing by a reserved command`, () => {
    const blanket = charter(10, { roles: { clerk: { powers: [{ command: "/oip/sign" }] } } });
    expect(judgeRecord(blanket).ok).toBe(true);
    expect(counts(signedBy(ann, 20, [refTo(blanket)]), [blanket])).toBeUndefined();
    const everything = charter(10, { roles: { clerk: { powers: [{ command: "/oip" }] } } });
    expect(counts(signedBy(ann, 20, [refTo(everything)]), [everything])).toBeUndefined();
  });

  it("names exactly one charter, and one of this collective", () => {
    expect(refusal(signedBy(ann, 20, [refTo(rules), refTo(rules)]), [rules])).toStrictEqual({
      clause: "L2 7.1",
      path: "/authority",
    });
    // A record that is no charter; a charter the verifier does not hold.
    const intent = ann.sign(intentBy(club, 15));
    expect(refusal(signedBy(ann, 20, [refTo(intent)]), [intent]).path).toBe("/authority/0");
    expect(refusal(signedBy(ann, 20, [refTo(rules)]), []).path).toBe("/authority/0");
    // A charter of another collective.
    const other = new Collective("other", [ann, bo], 2, 5);
    const theirs = other.sign(
      {
        oip: "1",
        type: "Collective",
        author: other.address,
        name: "Other",
        purpose: "None.",
        created: T(10),
      },
      { position: 0 },
    );
    expect(refusal(signedBy(ann, 20, [theirs]), []).path).toBe("/authority/0");
    // A string that refers to nothing, and a value that is no record, with the charter held.
    for (const entry of ["not a reference", `${club.address}/`, {}, { type: "Collective" }]) {
      const record = rawSign(
        intentBy(club, 20),
        [{ member: ann.address, versionId: ann.versionId(0), invocation: ann.operational() }],
        { purpose: "assertionMethod", authority: [entry] as string[] },
      );
      expect(judged(record).proofs, JSON.stringify(entry)).toHaveLength(1);
      expect(refusal(record, [rules]), JSON.stringify(entry)).toStrictEqual({
        clause: "L2 7.1",
        path: "/authority/0",
      });
      expect(counts(record, [rules])).toBeUndefined();
    }
  });

  it(`${clause("L1 6.1")} is by a valid operational key of the member`, () => {
    // A control key signs identity events, and no record for anybody.
    const byControl = rawSign(intentBy(club, 20), [{ control: ann.control(0) }], {
      purpose: "assertionMethod",
      authority: [refTo(rules)],
    });
    expect(judged(byControl).proofs.map((proof) => proof.method.kind)).toStrictEqual(["control"]);
    expect(refusal(byControl, [rules])).toStrictEqual({
      clause: "L1 6.1",
      path: "/verificationMethod",
    });
    expect(counts(byControl, [rules])).toBeUndefined();
    // A mind whose log the verifier does not hold: its key is not known to be valid.
    const stranger = new KeyMind("stranger");
    const generous = charter(12, { assignments: [{ mind: stranger.address, role: "clerk" }] });
    const record = signedBy(stranger, 20, [refTo(generous)]);
    expect(refusal(record, [generous]).path).not.toBe("/authority/0");
    expect(counts(record, [generous])).toBeUndefined();
  });

  it(`${clause("L2 7.2")} signs only the types that can be delegated`, () => {
    const lineage = ann.sign(
      { oip: "1", type: "Lineage", author: club.address, child: dee.address, created: T(20) },
      { more: { authority: [refTo(rules)] } },
    );
    const value = judgeRecord(lineage);
    if (value.ok) {
      expect(signedTime(value.value, club.address, holding([rules, lineage]))).toBeUndefined();
      const log = holding([rules]).identity.log(club.address);
      expect(
        log.ok &&
          roleProofTime(
            value.value,
            value.value.proofs[0]!,
            club.address,
            log.value,
            holding([rules]),
          ),
      ).toMatchObject({
        ok: false,
        issues: [{ clause: "L2 7.2" }],
      });
    }
  });
});

describe(`${clause("L2 7.1")} a role, and what is known of the collective`, () => {
  const rules = charter(10);

  it(`${clause("core 9.4")} needs the collective's log to be known up to the evidence for the proof`, () => {
    // Cy is a clerk, and a member until 100. A verifier whose copy of the club's log
    // is older than the proof cannot tell whether Cy still was one.
    const record = signedBy(cy, 60, [refTo(rules)]);
    const context = holding([rules, record]);
    const knownUpTo = (seconds: number) => {
      const identity = new LogBook(context.identity.evidence);
      for (const mind of minds) identity.hold(mind.events, mind === club ? at(seconds) : LATER);
      const log = identity.log(club.address);
      if (!log.ok) throw new Error("the club's log does not verify");
      const value = judged(record);
      return roleProofTime(value, value.proofs[0]!, club.address, log.value, {
        ...context,
        identity,
      });
    };
    expect(knownUpTo(60)).toStrictEqual({ ok: true, value: at(60) });
    expect(knownUpTo(59.999999999)).toMatchObject({
      ok: false,
      issues: [{ clause: "core 9.4", path: "/verificationMethod" }],
    });
  });

  it(`${clause("L1 7.3")} is nobody's from the first conflicting event of a duplicitous collective`, () => {
    // At 100 two members signed two events for one position. Ann is a member after
    // either, and a clerk throughout.
    const rival = new Collective("club", [ann, bo, cy], 2, 5).update(100, [ann, bo], {
      homes: ["https://club.example"],
    });
    expect(rival.address).toBe(club.address);
    /** What a verifier holds, with the rival event too, seen when it was made as the other was. */
    const withBoth = (records: readonly object[]) => {
      const context = holding(records);
      (context.identity.evidence as FirstSeen).sawEvent(contentId(rival.events[1]), at(100));
      (context.identity as LogBook).hold(rival.events, LATER);
      return context;
    };
    const counts = (seconds: number, both: boolean) => {
      const record = signedBy(ann, seconds, [refTo(rules)]);
      const context = (both ? withBoth : holding)([rules, record]);
      return signedTime(judged(record), club.address, context);
    };
    expect(withBoth([]).identity.log(club.address)).toMatchObject({
      value: { duplicitous: true },
    });
    // With either event alone the record counts, before and after.
    expect(counts(99, false)).toBe(at(99));
    expect(counts(150, false)).toBe(at(150));
    // With both, it counts up to the moment the branches part.
    expect(counts(99.999999999, true)).toBe(at(99.999999999));
    expect(counts(100, true)).toBeUndefined();
    expect(counts(150, true)).toBeUndefined();
  });
});

describe(`${clause("L2 6.2")} the charter in force`, () => {
  it("is the one signed for the collective most recently at or before the time", () => {
    const [first, second] = [charter(10), charter(50, { name: "The club, revised" })];
    const context = holding([first, second]);
    const inForce = (seconds: number) => charterInForce(club.address, at(seconds), context);
    expect(inForce(9)).toBeUndefined();
    expect(inForce(10)).toBe(contentId(first));
    expect(inForce(49)).toBe(contentId(first));
    expect(inForce(50)).toBe(contentId(second));
    // A proof counts only by the charter in force at its own time.
    expect(counts(signedBy(ann, 40, [refTo(first)]), [first, second])).toBe(at(40));
    expect(counts(signedBy(ann, 60, [refTo(first)]), [first, second])).toBeUndefined();
    expect(counts(signedBy(ann, 60, [refTo(second)]), [first, second])).toBe(at(60));
    expect(counts(signedBy(ann, 40, [refTo(second)]), [first, second])).toBeUndefined();
  });

  it("is, of two signed at the same time, the one with the lower content ID", () => {
    const pair = [charter(10, { name: "One" }), charter(10, { name: "Two" })];
    const lower = pair.map((made) => contentId(made)).sort()[0];
    for (const order of [pair, [...pair].reverse()]) {
      expect(charterInForce(club.address, at(20), holding(order))).toBe(lower);
    }
  });

  it("is a charter of that collective, whatever the view answers with", () => {
    const rules = charter(10);
    const other = new Collective("other", [ann, bo], 2, 5);
    const theirs = other.sign(
      {
        oip: "1",
        type: "Collective",
        author: other.address,
        name: "Other",
        purpose: "None.",
        created: T(10),
      },
      { position: 0 },
    );
    const intent = club.sign(intentBy(club, 15), { position: 0 });
    const context = holding([rules, theirs, intent]);
    const answering = (records: readonly object[]): DelegationContext => {
      const view: RecordView = {
        record: (id) => context.records.record(id),
        revocationsOf: (id) => context.records.revocationsOf(id),
        chartersOf: () => records.map((record) => judged(record)),
      };
      return { ...context, records: view };
    };
    expect(charterInForce(club.address, at(20), answering([theirs, intent]))).toBeUndefined();
    expect(charterInForce(club.address, at(20), answering([theirs, intent, rules]))).toBe(
      contentId(rules),
    );
    // Nor one given with the question.
    expect(
      charterInForce(club.address, at(20), answering([]), [judged(theirs), judged(intent)]),
    ).toBeUndefined();
  });

  it("is signed by the collective's own authority, by evidence of when", () => {
    // Signed by one member in the collective's name: no charter.
    const { proof: _, ...content } = charter(10);
    const forged = ann.sign(content);
    expect(charterInForce(club.address, at(20), holding([forged]))).toBeUndefined();
    // Dated 10 and first seen at 30: in force from 30.
    const backdated = charter(10, { name: "Seen late" });
    const context = holding([backdated], new Map([[backdated, 30]]));
    expect(charterInForce(club.address, at(29), context)).toBeUndefined();
    expect(charterInForce(club.address, at(30), context)).toBe(contentId(backdated));
    // A charter given with the question counts beside those held: here the verifier has
    // evidence for it and does not hold it.
    const given = charter(10, { name: "Given" });
    const bare = { identity: holding([given]).identity, records: new RecordSet() };
    expect(charterInForce(club.address, at(20), bare)).toBeUndefined();
    expect(charterInForce(club.address, at(20), bare, [judged(given)])).toBe(contentId(given));
    expect(charterInForce(dee.address, at(20), holding([charter(10)]))).toBeUndefined();
  });
});

describe(`${clause("L2 7.1")} a record counts for a mind`, () => {
  const rules = charter(10);

  it("from the earliest time any route gives", () => {
    // The club's own key at 30, and Ann's role proof at 20, on one record.
    const both = club.sign(signedBy(ann, 20, [refTo(rules)]), { position: 0, created: T(30) });
    expect(counts(both, [rules])).toBe(at(20));
    const own = club.sign(intentBy(club, 30), { position: 0 });
    expect(counts(own, [])).toBe(at(30));
    expect(countsFor(judged(own), club.address, holding([own]))).toBe(true);
    expect(countsFor(judged(own), ann.address, holding([own]))).toBe(false);
  });

  it(`${clause("core 9.6")} by no route on a proof evaluated more than 300 seconds after it expires`, () => {
    const expiring = signedBy(ann, 20, [refTo(rules)], { expires: T(50) });
    expect(counts(expiring, [rules], new Map([[expiring, 350]]))).toBe(at(350));
    expect(counts(expiring, [rules], new Map([[expiring, 351]]))).toBeUndefined();
  });

  it(`${clause("L2 5.2")} through a signer that acts for it, by a role or a delegation`, () => {
    const record = signedBy(ann, 20, [refTo(rules)]);
    const context = holding([rules, record]);
    expect(actsFor(judged(record), ann.address, club.address, context)).toBe(true);
    expect(actsFor(judged(record), bo.address, club.address, context)).toBe(false);
    expect(actsFor(judged(record), ann.address, dee.address, context)).toBe(false);
    const log = context.identity.log(club.address);
    expect(
      log.ok && roleTime(judged(record), club.address, log.value, context, bo.address),
    ).toBeUndefined();
    // Through a delegation: Dee lets Ann sign her Intents.
    const grant = dee.sign({
      oip: "1",
      type: "Delegation",
      author: dee.address,
      delegate: ann.address,
      subject: dee.address,
      command: "/oip/sign/Intent",
      expires: T(10_000),
      nonce: "nonce-0001",
      created: T(10),
    });
    const forDee = ann.sign(intentBy(dee, 20), {
      more: { authority: [formatRecordRef(dee.address, contentId(grant))] },
    });
    const held = holding([grant, forDee]);
    expect(actsFor(judged(forDee), ann.address, dee.address, held)).toBe(true);
    expect(signedTime(judged(forDee), dee.address, held)).toBe(at(20));
  });
});

describe(`${clause("L2 6.2")} a charter, its copies and what replaces it`, () => {
  /** A charter that makes one member the clerk, not yet signed. */
  const draft = (
    name: string,
    clerk: Mind,
    seconds: number,
    more: JsonObject = {},
  ): JsonObject => ({
    oip: "1",
    type: "Collective",
    author: club.address,
    name,
    purpose: "To translate leases.",
    roles: { clerk: { powers: [{ command: "/oip/sign/Intent" }] } },
    assignments: [{ mind: clerk.address, role: "clerk" }],
    created: T(seconds),
    ...more,
  });
  const byBoth = (content: JsonObject) => bo.sign(ann.sign(content)) as Signed;
  // The first charter makes Cy the clerk. Ann and Bo sign it at 10.
  const first = draft("First", cy, 10);
  const early = byBoth(first);
  // At 30 Cy adds his own signature to it.
  const late = (cy.sign(first, { created: T(30) }) as Signed).proof[0]!;
  /** The first charter with Ann's proof and Cy's, and without Bo's: completed at 30, by this copy. */
  const withheld = { ...first, proof: [early.proof[0]!, late] } as Signed;
  const whole = { ...first, proof: [...early.proof, late] } as Signed;
  const inForce = (seconds: number, held: readonly object[], also: readonly object[] = []) =>
    charterInForce(
      club.address,
      at(seconds),
      holding([...held, ...also]),
      also.map((copy) => judged(copy)),
    );

  it("is completed when it is first signed, with the proofs of every copy held", () => {
    // The second charter makes Ann the clerk and Cy nothing. Ann and Bo sign it at 20.
    const second = byBoth(draft("Second", ann, 20));
    expect(contentId(withheld)).toBe(contentId(early));
    for (const held of [
      [early, second],
      [whole, second],
      [second, withheld, early],
    ]) {
      expect(inForce(15, held)).toBe(contentId(first));
      expect(inForce(40, held)).toBe(contentId(second));
      // A copy that leaves out the proof that completed it early does not make it later.
      expect(inForce(40, held, [withheld])).toBe(contentId(second));
    }
    // So Cy does not sign for the club at 40 by the charter that was replaced at 20,
    // whether he gives it whole, with the proofs he chooses, or names it.
    const given = signedBy(cy, 40, [withheld]);
    const named = signedBy(cy, 40, [refTo(first)]);
    expect(counts(given, [early, second])).toBeUndefined();
    expect(counts(named, [early, second])).toBeUndefined();
    expect(refusal(given, [early, second])).toStrictEqual({
      clause: "L2 6.2",
      path: "/authority/0",
    });
    // Ann does, by the second.
    expect(counts(signedBy(ann, 40, [refTo(second)]), [early, second])).toBe(at(40));
  });

  it("is, for a verifier that holds no earlier proof, the later charter it looks like", () => {
    // A threshold can be completed at any time. A verifier that never saw Bo's proof on
    // the first charter cannot tell this copy from a charter completed at 30.
    const second = byBoth(draft("Second", ann, 20));
    expect(inForce(40, [withheld, second])).toBe(contentId(first));
    expect(inForce(25, [withheld, second])).toBe(contentId(second));
  });

  it("is in force at no time from the completion of a charter that supersedes it", () => {
    // The second charter names the first in `supersedes`. That ends the first for good,
    // whoever signs it later and whichever of its proofs a verifier holds.
    const second = byBoth(draft("Second", ann, 20, { supersedes: refTo(first) }));
    for (const held of [
      [withheld, second],
      [whole, second],
    ]) {
      expect(inForce(40, held)).toBe(contentId(second));
      expect(inForce(40, held, [withheld])).toBe(contentId(second));
      expect(inForce(1000, held)).toBe(contentId(second));
    }
    expect(inForce(15, [whole, second])).toBe(contentId(first));
    expect(counts(signedBy(cy, 40, [withheld]), [second])).toBeUndefined();
    // A superseding charter that is not completed ends nothing.
    const proposed = ann.sign(draft("Third", ann, 25, { supersedes: refTo(second) })) as Signed;
    expect(inForce(40, [whole, second, proposed])).toBe(contentId(second));
    // One that supersedes a charter it does not follow in time ends it all the same.
    const third = byBoth(draft("Third", bo, 5, { supersedes: refTo(first) }));
    expect(inForce(40, [whole, third])).toBe(contentId(third));
    expect(inForce(12, [whole, third])).toBe(contentId(third));
    // With the last of a line superseded, nothing earlier comes back.
    const fourth = byBoth(draft("Fourth", bo, 50, { supersedes: refTo(second) }));
    expect(inForce(60, [whole, second, fourth])).toBe(contentId(fourth));
    expect(inForce(45, [whole, second, fourth])).toBe(contentId(second));
  });
});
