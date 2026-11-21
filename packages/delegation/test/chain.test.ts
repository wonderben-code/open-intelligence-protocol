// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, formatRecordRef, type Instant, proofDigest } from "@oip/core";
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
  delegatedProofTime,
  delegatedTime,
  type DelegationContext,
  MAX_CHAIN,
  RecordSet,
  revokedTime as revokedTimeOf,
  sentFor,
} from "../src/index.ts";

/** The time from which a delegation is revoked, or `undefined`: the value `revokedTime` answers with. */
function revokedTime(...asked: Parameters<typeof revokedTimeOf>): Instant | undefined {
  const answer = revokedTimeOf(...asked);
  if (!answer.ok) throw new Error(JSON.stringify(answer.issues));
  return answer.value;
}

/** Amina, who delegates; her agent; and the agent's own helper. */
const amina = new KeyMind("amina");
const agent = new KeyMind("agent");
const helper = new KeyMind("helper");
const stranger = new KeyMind("stranger");
const minds = [amina, agent, helper, stranger];

type Signed = JsonObject & { proof: JsonObject[] };

let nonce = 0;
/** A delegation signed by its author's own key at `seconds`. */
function delegation(author: Mind, delegate: Mind, seconds: number, more: JsonObject = {}): Signed {
  return author.sign({
    oip: "1",
    type: "Delegation",
    author: author.address,
    delegate: delegate.address,
    subject: amina.address,
    command: "/oip/sign/Intent",
    expires: T(10_000),
    nonce: `nonce-${String(nonce++).padStart(4, "0")}`,
    created: T(seconds),
    ...more,
  });
}

const refTo = (record: object) => formatRecordRef(amina.address, contentId(record));

/** An Intent of Amina's, signed at `seconds` by a mind that lists a chain. */
function signedFor(
  by: Mind,
  seconds: number,
  authority: readonly unknown[],
  more: JsonObject = {},
) {
  return by.sign(intentBy(amina, seconds, more), { more: { authority: authority as string[] } });
}

/**
 * What a verifier holds: every mind's log, the records given, and each
 * proof seen when it was made unless `seen` gives another time.
 */
function holding(records: readonly object[], seen: ReadonlyMap<object, number> = new Map()) {
  const evidence = new FirstSeen();
  for (const mind of minds) {
    for (const event of mind.events) {
      evidence.sawEvent(contentId(event), at(0));
    }
  }
  const set = new RecordSet();
  /** Each proof on a record, and on a delegation a proof carries whole, as seen. */
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
  return { context, set, evidence };
}

function judged(record: object): JudgedRecord {
  const result = judgeRecord(record);
  if (!result.ok) throw new Error(JSON.stringify(result.issues));
  return result.value;
}

/** Whether a record counts for Amina through delegation, and from when. */
const counts = (record: object, held: readonly object[], seen?: ReadonlyMap<object, number>) =>
  delegatedTime(judged(record), amina.address, holding([...held, record], seen).context);

/** Why the first proof on a record does not count for Amina. */
function refusal(record: object, held: readonly object[], seen?: ReadonlyMap<object, number>) {
  const value = judged(record);
  const [proof] = value.proofs;
  if (proof === undefined) throw new Error("the record has no proof that verifies");
  const result = delegatedProofTime(
    value,
    proof,
    amina.address,
    holding([...held, record], seen).context,
  );
  if (result.ok) throw new Error("the proof counts");
  const [first] = result.issues;
  return { clause: first.clause, path: first.path };
}

describe(`${clause("L1 11.6")} a proof that relies on delegation`, () => {
  const grant = delegation(amina, agent, 10);

  it("counts for the principal from its own evaluation time, with the chain named or given whole", () => {
    expect(counts(signedFor(agent, 20, [refTo(grant)]), [grant])).toBe(at(20));
    // Given whole, the verifier need not hold the delegation.
    expect(counts(signedFor(agent, 20, [grant]), [])).toBe(at(20));
    // The time is the proof's evidence, not its date.
    const late = signedFor(agent, 20, [refTo(grant)]);
    expect(counts(late, [grant], new Map([[late, 50]]))).toBe(at(50));
  });

  it("does not count when the verifier does not hold a delegation it names", () => {
    expect(refusal(signedFor(agent, 20, [refTo(grant)]), [])).toStrictEqual({
      clause: "L1 11.6",
      path: "/authority/0",
    });
    expect(counts(signedFor(agent, 20, [refTo(grant)]), [])).toBeUndefined();
  });

  it("lists delegations, and from one to eight of them", () => {
    expect(MAX_CHAIN).toBe(8);
    const intent = agent.sign(intentBy(amina, 15));
    // An entry that names a record which is no delegation, or gives one.
    expect(refusal(signedFor(agent, 20, [refTo(intent)]), [intent])).toStrictEqual({
      clause: "L1 11.6",
      path: "/authority/0",
    });
    expect(refusal(signedFor(agent, 20, [intent]), []).path).toBe("/authority/0");
    // A delegation given whole that is not well formed.
    const { expires: _, ...broken } = grant;
    expect(refusal(signedFor(agent, 20, [broken]), []).path).toBe("/authority/0");
  });

  it("acts for nobody when it lists no chain", () => {
    const own = agent.sign(intentBy(amina, 20));
    expect(counts(own, [grant])).toBeUndefined();
    // Asked of that proof by itself, the answer says what is missing.
    expect(refusal(own, [grant])).toStrictEqual({ clause: "L1 11.6", path: "/authority" });
  });

  it(`${clause("L1 6.1")} is by a valid operational key of its signer`, () => {
    // A control key signs identity events, and no record for anybody.
    const byControl = rawSign(intentBy(amina, 20), [{ control: agent.control(0) }], {
      purpose: "assertionMethod",
      authority: [refTo(grant)],
    });
    expect(judged(byControl).proofs.map((proof) => proof.method.kind)).toStrictEqual(["control"]);
    expect(refusal(byControl, [grant])).toStrictEqual({
      clause: "L1 6.1",
      path: "/verificationMethod",
    });
    expect(counts(byControl, [grant])).toBeUndefined();
    // A signer whose log the verifier does not hold: the chain is sound, and the key unknown.
    const unheld = new KeyMind("unheld");
    const toUnheld = delegation(amina, unheld, 10);
    const record = signedFor(unheld, 20, [refTo(toUnheld)]);
    expect(refusal(record, [toUnheld]).path).not.toMatch(/^\/authority/);
    expect(counts(record, [toUnheld])).toBeUndefined();
  });

  it("counts from the earliest proof that does, in whatever order the proofs stand", () => {
    // The agent signs at 30 by its delegation, and its helper at 20 by a chain of two.
    const further = delegation(agent, helper, 12);
    const content = intentBy(amina, 20);
    const proofOf = (by: Mind, seconds: number, authority: string[]) =>
      (by.sign(content, { created: T(seconds), more: { authority } }) as Signed).proof[0]!;
    const late = proofOf(agent, 30, [refTo(grant)]);
    const early = proofOf(helper, 20, [refTo(grant), refTo(further)]);
    for (const proof of [
      [late, early],
      [early, late],
    ]) {
      const record = { ...content, proof };
      const { context } = holding([grant, further, record]);
      const time = (signer?: string) =>
        delegatedTime(
          judged(record),
          amina.address,
          context,
          signer === undefined ? {} : { signer },
        );
      expect(time()).toBe(at(20));
      expect(time(agent.address)).toBe(at(30));
      expect(time(helper.address)).toBe(at(20));
      expect(time(stranger.address)).toBeUndefined();
    }
  });

  it("is by another mind than the one it acts for", () => {
    // A delegation to oneself is no delegation (11.1), so a chain cannot end at its principal
    // by one. A proof by the principal that lists a chain all the same acts for nobody.
    const looped = signedFor(amina, 20, [refTo(grant)]);
    expect(refusal(looped, [grant])).toStrictEqual({
      clause: "L1 11.4",
      path: "/verificationMethod",
    });
  });
});

describe(`${clause("L1 11.4")} a delegation chain`, () => {
  const grant = delegation(amina, agent, 10);
  const further = delegation(agent, helper, 12);

  it("runs from the principal to the signer, link by link, in the order listed (items 2 and 3)", () => {
    const chain = [refTo(grant), refTo(further)];
    expect(counts(signedFor(helper, 20, chain), [grant, further])).toBe(at(20));
    // The verifier checks the list as given: no other order, and no subset.
    expect(
      refusal(signedFor(helper, 20, [refTo(further), refTo(grant)]), [grant, further]),
    ).toStrictEqual({
      clause: "L1 11.4",
      path: "/authority/0",
    });
    expect(refusal(signedFor(helper, 20, [refTo(further)]), [grant, further]).path).toBe(
      "/authority/0",
    );
    expect(refusal(signedFor(helper, 20, [refTo(grant)]), [grant, further]).path).toBe(
      "/authority/0",
    );
    // A link that does not follow: the helper's delegation is not by the agent's delegate.
    const elsewhere = delegation(stranger, helper, 12);
    expect(
      refusal(signedFor(helper, 20, [refTo(grant), refTo(elsewhere)]), [grant, elsewhere]),
    ).toStrictEqual({
      clause: "L1 11.4",
      path: "/authority/1",
    });
    // Signed by a mind the chain does not end at.
    expect(refusal(signedFor(stranger, 20, chain), [grant, further]).path).toBe("/authority/1");
  });

  it("is of the principal's authority throughout (item 2)", () => {
    const others = delegation(agent, helper, 12, { subject: agent.address });
    expect(
      refusal(signedFor(helper, 20, [refTo(grant), refTo(others)]), [grant, others]),
    ).toStrictEqual({
      clause: "L1 11.4",
      path: "/authority/1",
    });
    const notHers = delegation(stranger, agent, 10);
    expect(refusal(signedFor(agent, 20, [refTo(notHers)]), [notHers]).path).toBe("/authority/0");
  });

  it("is signed by each author's own authority, no later than the proof that uses it (item 1)", () => {
    // Made at 30, used by a proof seen at 20.
    const later = delegation(amina, agent, 30);
    expect(refusal(signedFor(agent, 20, [refTo(later)]), [later])).toStrictEqual({
      clause: "L1 11.4",
      path: "/authority/0",
    });
    // Dated 10, but first seen at 40: evidence, not the date written.
    const backdated = delegation(amina, agent, 10);
    const proof = signedFor(agent, 20, [refTo(backdated)]);
    expect(counts(proof, [backdated], new Map([[backdated, 40]]))).toBeUndefined();
    expect(counts(proof, [backdated], new Map([[proof, 45]]))).toBe(at(45));
    // Signed by the delegate in the author's name: a delegation cannot be signed under delegation.
    const { proof: _, ...unsigned } = delegation(amina, agent, 10);
    const forged = agent.sign(unsigned);
    expect(refusal(signedFor(agent, 20, [refTo(forged)]), [forged]).path).toBe("/authority/0");
  });

  it("is used within its time, give or take 300 seconds (item 5)", () => {
    const window = delegation(amina, agent, 10, { notBefore: T(1000), expires: T(2000) });
    const used = (seconds: number) => counts(signedFor(agent, seconds, [refTo(window)]), [window]);
    expect(used(699)).toBeUndefined();
    expect(used(700)).toBe(at(700));
    expect(used(2300)).toBe(at(2300));
    expect(used(2301)).toBeUndefined();
    // A proof made in time and first seen out of it is out of it.
    const proof = signedFor(agent, 1500, [refTo(window)]);
    expect(counts(proof, [window], new Map([[proof, 2301]]))).toBeUndefined();
  });

  it("grants no more at each link than the link before (item 4)", () => {
    const pay = delegation(amina, agent, 10, {
      command: "/x402/pay",
      policy: [
        ["==", ".want", "Translate a lease."],
        ["==", ".type", "Intent"],
      ],
      expires: T(5000),
    });
    const narrowed = (more: JsonObject) =>
      delegation(agent, helper, 12, { command: "/x402/pay", ...more });
    const through = (link: Signed) => {
      const record = signedFor(helper, 20, [refTo(pay), refTo(link)]);
      return delegatedTime(judged(record), amina.address, holding([pay, link, record]).context, {
        need: "/x402/pay/usd",
      });
    };
    const kept = [
      ["==", ".type", "Intent"],
      ["==", ".want", "Translate a lease."],
    ];
    // The same command or one under it; the same statements in any order, and more; no later an expiry.
    expect(through(narrowed({ policy: kept, expires: T(5000) }))).toBe(at(20));
    expect(
      through(
        narrowed({
          command: "/x402/pay/usd",
          policy: [...kept, ["!=", ".want", ""]],
          expires: T(100),
        }),
      ),
    ).toBe(at(20));
    // A wider command, a statement dropped, a later expiry.
    expect(through(narrowed({ command: "/x402", policy: kept, expires: T(5000) }))).toBeUndefined();
    expect(through(narrowed({ policy: [kept[0]], expires: T(5000) }))).toBeUndefined();
    expect(through(narrowed({ policy: [], expires: T(5000) }))).toBeUndefined();
    expect(through(narrowed({ policy: kept, expires: T(5001) }))).toBeUndefined();
  });

  it("covers the signing of the record's type, which is one that can be delegated (item 6)", () => {
    const offers = delegation(amina, agent, 10, { command: "/oip/sign/Offer" });
    expect(refusal(signedFor(agent, 20, [refTo(offers)]), [offers])).toStrictEqual({
      clause: "L1 11.4",
      path: "/authority/0",
    });
    // A delegation is signed by its author's own authority and by nothing else.
    const { proof: _, ...unsigned } = delegation(amina, helper, 15);
    const byAgent = agent.sign(unsigned, {
      more: { authority: [refTo(delegation(amina, agent, 10))] },
    });
    const value = judged(byAgent);
    const result = delegatedProofTime(value, value.proofs[0]!, amina.address, holding([]).context);
    expect(result).toMatchObject({ ok: false, issues: [{ clause: "L1 11.2", path: "/type" }] });
  });

  it("holds the record to every policy in it, not only the last (item 6)", () => {
    const wide = delegation(amina, agent, 10, { policy: [["<=", ".budget", "500"]] });
    const narrow = delegation(agent, helper, 12, {
      policy: [
        ["<=", ".budget", "500"],
        ["<=", ".budget", "200"],
      ],
    });
    const spend = (by: Mind, budget: string, chain: readonly Signed[]) =>
      counts(signedFor(by, 20, chain.map(refTo), { budget }), chain);
    expect(spend(agent, "500", [wide])).toBe(at(20));
    expect(spend(agent, "500.01", [wide])).toBeUndefined();
    expect(spend(helper, "150", [wide, narrow])).toBe(at(20));
    expect(spend(helper, "300", [wide, narrow])).toBeUndefined();
    // The reason names the delegation and the statement.
    expect(
      refusal(signedFor(helper, 20, [refTo(wide), refTo(narrow)], { budget: "300" }), [
        wide,
        narrow,
      ]),
    ).toStrictEqual({
      clause: "L1 11.3",
      path: "/authority/1/policy/1",
    });
    // A member the policy constrains and the record lacks is an error, which fails it.
    expect(counts(signedFor(agent, 20, [refTo(wide)]), [wide])).toBeUndefined();
  });
});

describe(`${clause("L1 11.5")} revocation`, () => {
  const grant = delegation(amina, agent, 10);
  const revocation = (author: Mind, seconds: number, target: object = grant) =>
    author.sign({
      oip: "1",
      type: "Revocation",
      author: author.address,
      revokes: refTo(target),
      created: T(seconds),
    });

  it("ends a delegation from the revocation's own evaluation time (item 7)", () => {
    const revoked = revocation(amina, 30);
    const before = signedFor(agent, 29, [refTo(grant)]);
    const after = signedFor(agent, 30, [refTo(grant)]);
    expect(counts(before, [grant, revoked])).toBe(at(29));
    expect(counts(after, [grant, revoked])).toBeUndefined();
    expect(refusal(after, [grant, revoked])).toStrictEqual({
      clause: "L1 11.5",
      path: "/authority/0",
    });
  });

  it("takes effect from evidence: a backdated revocation does not void what came before it", () => {
    // Dated 15, first seen at 60. A proof seen at 40 came before it.
    const backdated = revocation(amina, 15);
    const used = signedFor(agent, 40, [refTo(grant)]);
    const seen = new Map<object, number>([[backdated, 60]]);
    expect(counts(used, [grant, backdated], seen)).toBe(at(40));
    const later = signedFor(agent, 61, [refTo(grant)]);
    expect(counts(later, [grant, backdated], seen)).toBeUndefined();
  });

  it("is the author's to make, and nobody else's", () => {
    const further = delegation(agent, helper, 12);
    const chain = [refTo(grant), refTo(further)];
    // Amina cannot revoke the agent's delegation to its helper; she revokes her own, which ends the chain.
    const notHers = revocation(amina, 15, further);
    expect(counts(signedFor(helper, 20, chain), [grant, further, notHers])).toBe(at(20));
    const hers = revocation(amina, 15);
    expect(counts(signedFor(helper, 20, chain), [grant, further, hers])).toBeUndefined();
    const agents = revocation(agent, 15, further);
    expect(counts(signedFor(helper, 20, chain), [grant, further, agents])).toBeUndefined();
    // A stranger's "revocation" of her delegation, signed by the stranger.
    expect(counts(signedFor(agent, 20, [refTo(grant)]), [grant, revocation(stranger, 15)])).toBe(
      at(20),
    );
  });

  it("stands whatever is later declared of the key that signed it", () => {
    // Ines delegates at 10 and revokes at 30. At 100 she replaces her key and declares
    // it compromised since 20: before her revocation, and after her delegation.
    const [ines, bot] = [new KeyMind("ines"), new KeyMind("bot")];
    const grant = ines.sign({
      oip: "1",
      type: "Delegation",
      author: ines.address,
      delegate: bot.address,
      subject: ines.address,
      command: "/oip/sign/Intent",
      expires: T(10_000),
      nonce: "compromise-0001",
      created: T(10),
    }) as Signed;
    const revoked = ines.sign({
      oip: "1",
      type: "Revocation",
      author: ines.address,
      revokes: formatRecordRef(ines.address, contentId(grant)),
      created: T(30),
    });
    const used = bot.sign(intentBy(ines, 40), {
      more: { authority: [formatRecordRef(ines.address, contentId(grant))] },
    });
    const told = (mind: KeyMind) => {
      const evidence = new FirstSeen();
      const set = new RecordSet();
      for (const event of [...mind.events, ...bot.events]) {
        evidence.sawEvent(contentId(event), BigInt(Date.parse(event.created)) * 1_000_000n);
      }
      for (const record of [grant, revoked, used]) {
        for (const proof of record.proof) {
          evidence.sawProof(
            proofDigest(proof),
            BigInt(Date.parse(String((proof as JsonObject)["created"]))) * 1_000_000n,
          );
        }
        set.add(record);
      }
      const identity = new LogBook(evidence);
      for (const held of [mind, bot]) identity.hold(held.events, LATER);
      return {
        counts: delegatedTime(judged(used), ines.address, { identity, records: set }),
        revokedAt: revokedTime(contentId(grant), ines.address, set, identity),
      };
    };
    expect(told(ines)).toStrictEqual({ counts: undefined, revokedAt: at(30) });
    const declared = new KeyMind("ines").update(100, {
      keys: [{ key: ines.operational(1).publicKey }],
      revoked: [{ key: ines.operational(0).publicKey, compromisedSince: T(20) }],
    });
    expect(declared.address).toBe(ines.address);
    // The declaration takes back what the key signed from 20 on, and not her taking back.
    expect(told(declared)).toStrictEqual({ counts: undefined, revokedAt: at(30) });
  });

  it("is of the delegation's author by its own account: signed under another author, it revokes nothing", () => {
    // Amina signs a revocation that names the stranger as its author.
    const misnamed = amina.sign({
      oip: "1",
      type: "Revocation",
      author: stranger.address,
      revokes: refTo(grant),
      created: T(15),
    });
    const { context, set } = holding([grant, misnamed]);
    expect(set.revocationsOf(contentId(grant))).toHaveLength(1);
    expect(revokedTime(contentId(grant), amina.address, set, context.identity)).toBeUndefined();
    expect(counts(signedFor(agent, 20, [refTo(grant)]), [grant, misnamed])).toBe(at(20));
  });

  it("is the earliest of those held", () => {
    const [first, second] = [revocation(amina, 50), revocation(amina, 30)];
    const { context, set } = holding([grant, first, second]);
    const time = (records = set): Instant | undefined =>
      revokedTime(contentId(grant), amina.address, records, context.identity);
    expect(time()).toBe(at(30));
    expect(revokedTime(contentId(grant), agent.address, set, context.identity)).toBeUndefined();
    expect(time(new RecordSet())).toBeUndefined();
    // In whichever order they are held.
    const reordered = holding([grant, second, first]);
    expect(
      revokedTime(contentId(grant), amina.address, reordered.set, reordered.context.identity),
    ).toBe(at(30));
  });

  it("is signed by the author's own authority: one in the author's name alone revokes nothing", () => {
    // The agent writes Amina's name on a revocation, at 15, and signs it itself.
    const forged = agent.sign({
      oip: "1",
      type: "Revocation",
      author: amina.address,
      revokes: refTo(grant),
      created: T(15),
    });
    const { context, set } = holding([grant, forged]);
    expect(set.revocationsOf(contentId(grant))).toHaveLength(1);
    expect(revokedTime(contentId(grant), amina.address, set, context.identity)).toBeUndefined();
    expect(counts(signedFor(agent, 20, [refTo(grant)]), [grant, forged])).toBe(at(20));
    // Beside a true one, it changes nothing.
    const hers = revocation(amina, 30);
    const both = holding([grant, hers, forged]);
    expect(revokedTime(contentId(grant), amina.address, both.set, both.context.identity)).toBe(
      at(30),
    );
  });
});

describe(`${clause("L1 11.4")} a delegation's author, at the proof's time`, () => {
  /** A delegation by one mind to another, for itself, signed at `seconds`. */
  const grantBy = (author: Mind, delegate: Mind, seconds: number, principal: Mind = author) =>
    author.sign({
      oip: "1",
      type: "Delegation",
      author: author.address,
      delegate: delegate.address,
      subject: principal.address,
      command: "/oip/sign/Intent",
      expires: T(100_000),
      nonce: `author-${String(nonce++).padStart(4, "0")}`,
      created: T(seconds),
    }) as Signed;
  /** An Intent of the principal's, signed at `seconds` by a delegate that lists the chain. */
  const usedBy = (delegate: Mind, principal: Mind, seconds: number, chain: readonly object[]) =>
    delegate.sign(intentBy(principal, seconds), {
      more: { authority: chain.map((link) => formatRecordRef(principal.address, contentId(link))) },
    }) as Signed;
  /**
   * What a verifier holds: the records, each proof seen when it was made, and each mind's
   * log as its events were made, known up to the time given for it, or to the end of time.
   */
  function knowing(
    minds: readonly Mind[],
    records: readonly object[],
    upTo: ReadonlyMap<Mind, number> = new Map(),
  ): DelegationContext {
    const evidence = new FirstSeen();
    const set = new RecordSet();
    for (const mind of minds) {
      for (const event of mind.events) {
        evidence.sawEvent(contentId(event), BigInt(Date.parse(event.created)) * 1_000_000n);
      }
    }
    for (const record of records) {
      for (const proof of (record as Signed).proof) {
        evidence.sawProof(
          proofDigest(proof),
          BigInt(Date.parse(String(proof["created"]))) * 1_000_000n,
        );
      }
      set.add(record);
    }
    const identity = new LogBook(evidence);
    for (const mind of minds) {
      const known = upTo.get(mind);
      identity.hold(mind.events, known === undefined ? LATER : at(known));
    }
    return { identity, records: set };
  }
  const verdict = (record: Signed, principal: Mind, context: DelegationContext) => {
    const value = judged(record);
    const result = delegatedProofTime(value, value.proofs[0]!, principal.address, context);
    return result.ok
      ? result.value
      : { clause: result.issues[0].clause, path: result.issues[0].path };
  };

  it(`${clause("core 9.4")} is known from a log held up to the evidence for the proof`, () => {
    // Ines delegates at 10 and revokes at 1500. Her agent signs for her at 2000.
    const [ines, bot] = [new KeyMind("ines"), new KeyMind("bot")];
    const grant = grantBy(ines, bot, 10);
    const revocation = ines.sign({
      oip: "1",
      type: "Revocation",
      author: ines.address,
      revokes: formatRecordRef(ines.address, contentId(grant)),
      created: T(1500),
    });
    const used = usedBy(bot, ines, 2000, [grant]);
    const held = [grant, revocation, used];
    // With her log known in full, the revocation counts and the proof does not.
    expect(verdict(used, ines, knowing([ines, bot], held))).toStrictEqual({
      clause: "L1 11.5",
      path: "/authority/0",
    });
    // With her log as it was obtained at 1000, the verifier cannot judge the revocation it
    // holds. It does not take that for "not revoked".
    const stale = { clause: "core 9.4", path: "/authority/0" };
    expect(verdict(used, ines, knowing([ines, bot], held, new Map([[ines, 1000]])))).toStrictEqual(
      stale,
    );
    // Nor without the revocation: the copy may lack what ended the delegation.
    const unaware = knowing([ines, bot], [grant, used], new Map([[ines, 1999.999999999]]));
    expect(verdict(used, ines, unaware)).toStrictEqual(stale);
    // Known up to the evidence for the proof, to the nanosecond, it counts.
    expect(verdict(used, ines, knowing([ines, bot], [grant, used], new Map([[ines, 2000]])))).toBe(
      at(2000),
    );
    // Every author of the chain, not only the first.
    const sub = new KeyMind("sub");
    const further = grantBy(bot, sub, 20, ines);
    const deeper = usedBy(sub, ines, 2000, [grant, further]);
    const all = [grant, further, deeper];
    expect(verdict(deeper, ines, knowing([ines, bot, sub], all))).toBe(at(2000));
    expect(
      verdict(deeper, ines, knowing([ines, bot, sub], all, new Map([[bot, 1000]]))),
    ).toStrictEqual({ clause: "core 9.4", path: "/authority/1" });
  });

  it(`${clause("core 9.4")} is known, for a collective, from its members' logs as well`, () => {
    // A club of two delegates by its threshold. Either member may have signed a revocation.
    const [ann, bo, bot] = [new KeyMind("ann"), new KeyMind("bo"), new KeyMind("bot")];
    const club = new Collective("club", [ann, bo], 2, 5);
    const content = {
      oip: "1",
      type: "Delegation",
      author: club.address,
      delegate: bot.address,
      subject: club.address,
      command: "/oip/sign/Intent",
      expires: T(100_000),
      nonce: "club-0001",
      created: T(10),
    };
    const grant = bo.sign(ann.sign(content)) as Signed;
    const used = usedBy(bot, club, 2000, [grant]);
    const minds = [ann, bo, bot, club];
    expect(verdict(used, club, knowing(minds, [grant, used]))).toBe(at(2000));
    for (const member of [ann, bo, club]) {
      expect(
        verdict(used, club, knowing(minds, [grant, used], new Map([[member, 1000]]))),
        member.name,
      ).toStrictEqual({ clause: "core 9.4", path: "/authority/0" });
    }
    // A member that joined later may have signed a revocation too, from when it joined.
    const cy = new KeyMind("cy");
    // A mind that joins signs the event that adds it.
    club.update(20, [ann, bo, cy], {
      controller: { members: [ann.address, bo.address, cy.address], threshold: 2 },
    });
    const wider = [...minds, cy];
    expect(verdict(used, club, knowing(wider, [grant, used]))).toBe(at(2000));
    expect(verdict(used, club, knowing(wider, [grant, used], new Map([[cy, 1000]])))).toStrictEqual(
      { clause: "core 9.4", path: "/authority/0" },
    );
    // A change of membership after the proof's time changes nothing for it.
    const dee = new KeyMind("dee");
    club.update(3000, [ann, bo, cy, dee], {
      controller: { members: [ann.address, bo.address, cy.address, dee.address], threshold: 3 },
    });
    expect(verdict(used, club, knowing([...wider, dee], [grant, used]))).toBe(at(2000));
  });

  it("is not retired: a mind that can sign nothing can revoke nothing (item 8)", () => {
    // Ines delegates at 10 and retires at 50.
    const [ines, bot] = [new KeyMind("ines"), new KeyMind("bot")];
    const grant = grantBy(ines, bot, 10);
    ines.retire(50);
    const at40 = usedBy(bot, ines, 40, [grant]);
    const at50 = usedBy(bot, ines, 50, [grant]);
    const later = usedBy(bot, ines, 5000, [grant]);
    const context = knowing([ines, bot], [grant, at40, at50, later]);
    expect(verdict(at40, ines, context)).toBe(at(40));
    const retired = { clause: "L1 11.4", path: "/authority/0" };
    expect(verdict(at50, ines, context)).toStrictEqual(retired);
    expect(verdict(later, ines, context)).toStrictEqual(retired);
    // A delegate that passed its authority on and then retired has ended what it passed on.
    const [pia, mid, end] = [new KeyMind("pia"), new KeyMind("mid"), new KeyMind("end")];
    const first = grantBy(pia, mid, 10);
    const second = grantBy(mid, end, 20, pia);
    mid.retire(50);
    const before = usedBy(end, pia, 40, [first, second]);
    const after = usedBy(end, pia, 60, [first, second]);
    const chain = knowing([pia, mid, end], [first, second, before, after]);
    expect(verdict(before, pia, chain)).toBe(at(40));
    expect(verdict(after, pia, chain)).toStrictEqual({ clause: "L1 11.4", path: "/authority/1" });
  });

  it(`${clause("L1 7.3")} is not duplicitous at or after its first conflicting event`, () => {
    // Two events of Ines's stand at one position, both first seen at 100.
    const [ines, bot] = [new KeyMind("ines"), new KeyMind("bot")];
    const grant = grantBy(ines, bot, 10);
    const rival = new KeyMind("ines").update(100, { homes: ["https://ines.example"] });
    ines.update(100);
    const before = usedBy(bot, ines, 99, [grant]);
    const after = usedBy(bot, ines, 100, [grant]);
    const context = knowing([ines, bot], [grant, before, after]);
    (context.identity.evidence as FirstSeen).sawEvent(contentId(rival.events[1]), at(100));
    (context.identity as LogBook).hold(rival.events, LATER);
    expect(context.identity.log(ines.address)).toMatchObject({ value: { duplicitous: true } });
    expect(verdict(before, ines, context)).toBe(at(99));
    expect(verdict(after, ines, context)).toStrictEqual({
      clause: "L1 7.3",
      path: "/authority/0",
    });
    // With either branch alone, she is not duplicitous, and both count.
    const single = knowing([ines, bot], [grant, before, after]);
    expect(verdict(after, ines, single)).toBe(at(100));
  });
});

describe(`${clause("L1 11.2")} a packet sent on another mind's behalf`, () => {
  const mayContact = delegation(amina, agent, 10, { command: "/oip/send" });
  /** A packet from one mind, signed by a mind that lists a chain. */
  const packet = (
    from: Mind,
    by: Mind,
    seconds: number,
    authority: readonly unknown[] | undefined,
    more: JsonObject = {},
  ) =>
    by.sign(
      {
        oip: "1",
        type: "Packet",
        from: from.address,
        to: [stranger.address],
        created: T(seconds),
        expires: T(seconds + 1000),
        nonce: "c4e2a9f7d1b8306e",
        purpose: { verb: "request" },
        content: { mediaType: "text/plain", body: "Could it be ready early?" },
        provenance: { onBehalfOf: amina.address },
        ...more,
      },
      authority === undefined ? {} : { more: { authority: authority as string[] } },
    );
  const sent = (record: object, held: readonly object[], seen?: ReadonlyMap<object, number>) =>
    sentFor(judged(record), amina.address, holding([...held, record], seen).context);

  it("is one that names the subject, signed by its sender with a chain that covers /oip/send", () => {
    expect(sent(packet(agent, agent, 20, [refTo(mayContact)]), [mayContact])).toBe(at(20));
  });

  it("is not one for a claim in `provenance` alone, or for a chain that grants something else", () => {
    // No chain at all.
    expect(sent(packet(agent, agent, 20, undefined), [])).toBeUndefined();
    // A chain that lets the agent sign Intents, not send.
    const mayIntend = delegation(amina, agent, 10);
    expect(sent(packet(agent, agent, 20, [refTo(mayIntend)]), [mayIntend])).toBeUndefined();
    // Another subject named, or none.
    expect(
      sent(
        packet(agent, agent, 20, [refTo(mayContact)], {
          provenance: { onBehalfOf: helper.address },
        }),
        [mayContact],
      ),
    ).toBeUndefined();
    expect(
      sent(packet(agent, agent, 20, [refTo(mayContact)], { provenance: {} }), [mayContact]),
    ).toBeUndefined();
  });

  it("is signed by its sender: a chain on a proof by anyone else does not make it one", () => {
    // The packet says it is from the helper; the agent, who holds the delegation, signs it.
    expect(sent(packet(helper, agent, 20, [refTo(mayContact)]), [mayContact])).toBeUndefined();
  });

  it(`${clause("core 9.6")} does not count on a proof evaluated more than 300 seconds after it expires`, () => {
    const made = packet(agent, agent, 20, [refTo(mayContact)]);
    // It expires at 1020.
    expect(sent(made, [mayContact], new Map([[made, 1320]]))).toBe(at(1320));
    expect(sent(made, [mayContact], new Map([[made, 1321]]))).toBeUndefined();
  });

  it("is a packet, and no other record with those members", () => {
    const intent = signedFor(agent, 20, [refTo(mayContact)], {
      provenance: { onBehalfOf: amina.address },
    });
    expect(sent(intent, [mayContact])).toBeUndefined();
  });
});

describe("the records a verifier holds", () => {
  const grant = delegation(amina, agent, 10);

  it("are held by content ID, each judged once", () => {
    const set = new RecordSet();
    expect(set.add(grant)).toStrictEqual({ ok: true, value: contentId(grant) });
    expect(set.record(contentId(grant))?.record).toStrictEqual(grant);
    expect(set.record(contentId(agent.sign(intentBy(amina, 1))))).toBeUndefined();
    expect(set.add({ type: "Delegation" }).ok).toBe(false);
    expect(set.add("a record").ok).toBe(false);
  });

  it(`${clause("core 3.1")} keep every proof a record was shown with: no copy takes one away`, () => {
    const { proof: _, ...content } = grant;
    const stripped = { ...content, proof: [{ ...grant.proof[0], proofValue: "z1111" }] };
    const cosigned = agent.sign(grant);
    for (const order of [
      [grant, stripped, cosigned],
      [stripped, cosigned, grant],
      [cosigned, grant, stripped],
    ]) {
      const set = new RecordSet();
      for (const copy of order)
        expect(set.add(copy)).toStrictEqual({ ok: true, value: contentId(grant) });
      const held = set.record(contentId(grant));
      expect(held?.proofs.map((proof) => proof.digest).sort()).toStrictEqual(
        cosigned.proof.map((proof) => proofDigest(proof as never)).sort(),
      );
      expect(Object.isFrozen(held)).toBe(true);
    }
  });

  it("keep a proof held when a copy without it brings another", () => {
    // The author's copy first, then a copy that has only a stranger's proof.
    const { proof: _, ...content } = grant;
    const strangers = stranger.sign(content);
    const set = new RecordSet();
    set.add(grant);
    set.add(strangers);
    expect(
      set
        .record(contentId(grant))
        ?.proofs.map((proof) => proof.digest)
        .sort(),
    ).toStrictEqual(
      [...grant.proof, ...strangers.proof].map((proof) => proofDigest(proof as never)).sort(),
    );
    // A revocation shown signed and then without its author's proof is signed still.
    const revocation = amina.sign({
      oip: "1",
      type: "Revocation",
      author: amina.address,
      revokes: refTo(grant),
      created: T(30),
    });
    const { proof: _signature, ...bare } = revocation;
    const { context, set: held } = holding([grant, revocation, stranger.sign(bare)]);
    expect(revokedTime(contentId(grant), amina.address, held, context.identity)).toBe(at(30));
  });

  it("find the revocations that name a record, whoever made them", () => {
    const set = new RecordSet();
    const revoke = (author: Mind) =>
      author.sign({
        oip: "1",
        type: "Revocation",
        author: author.address,
        revokes: refTo(grant),
        created: T(30),
      });
    const [hers, another] = [revoke(amina), revoke(stranger)];
    for (const record of [grant, hers, another, hers]) set.add(record);
    expect(
      set
        .revocationsOf(contentId(grant))
        .map((held) => contentId(held.record))
        .sort(),
    ).toStrictEqual([contentId(hers), contentId(another)].sort());
    expect(set.revocationsOf(contentId(hers))).toStrictEqual([]);
  });
});
