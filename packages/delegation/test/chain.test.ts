// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, formatRecordRef, type Instant, proofDigest } from "@oip/core";
import { FirstSeen, type JudgedRecord, judgeRecord, LogBook } from "@oip/identity";
import { clause, type JsonObject } from "@oip/testkit";
import { at, intentBy, KeyMind, LATER, type Mind, T } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import {
  delegatedProofTime,
  delegatedTime,
  type DelegationContext,
  MAX_CHAIN,
  RecordSet,
  revokedTime,
  sentFor,
} from "../src/index.ts";

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

  it("is the earliest of those held", () => {
    const [first, second] = [revocation(amina, 50), revocation(amina, 30)];
    const { context, set } = holding([grant, first, second]);
    const time = (records = set): Instant | undefined =>
      revokedTime(contentId(grant), amina.address, records, context.identity);
    expect(time()).toBe(at(30));
    expect(revokedTime(contentId(grant), agent.address, set, context.identity)).toBeUndefined();
    expect(time(new RecordSet())).toBeUndefined();
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
