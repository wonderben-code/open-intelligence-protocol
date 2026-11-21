// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, formatRecordRef, proofDigest } from "@oip/core";
import type { Delegation } from "@oip/schema";
import { clause } from "@oip/testkit";
import { at, T } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { carried, Lookup, Mind, Reader } from "../src/index.ts";
import { freshKeystore, refusal } from "./helpers.ts";
import { World } from "./world.ts";

const A = "https://resolver-a.example";
const HOME = "https://host.example";

let world: World;
beforeEach(() => {
  world = new World(1000);
  world.resolver(A);
  world.host(HOME);
});
afterEach(() => {
  world.close();
});

/** A mind of a kind, at the home, which has said where it takes packets. */
async function mindOf(kind: string) {
  const made = await freshKeystore(world, [A]);
  const mind = await Mind.create(made.options, { kind, homes: [HOME] });
  await mind.publishLocation();
  return { ...made, mind };
}

/** The four of the papers' scenario: Amina and her assistant, Lexis Ltd and its agent. */
async function cast() {
  const amina = (await mindOf("human")).mind;
  const assistant = (await mindOf("agent")).mind;
  const firm = await mindOf("institution");
  const agent = (await mindOf("agent")).mind;
  // Time passes between a mind's making and what it signs. A resolver first sees each thing
  // at a moment of its own, and a proof first seen at the moment its signer was made, to
  // the nanosecond, would be older than its signer.
  world.clock.at = at(1010);
  return { amina, assistant, lexis: firm.mind, agent };
}

const ref = (mind: Mind, record: object): string =>
  formatRecordRef(mind.address, contentId(record));

/** Brings records from one mind to another in a sealed packet. The other reads its mailbox, and holds them. */
async function pass(from: Mind, to: Mind, ...records: object[]): Promise<void> {
  const [first, ...rest] = records.map((record) => carried(record));
  const sent = await from.send({
    to: [to.address],
    verb: "inform",
    content:
      first !== undefined && rest.length === 0 ? first : { parts: [first, ...rest] as never },
  });
  expect(sent.deliveries.map((delivery) => delivery.stored)).toStrictEqual([true]);
  const inbox = await to.receive();
  expect(inbox.refused).toStrictEqual([]);
  expect(inbox.received.map((received) => received.id)).toStrictEqual([sent.id]);
}

const FAR = T(5_000_000);

/** What Lexis Ltd lets its agent commit it to: paid in US dollars, at most 500, and the agent no party. */
const mandateOf = (lexis: Mind, agent: Mind): Promise<Delegation> =>
  lexis.delegate({
    delegate: agent.address,
    command: "/oip/sign/Commitment",
    policy: [
      ["==", ".terms.price.currency", "USD"],
      ["<=", ".terms.price.amount", "500"],
      ["==", ".terms.price.payee", lexis.address],
      ["all", ".parties", ["!=", ".mind", agent.address]],
    ],
    expires: FAR,
  });

/** A translation, promised by Lexis Ltd to Amina, for a price she pays. */
const deal = (lexis: Mind, amina: Mind, amount: string, more: object = {}) => ({
  parties: [
    { mind: lexis.address, role: "debtor", required: true },
    { mind: amina.address, role: "creditor", required: true },
  ],
  promise: `Lexis Ltd will deliver an English translation of the lease; Amina will pay ${amount} USD on delivery.`,
  terms: {
    deadline: T(200_000),
    price: { amount, currency: "USD", payer: amina.address, payee: lexis.address },
  },
  ...more,
});

describe("the scenario of the papers, through the client", () => {
  it(`${clause("L2 7.1", "L2 7.3", "L2 8.1", "L2 8.3", "L1 11.4")} an Intent, an Offer and a Commitment an agent signs for its firm, accepted, fulfilled`, async () => {
    const { amina, lexis, agent } = await cast();
    // Lexis Ltd lets its agent make Offers and Commitments for it, within limits.
    const mandate = await mandateOf(lexis, agent);
    const offering = await lexis.delegate({
      delegate: agent.address,
      command: "/oip/sign/Offer",
      expires: FAR,
    });
    expect(mandate).toMatchObject({
      type: "Delegation",
      author: lexis.address,
      subject: lexis.address,
      delegate: agent.address,
    });
    await pass(lexis, agent, mandate, offering);

    // Amina says what she wants.
    const intent = await amina.intent({
      want: "A Swahili commercial lease translated into English.",
      constraints: { budget: { max: "150", currency: "USD" } },
    });
    await amina.publishRecord(intent);
    expect(await amina.statusOf(intent)).toBe("open");
    await pass(amina, agent, intent);

    // The agent offers, for Lexis Ltd.
    const offer = await agent.offer(
      {
        author: lexis.address,
        provides: "An English translation of a Swahili commercial lease.",
        terms: { summary: "By tomorrow evening.", price: { amount: "120", currency: "USD" } },
        answers: ref(amina, intent),
      },
      { chain: [offering] },
    );
    expect(await agent.countsFor(offer, lexis.address)).toBe(true);
    expect(await agent.statusOf(offer)).toBe("open");

    // The agent writes the Commitment and signs it for Lexis Ltd. It is no party itself.
    const proposed = await agent.commitment(
      deal(lexis, amina, "120", {
        resolves: [ref(amina, intent), ref(lexis, offer)],
        closesIntent: true,
      }),
      { chain: [mandate] },
    );
    expect(proposed.author).toBe(agent.address);
    expect(await agent.statusOf(proposed)).toBe("proposed");
    await pass(agent, amina, offer, proposed);

    // Amina reads it. It counts for Lexis Ltd, by the delegation the agent's proof carries.
    world.clock.at = at(1120);
    expect(await amina.countsFor(proposed, lexis.address)).toBe(true);
    expect(await amina.countsFor(proposed)).toBe(false);
    const accepted = await amina.cosign(proposed);
    expect(contentId(accepted)).toBe(contentId(proposed));
    expect(accepted.proof).toHaveLength(2);
    expect(await amina.statusOf(accepted)).toBe("accepted");
    // Her Intent is satisfied: the Commitment is accepted, counts for her, and closes it.
    expect(await amina.statusOf(intent)).toBe("satisfied");
    await pass(amina, agent, accepted);
    await pass(amina, lexis, accepted);
    // The agent holds the same Commitment, now with both proofs.
    expect(await agent.statusOf(proposed)).toBe("accepted");
    expect(await agent.statusOf(intent)).toBe("satisfied");

    // Lexis Ltd delivers, and says so. Its word alone is a claim.
    const delivered = await lexis.receipt({
      about: ref(agent, accepted),
      outcome: "fulfilled",
      statement: "The translation was delivered.",
    });
    await pass(lexis, amina, delivered);
    expect(await amina.statusOf(accepted)).toBe("claimed-fulfilled");
    // Amina, who is owed it, confirms.
    const confirmed = await amina.receipt({
      about: ref(agent, accepted),
      outcome: "fulfilled",
      rating: { score: "1" },
    });
    expect(await amina.statusOf(accepted)).toBe("fulfilled");
    await pass(amina, lexis, confirmed);
    expect(await lexis.statusOf(accepted)).toBe("fulfilled");
    // What each holds is its own to keep.
    expect(
      amina
        .records()
        .map((record) => record.type)
        .sort(),
    ).toStrictEqual(["Commitment", "Intent", "Offer", "Receipt", "Receipt"].sort());
  });

  it(`${clause("L2 7.1", "L2 8.3")} a reader that holds no key works out what the parties do, from what they published`, async () => {
    const { amina, assistant, lexis, agent } = await cast();
    const mandate = await mandateOf(lexis, agent);
    const proposed = await agent.commitment(deal(lexis, amina, "120"), { chain: [mandate] });
    world.clock.at = at(1120);
    const accepted = await amina.cosign(proposed);
    await amina.publishRecord(accepted);
    const confirmed = await amina.receipt({ about: ref(agent, accepted), outcome: "fulfilled" });
    await amina.publishRecord(confirmed);
    world.clock.at = at(1200);

    // A stranger: a way to ask for logs and for what a mind published, and nothing else.
    const lookup = new Lookup({ resolvers: [A], fetch: world.fetch, clock: world.clock });
    const reader = new Reader({ lookup, clock: world.clock });
    expect(reader.held()).toStrictEqual([]);
    const { feed } = await lookup.feed(amina.address);
    for (const { entry } of feed.entries) {
      reader.hold((await lookup.record(amina.address, entry.object)).record);
    }
    expect(
      reader
        .held()
        .map((record) => record.type)
        .sort(),
    ).toStrictEqual(["Commitment", "Receipt"]);
    const [held] = reader.held().filter((record) => record.type === "Commitment");
    expect(contentId(held as object)).toBe(contentId(accepted));
    // It reaches the verdicts the parties reach, by the records and the logs alone.
    expect(await reader.countsFor(held, lexis.address)).toBe(true);
    expect(await reader.countsFor(held, amina.address)).toBe(true);
    // The agent signed it, for the firm and so for itself too. A mind that signed nothing is bound by nothing.
    expect(await reader.countsFor(held, agent.address)).toBe(true);
    expect(await reader.countsFor(held, assistant.address)).toBe(false);
    expect(await reader.status(held)).toBe("fulfilled");
    // Without the Receipt it would know of a promise, and not that it was kept.
    const other = new Reader({ lookup, clock: world.clock });
    other.hold(held);
    expect(await other.status(held)).toBe("accepted");
    // What is no record is held by nobody.
    expect(await refusal(() => Promise.resolve(reader.hold({ type: "Commitment" })))).toBe(
      "oip: invalid-record",
    );
  });

  it(`${clause("L1 11.3", "L2 5.4")} the agent binds its firm to nothing its mandate does not allow`, async () => {
    const { amina, lexis, agent } = await cast();
    const mandate = await mandateOf(lexis, agent);
    const outside = [
      // More than 500; another currency; the firm the one that pays; the agent itself a party.
      deal(lexis, amina, "600"),
      deal(lexis, amina, "120", {
        terms: {
          price: { amount: "120", currency: "EUR", payer: amina.address, payee: lexis.address },
        },
      }),
      deal(lexis, amina, "120", {
        terms: {
          price: { amount: "120", currency: "USD", payer: lexis.address, payee: amina.address },
        },
      }),
      deal(lexis, amina, "120", {
        parties: [
          { mind: lexis.address, role: "debtor", required: true },
          { mind: amina.address, role: "creditor", required: true },
          { mind: agent.address, role: "witness" },
        ],
      }),
      // No price at all: a policy that constrains a member requires it.
      deal(lexis, amina, "120", { terms: { deadline: T(200_000) } }),
    ];
    for (const fields of outside) {
      const proposed = await agent.commitment(fields, { chain: [mandate] });
      await pass(agent, amina, proposed);
      expect(await amina.countsFor(proposed, lexis.address), fields.promise).toBe(false);
      const signed = await amina.cosign(proposed);
      // Amina's signature is hers. The firm is not bound, and the Commitment is not accepted.
      expect(await amina.countsFor(signed)).toBe(true);
      expect(await amina.statusOf(signed)).toBe("proposed");
    }
    // Within it, the same agent binds the firm.
    const within = await agent.commitment(deal(lexis, amina, "500"), { chain: [mandate] });
    expect(await amina.statusOf(await amina.cosign(within))).toBe("accepted");
  });

  it(`${clause("L1 11.6", "L2 7.1")} two agents strike a deal, each for its principal, each with its own delegation`, async () => {
    const { amina, assistant, lexis, agent } = await cast();
    const mandate = await mandateOf(lexis, agent);
    // Amina's assistant may commit her only to pay Lexis Ltd, at most 150 US dollars.
    const allowance = await amina.delegate({
      delegate: assistant.address,
      command: "/oip/sign/Commitment",
      policy: [
        ["==", ".terms.price.currency", "USD"],
        ["<=", ".terms.price.amount", "150"],
        ["==", ".terms.price.payer", amina.address],
        ["==", ".terms.price.payee", lexis.address],
      ],
      expires: FAR,
    });
    // The assistant is given it, and so is the firm's agent, which will want to check it.
    await pass(amina, assistant, allowance);
    await pass(amina, agent, allowance);
    const rush = await agent.commitment(deal(lexis, amina, "30"), { chain: [mandate] });
    await pass(agent, assistant, rush);
    // Named, and not carried: the proof counts for a verifier that already holds the delegation.
    world.clock.at = at(1100);
    const both = await assistant.cosign(rush, { chain: [allowance], as: "references" });
    expect(both.proof).toHaveLength(2);
    expect(await assistant.statusOf(both)).toBe("accepted");
    expect(await assistant.countsFor(both, amina.address)).toBe(true);
    expect(await assistant.countsFor(both, lexis.address)).toBe(true);
    await pass(assistant, agent, both);
    expect(await agent.statusOf(both)).toBe("accepted");
    // The firm itself was never shown the delegation: for it, Amina is not bound.
    await pass(assistant, lexis, both);
    expect(await lexis.countsFor(both, amina.address)).toBe(false);
    expect(await lexis.statusOf(both)).toBe("proposed");
    // Shown it only later, the firm has no evidence that it existed when the assistant signed
    // (11.4, item 1): a proof that carries its delegations has them seen with it.
    world.clock.at = at(1200);
    await pass(assistant, lexis, allowance);
    expect(await lexis.statusOf(both)).toBe("proposed");
    const carried_ = await assistant.cosign(rush, { chain: [allowance] });
    await pass(assistant, lexis, carried_);
    expect(await lexis.statusOf(both)).toBe("accepted");
    // More than the assistant may promise for her.
    const dear = await agent.commitment(deal(lexis, amina, "151"), { chain: [mandate] });
    const signed = await assistant.cosign(dear, { chain: [allowance] });
    expect(await assistant.countsFor(signed, amina.address)).toBe(false);
    expect(await assistant.statusOf(signed)).toBe("proposed");
  });
});

describe(`${clause("L1 11.5")} a delegation that is taken back`, () => {
  it("lets the delegate bind its principal no more, from when a verifier sees the revocation, and what came before stands", async () => {
    const { amina, lexis, agent } = await cast();
    const mandate = await mandateOf(lexis, agent);
    const before = await amina.cosign(
      await agent.commitment(deal(lexis, amina, "120"), { chain: [mandate] }),
    );
    expect(await amina.statusOf(before)).toBe("accepted");
    world.clock.at = at(2000);
    const revocation = await lexis.revoke(mandate);
    expect(revocation).toMatchObject({
      type: "Revocation",
      author: lexis.address,
      revokes: ref(lexis, mandate),
    });
    // It is on the firm's feed, for whoever checks before relying on the agent.
    const { feed } = await amina.lookup.feed(lexis.address);
    expect(feed.entries.map(({ entry }) => entry.objectType)).toStrictEqual(["Revocation"]);
    const fetched = await amina.lookup.record(lexis.address, feed.entries[0]?.entry.object ?? "");
    amina.hold(fetched.record);
    world.clock.at = at(2100);
    const after = await amina.cosign(
      await agent.commitment(deal(lexis, amina, "130"), { chain: [mandate] }),
    );
    expect(await amina.countsFor(after, lexis.address)).toBe(false);
    expect(await amina.statusOf(after)).toBe("proposed");
    // What the agent signed before the revocation was seen still binds the firm.
    expect(await amina.statusOf(before)).toBe("accepted");
    // Only the mind that made a delegation takes it back.
    expect(await refusal(() => agent.revoke(mandate))).toBe("oip: forbidden");
  });
});

describe(`${clause("core 9.4")} the client's own record of when it first obtained a proof`, () => {
  /** Amina's client, started again: the same mind, opened from what its keystore holds. */
  const again = async (amina: Awaited<ReturnType<typeof mindOf>>): Promise<Mind> => {
    amina.mind.close();
    return Mind.open(amina.options);
  };

  it(`${clause("core 9.3")} is evidence a program keeps between runs: what was signed under a delegation that has since expired still counts`, async () => {
    const amina = await mindOf("human");
    const lexis = (await mindOf("institution")).mind;
    const agent = (await mindOf("agent")).mind;
    world.clock.at = at(1010);
    const mandate = await lexis.delegate({
      delegate: agent.address,
      command: "/oip/sign/Commitment",
      expires: T(3000),
    });
    const accepted = await amina.mind.cosign(
      await agent.commitment(deal(lexis, amina.mind, "120"), { chain: [mandate] }),
    );
    expect(await amina.mind.statusOf(accepted)).toBe("accepted");
    // What the program keeps: the record, and when each of its proofs was first obtained.
    const id = contentId(accepted);
    const kept = amina.mind.sightings(id);
    expect(Object.keys(kept).sort()).toStrictEqual(
      [...accepted.proof.map((proof) => proofDigest(proof)), proofDigest(mandate.proof[0])].sort(),
    );
    for (const time of Object.values(kept)) expect(time).toBe(at(1010));
    // Long after the delegation has expired, the program runs again.
    world.clock.at = at(10_000);
    const later = await again(amina);
    expect(later.records()).toStrictEqual([]);
    expect(later.hold(accepted, kept)).toBe(id);
    expect(await later.countsFor(accepted, lexis.address)).toBe(true);
    expect(await later.statusOf(accepted)).toBe("accepted");
    expect(later.sightings(id)).toStrictEqual(kept);
    // Held with no such record, the agent's proof is first seen now: after the delegation
    // expired (core 9.6, Layer 1, 11.4), so the firm is not shown to be bound.
    const forgetful = await again({ ...amina, mind: later });
    forgetful.hold(accepted);
    expect(await forgetful.countsFor(accepted, lexis.address)).toBe(false);
    expect(await forgetful.statusOf(accepted)).toBe("proposed");
    expect(Object.values(forgetful.sightings(id))).toStrictEqual(
      Object.values(kept).map(() => at(10_000)),
    );
  });

  it(`${clause("L1 11.5")} keeps what came before a revocation before it, and what came after it after`, async () => {
    const amina = await mindOf("human");
    const lexis = (await mindOf("institution")).mind;
    const agent = (await mindOf("agent")).mind;
    world.clock.at = at(1010);
    const mandate = await mandateOf(lexis, agent);
    const before = await amina.mind.cosign(
      await agent.commitment(deal(lexis, amina.mind, "120"), { chain: [mandate] }),
    );
    world.clock.at = at(2000);
    const revocation = await lexis.revoke(mandate);
    amina.mind.hold(revocation);
    world.clock.at = at(2100);
    const after = await amina.mind.cosign(
      await agent.commitment(deal(lexis, amina.mind, "130"), { chain: [mandate] }),
    );
    expect(await amina.mind.countsFor(before, lexis.address)).toBe(true);
    expect(await amina.mind.countsFor(after, lexis.address)).toBe(false);
    const kept = [before, revocation, after].map((record) => ({
      record,
      seen: amina.mind.sightings(contentId(record)),
    }));
    // Run again, with the records held in an order that says nothing of when they came.
    world.clock.at = at(5000);
    const later = await again(amina);
    for (const { record, seen } of [...kept].reverse()) later.hold(record, seen);
    expect(await later.countsFor(before, lexis.address)).toBe(true);
    expect(await later.countsFor(after, lexis.address)).toBe(false);
  });

  it("is not believed where it says a proof was obtained later than now, or is of another proof", async () => {
    const amina = await mindOf("human");
    world.clock.at = at(1010);
    const intent = await amina.mind.intent({ want: "A hall for the spring meeting." });
    const id = contentId(intent);
    const [digest = ""] = Object.keys(amina.mind.sightings(id));
    expect(digest).toBe(proofDigest(intent.proof[0]));
    world.clock.at = at(2000);
    const later = await again(amina);
    later.hold(intent, {
      [digest]: at(9000),
      "sha256:another": at(5),
      constructor: at(5),
    });
    expect(later.sightings(id)).toStrictEqual({ [digest]: at(2000) });
    // What is no time says nothing, and the proof is first seen now.
    const careless = await again({ ...amina, mind: later });
    careless.hold(intent, { [digest]: "1010" } as never);
    expect(careless.sightings(id)).toStrictEqual({ [digest]: at(2000) });
    // A record that says nothing of a proof says nothing: the proof is first seen now.
    const silent = await again({ ...amina, mind: careless });
    silent.hold(intent, {});
    expect(silent.sightings(id)).toStrictEqual({ [digest]: at(2000) });
    // A record the mind does not hold has no such record.
    expect(silent.sightings("bciqnothing")).toStrictEqual({});
  });
});

describe(`${clause("L1 11.4")} a delegation passed on`, () => {
  it("gives the next mind no more than the chain gives, and its proof names the whole chain", async () => {
    const { amina, assistant, lexis, agent } = await cast();
    const mandate = await mandateOf(lexis, agent);
    // The firm's agent lets a junior agent commit the firm to less.
    const junior = assistant;
    const passed = await agent.subDelegate([mandate], {
      delegate: junior.address,
      command: "/oip/sign/Commitment",
      policy: [["<=", ".terms.price.amount", "50"]],
      notBefore: T(1000),
      expires: T(100_000),
    });
    expect(passed.notBefore).toBe(T(1000));
    expect(passed).toMatchObject({ author: agent.address, subject: lexis.address });
    expect(passed.policy).toHaveLength(5);
    const small = await junior.commitment(deal(lexis, amina, "50"), { chain: [mandate, passed] });
    expect(await amina.statusOf(await amina.cosign(small))).toBe("accepted");
    const large = await junior.commitment(deal(lexis, amina, "51"), { chain: [mandate, passed] });
    expect(await amina.countsFor(large, lexis.address)).toBe(false);
    // A link of the chain left out, or the chain in another order, is no chain.
    for (const chain of [[passed], [passed, mandate]]) {
      const broken = await junior.commitment(deal(lexis, amina, "40"), { chain });
      expect(await amina.countsFor(broken, lexis.address)).toBe(false);
    }
    // It cannot pass on what it was not given.
    const asking = (grant: object) =>
      refusal(() =>
        agent.subDelegate([mandate], {
          delegate: junior.address,
          command: "/oip/sign/Commitment",
          expires: T(100_000),
          ...grant,
        }),
      );
    expect(await asking({ command: "/oip/sign/Offer" })).toBe("oip: forbidden");
    expect(await asking({ expires: T(6_000_000) })).toBe("oip: forbidden");
    expect(
      await refusal(() =>
        junior.subDelegate([mandate], {
          delegate: amina.address,
          command: "/oip/sign/Commitment",
          expires: T(100_000),
        }),
      ),
    ).toBe("oip: forbidden");
    expect(
      await refusal(() =>
        junior.subDelegate([], {
          delegate: amina.address,
          command: "/oip/sign/Commitment",
          expires: T(100_000),
        }),
      ),
    ).toBe("oip: forbidden");
  });
});

describe(`${clause("L1 11.2")} a packet sent for another mind`, () => {
  it("is taken as sent for it only where the sender's proof carries a delegation to send", async () => {
    const { amina, assistant, agent } = await cast();
    const sending = await amina.delegate({
      delegate: assistant.address,
      command: "/oip/send",
      expires: FAR,
    });
    const signing = await amina.delegate({
      delegate: assistant.address,
      command: "/oip/sign/Intent",
      expires: FAR,
    });
    const ask = (chain: readonly Delegation[]) =>
      assistant.send({
        to: [agent.address],
        verb: "request",
        content: { mediaType: "text/plain", body: "Could it be twelve hours sooner?" },
        onBehalfOf: { mind: amina.address, chain },
      });
    const sent = await ask([sending]);
    expect(sent.packet.provenance).toStrictEqual({ onBehalfOf: amina.address });
    // One whose delegation is for something else says it is sent for her, and is not.
    const claimed = await ask([signing]);
    const { received } = await agent.receive();
    expect(received.map((arrived) => [arrived.id, arrived.from, arrived.sentFor])).toStrictEqual([
      [sent.id, assistant.address, amina.address],
      [claimed.id, assistant.address, undefined],
    ]);
  });

  it(`${clause("L1 11.4")} a record read from a home counts for the mind its signer acts for, on a clock that moves`, async () => {
    const { amina, lexis, agent } = await cast();
    const mandate = await mandateOf(lexis, agent);
    const proposed = await agent.commitment(deal(lexis, amina, "120"), { chain: [mandate] });
    await agent.publishRecord(proposed);
    // Every reading of the clock is later than the one before, as on a real one. The record
    // is fetched, and then held: two readings. The delegation its proof carries is first
    // seen at the first, with the proof, or it would be signed after the proof that uses it.
    const { clock } = world;
    clock.now = () => {
      clock.at += 1_000_000n;
      return clock.at;
    };
    try {
      const fetched = await amina.lookup.record(agent.address, contentId(proposed));
      amina.hold(fetched.record);
      expect(await amina.countsFor(fetched.record, lexis.address)).toBe(true);
    } finally {
      // As the world made it: a clock that stands where a test puts it.
      clock.now = () => clock.at;
    }
  });

  it.each([
    ["the delegation first", true],
    ["the record first", false],
  ])(
    `${clause("L1 11.4", "L1 11.6")} a record whose proof names its delegation counts by a delegation the same packet carries, on a clock that moves: %s`,
    async (_, delegationFirst) => {
      const { amina, lexis, agent } = await cast();
      const mandate = await mandateOf(lexis, agent);
      // The proof names the delegation by its reference, and does not carry it.
      const proposed = await agent.commitment(deal(lexis, amina, "120"), {
        chain: [mandate],
        as: "references",
      });
      const records = delegationFirst ? [mandate, proposed] : [proposed, mandate];
      const sent = await agent.send({
        to: [amina.address],
        verb: "inform",
        content: { parts: records.map((record) => carried(record)) },
      });
      expect(sent.deliveries.map((delivery) => delivery.stored)).toStrictEqual([true]);
      // A real clock: every reading is later than the one before. What one packet carries
      // came together, and is first seen together.
      const { clock } = world;
      clock.now = () => {
        clock.at += 1_000_000n;
        return clock.at;
      };
      try {
        expect((await amina.receive()).received).toHaveLength(1);
        expect(await amina.countsFor(proposed, lexis.address)).toBe(true);
      } finally {
        clock.now = () => clock.at;
      }
    },
  );

  it(`${clause("L1 11.4")} is taken as sent for it on a clock that moves: the delegation it carries is first seen when the packet is`, async () => {
    const { amina, assistant, agent } = await cast();
    const sending = await amina.delegate({
      delegate: assistant.address,
      command: "/oip/send",
      expires: FAR,
    });
    const sent = await assistant.send({
      to: [agent.address],
      verb: "request",
      content: { mediaType: "text/plain", body: "Could it be twelve hours sooner?" },
      onBehalfOf: { mind: amina.address, chain: [sending] },
    });
    // A real clock: every reading is later than the one before. A delegation that was first
    // seen at a later reading than the proof that carries it would be signed after that
    // proof, as far as the receiver could tell (item 1), and the packet sent for nobody.
    const { clock } = world;
    clock.now = () => {
      clock.at += 1_000_000n;
      return clock.at;
    };
    try {
      const { received } = await agent.receive();
      expect(received.map((arrived) => [arrived.id, arrived.sentFor])).toStrictEqual([
        [sent.id, amina.address],
      ]);
    } finally {
      // As the world made it: a clock that stands where a test puts it.
      clock.now = () => clock.at;
    }
  });
});

describe(`${clause("L1 11.5")} a verifier that looks before it acts`, () => {
  it("finds on its author's feed that a delegation was taken back, and acts for the delegate no more", async () => {
    const { amina, assistant, agent } = await cast();
    const sending = await amina.delegate({
      delegate: assistant.address,
      command: "/oip/send",
      expires: FAR,
    });
    const ask = (words: string) =>
      assistant.send({
        to: [agent.address],
        verb: "request",
        content: { mediaType: "text/plain", body: words },
        onBehalfOf: { mind: amina.address, chain: [sending] },
      });
    await ask("Could it be twelve hours sooner?");
    const [early] = (await agent.receive()).received;
    expect(early?.sentFor).toBe(amina.address);
    expect(await agent.delegationsStand(early?.packet)).toBe(true);
    // Amina takes the delegation back, and publishes that: which is all 11.5 asks of her.
    world.clock.at = at(2000);
    await amina.revoke(sending);
    world.clock.at = at(2100);
    await ask("And cheaper?");
    const [late] = (await agent.receive()).received;
    // Nobody sent the agent the Revocation. By what it holds, the packet is sent for Amina.
    expect(late?.sentFor).toBe(amina.address);
    expect(await agent.delegationsStand(late?.packet)).toBe(true);
    // It looks at the feed of the delegation's author before it acts.
    world.clock.at = at(2200);
    expect(await agent.holdRevocations(late?.packet)).toBe(1);
    expect(await agent.delegationsStand(late?.packet)).toBe(false);
    expect(await agent.delegationsStand(early?.packet)).toBe(false);
    // A proof is judged as of when it was made, by the evidence of time (core 9): both packets
    // were seen before the Revocation was, and both were sent for her. What to do for them now
    // is the other question.
    expect(await agent.sentFor(late?.packet)).toBe(amina.address);
    // Looked at again, the feed has nothing new.
    expect(await agent.holdRevocations(late?.packet)).toBe(0);
    // A packet that comes once the Revocation is held was sent for nobody.
    await ask("Tomorrow, then?");
    const [after] = (await agent.receive()).received;
    expect(after?.sentFor).toBeUndefined();
    expect(await agent.sentFor(after?.packet)).toBeUndefined();
  });

  it("is not kept from its author's Revocation by a copy that nobody signed", async () => {
    const { amina, assistant, agent } = await cast();
    const sending = await amina.delegate({
      delegate: assistant.address,
      command: "/oip/send",
      expires: FAR,
    });
    const sent = await assistant.send({
      to: [agent.address],
      verb: "request",
      content: { mediaType: "text/plain", body: "Could it be twelve hours sooner?" },
      onBehalfOf: { mind: amina.address, chain: [sending] },
    });
    const [arrived] = (await agent.receive()).received;
    expect([arrived?.id, arrived?.sentFor]).toStrictEqual([sent.id, amina.address]);
    world.clock.at = at(2000);
    const revocation = await amina.revoke(sending);
    // The delegate reads the Revocation on her feed, and gives the verifier a copy first: the
    // same record by its content ID, under a signature that is nobody's.
    const [proof] = revocation.proof;
    const forged = {
      ...revocation,
      proof: [{ ...proof, proofValue: "A".repeat(86) }],
    };
    expect(contentId(forged)).toBe(contentId(revocation));
    world.clock.at = at(2100);
    await pass(assistant, agent, forged);
    expect(agent.records().map((record) => record.type)).toContain("Revocation");
    // It says nothing of Amina, and the delegation stands by it.
    expect(await agent.countsFor(forged, amina.address)).toBe(false);
    expect(await agent.delegationsStand(arrived?.packet)).toBe(true);
    // The feed is read all the same: a copy that does not count for its author is no copy of
    // her word, and hers is fetched.
    world.clock.at = at(2200);
    expect(await agent.holdRevocations(arrived?.packet)).toBe(1);
    expect(await agent.delegationsStand(arrived?.packet)).toBe(false);
    // With hers held, there is nothing more to fetch.
    expect(await agent.holdRevocations(arrived?.packet)).toBe(0);
  });

  it("judges a delegation that a proof names by the copy it holds, and acts for none it was not shown", async () => {
    const { amina, assistant, agent } = await cast();
    const grant = await amina.delegate({
      delegate: assistant.address,
      command: "/oip/sign/Intent",
      expires: FAR,
    });
    world.clock.at = at(1100);
    const wanted = await assistant.intent(
      { author: amina.address, want: "A lease translated." },
      { chain: [grant], as: "references" },
    );
    expect(wanted.proof[0]?.["authority"]).toStrictEqual([ref(amina, grant)]);
    // Named, and not held: nothing shows that it stands. Her feed has no Revocation.
    expect(await agent.delegationsStand(wanted)).toBe(false);
    expect(await agent.holdRevocations(wanted)).toBe(0);
    agent.hold(grant);
    expect(await agent.delegationsStand(wanted)).toBe(true);
    world.clock.at = at(2000);
    await amina.revoke(grant);
    world.clock.at = at(2100);
    // The reference says whose the delegation is, and so whose feed is read.
    expect(await agent.holdRevocations(wanted)).toBe(1);
    expect(await agent.delegationsStand(wanted)).toBe(false);
  });

  it("takes nothing that is no delegation for one that stands", async () => {
    const { amina, agent } = await cast();
    const resting = (...authority: unknown[]) => ({ proof: [{ authority }] });
    const whole = { type: "Delegation", author: amina.address, expires: FAR };
    expect(await agent.delegationsStand(resting(whole))).toBe(true);
    // Nobody's, or with no end that can be read (11.1).
    for (const wrong of [
      { author: "nobody" },
      { author: 7 },
      { expires: undefined },
      { expires: "tomorrow" },
      { expires: 4_102_444_800 },
    ]) {
      expect(await agent.delegationsStand(resting(whole, { ...whole, ...wrong }))).toBe(false);
    }
    // A reference that is none names nothing that is held.
    expect(await agent.delegationsStand(resting("no reference"))).toBe(false);
    // What is neither is not a Revocation's to take back: a charter is judged where the
    // proof is (Layer 2, 6.2).
    expect(await agent.delegationsStand(resting({ type: "Collective" }, null))).toBe(true);
    // Only a mind has a feed to read.
    expect(
      await agent.holdRevocations(resting({ ...whole, author: "nobody" }, "no reference", null, 7)),
    ).toBe(0);
    expect(await agent.holdRevocations({ proof: [null, { authority: "none" }] })).toBe(0);
  });

  it("reads no feed of a mind that has no home, and stops where a feed cannot be read", async () => {
    const { amina, assistant, agent } = await cast();
    const made = await freshKeystore(world, [A]);
    const homeless = await Mind.create(made.options, { kind: "human" });
    world.clock.at = at(1100);
    const lent = await homeless.delegate({
      delegate: assistant.address,
      command: "/oip/sign/Intent",
      expires: FAR,
    });
    world.clock.at = at(1200);
    const hers = await assistant.intent(
      { author: homeless.address, want: "A room." },
      { chain: [lent] },
    );
    // It has published nothing anywhere: what it revokes, it gives out itself (11.5).
    expect(await agent.holdRevocations(hers)).toBe(0);
    expect(await agent.delegationsStand(hers)).toBe(true);
    const revocation = await homeless.revoke(lent);
    agent.hold(revocation);
    expect(await agent.delegationsStand(hers)).toBe(false);
    // A feed that cannot be read shows nothing either way, and the caller is told.
    const grant = await amina.delegate({
      delegate: assistant.address,
      command: "/oip/sign/Intent",
      expires: FAR,
    });
    const wanted = await assistant.intent(
      { author: amina.address, want: "A lease translated." },
      { chain: [grant] },
    );
    world.before = (request) => {
      if (request.url.includes("/feed")) throw new TypeError("fetch failed");
    };
    expect(await refusal(() => agent.holdRevocations(wanted))).toMatch(/^transport: /u);
    world.before = undefined;
    expect(await agent.holdRevocations(wanted)).toBe(0);
  });

  it("has nothing to look for where a record rests on no delegation, and acts for no delegation that has run out", async () => {
    const { amina, assistant, agent } = await cast();
    const own = await amina.intent({ want: "A translation." });
    expect(await agent.holdRevocations(own)).toBe(0);
    expect(await agent.delegationsStand(own)).toBe(true);
    expect(await agent.holdRevocations({ no: "record" })).toBe(0);
    // A delegation that has expired stands no more, though what was signed under it counts.
    const brief = await amina.delegate({
      delegate: assistant.address,
      command: "/oip/send",
      expires: T(1500),
    });
    const sent = await assistant.send({
      to: [agent.address],
      verb: "request",
      content: { mediaType: "text/plain", body: "Quickly." },
      onBehalfOf: { mind: amina.address, chain: [brief] },
    });
    const [arrived] = (await agent.receive()).received;
    expect([arrived?.id, arrived?.sentFor]).toStrictEqual([sent.id, amina.address]);
    expect(await agent.delegationsStand(arrived?.packet)).toBe(true);
    world.clock.at = at(1501);
    expect(await agent.delegationsStand(arrived?.packet)).toBe(false);
    expect(await agent.sentFor(arrived?.packet)).toBe(amina.address);
  });
});

describe("the edges of dealing", () => {
  it(`${clause("L1 11.1", "L1 11.2")} what makes no delegation is refused`, async () => {
    const { lexis, agent } = await cast();
    const grant = { delegate: agent.address, command: "/oip/sign/Offer", expires: FAR };
    for (const wrong of [
      { delegate: lexis.address },
      { command: "/oip/sign" },
      { command: "/oip/sign/Delegation" },
      { command: "sign" },
      { expires: "tomorrow" },
      { policy: [["like", ".want", "x"]] },
    ]) {
      expect(await refusal(() => lexis.delegate({ ...grant, ...wrong } as never))).toBe(
        "oip: invalid-record",
      );
    }
    expect((await lexis.delegate({ ...grant, notBefore: T(2000) })).notBefore).toBe(T(2000));
    expect(lexis.records()).toHaveLength(1);
  });

  it(`${clause("L2 4.3", "L2 8.1", "L2 8.2")} an Intent or an Offer is withdrawn by a record that supersedes it`, async () => {
    const { amina, lexis } = await cast();
    const intent = await amina.intent({ want: "A lease translated." });
    const withdrawn = await amina.intent({
      want: "A lease translated.",
      supersedes: ref(amina, intent),
      status: "withdrawn",
    });
    expect(await amina.statusOf(intent)).toBe("withdrawn");
    expect(await amina.statusOf(withdrawn)).toBe("withdrawn");
    const offer = await lexis.offer({
      provides: "Translations.",
      terms: { summary: "Per page.", quantity: 1 },
      expires: T(3000),
    });
    expect(await lexis.statusOf(offer)).toBe("open");
    world.clock.at = at(3001);
    expect(await lexis.statusOf(offer)).toBe("expired");
  });

  it("what is no record is not held, a record with no status has none, and a mind nobody can resolve signs nothing that counts", async () => {
    const { amina, lexis } = await cast();
    expect(await refusal(() => Promise.resolve(amina.hold("a record")))).toBe(
      "oip: invalid-record",
    );
    expect(await refusal(() => Promise.resolve(amina.hold({ oip: "1", type: "Intent" })))).toBe(
      "oip: invalid-record",
    );
    const receipt = await amina.receipt({
      about: `${lexis.address}/${contentId({ a: 1 })}`,
      outcome: "progress",
    });
    expect(await refusal(() => amina.statusOf(receipt))).toBe("oip: invalid-record");
    expect(await refusal(() => amina.intent({ want: 5 } as never))).toBe("oip: invalid-record");
    // An Intent of a mind whose log cannot be asked for counts for nobody, until it can.
    const intent = await lexis.intent({ want: "Readers." });
    // Time passes: the log Amina holds of the firm is from before she first sees the Intent.
    world.clock.at = at(1020);
    world.before = (request) => {
      if (request.url.endsWith(lexis.address.slice("did:oip:".length))) {
        throw new TypeError("fetch failed");
      }
    };
    expect(await amina.countsFor(intent, lexis.address)).toBe(false);
    world.before = undefined;
    expect(await amina.countsFor(intent, lexis.address)).toBe(true);
  });

  it(`${clause("L1 11.5")} a mind with no home signs its revocation, and gives it out itself`, async () => {
    const made = await freshKeystore(world, [A]);
    const homeless = await Mind.create(made.options, { kind: "human" });
    const { agent } = await cast();
    const grant = await homeless.delegate({
      delegate: agent.address,
      command: "/oip/sign/Intent",
      expires: FAR,
    });
    const before = world.asked.length;
    const revocation = await homeless.revoke(grant);
    expect(revocation.revokes).toBe(ref(homeless, grant));
    expect(world.asked.slice(before).filter((asked) => !asked.startsWith("GET "))).toStrictEqual(
      [],
    );
    expect(homeless.records().map((record) => record.type)).toStrictEqual([
      "Delegation",
      "Revocation",
    ]);
  });

  it(`${clause("L1 12.5", "core 8.3")} what a packet carries that the client may not rely on is not held`, async () => {
    const { amina, lexis } = await cast();
    // A record that depends on an extension this client does not implement, and one it can read.
    const beyond = await amina.sign({
      oip: "1",
      type: "Intent",
      author: amina.address,
      created: T(1010),
      want: "Something new.",
      ext: { "ext.example": { rule: "new" } },
      critical: ["ext.example"],
    });
    const plain = await amina.sign({
      oip: "1",
      type: "Intent",
      author: amina.address,
      created: T(1010),
      want: "Something old.",
    });
    await amina.send({
      to: [lexis.address],
      verb: "inform",
      content: {
        parts: [carried(beyond), carried(plain), { mediaType: "text/plain", body: "Two Intents." }],
      },
    });
    expect((await lexis.receive()).received).toHaveLength(1);
    expect(lexis.records().map((record) => contentId(record))).toStrictEqual([contentId(plain)]);
  });

  it("a failure that is nobody's answer reaches the caller as it is", async () => {
    const { amina, lexis, agent } = await cast();
    const intent = await lexis.intent({ want: "Readers." });
    const spare = await mindOf("agent");
    spare.mind.close();
    // Randomness that fails, when the next delegation of a chain is made.
    const dry = await Mind.open({
      ...spare.options,
      randomness: {
        bytes: () => {
          throw new RangeError("no entropy");
        },
      },
    });
    const own = await amina.delegate({
      delegate: dry.address,
      command: "/oip/sign/Intent",
      expires: FAR,
    });
    await expect(
      dry.subDelegate([own], {
        delegate: agent.address,
        command: "/oip/sign/Intent",
        expires: T(100_000),
      }),
    ).rejects.toThrow(RangeError);
    dry.close();
    // What stands in for `fetch` is broken for one mind's log, when a record it signed is judged.
    const broken: typeof world.fetch = (request) =>
      request.url.endsWith(lexis.address.slice("did:oip:".length))
        ? Promise.resolve({
            status: 200,
            body: null,
            headers: {
              get: () => {
                throw new RangeError("not a response");
              },
            },
          } as unknown as Response)
        : world.fetch(request);
    const judging = await Mind.open({ ...spare.options, fetch: broken });
    await expect(judging.countsFor(intent, lexis.address)).rejects.toThrow(RangeError);
  });
});
