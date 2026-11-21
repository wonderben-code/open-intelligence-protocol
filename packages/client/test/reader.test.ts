// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A reader that holds no key: what it makes of records it reads from feeds,
 * long after they were made, and in whatever order it comes by them.
 */

import { contentId, formatRecordRef } from "@oip/core";
import type { Delegation } from "@oip/schema";
import { clause } from "@oip/testkit";
import { at, T } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { Lookup, Mind, Reader } from "../src/index.ts";
import { freshKeystore, refusal } from "./helpers.ts";
import { World } from "./world.ts";

const A = "https://resolver-a.example";
const HOME = "https://host.example";
const FAR = T(5_000_000);

let world: World;
beforeEach(() => {
  world = new World(1000);
  world.resolver(A);
  world.host(HOME);
});
afterEach(() => {
  world.close();
});

/** A mind of a kind, at the home. */
async function mindOf(kind: string): Promise<Mind> {
  const made = await freshKeystore(world, [A]);
  const mind = await Mind.create(made.options, { kind, homes: [HOME] });
  await mind.publishLocation();
  return mind;
}

/** Amina, Lexis Ltd and its agent. */
async function cast() {
  const amina = await mindOf("human");
  const lexis = await mindOf("institution");
  const agent = await mindOf("agent");
  world.clock.at = at(1010);
  return { amina, lexis, agent };
}

/** A stranger: a way to ask for logs and for what a mind published, and nothing else. */
function stranger(): { lookup: Lookup; reader: Reader } {
  const lookup = new Lookup({ resolvers: [A], fetch: world.fetch, clock: world.clock });
  return { lookup, reader: new Reader({ lookup }) };
}

/** Reads a mind's feed as a stranger does, and holds every record it lists. */
async function read({ lookup, reader }: ReturnType<typeof stranger>, mind: Mind): Promise<void> {
  const { feed } = await lookup.feed(mind.address);
  for (const { entry } of feed.entries) {
    reader.hold((await lookup.record(mind.address, entry.object)).record);
    // Each record comes a moment after the one before, as on any network.
    world.clock.at += 5_000_000n;
  }
}

/** The address of a mind that nobody is: well formed, and held by no resolver. */
const nobody = (index: number): string =>
  `did:oip:bciqa${"a".repeat(48)}${String.fromCodePoint(97 + (index % 26), 97 + Math.floor(index / 26))}a`;

const mandateOf = (lexis: Mind, agent: Mind): Promise<Delegation> =>
  lexis.delegate({ delegate: agent.address, command: "/oip/sign/Commitment", expires: FAR });

const deal = (lexis: Mind, amina: Mind, more: object = {}) => ({
  parties: [
    { mind: lexis.address, role: "debtor", required: true },
    { mind: amina.address, role: "creditor", required: true },
  ],
  promise: "Lexis Ltd will deliver an English translation of the lease; Amina will pay 120 USD.",
  terms: {
    deadline: T(200_000),
    price: { amount: "120", currency: "USD", payer: amina.address, payee: lexis.address },
  },
  ...more,
});

describe("a reader of history", () => {
  it(`${clause("L1 11.4", "L1 11.5", "core 9.3")} counts no signature made under a delegation whose Revocation it holds, in whichever order it read the two`, async () => {
    const { amina, lexis, agent } = await cast();
    const mandate = await mandateOf(lexis, agent);
    // The firm takes the delegation back, and says so on its feed.
    world.clock.at = at(2000);
    await lexis.revoke(mandate);
    // Later the agent signs for the firm all the same, and publishes that.
    world.clock.at = at(3000);
    const late = await agent.commitment(deal(lexis, amina), { chain: [mandate] });
    await agent.publishRecord(late);
    world.clock.at = at(4000);

    // The agent's feed first, and then the firm's.
    const first = stranger();
    await read(first, agent);
    // By what it has read so far, the firm is bound: it knows of no Revocation.
    expect(await first.reader.countsFor(late, lexis.address)).toBe(true);
    await read(first, lexis);
    expect(first.reader.held().map((record) => record.type)).toStrictEqual([
      "Commitment",
      "Revocation",
    ]);
    expect(await first.reader.countsFor(late, lexis.address)).toBe(false);
    // The agent's own signature is its own still.
    expect(await first.reader.countsFor(late, agent.address)).toBe(true);

    // The firm's feed first, and then the agent's: the same.
    const second = stranger();
    await read(second, lexis);
    await read(second, agent);
    expect(second.reader.held().map((record) => record.type)).toStrictEqual([
      "Revocation",
      "Commitment",
    ]);
    expect(await second.reader.countsFor(late, lexis.address)).toBe(false);

    // A reader that was given the Commitment alone looks at the feed of the delegation's
    // author before it says who is bound (11.5).
    const third = stranger();
    third.reader.hold(late);
    expect(await third.reader.delegationsStand(late)).toBe(true);
    expect(await third.reader.holdRevocations(late)).toBe(1);
    expect(await third.reader.delegationsStand(late)).toBe(false);
    expect(await third.reader.countsFor(late, lexis.address)).toBe(false);
  });

  it(`${clause("L1 11.4", "L1 11.6")} counts a signature whose proof names its delegation by the delegation it holds, whichever of the two it took in first`, async () => {
    const { amina, lexis, agent } = await cast();
    const mandate = await mandateOf(lexis, agent);
    world.clock.at = at(1100);
    const named = await agent.commitment(deal(lexis, amina), {
      chain: [mandate],
      as: "references",
    });
    world.clock.at = at(2000);
    const { reader } = stranger();
    reader.hold(named);
    expect(await reader.countsFor(named, lexis.address)).toBe(false);
    // The delegation comes later, as a second request's answer does.
    world.clock.at = at(2001);
    reader.hold(mandate);
    expect(await reader.countsFor(named, lexis.address)).toBe(true);
  });

  it(`${clause("core 9.7")} judges a signature that rests on a delegation by now: one that has run out binds nobody for a reader that came later`, async () => {
    const { amina, lexis, agent } = await cast();
    const brief = await lexis.delegate({
      delegate: agent.address,
      command: "/oip/sign/Commitment",
      expires: T(3000),
    });
    world.clock.at = at(1100);
    const made = await agent.commitment(deal(lexis, amina), { chain: [brief] });
    // A reader that looks while the delegation runs finds the firm bound.
    world.clock.at = at(2000);
    const early = stranger();
    early.reader.hold(made);
    expect(await early.reader.countsFor(made, lexis.address)).toBe(true);
    // The same reader, asked again once it has run out, has no evidence of its own that the
    // signature was made in time: what it holds, it holds as of now.
    world.clock.at = at(3400);
    expect(await early.reader.countsFor(made, lexis.address)).toBe(false);
    // A mind that took the record in while the delegation ran noted when, and counts it still.
    world.clock.at = at(2000);
  });

  it(`${clause("core 9.4")} is no later than a mind that took the same records in as they were made: the mind's own first sight is evidence, and the reader's look is not`, async () => {
    const { amina, lexis, agent } = await cast();
    const mandate = await mandateOf(lexis, agent);
    world.clock.at = at(1100);
    const made = await agent.commitment(deal(lexis, amina), { chain: [mandate] });
    // Amina is shown the Commitment while the delegation stands.
    amina.hold(made);
    expect(await amina.countsFor(made, lexis.address)).toBe(true);
    world.clock.at = at(2000);
    const revocation = await lexis.revoke(mandate);
    world.clock.at = at(3000);
    amina.hold(revocation);
    // What was signed before the delegation was taken back stands, for her (11.5).
    expect(await amina.countsFor(made, lexis.address)).toBe(true);
    // A reader that comes now cannot tell which was first, and counts neither way but the safe one.
    const { reader } = stranger();
    reader.hold(made);
    reader.hold(revocation);
    expect(await reader.countsFor(made, lexis.address)).toBe(false);
  });
});

describe("what a reader holds", () => {
  it(`${clause("L2 2")} is each record with the proofs of every copy it saw that verify: a lesser copy, or one with spoiled signatures, takes none away`, async () => {
    const { amina, lexis, agent } = await cast();
    const mandate = await mandateOf(lexis, agent);
    world.clock.at = at(1100);
    const proposed = await agent.commitment(deal(lexis, amina), { chain: [mandate] });
    const accepted = await amina.cosign(proposed);
    expect([proposed.proof.length, accepted.proof.length]).toStrictEqual([1, 2]);
    const id = contentId(accepted);
    world.clock.at = at(1200);

    const { reader } = stranger();
    reader.hold(accepted);
    const proofsHeld = (): number => (reader.held()[0] as { proof: unknown[] }).proof.length;
    expect(proofsHeld()).toBe(2);
    // The copy with the agent's proof alone comes after.
    reader.hold(proposed);
    expect(reader.held()).toHaveLength(1);
    expect(proofsHeld()).toBe(2);
    // And a copy whose signatures verify nothing.
    const spoiled = {
      ...accepted,
      proof: accepted.proof.map((proof) => ({ ...proof, proofValue: "A".repeat(86) })),
    };
    expect(contentId(spoiled)).toBe(id);
    reader.hold(spoiled);
    expect(proofsHeld()).toBe(2);
    expect(reader.held()[0]).toStrictEqual(accepted);
    expect(await reader.status(reader.held()[0])).toBe("accepted");
    // Every proof kept has its time, and the delegation the agent's proof carries has too.
    expect(Object.keys(reader.sightings(id))).toHaveLength(3);

    // A mind's own records are kept the same way, and what it keeps of them can be held again.
    lexis.hold(accepted);
    lexis.hold(proposed);
    const [kept] = lexis.records().filter((record) => record.type === "Commitment");
    expect((kept as { proof: unknown[] }).proof).toHaveLength(2);
    const again = stranger();
    again.reader.hold(kept, lexis.sightings(id));
    expect(await again.reader.status(kept)).toBe("accepted");

    // A record none of whose proofs verifies is held as it was given, and is nobody's word.
    const nobody = stranger();
    nobody.reader.hold(spoiled);
    expect(nobody.reader.held()).toStrictEqual([spoiled]);
    expect(await nobody.reader.countsFor(spoiled, amina.address)).toBe(false);
    expect(await nobody.reader.status(spoiled)).toBe("proposed");
  });

  it(`${clause("L2 7.3", "core 9.4")} asks first for the logs that decide: an author cannot have its record count for nobody by naming many minds before the parties`, async () => {
    const { amina, lexis, agent } = await cast();
    const mandate = await mandateOf(lexis, agent);
    world.clock.at = at(1100);
    // Sixty-four references to minds that nobody is, written before the parties.
    const links = Array.from({ length: 64 }, (_, index) => ({
      rel: "see",
      ref: formatRecordRef(nobody(index), contentId({ n: index })),
    }));
    const crowded = await agent.commitment({ links, ...deal(lexis, amina) }, { chain: [mandate] });
    expect(Object.keys(crowded).indexOf("links")).toBeLessThan(
      Object.keys(crowded).indexOf("parties"),
    );
    const accepted = await amina.cosign(crowded);
    world.clock.at = at(1200);
    const { reader } = stranger();
    expect(await reader.countsFor(accepted, lexis.address)).toBe(true);
    expect(await reader.countsFor(accepted, amina.address)).toBe(true);
    expect(await reader.status(accepted)).toBe("accepted");
    // The parties' own minds say the same.
    expect(await amina.statusOf(accepted)).toBe("accepted");
  });

  it(`${clause("core 9.4")} says so where a record rests on more logs than a client asks for, and gives no verdict`, async () => {
    const { amina, lexis, agent } = await cast();
    world.clock.at = at(1100);
    // As many parties as a Commitment may have: sixty-four minds whose logs decide.
    const full = await lexis.commitment({
      ...deal(lexis, amina),
      parties: [
        { mind: lexis.address, role: "debtor", required: true },
        { mind: amina.address, role: "creditor", required: true },
        ...Array.from({ length: 62 }, (_, index) => ({ mind: nobody(index), role: "witness" })),
      ],
    });
    const { reader } = stranger();
    expect(await reader.countsFor(full, lexis.address)).toBe(true);
    // With one signature more, by a mind that is no party, there is one log too many.
    const many = await agent.cosign(full);
    expect(await refusal(() => reader.countsFor(many, lexis.address))).toBe("oip: too-large");
    expect(await refusal(() => reader.status(many))).toBe("oip: too-large");
  });

  it(`${clause("L2 8.3", "L1 11.4")} asks for the logs a Receipt rests on: one a creditor's delegate signed for her fulfils the Commitment`, async () => {
    const { amina, lexis, agent } = await cast();
    const assistant = await mindOf("agent");
    world.clock.at = at(1020);
    const mandate = await mandateOf(lexis, agent);
    const receipts = await amina.delegate({
      delegate: assistant.address,
      command: "/oip/sign/Receipt",
      expires: FAR,
    });
    world.clock.at = at(1100);
    const accepted = await amina.cosign(
      await agent.commitment(deal(lexis, amina), { chain: [mandate] }),
    );
    world.clock.at = at(1200);
    const confirmed = await assistant.receipt(
      {
        author: amina.address,
        about: formatRecordRef(agent.address, contentId(accepted)),
        outcome: "fulfilled",
      },
      { chain: [receipts] },
    );
    world.clock.at = at(1300);
    const { reader } = stranger();
    reader.hold(accepted);
    expect(await reader.status(accepted)).toBe("accepted");
    // The assistant is named nowhere but in the Receipt's proof.
    reader.hold(confirmed);
    expect(await reader.status(accepted)).toBe("fulfilled");
  });

  it("is told of what is no record, no packet and no content as of anything else: nothing is held, and nothing breaks", async () => {
    const { amina } = await cast();
    const { reader } = stranger();
    for (const nothing of [null, undefined, 7, "text", [], {}]) {
      expect(await reader.sentFor(nothing), JSON.stringify(nothing)).toBeUndefined();
      expect(() => {
        reader.holdCarried(nothing);
      }).not.toThrow();
      expect(await refusal(() => Promise.resolve(reader.hold(nothing)))).toBe(
        "oip: invalid-record",
      );
    }
    reader.holdCarried({ parts: [null, 7, { mediaType: "application/oip+json", body: null }] });
    // A record is carried as a record, and as nothing else.
    const intent = await amina.intent({ want: "A translation." });
    reader.holdCarried({ mediaType: "text/plain", body: intent });
    reader.holdCarried({ parts: [{ mediaType: "application/json", body: intent }] });
    expect(reader.held()).toStrictEqual([]);
    reader.holdCarried({ parts: [{ mediaType: "application/oip+json", body: intent }] });
    expect(reader.held()).toStrictEqual([intent]);
    expect(reader.sightings(contentId({ no: "record held" }))).toStrictEqual({});
  });

  it(`${clause("core 9.4")} reads the clock of its lookup, and no other`, async () => {
    const { amina, lexis, agent } = await cast();
    const mandate = await mandateOf(lexis, agent);
    world.clock.at = at(1100);
    const accepted = await amina.cosign(
      await agent.commitment(deal(lexis, amina), { chain: [mandate] }),
    );
    world.clock.at = at(1200);
    const { lookup, reader } = stranger();
    expect(lookup.clock).toBe(world.clock);
    reader.hold(accepted);
    expect(await reader.status(accepted)).toBe("accepted");
    // What it holds, it holds as of the lookup's clock at its latest look.
    const [seen] = Object.values(reader.sightings(contentId(accepted)));
    expect(seen).toBe(at(1200));
  });
});

describe("a mind, which takes records in as they are made", () => {
  it(`${clause("core 9.4")} believes no kept sighting that is later than now`, async () => {
    const { amina, lexis, agent } = await cast();
    const mandate = await mandateOf(lexis, agent);
    world.clock.at = at(1100);
    const made = await agent.commitment(deal(lexis, amina), { chain: [mandate] });
    const id = contentId(made);
    world.clock.at = at(1200);
    // A file of sightings that says the future: each is taken as now.
    const digests = Object.keys(agent.sightings(id));
    expect(digests.length).toBeGreaterThan(0);
    amina.hold(made, Object.fromEntries(digests.map((digest) => [digest, at(9000)])));
    expect(new Set(Object.values(amina.sightings(id)))).toStrictEqual(new Set([at(1200)]));
    // One that says the past is believed: it is the mind's own record, kept from before.
    const other = await mindOf("human");
    other.hold(made, Object.fromEntries(digests.map((digest) => [digest, at(1150)])));
    expect(new Set(Object.values(other.sightings(id)))).toStrictEqual(new Set([at(1150)]));
  });
});
