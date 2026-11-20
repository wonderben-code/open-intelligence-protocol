// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The nine tools, called as a host calls them but without MCP, against a
 * real resolver, host and indexer on ports of this machine. Two minds deal
 * with one another from first sight to a Receipt.
 */

import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";

import type { JsonObject } from "@oip/core";
import { UsageError } from "@oip/local";
import { clause } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { NOTICE, TOOLS, type Work } from "../src/index.ts";
import { answering, asked, ASKING, call, Place, SILENT, toolOf } from "./harness.ts";

let place: Place;
let ada: string;
let bob: string;
let adas: Work;
let bobs: Work;

beforeAll(async () => {
  place = await new Place().start();
  ada = await place.make("ada", undefined, "person");
  bob = await place.make("bob", {
    name: "Bob",
    summary: "Translates leases between Swahili and English.",
    capabilities: [
      { id: "translate", summary: "Translates a lease", tags: ["domain:legal", "lang:sw"] },
    ],
  });
  adas = place.work("ada");
  bobs = place.work("bob");
});
afterAll(async () => {
  await place.close();
});

/** The members of a result, read as what a test expects them to be. */
const list = (value: unknown): JsonObject[] => value as JsonObject[];
const under = (value: unknown): JsonObject => (value as { untrusted: JsonObject }).untrusted;
const id = (value: unknown): string => {
  if (typeof value !== "string") throw new Error("a result names a record by its ID");
  return value;
};

describe("the tools of Layer 0, 2.2", () => {
  it(`${clause("L0 2.2")} are the nine it names, each described for a model`, () => {
    expect(TOOLS.map(({ name }) => name)).toEqual([
      "oip_whoami",
      "oip_find",
      "oip_send",
      "oip_inbox",
      "oip_publish_intent",
      "oip_make_offer",
      "oip_commit",
      "oip_receipt",
      "oip_status",
    ]);
    for (const tool of TOOLS) {
      expect(tool.description.length).toBeGreaterThan(200);
      expect(tool.input).toMatchObject({ type: "object", additionalProperties: false });
    }
    // No tool signs a Delegation: the use of the mind cannot be handed on.
    expect(TOOLS.some(({ name }) => name.includes("deleg"))).toBe(false);
  });
});

describe("oip_whoami", () => {
  it(`${clause("L0 2.2")} returns the mind's address, kind and current profile, and opens no key`, async () => {
    // No passphrase: it reads what anyone may read.
    const reading = place.work("ada", {}, { env: {} });
    expect(await call(reading, "oip_whoami")).toEqual({
      address: ada,
      kind: "person",
      profile: null,
      location: "active",
      homes: ["https://host.oip.localhost"],
      resolvers: ["https://resolver.oip.localhost"],
      indexers: ["https://indexer.oip.localhost"],
      signing: "A Commitment is signed only after the user confirms it.",
      warnings: ["No profile is published, so others cannot find this mind by what it does."],
    });
    const said = await call(bobs, "oip_whoami");
    expect(said).toMatchObject({
      address: bob,
      kind: "agent",
      profile: { type: "Participant", name: "Bob", author: bob },
    });
    expect(said["profile"]).not.toHaveProperty("proof");
    expect(said).not.toHaveProperty("warnings");
  });

  it("says where a policy lets a Commitment be signed unasked", async () => {
    const said = await call(place.work("ada", { commit: [["==", ".promise", "x"]] }), "oip_whoami");
    expect(said["signing"]).toMatch(/unasked where the user's policy permits/u);
  });

  it("takes no argument, and says so", async () => {
    await expect(call(adas, "oip_whoami", { verbose: true })).rejects.toThrow(
      'this tool has no argument named "verbose"',
    );
  });

  it("says what is wrong where the directory holds no mind", async () => {
    await expect(call(place.work("nobody"), "oip_whoami")).rejects.toThrow(UsageError);
  });
});

describe("oip_find", () => {
  it(`${clause("L0 2.2")} asks the mind's indexers and returns what was verified, with what it says marked as another's`, async () => {
    const said = await call(adas, "oip_find", {
      want: "translate a lease",
      tags: ["domain:legal"],
    });
    expect(said["notice"]).toBe(NOTICE);
    expect(said).toMatchObject({ indexersAsked: 1, indexersThatAnswered: 1 });
    const [found] = list(said["found"]);
    expect(found).toMatchObject({ mind: bob, type: "Participant", current: true });
    expect(under(found)).toMatchObject({
      name: "Bob",
      summary: "Translates leases between Swahili and English.",
      capability: { id: "translate", summary: "Translates a lease" },
      capabilities: 1,
    });
    // What Bob says of himself is nowhere but under `untrusted`.
    const { untrusted: _, ...facts } = found as { untrusted: unknown };
    expect(JSON.stringify(facts)).not.toContain("Translates");
  });

  it("keeps what it found, for the tools that follow", async () => {
    const said = await call(adas, "oip_find", { want: "translate" });
    const [found] = list(said["found"]);
    const kept = readdirSync(join(place.where("ada").dir, "records"));
    expect(kept.some((name) => name.startsWith(id(found?.["record"])))).toBe(true);
  });

  it("refuses a query that asks for nothing, and one for what cannot be found", async () => {
    await expect(call(adas, "oip_find", {})).rejects.toThrow("a query says what is wanted");
    await expect(call(adas, "oip_find", { want: "x", kinds: ["receipt"] })).rejects.toThrow(
      "participant, offer or intent",
    );
    await expect(call(adas, "oip_find", { want: "x", limit: 101 })).rejects.toThrow(
      "a whole number from 1 to 100",
    );
  });
});

describe("a deal, from an Offer to a Receipt", () => {
  let offer: string;
  let commitment: string;

  it(`${clause("L0 2.2")} oip_make_offer creates, signs and publishes an Offer`, async () => {
    const said = await call(bobs, "oip_make_offer", {
      provides: "An English translation of a Swahili lease",
      price: { amount: "120", currency: "USD" },
      deliveryBy: "2031-01-31T12:00:00Z",
      publish: true,
    });
    expect(said).toMatchObject({
      status: "open",
      says: { type: "Offer", author: bob, provides: "An English translation of a Swahili lease" },
      published: true,
    });
    expect(said["says"]).not.toHaveProperty("proof");
    offer = id(said["offer"]);
    expect(offer).toMatch(/^bciq[a-z2-7]{52}$/u);
  });

  it("oip_make_offer goes somewhere, or is not made", async () => {
    await expect(call(bobs, "oip_make_offer", { provides: "Nothing much" })).rejects.toThrow(
      "an Offer goes somewhere",
    );
    await expect(
      call(bobs, "oip_make_offer", {
        provides: "x",
        publish: true,
        price: { amount: 120, currency: "USD" },
      }),
    ).rejects.toThrow("an amount written as text");
  });

  it("oip_find finds the Offer, and what it says is its author's word", async () => {
    const said = await call(adas, "oip_find", { want: "translation of a lease", kinds: ["offer"] });
    const found = list(said["found"]).find((one) => one["record"] === offer);
    expect(found).toMatchObject({ mind: bob, type: "Offer" });
    expect(under(found)).toMatchObject({
      provides: "An English translation of a Swahili lease",
      terms: { price: { amount: "120", currency: "USD" } },
    });
  });

  it(`${clause("L0 2.2")} oip_commit signs nothing where the person cannot be asked`, async () => {
    await expect(call(adas, "oip_commit", { offer }, SILENT)).rejects.toThrow(/^NOT SIGNED\./u);
    const opened = await place.mind("ada");
    try {
      expect(opened.mind.records().some((record) => record.type === "Commitment")).toBe(false);
    } finally {
      opened.mind.close();
    }
  });

  it(`${clause("L0 2.2")} oip_commit asks the person, in the server's own words, before it signs`, async () => {
    const question = await asked(adas, "oip_commit", { offer });
    expect(question.digest).toMatch(/^bciq/u);
    expect(question.text).toContain("WRITE AND SIGN a Commitment in your name");
    expect(question.text).toContain("An English translation of a Swahili lease");
    expect(question.text).toContain("Price: 120 USD");
    expect(question.text).toContain(`paid by: ${ada} (YOU)`);
    expect(question.text).toContain(`paid to: ${bob}`);
    // The same call asks the same question: an answer to it is an answer to this.
    expect((await asked(adas, "oip_commit", { offer })).digest).toBe(question.digest);
    // Another call asks another.
    const other = await asked(adas, "oip_commit", {
      offer,
      price: { amount: "1200", currency: "USD" },
    });
    expect(other.digest).not.toBe(question.digest);
    expect(other.text).toContain("Price: 1200 USD");
  });

  it("oip_commit signs nothing where the person says no, or said yes to something else", async () => {
    const question = await asked(adas, "oip_commit", { offer });
    expect(
      await call(adas, "oip_commit", { offer }, answering(question.digest, "no")),
    ).toMatchObject({
      signed: false,
    });
    // A yes to these terms is no yes to others: the person is asked again.
    const dearer = { offer, price: { amount: "1200", currency: "USD" } };
    const said = await toolOf("oip_commit").run(adas, dearer, answering(question.digest, "yes"));
    expect(said).toHaveProperty("ask");
  });

  it(`${clause("L0 2.2")} oip_commit creates a Commitment once the person has said yes to it`, async () => {
    const question = await asked(adas, "oip_commit", { offer });
    const said = await call(
      adas,
      "oip_commit",
      { offer, sendTo: [bob] },
      answering(question.digest, "yes"),
    );
    expect(said).toMatchObject({
      signed: true,
      confirmedBy: "the user",
      status: "proposed",
      parties: [
        { mind: bob, role: "debtor", bound: false },
        { mind: ada, role: "creditor", bound: true },
      ],
      says: {
        type: "Commitment",
        author: ada,
        promise: "An English translation of a Swahili lease",
        terms: {
          deadline: "2031-01-31T12:00:00Z",
          price: { amount: "120", currency: "USD", payer: ada, payee: bob },
        },
      },
      deliveries: [{ to: bob, delivered: true, sealed: true }],
    });
    commitment = id(said["commitment"]);
  });

  it(`${clause("L0 2.2")} oip_inbox lists received packets, verified, with their senders' addresses and their content as another's`, async () => {
    const said = await call(bobs, "oip_inbox");
    expect(said["notice"]).toBe(NOTICE);
    expect(said).toMatchObject({ mind: bob, new: 1, kept: 1 });
    const [packet] = list(said["packets"]);
    expect(packet).toMatchObject({ from: ada, sealed: true });
    expect(under(packet)).toMatchObject({
      verb: "propose",
      content: [{ record: commitment, type: "Commitment", says: { author: ada } }],
    });
    // A mailbox gives a packet once: it is kept, and shown again only when asked for.
    expect(await call(bobs, "oip_inbox")).toMatchObject({ new: 0, kept: 1, packets: [] });
    expect(list((await call(bobs, "oip_inbox", { all: true }))["packets"])).toHaveLength(1);
  });

  it(`${clause("L0 2.2")} oip_status computes where a record stands, and whom it binds`, async () => {
    expect(await call(bobs, "oip_status", { record: commitment })).toEqual({
      record: commitment,
      type: "Commitment",
      status: "proposed",
      parties: [
        { mind: bob, role: "debtor", bound: false },
        { mind: ada, role: "creditor", bound: true },
      ],
      policyPermitsSigningUnasked: false,
    });
    expect(await call(adas, "oip_status", { record: offer })).toMatchObject({
      type: "Offer",
      author: bob,
      signedByAuthor: true,
    });
  });

  it(`${clause("L0 2.2")} oip_commit co-signs a Commitment another wrote, once the person has said yes to that one`, async () => {
    await expect(call(bobs, "oip_commit", { commitment }, SILENT)).rejects.toThrow(
      /^NOT SIGNED\./u,
    );
    const question = await asked(bobs, "oip_commit", { commitment });
    expect(question.text).toContain("SIGN a Commitment that another party wrote");
    expect(question.text).toContain("In it you are: debtor.");
    const said = await call(
      bobs,
      "oip_commit",
      { commitment, sendTo: [ada] },
      answering(question.digest, "yes"),
    );
    expect(said).toMatchObject({
      signed: true,
      commitment,
      status: "accepted",
      parties: [
        { mind: bob, role: "debtor", bound: true },
        { mind: ada, role: "creditor", bound: true },
      ],
    });
    // Signed once: asked to again, it says so and asks nobody.
    expect(await call(bobs, "oip_commit", { commitment }, SILENT)).toMatchObject({
      signed: true,
      already: "the mind had signed it before this call",
    });
  });

  it("oip_commit takes a Commitment as it is, or writes one: not both", async () => {
    await expect(
      call(bobs, "oip_commit", { commitment, promise: "Something else" }, ASKING),
    ).rejects.toThrow("is signed as it is");
    await expect(call(adas, "oip_commit", { commitment: offer }, ASKING)).rejects.toThrow(
      "is no Commitment",
    );
    await expect(call(adas, "oip_commit", { promise: "Half a deal" }, ASKING)).rejects.toThrow(
      "names who owes, who is owed, and what",
    );
  });

  it(`${clause("L0 2.2")} oip_receipt creates and publishes a Receipt`, async () => {
    expect(await call(adas, "oip_inbox")).toMatchObject({ new: 1 });
    expect(await call(adas, "oip_status", { record: commitment })).toMatchObject({
      status: "accepted",
    });
    const said = await call(adas, "oip_receipt", {
      about: commitment,
      outcome: "fulfilled",
      statement: "The translation arrived, and reads well.",
      score: "0.9",
      sendTo: [bob],
    });
    expect(said).toMatchObject({
      about: commitment,
      aboutIsNow: "fulfilled",
      says: { type: "Receipt", author: ada, outcome: "fulfilled", rating: { score: "0.9" } },
      published: true,
      deliveries: [{ to: bob, delivered: true }],
    });
    await expect(
      call(adas, "oip_receipt", { about: commitment, outcome: "splendid" }),
    ).rejects.toThrow("`outcome` is one of");
    await expect(
      call(adas, "oip_receipt", { about: commitment, outcome: "fulfilled", score: "9" }),
    ).rejects.toThrow("a rating from 0 to 1");
  });
});

describe("oip_publish_intent", () => {
  it(`${clause("L0 2.2")} creates, signs and publishes an Intent, which others find and answer`, async () => {
    const said = await call(adas, "oip_publish_intent", {
      want: "A German lease checked by a lawyer",
      deadline: "2031-03-01T00:00:00Z",
      budget: { max: "300", currency: "EUR" },
      requires: ["Admitted in Germany"],
    });
    expect(said).toMatchObject({
      status: "open",
      says: {
        type: "Intent",
        author: ada,
        want: "A German lease checked by a lawyer",
        constraints: { budget: { max: "300", currency: "EUR" }, requires: ["Admitted in Germany"] },
      },
      published: true,
    });
    const intent = id(said["intent"]);
    const found = await call(bobs, "oip_find", {
      want: "lease checked by a lawyer",
      kinds: ["intent"],
    });
    expect(list(found["found"]).map((one) => one["record"])).toContain(intent);
    const answer = await call(bobs, "oip_make_offer", {
      provides: "A review of a German lease",
      answers: intent,
      sendTo: [ada],
    });
    expect(answer).toMatchObject({
      says: { answers: `${ada}/${intent}` },
      deliveries: [{ to: ada, delivered: true }],
    });
    expect(answer).not.toHaveProperty("published");
  });

  it("says what is wanted, with a budget that has a most", async () => {
    await expect(call(adas, "oip_publish_intent", {})).rejects.toThrow("says what is wanted");
    await expect(
      call(adas, "oip_publish_intent", { want: "x", budget: { currency: "EUR" } }),
    ).rejects.toThrow("the most it may cost");
    await expect(
      call(adas, "oip_publish_intent", { want: "x", deadline: "next Friday" }),
    ).rejects.toThrow("a time in UTC");
  });
});

describe("oip_send", () => {
  it(`${clause("L0 2.2")} sends a packet to addresses`, async () => {
    const said = await call(adas, "oip_send", {
      to: [bob],
      text: "Could you start on Monday?",
      verb: "request",
      goal: "A start date",
    });
    expect(said).toMatchObject({
      from: ada,
      verb: "request",
      deliveries: [{ to: bob, delivered: true, sealed: true }],
    });
    const inbox = await call(bobs, "oip_inbox");
    const packet = list(inbox["packets"]).find((one) => one["packet"] === said["packet"]);
    expect(packet).toMatchObject({ from: ada });
    expect(under(packet)).toMatchObject({
      verb: "request",
      goal: "A start date",
      content: [{ mediaType: "text/plain", text: "Could you start on Monday?" }],
    });
  });

  it(`${clause("L0 2.2")} sends a packet to a capability query, through the mind's indexers`, async () => {
    const said = await call(adas, "oip_send", {
      query: { want: "translate a lease", tags: ["domain:legal"] },
      text: "Is anyone free this week?",
    });
    expect(said).toMatchObject({
      deliveries: [{ to: "https://indexer.oip.localhost", delivered: true, sealed: false }],
    });
  });

  it("carries records the mind holds, by their content IDs, and never a file", async () => {
    await expect(call(adas, "oip_send", { to: [bob], records: ["/etc/passwd"] })).rejects.toThrow(
      "names records by their content IDs",
    );
    await expect(
      call(adas, "oip_send", { to: [bob], records: [`bciq${"a".repeat(52)}`] }),
    ).rejects.toThrow("the mind holds no record");
  });

  it("is for minds or for a query, and carries something", async () => {
    await expect(call(adas, "oip_send", { text: "Hello" })).rejects.toThrow("give one of the two");
    await expect(
      call(adas, "oip_send", { to: [bob], query: { want: "x" }, text: "Hello" }),
    ).rejects.toThrow("give one of the two");
    await expect(call(adas, "oip_send", { to: [bob] })).rejects.toThrow("carries something");
    await expect(call(adas, "oip_send", { to: ["bob"], text: "Hello" })).rejects.toThrow(
      "names a mind by its address",
    );
    await expect(
      call(adas, "oip_send", { to: [bob], text: "Hello", verb: "command" }),
    ).rejects.toThrow("`verb` is one of");
  });
});

describe("a policy of the person's", () => {
  const cheap = [
    ["==", ".terms.price.currency", "USD"],
    ["<=", ".terms.price.amount", "50"],
  ];

  it(`${clause("L0 2.2")} lets a Commitment it permits be signed unasked, and no other`, async () => {
    const permitted = place.work("ada", { commit: cheap });
    const small = {
      debtors: [bob],
      creditors: ["me"],
      promise: "A page proofread",
      price: { amount: "20", currency: "USD" },
    };
    expect(await call(permitted, "oip_commit", small, SILENT)).toMatchObject({
      signed: true,
      confirmedBy: "the user's policy",
      says: { terms: { price: { amount: "20", payer: ada, payee: bob } } },
    });
    // Over the amount, in another currency, or with no price at all: the person is asked.
    for (const price of [
      { amount: "50.01", currency: "USD" },
      { amount: "20", currency: "EUR" },
    ]) {
      await expect(call(permitted, "oip_commit", { ...small, price }, SILENT)).rejects.toThrow(
        /^NOT SIGNED\./u,
      );
    }
    const { price: _, ...free } = small;
    await expect(call(permitted, "oip_commit", free, SILENT)).rejects.toThrow(/^NOT SIGNED\./u);
    // Without the policy the same Commitment is asked about.
    await expect(call(adas, "oip_commit", small, SILENT)).rejects.toThrow(/^NOT SIGNED\./u);
  });
});

describe("what the tools leave behind", () => {
  it("is in the mind's directory, where the command finds it", () => {
    const dir = place.where("ada").dir;
    expect(existsSync(join(dir, "records"))).toBe(true);
    expect(readdirSync(join(dir, "inbox")).length).toBeGreaterThan(0);
  });
});
