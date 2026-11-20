// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The tools where things are not as they usually are: a service out of
 * reach, a mind in an odd state, a packet that carries more than text.
 */

import { LOCAL } from "@oip/cli";
import { Mind } from "@oip/client";
import type { JsonObject } from "@oip/core";
import { Keystore } from "@oip/keystore";
import { fileStorage } from "@oip/keystore/node";
import { Home, lockOf, optionsOf } from "@oip/local";
import { clause } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { NOTICE, type Work } from "../src/index.ts";
import { answering, asked, call, Place } from "./harness.ts";

let place: Place;
let ada: string;
let bob: string;
let adas: Work;
let bobs: Work;

beforeAll(async () => {
  place = await new Place().start();
  ada = await place.make("ada", { name: "Ada" }, "person");
  bob = await place.make("bob", {
    name: "Bob",
    summary: "Proofreads.",
    languages: ["en", "sw"],
    capabilities: [{ id: "proofread", summary: "Proofreads a chapter" }],
  });
  adas = place.work("ada");
  bobs = place.work("bob");
});
afterAll(async () => {
  await place.close();
});

const list = (value: unknown): JsonObject[] => value as JsonObject[];
const under = (value: unknown): JsonObject => (value as { untrusted: JsonObject }).untrusted;
const id = (value: unknown): string => {
  if (typeof value !== "string") throw new Error("a result names a record by its ID");
  return value;
};

describe("where a service is out of reach", () => {
  it("oip_find says which indexers did not answer, and finds nothing by guessing", async () => {
    const lost = place.work("ada", {}, { fetch: place.failing(LOCAL.indexer) });
    expect(await call(lost, "oip_find", { want: "proofread" })).toStrictEqual({
      notice: NOTICE,
      found: [],
      indexersAsked: 1,
      indexersThatAnswered: 0,
      unanswered: [{ indexer: LOCAL.indexer, failure: "unreachable" }],
    });
  });

  it(`${clause("L0 2.2")} oip_find returns nothing it could not verify: what an indexer names and no host gives is refused, and said to be`, async () => {
    const offered = await call(bobs, "oip_make_offer", {
      provides: "Proofreading that an indexer knows of",
      publish: true,
    });
    // The indexer answers. The host that holds what it names does not.
    const lost = place.work("ada", {}, { fetch: place.failing(LOCAL.host) });
    const said = await call(lost, "oip_find", { want: "proofreading", kinds: ["offer"] });
    expect(said).toMatchObject({ found: [], indexersAsked: 1, indexersThatAnswered: 1 });
    expect(said["refused"]).toStrictEqual([
      { indexer: LOCAL.indexer, mind: bob, record: offered["offer"], failure: "unreachable" },
    ]);
    // With the host back it is found, and verified.
    const found = await call(adas, "oip_find", { want: "proofreading", kinds: ["offer"] });
    expect(list(found["found"]).map((one) => one["record"])).toContain(offered["offer"]);
    expect(found).not.toHaveProperty("refused");
  });

  it("a record that was signed is told of, with what did not follow its signing", async () => {
    // No host takes it: it is signed, and not published.
    const lost = place.work("bob", {}, { fetch: place.failing(LOCAL.host) });
    const unpublished = await call(lost, "oip_make_offer", {
      provides: "A chapter proofread, by an offer no host took",
      publish: true,
      sendTo: [ada],
    });
    expect(unpublished).toMatchObject({
      status: "open",
      published: false,
      publishFailure: "unreachable",
      deliveries: [{ to: ada, delivered: false, failure: "unreachable" }],
    });
    expect(id(unpublished["offer"])).toMatch(/^bciq/u);
    // The host takes it, and the indexer is not told.
    const unlisted = place.work("bob", {}, { fetch: place.failing(LOCAL.indexer) });
    expect(
      await call(unlisted, "oip_make_offer", {
        provides: "A chapter proofread, by an offer no indexer heard of",
        publish: true,
      }),
    ).toMatchObject({
      published: true,
      servicesThatDidNotTakeIt: [
        { service: "indexer", origin: LOCAL.indexer, failure: "unreachable" },
      ],
    });
  });

  it("a packet that could not go waits, and goes with the next reading of the mailboxes", async () => {
    const lost = place.work("ada", {}, { fetch: place.failing(LOCAL.host) });
    const sent = await call(lost, "oip_send", { to: [bob], text: "Are you there?" });
    expect(sent["deliveries"]).toStrictEqual([
      {
        to: bob,
        delivered: false,
        sealed: true,
        waiting: "kept, and tried again later, when oip_inbox reads",
        failure: "unreachable",
      },
    ]);
    // Read with the host out of reach, the mailbox is said not to have been read.
    const unread = await call(lost, "oip_inbox");
    expect(unread["mailboxesNotRead"]).toMatchObject([{ failure: "unreachable" }]);
    // Read with the host back, and once its turn has come, what waited goes.
    const later = place.work(
      "ada",
      {},
      { clock: { now: () => BigInt(Date.now()) * 1_000_000n + 120n * 1_000_000_000n } },
    );
    const read = await call(later, "oip_inbox");
    expect(read["sentAgain"]).toMatchObject([
      { packet: sent["packet"], deliveries: [{ to: bob, delivered: true }] },
    ]);
    expect(read).not.toHaveProperty("mailboxesNotRead");
  });
});

describe("a mind in an odd state", () => {
  it("that was never published is said to be so, by the tools that read and those that sign", async () => {
    const at = place.where("half-made");
    const home = new Home(at.dir);
    await Keystore.create({
      storage: fileStorage(home.keys),
      locks: await lockOf(at, "passphrase", true),
    });
    home.write(new Home(place.where("ada").dir).read());
    await expect(call(place.work("half-made"), "oip_whoami")).rejects.toThrow(
      "was never published",
    );
    await expect(call(place.work("half-made"), "oip_inbox")).rejects.toThrow();
  });

  it("that names no indexer has nobody to ask", async () => {
    await place.make("alone");
    const home = new Home(place.where("alone").dir);
    home.write({ ...home.read(), indexers: [] });
    await expect(call(place.work("alone"), "oip_find", { want: "anything" })).rejects.toThrow(
      "the mind names no indexer to ask",
    );
    expect(await call(place.work("alone"), "oip_whoami")).toMatchObject({ indexers: [] });
  });

  it("that has said nowhere it can be reached has no location", async () => {
    const at = place.where("nowhere");
    const home = new Home(at.dir);
    const config = new Home(place.where("ada").dir).read();
    const lock = await lockOf(at, config.lock, true);
    const keystore = await Keystore.create({ storage: fileStorage(home.keys), locks: lock });
    home.write(config);
    const mind = await Mind.create(optionsOf(at, home, config, keystore, lock), {
      kind: "agent",
      homes: [LOCAL.host],
    });
    mind.close();
    expect(await call(place.work("nowhere"), "oip_whoami")).toMatchObject({
      address: mind.address,
      location: null,
      profile: null,
    });
  });

  it("that is retired is said to be", async () => {
    await place.make("gone");
    const opened = await place.mind("gone");
    try {
      await opened.mind.retire({ control: opened.lock });
    } finally {
      opened.mind.close();
    }
    const said = await call(place.work("gone"), "oip_whoami");
    expect(said["warnings"]).toContain(
      "The mind is retired: what it signs now counts for nothing.",
    );
  });
});

describe("what a packet may carry", () => {
  it(`${clause("L0 2.2")} is given as its sender's, whatever it is: text, a record, a reference, or other data`, async () => {
    const offered = await call(bobs, "oip_make_offer", {
      provides: "A chapter proofread",
      sendTo: [ada],
    });
    const opened = await place.mind("bob");
    try {
      await opened.mind.send({
        to: [ada],
        verb: "deliver",
        goal: "The files",
        thread: id(offered["offer"]),
        replyTo: id(offered["packet"]),
        content: {
          parts: [
            { mediaType: "text/markdown", body: "# Done" },
            { mediaType: "application/json", body: { pages: 12, ok: true } },
            {
              mediaType: "application/pdf",
              ref: "https://files.example/chapter.pdf",
              digest: `sha256:${"0".repeat(64)}`,
            },
          ],
        },
      });
    } finally {
      opened.mind.close();
    }
    // Two are new, and one is asked for: the other is said to be there.
    const first = await call(adas, "oip_inbox", { limit: 1 });
    expect(first).toMatchObject({ new: 2, notShown: 1 });
    expect(list(first["packets"])).toHaveLength(1);
    const all = await call(adas, "oip_inbox", { all: true });
    const packets = list(all["packets"]);
    const delivered = packets.find((packet) => under(packet)["verb"] === "deliver");
    expect(under(delivered)).toStrictEqual({
      verb: "deliver",
      goal: "The files",
      replyTo: offered["packet"],
      thread: offered["offer"],
      content: [
        { mediaType: "text/markdown", text: "# Done" },
        { mediaType: "application/json", body: { pages: 12, ok: true } },
        {
          mediaType: "application/pdf",
          reference: "https://files.example/chapter.pdf",
          digest: `sha256:${"0".repeat(64)}`,
        },
      ],
    });
    const proposed = packets.find((packet) => under(packet)["verb"] === "propose");
    expect(under(proposed)["content"]).toMatchObject([
      { record: offered["offer"], type: "Offer", says: { provides: "A chapter proofread" } },
    ]);
    // Newest first.
    expect(packets.map((packet) => packet["receivedAt"])).toStrictEqual(
      packets
        .map((packet) => packet["receivedAt"])
        .sort()
        .reverse(),
    );
  });

  it("oip_send carries text and records together, in a thread, for as long as it says, sealed or not", async () => {
    const offered = await call(adas, "oip_make_offer", { provides: "A reply", sendTo: [bob] });
    const sent = await call(adas, "oip_send", {
      to: [bob, "me"],
      text: "Here it is again, with a word.",
      records: [id(offered["offer"])],
      verb: "propose",
      replyTo: id(offered["packet"]),
      thread: id(offered["packet"]),
      expiresIn: 60,
      unsealed: true,
    });
    expect(sent["deliveries"]).toMatchObject([
      { to: bob, delivered: true, sealed: false },
      { to: ada, delivered: true, sealed: false },
    ]);
    const inbox = await call(bobs, "oip_inbox");
    const packet = list(inbox["packets"]).find((one) => one["packet"] === sent["packet"]);
    expect(packet).toMatchObject({ from: ada, sealed: false });
    expect(under(packet)).toMatchObject({
      replyTo: offered["packet"],
      thread: offered["packet"],
      content: [
        { mediaType: "text/plain", text: "Here it is again, with a word." },
        { record: offered["offer"], type: "Offer" },
      ],
    });
    await expect(
      call(adas, "oip_send", { query: { want: "x" }, text: "Hello", expiresIn: 3601 }),
    ).rejects.toThrow("a whole number from 1 to 3600");
    expect(
      await call(adas, "oip_send", {
        query: { want: "proofread", maxFanout: 2 },
        text: "Hello to two of you",
      }),
    ).toMatchObject({ deliveries: [{ delivered: true }] });
  });
});

describe("oip_status", () => {
  it("says of a record that has no status who wrote it, and whether it is theirs", async () => {
    const found = await call(adas, "oip_find", { want: "proofread" });
    const [profile] = list(found["found"]);
    expect(under(profile)).toMatchObject({
      name: "Bob",
      summary: "Proofreads.",
      languages: ["en", "sw"],
      ranking: [{ indexer: LOCAL.indexer }],
    });
    expect(await call(adas, "oip_status", { record: id(profile?.["record"]) })).toStrictEqual({
      record: profile?.["record"],
      type: "Participant",
      author: bob,
      signedByAuthor: true,
    });
    await expect(call(adas, "oip_status", {})).rejects.toThrow("`record` names the record");
  });

  it("says whether the person's policy would let a Commitment be signed unasked", async () => {
    const carol = await place.make("carol");
    const terms = {
      debtors: [bob],
      creditors: ["me"],
      witnesses: [carol],
      promise: "A page",
      price: { amount: "3", currency: "USD", payer: "me", payee: bob },
      closesIntent: false,
    };
    const question = await asked(adas, "oip_commit", terms);
    const signed = await call(adas, "oip_commit", terms, answering(question.digest, "yes"));
    const permitted = place.work("ada", { commit: [["<=", ".terms.price.amount", "5"]] });
    expect(await call(permitted, "oip_status", { record: id(signed["commitment"]) })).toMatchObject(
      { status: "proposed", policyPermitsSigningUnasked: true },
    );
    expect(await call(adas, "oip_status", { record: id(signed["commitment"]) })).toMatchObject({
      policyPermitsSigningUnasked: false,
    });
  });
});
