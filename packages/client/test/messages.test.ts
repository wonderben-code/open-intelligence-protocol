// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, MEDIA_TYPE, mindId, signerFromPrivateKey } from "@oip/core";
import { judgeRecord, ownSignedTime } from "@oip/identity";
import { memoryStorage } from "@oip/keystore";
import { ackEvidence, verifyAck } from "@oip/net";
import { clause } from "@oip/testkit";
import { at, KeyMind, T } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { Lookup, type Message, Mind, type MindOptions } from "../src/index.ts";
import { freshKeystore, refusal } from "./helpers.ts";
import { World } from "./world.ts";

const A = "https://resolver-a.example";
const ONE = "https://host-one.example";
const TWO = "https://host-two.example";

let world: World;
beforeEach(() => {
  world = new World(100);
  world.resolver(A);
  world.host(ONE);
  world.host(TWO);
});
afterEach(() => {
  world.close();
});

/** A mind at a home, which has said where it takes packets. */
async function at_(home: string | undefined, more: Partial<MindOptions> = {}) {
  const made = await freshKeystore(world, [A], more);
  const mind = await Mind.create(made.options, {
    kind: "agent",
    ...(home === undefined ? {} : { homes: [home] }),
  });
  if (home !== undefined) await mind.publishLocation();
  return { ...made, mind };
}

const hello = (to: Message["to"], more: Partial<Message> = {}): Message => ({
  to,
  verb: "inform",
  content: { mediaType: "text/plain", body: "Hello." },
  ...more,
});

const inboxOf = (home: string, mind: Mind): string =>
  `${home}/oip/v1/minds/${mindId(mind.address) ?? ""}/inbox`;
const mailboxOf = (home: string, mind: Mind): string =>
  `${home}/oip/v1/minds/${mindId(mind.address) ?? ""}/mailbox`;

/** Posts a record to a URL, as anyone may. */
const post = async (url: string, record: unknown): Promise<number> =>
  (
    await world.direct(
      new Request(url, {
        method: "POST",
        headers: { "content-type": MEDIA_TYPE },
        body: JSON.stringify(record),
      }),
    )
  ).status;

describe(`${clause("L1 12.1")} a packet that is sent`, () => {
  it(`${clause("L1 12.6", "L1 13.2", "L1 15.3")} is signed, sealed to its recipient, and posted to the recipient's inbox`, async () => {
    const ada = await at_(ONE);
    const bob = await at_(TWO);
    const posted: { url: string; body: string }[] = [];
    world.before = async (request) => {
      if (request.method === "POST") {
        posted.push({ url: request.url, body: await request.clone().text() });
      }
    };
    const sent = await ada.mind.send(hello([bob.mind.address], { goal: "To say hello." }));
    world.before = undefined;
    expect(sent.packet).toMatchObject({
      type: "Packet",
      from: ada.mind.address,
      to: [bob.mind.address],
      created: T(100),
      expires: T(3700),
      purpose: { verb: "inform", goal: "To say hello." },
      content: { mediaType: "text/plain", body: "Hello." },
    });
    expect(sent.packet.nonce).toMatch(/^[A-Za-z0-9_-]{22}$/u);
    expect(sent.id).toBe(contentId(sent.packet));
    expect(sent.deliveries).toStrictEqual([
      {
        to: bob.mind.address,
        sealed: true,
        stored: true,
        endpoint: inboxOf(TWO, bob.mind),
      },
    ]);
    // What crossed the wire names the recipient and says nothing else.
    expect(posted).toHaveLength(1);
    expect(posted[0]?.url).toBe(inboxOf(TWO, bob.mind));
    const record = JSON.parse(posted[0]?.body ?? "") as Record<string, unknown>;
    expect(Object.keys(record).sort()).toStrictEqual(
      ["ciphertext", "enc", "key", "oip", "suite", "to", "type"].sort(),
    );
    expect(record).toMatchObject({ type: "Sealed", to: bob.mind.address });
    expect(record["key"]).toBe(bob.mind.state.agreement[0]);
    expect(posted[0]?.body).not.toContain("Hello");
    expect(posted[0]?.body).not.toContain(ada.mind.address);
    // The sender's signature counts for anyone who holds the packet.
    const judged = judgeRecord(sent.packet);
    const reader = new Lookup({ resolvers: [A], fetch: world.fetch, clock: world.clock });
    await reader.resolve(ada.mind.address);
    expect(judged.ok && judged.value.proofs).toHaveLength(1);
  });

  it(`${clause("L1 12.4", "L1 13.5")} is found by its recipient, judged, returned once, and removed`, async () => {
    const ada = await at_(ONE);
    const bob = await at_(TWO);
    const sent = await ada.mind.send(hello([bob.mind.address]));
    world.clock.at = at(160);
    const inbox = await bob.mind.receive();
    expect(inbox).toStrictEqual({
      received: [
        {
          id: sent.id,
          packet: sent.packet,
          from: ada.mind.address,
          sealed: true,
          time: at(160),
        },
      ],
      refused: [],
      waiting: 0,
      sources: [{ mailbox: mailboxOf(TWO, bob.mind), items: 1 }],
    });
    // It is gone from the mailbox.
    expect(await bob.mind.receive()).toStrictEqual({
      received: [],
      refused: [],
      waiting: 0,
      sources: [{ mailbox: mailboxOf(TWO, bob.mind), items: 0 }],
    });
    // The sender finds nothing of it in its own.
    expect((await ada.mind.receive()).received).toStrictEqual([]);
  });

  it(`${clause("L1 12.6")} goes unsealed only where the sender says so`, async () => {
    const ada = await at_(ONE);
    const bob = await at_(TWO);
    let body = "";
    world.before = async (request) => {
      if (request.method === "POST") body = await request.clone().text();
    };
    const sent = await ada.mind.send(hello([bob.mind.address], { seal: false }));
    world.before = undefined;
    expect(JSON.parse(body)).toStrictEqual(sent.packet);
    expect(sent.deliveries[0]).toMatchObject({ sealed: false, stored: true });
    expect((await bob.mind.receive()).received).toMatchObject([{ id: sent.id, sealed: false }]);
  });

  it(`${clause("L1 12.1")} carries what its sender gives it: a thread, what it answers, context and constraints`, async () => {
    const ada = await at_(ONE);
    const bob = await at_(TWO);
    const first = await ada.mind.send(hello([bob.mind.address]));
    const sent = await bob.mind.send({
      to: [ada.mind.address],
      verb: "x.example:greet",
      content: { parts: [{ mediaType: "text/plain", body: "Hello yourself." }] },
      expiresIn: 60,
      thread: first.id,
      replyTo: first.id,
      context: { summary: "A greeting returned.", language: "en" },
      constraints: { retention: "none", forwardOk: false },
    });
    expect(sent.packet).toMatchObject({
      expires: T(160),
      thread: first.id,
      replyTo: first.id,
      purpose: { verb: "x.example:greet" },
      context: { summary: "A greeting returned.", language: "en" },
      constraints: { retention: "none", forwardOk: false },
    });
    expect((await ada.mind.receive()).received.map((received) => received.packet)).toStrictEqual([
      sent.packet,
    ]);
  });

  it(`${clause("L1 12.1")} goes to each recipient by itself, and one that cannot be reached is said`, async () => {
    const ada = await at_(ONE);
    const bob = await at_(TWO);
    const cyd = await at_(undefined);
    const dee = await at_("https://host-gone.example");
    const unknown = new KeyMind("unknown").address;
    const sent = await ada.mind.send(
      hello([bob.mind.address, cyd.mind.address, dee.mind.address, unknown]),
    );
    expect(sent.deliveries).toStrictEqual([
      { to: bob.mind.address, sealed: true, stored: true, endpoint: inboxOf(TWO, bob.mind) },
      // No location record; a host that does not answer, at its inbox or its mailbox; no log.
      { to: cyd.mind.address, sealed: true, stored: false, failure: "not-found" },
      { to: dee.mind.address, sealed: true, stored: false, failure: "unreachable" },
      { to: unknown, sealed: true, stored: false, failure: "not-found" },
    ]);
    // Each recipient is told of the others: the packet is one packet.
    expect((await bob.mind.receive()).received[0]?.packet.to).toHaveLength(4);
  });

  it(`${clause("L1 15.3")} goes to a mailbox where no other endpoint takes it, and only to mailboxes while the recipient is paused`, async () => {
    const ada = await at_(ONE);
    const bob = await at_(TWO);
    // The inbox is away, and the mailbox is not.
    const real = world.at(TWO);
    world.put(TWO, (request) =>
      request.url.endsWith("/inbox")
        ? new Response(
            JSON.stringify({ type: "urn:oip:error:rate-limited", title: "Later", status: 429 }),
            { status: 429, headers: { "content-type": "application/problem+json" } },
          )
        : real(request),
    );
    const first = await ada.mind.send(hello([bob.mind.address]));
    expect(first.deliveries[0]).toMatchObject({
      stored: true,
      endpoint: mailboxOf(TWO, bob.mind),
    });
    world.put(TWO, real);
    await bob.mind.publishLocation({ status: "paused" });
    const before = world.asked.length;
    const second = await ada.mind.send(hello([bob.mind.address]));
    expect(second.deliveries[0]?.endpoint).toBe(mailboxOf(TWO, bob.mind));
    expect(world.asked.slice(before).filter((asked) => asked.endsWith("/inbox"))).toStrictEqual([]);
    expect((await bob.mind.receive()).received.map((received) => received.id)).toStrictEqual([
      first.id,
      second.id,
    ]);
    // Where every endpoint refuses, the first refusal is the one told.
    world.put(
      TWO,
      () =>
        new Response(
          JSON.stringify({ type: "urn:oip:error:rate-limited", title: "Later", status: 429 }),
          { status: 429, headers: { "content-type": "application/problem+json" } },
        ),
    );
    await bob.mind.publishLocation({ status: "active" }).catch(() => undefined);
    world.put(TWO, (request) =>
      request.method === "POST"
        ? new Response(
            JSON.stringify({
              type: request.url.endsWith("/inbox")
                ? "urn:oip:error:rate-limited"
                : "urn:oip:error:too-large",
              title: "No",
              status: 429,
            }),
            { status: 429, headers: { "content-type": "application/problem+json" } },
          )
        : real(request),
    );
    expect((await ada.mind.send(hello([bob.mind.address]))).deliveries[0]).toStrictEqual({
      to: bob.mind.address,
      sealed: true,
      stored: false,
      failure: "rate-limited",
    });
  });

  it(`${clause("L1 12.6")} is not sent unsealed to a recipient it cannot be sealed to`, async () => {
    const ada = await at_(ONE);
    const bob = await at_(TWO);
    await bob.mind.update({ agreement: [] }, { control: bob.lock });
    const before = world.asked.length;
    const sent = await ada.mind.send(hello([bob.mind.address]));
    expect(sent.deliveries).toStrictEqual([
      { to: bob.mind.address, sealed: true, stored: false, failure: "invalid-record" },
    ]);
    expect(world.asked.slice(before).filter((asked) => asked.startsWith("POST"))).toStrictEqual([]);
    // The sender may choose to send it in the clear.
    const open = await ada.mind.send(hello([bob.mind.address], { seal: false }));
    expect(open.deliveries[0]).toMatchObject({ sealed: false, stored: true });
  });

  it(`${clause("L1 12.1")} is not made of what makes no packet, and then nothing is sent`, async () => {
    const ada = await at_(ONE);
    const bob = await at_(TWO);
    const before = world.asked.length;
    const cases: Message[] = [
      hello([]),
      hello(Array.from({ length: 65 }, () => bob.mind.address)),
      hello([bob.mind.address], { expiresIn: 0 }),
      hello([bob.mind.address], { expiresIn: 7 * 24 * 3600 + 1 }),
      hello([bob.mind.address], { expiresIn: 1.5 }),
      hello([bob.mind.address], { verb: "Not A Verb" }),
      hello([bob.mind.address], { goal: "x".repeat(257) }),
      hello([bob.mind.address], { content: {} as never }),
      hello({ subject: "news.weather" }),
      hello({ query: { tags: ["lang:pt"] } }, { expiresIn: 3601 }),
    ];
    for (const message of cases) {
      expect(await refusal(() => ada.mind.send(message)), JSON.stringify(message.to)).toBe(
        "oip: invalid-record",
      );
    }
    expect(world.asked.slice(before).filter((asked) => asked.startsWith("POST"))).toStrictEqual([]);
    ada.mind.close();
    const short = await Mind.open({
      ...ada.options,
      randomness: { bytes: () => new Uint8Array(1) },
    });
    await expect(short.send(hello([bob.mind.address]))).rejects.toThrow(
      /did not give what was asked/u,
    );
  });
});

describe(`${clause("L1 13.2")} an acknowledgement`, () => {
  it("is the recipient's own for the packet, and evidence for the proofs it lists", async () => {
    const ada = await at_(ONE);
    // A recipient whose host holds one of its operational keys, and signs for it.
    const hostKey = signerFromPrivateKey(new Uint8Array(32).fill(7));
    let recipient = "";
    const { archive } = world.host(TWO, {
      signer: (mind) => (mind === recipient ? hostKey : undefined),
    });
    const bob = await at_(TWO);
    recipient = bob.mind.address;
    await bob.mind.update(
      {
        keys: [
          ...bob.mind.state.keys.map((key) => ({ key })),
          { key: hostKey.publicKey, label: "host" },
        ],
      },
      { control: bob.lock },
    );
    // The host has met the sender: it holds her log, and can judge what she sends.
    archive.publish(mindId(ada.mind.address) ?? "", {
      oip: "1",
      type: "Bundle",
      mind: ada.mind.address,
      log: ada.mind.resolved.log.entries.map((entry) => entry.event),
    } as never);
    world.clock.at = at(200);
    const sent = await ada.mind.send(hello([bob.mind.address], { seal: false }));
    const [delivery] = sent.deliveries;
    expect(delivery).toMatchObject({ stored: true, endpoint: inboxOf(TWO, bob.mind) });
    const ack = delivery?.ack;
    expect(ack).toMatchObject({
      type: "Ack",
      author: bob.mind.address,
      packet: sent.id,
      received: T(200),
      proofs: [expect.stringMatching(/^sha256:/u)],
    });
    expect(ack?.sealed).toBeUndefined();
    expect(ack?.proof[0]?.["verificationMethod"]).toContain(hostKey.publicKey);
    // Anyone who holds it and the packet has evidence of when the packet's proof existed.
    const reader = new Lookup({ resolvers: [A], fetch: world.fetch, clock: world.clock });
    world.clock.at = at(900);
    await reader.resolve(bob.mind.address);
    const verified = verifyAck(ack, { view: reader.view, now: at(900), seen: reader.seen });
    const judged = judgeRecord(sent.packet);
    expect(verified.ok && judged.ok && ackEvidence(verified.value, judged.value)).toStrictEqual({
      time: at(200),
      proofs: ack?.proofs,
    });
    // The recipient reads the packet all the same. A sealed one is stored, and not acknowledged:
    // the host cannot read it.
    const sealed = await ada.mind.send(hello([bob.mind.address]));
    expect(sealed.deliveries[0]?.ack).toBeUndefined();
    expect((await bob.mind.receive()).received.map((received) => received.id)).toStrictEqual([
      sent.id,
      sealed.id,
    ]);
  });

  it("is taken from an endpoint only if it is the recipient's, for this packet, as it was sent", async () => {
    const ada = await at_(ONE);
    const bob = await at_(TWO);
    const eve = await at_(undefined);
    const other = await ada.mind.send(hello([bob.mind.address]));
    interface Posted {
      packet: string;
      sealed: string | undefined;
    }
    const ackBy = (mind: Mind, more: object) =>
      mind.sign({
        oip: "1",
        type: "Ack",
        author: bob.mind.address,
        received: T(100),
        created: T(100),
        ...more,
      });
    const answers: [what: string, answer: (posted: Posted) => Promise<object>, taken: boolean][] = [
      ["the recipient's own", ({ packet }) => ackBy(bob.mind, { packet }), true],
      ["by another mind", ({ packet }) => ackBy(eve.mind, { packet }), false],
      ["for another packet", () => ackBy(bob.mind, { packet: other.id }), false],
      [
        "for a sealed record that was not sent",
        ({ packet }) => ackBy(bob.mind, { packet, sealed: other.id }),
        false,
      ],
      ["another record", () => Promise.resolve(other.packet), false],
      ["what is no record", () => Promise.resolve({ oip: "1", type: "Ack" }), false],
    ];
    const real = world.at(TWO);
    for (const [what, answer, taken] of answers) {
      // An endpoint that reads what it is sent: the packet came unsealed.
      world.put(TWO, async (request) => {
        if (request.method !== "POST") return real(request);
        const packet = contentId(await request.json());
        return new Response(JSON.stringify(await answer({ packet, sealed: undefined })), {
          status: 202,
          headers: { "content-type": MEDIA_TYPE },
        });
      });
      const sent = await ada.mind.send(hello([bob.mind.address], { seal: false }));
      expect(sent.deliveries[0]?.stored, what).toBe(true);
      expect(sent.deliveries[0]?.ack !== undefined, what).toBe(taken);
    }
    // An endpoint that holds the recipient's agreement key says which sealed record it opened.
    world.put(TWO, async (request) => {
      if (request.method !== "POST") return real(request);
      const sealed = contentId(await request.json());
      return new Response(JSON.stringify(await ackBy(bob.mind, { packet: expected, sealed })), {
        status: 202,
        headers: { "content-type": MEDIA_TYPE },
      });
    });
    // The sender's nonce is known to the test, so that the test knows the packet before it is sealed.
    let expected = "";
    ada.mind.close();
    const fixed = await Mind.open({
      ...ada.options,
      randomness: { bytes: (length) => new Uint8Array(length).fill(9) },
    });
    expected = contentId(
      await fixed.sign({
        oip: "1",
        type: "Packet",
        from: fixed.address,
        to: [bob.mind.address],
        created: T(100),
        expires: T(3700),
        nonce: "CQkJCQkJCQkJCQkJCQkJCQ",
        purpose: { verb: "inform" },
        content: { mediaType: "text/plain", body: "Hello." },
      }),
    );
    const sent = await fixed.send(hello([bob.mind.address]));
    expect(sent.id).toBe(expected);
    expect(sent.deliveries[0]?.ack).toMatchObject({ packet: expected });
    expect(sent.deliveries[0]?.ack?.sealed).toMatch(/^b/u);
  });

  it("is not taken where the recipient's log cannot be asked for when it comes", async () => {
    const ada = await at_(ONE);
    const bob = await at_(TWO);
    const real = world.at(TWO);
    world.put(TWO, async (request) => {
      if (request.method !== "POST") return real(request);
      const packet = contentId(await request.json());
      const ack = await bob.mind.sign({
        oip: "1",
        type: "Ack",
        author: bob.mind.address,
        packet,
        received: T(100),
        created: T(100),
      });
      return new Response(JSON.stringify(ack), {
        status: 202,
        headers: { "content-type": MEDIA_TYPE },
      });
    });
    // The resolver answers until the packet is posted, and not after.
    let posted = false;
    world.before = (request) => {
      if (request.method === "POST" && request.url.endsWith("/inbox")) posted = true;
      else if (posted && request.url.startsWith(A)) throw new TypeError("fetch failed");
    };
    const sent = await ada.mind.send(hello([bob.mind.address], { seal: false }));
    world.before = undefined;
    expect(sent.deliveries[0]).toStrictEqual({
      to: bob.mind.address,
      sealed: false,
      stored: true,
      endpoint: inboxOf(TWO, bob.mind),
    });
  });
});

describe(`${clause("L1 12.4")} what a mind finds in its mailbox`, () => {
  it(`${clause("L1 13.5")} is refused where it is no packet for it, said why, and removed`, async () => {
    const ada = await at_(ONE);
    const bob = await at_(TWO);
    const cyd = await at_(ONE);
    const mailbox = mailboxOf(TWO, bob.mind);
    const packet = (more: object = {}) => ({
      oip: "1",
      type: "Packet",
      from: ada.mind.address,
      to: [bob.mind.address],
      created: T(100),
      expires: T(3700),
      nonce: "nonce-0001",
      purpose: { verb: "inform" },
      content: { mediaType: "text/plain", body: "Hello." },
      ...more,
    });
    const good = await ada.mind.sign(packet());
    const elsewhere = await ada.mind.sign(packet({ to: [cyd.mind.address] }));
    const forged = await cyd.mind.sign(packet({ nonce: "nonce-0002" }));
    const expired = await ada.mind.sign(packet({ created: T(10), expires: T(20) }));
    const queried = await ada.mind.sign(packet({ to: { query: {} } }));
    const profile = await ada.mind.sign({
      oip: "1",
      type: "Participant",
      author: ada.mind.address,
      created: T(100),
      name: "Ada",
      kind: "agent",
    });
    // Sealed to the recipient's name with another mind's key, and sealed for another mind.
    const sent = await ada.mind.send(hello([cyd.mind.address]));
    expect(sent.deliveries[0]?.stored).toBe(true);
    const lookup = new Lookup({ resolvers: [A], fetch: world.fetch, clock: world.clock });
    await lookup.resolve(cyd.mind.address);
    const { sealPacket } = await import("@oip/net");
    const sealed = await sealPacket({
      packet: elsewhere,
      to: cyd.mind.address,
      view: lookup.view,
      randomness: new Uint8Array(32).fill(1),
    });
    const misdirected = sealed.ok ? { ...sealed.value, to: bob.mind.address } : undefined;
    // A mailbox that stores whatever it is given, and judges none of it (13.5).
    const held = [elsewhere, forged, expired, queried, profile, misdirected, "no record", good];
    const removed: string[] = [];
    const real = world.at(TWO);
    world.put(TWO, (request) => {
      if (!request.url.includes("/mailbox")) return real(request);
      if (request.method === "DELETE") {
        removed.push(decodeURIComponent(request.url.split("/").at(-1) ?? ""));
        return new Response(null, { status: 204 });
      }
      const items = held
        .map((record, index) => ({ cursor: `item ${String(index)}`, record }))
        .filter(({ cursor }) => !removed.includes(cursor));
      return new Response(JSON.stringify({ items }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    world.clock.at = at(400);
    const inbox = await bob.mind.receive();
    expect(inbox.sources).toStrictEqual([{ mailbox, items: 8 }]);
    expect(inbox.received.map((received) => received.id)).toStrictEqual([contentId(good)]);
    expect(inbox.waiting).toBe(0);
    expect(inbox.refused.map((refused) => `${refused.clause}: ${refused.message}`)).toStrictEqual([
      "L1 12.4: the receiver is not among the packet's recipients",
      "L1 12.4: the packet carries no proof that counts by its sender's own authority",
      "L1 12.4: `expires` is more than 300 seconds in the past",
      "L1 12.4: a packet addressed to a query is accepted only inside a Forwarded record from a broker",
      "L1 12.4: the record is neither a Packet nor a Forwarded record",
      "L1 12.6: the record is sealed to a key this receiver does not hold",
      "core 1.1: a record is a JSON object",
    ]);
    // Each was removed once it was judged, whatever the judgement.
    expect(removed).toStrictEqual(held.map((_, index) => `item ${String(index)}`));
    expect((await bob.mind.receive()).sources).toStrictEqual([{ mailbox, items: 0 }]);
  });

  it("is returned once, though it arrives twice, and though the process ends before it is removed", async () => {
    const ada = await at_(ONE);
    const bob = await at_(TWO);
    const sent = await ada.mind.send(hello([bob.mind.address]));
    // The same packet again, in the clear, by the mailbox: the host cannot tell that it holds it.
    expect(await post(mailboxOf(TWO, bob.mind), sent.packet)).toBe(202);
    // The mailbox cannot be asked to remove anything.
    world.before = (request) => {
      if (request.method === "DELETE") throw new TypeError("fetch failed");
    };
    const first = await bob.mind.receive();
    expect(first.sources[0]?.items).toBe(2);
    expect(first.received.map((received) => received.id)).toStrictEqual([sent.id]);
    world.before = undefined;
    // The process ends. The next one remembers what was accepted.
    bob.mind.close();
    const again = await Mind.open(bob.options);
    const second = await again.receive();
    expect(second).toMatchObject({ received: [], refused: [], waiting: 0 });
    expect(second.sources[0]?.items).toBe(2);
    expect((await again.receive()).sources[0]?.items).toBe(0);
    // A client that remembers nothing would take it for new: that is what the memory is for.
    expect(await post(mailboxOf(TWO, bob.mind), sent.packet)).toBe(202);
    again.close();
    const forgetful = await Mind.open({ ...bob.options, memory: memoryStorage() });
    expect((await forgetful.receive()).received.map((received) => received.id)).toStrictEqual([
      sent.id,
    ]);
  });

  it(`${clause("core 9.4")} waits where its sender's log cannot be asked for, and is judged when it can`, async () => {
    const ada = await at_(ONE);
    const bob = await at_(TWO);
    const sent = await ada.mind.send(hello([bob.mind.address]));
    const sender = mindId(ada.mind.address) ?? "";
    world.before = (request) => {
      if (request.url.startsWith(A) && request.url.endsWith(sender)) {
        throw new TypeError("fetch failed");
      }
    };
    const first = await bob.mind.receive();
    expect(first).toMatchObject({ received: [], refused: [], waiting: 1 });
    world.before = undefined;
    const second = await bob.mind.receive();
    expect(second.received.map((received) => received.id)).toStrictEqual([sent.id]);
    expect(second.waiting).toBe(0);
  });

  it(`${clause("core 9.4")} is judged by its sender's log as it stands when the packet is first seen`, async () => {
    const ada = await at_(ONE);
    const bob = await at_(TWO);
    // Bob has met Ada before, and holds her log from then.
    await bob.mind.lookup.resolve(ada.mind.address);
    const [old] = ada.mind.state.keys;
    const before = await ada.mind.send(hello([bob.mind.address]));
    // Ada's key is taken, and she revokes it. The thief sends a packet signed with it.
    const stolen = { ...before.packet, nonce: "nonce-of-a-thief" } as Record<string, unknown>;
    delete stolen["proof"];
    const thief = await ada.mind.sign(stolen);
    world.clock.at = at(200);
    await ada.mind.addKey({ control: ada.lock });
    await ada.mind.revokeKey(old ?? "", { control: ada.lock });
    world.clock.at = at(300);
    expect(await post(mailboxOf(TWO, bob.mind), thief)).toBe(202);
    const inbox = await bob.mind.receive();
    // Neither was seen before the key was removed: by the log as it stands, neither counts.
    expect(inbox.received).toStrictEqual([]);
    expect(inbox.refused).toHaveLength(2);
    const judged = judgeRecord(thief);
    expect(
      judged.ok && ownSignedTime(judged.value, ada.mind.address, bob.mind.lookup.view),
    ).toBeUndefined();
  });

  it("is read from every mailbox the mind names, and one that fails is said to have failed", async () => {
    const ada = await at_(ONE);
    const made = await freshKeystore(world, [A]);
    const bob = await Mind.create(made.options, { kind: "agent", homes: [ONE, TWO] });
    // With no location record yet, the mailboxes it reads are those of its homes.
    expect((await bob.receive()).sources).toStrictEqual([
      { mailbox: mailboxOf(ONE, bob), items: 0 },
      { mailbox: mailboxOf(TWO, bob), items: 0 },
    ]);
    await bob.publishLocation();
    const sent = await ada.mind.send(hello([bob.address]));
    expect(sent.deliveries[0]?.endpoint).toBe(inboxOf(ONE, bob));
    expect(await post(mailboxOf(TWO, bob), sent.packet)).toBe(202);
    world.down(ONE);
    const first = await bob.receive();
    expect(first.sources).toStrictEqual([
      { mailbox: mailboxOf(ONE, bob), items: undefined, failure: "unreachable" },
      { mailbox: mailboxOf(TWO, bob), items: 1 },
    ]);
    expect(first.received.map((received) => received.id)).toStrictEqual([sent.id]);
    world.up(ONE);
    // The copy at the other home is a duplicate.
    const second = await bob.receive();
    expect(second.sources.map((source) => source.items)).toStrictEqual([1, 0]);
    expect(second.received).toStrictEqual([]);
  });

  it("is nothing for a mind with no mailbox", async () => {
    const cyd = await at_(undefined);
    expect(await cyd.mind.receive()).toStrictEqual({
      received: [],
      refused: [],
      waiting: 0,
      sources: [],
    });
  });
});

/**
 * Puts a mailbox in front of a home's that answers what a test gives it, and
 * lets every other request through.
 *
 * @returns The cursors the mind asked to have removed, as they are asked.
 */
function mailboxAt(home: string, answer: (asked: URL) => unknown): string[] {
  const removed: string[] = [];
  const real = world.at(home);
  world.put(home, (request) => {
    const asked = new URL(request.url);
    if (!asked.pathname.includes("/mailbox")) return real(request);
    if (request.method === "DELETE") {
      removed.push(decodeURIComponent(asked.pathname.split("/").at(-1) ?? ""));
      return new Response(null, { status: 204 });
    }
    return new Response(JSON.stringify(answer(asked)), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  });
  return removed;
}

/** What stands in for `fetch`, broken for some requests: its answer has headers that cannot be read. */
const broken =
  (when: (request: Request) => boolean): typeof world.fetch =>
  (request) =>
    when(request)
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

describe(`${clause("L1 13.5")} a mailbox, as a stranger that serves it`, () => {
  it("is read page by page, and no further than a page that does not go forward", async () => {
    const bob = await at_(TWO);
    const asked: string[] = [];
    const removed = mailboxAt(TWO, (url) => {
      asked.push(url.search);
      const after = url.searchParams.get("after");
      if (after === null) return { items: [{ cursor: "a b", record: "one" }], next: "a b" };
      if (after === "a b") return { items: [{ cursor: "c", record: "two" }], next: "c" };
      // The same page again, with the same thing said to follow.
      return { items: [{ cursor: "d", record: "three" }], next: "c" };
    });
    const inbox = await bob.mind.receive();
    expect(asked).toStrictEqual(["", "?after=a%20b", "?after=c"]);
    expect(inbox.sources[0]?.items).toBe(3);
    expect(inbox.refused).toHaveLength(3);
    expect(removed).toStrictEqual(["a b", "c", "d"]);
  });

  it("is read as far as a client reads in one call, and the rest by the next", async () => {
    const bob = await at_(TWO);
    let served = 0;
    mailboxAt(TWO, () => {
      const items = Array.from({ length: 600 }, () => ({ cursor: String(served++), record: 0 }));
      return { items, next: String(served) };
    });
    const inbox = await bob.mind.receive();
    expect(inbox.sources[0]?.items).toBe(1000);
    expect(inbox.refused).toHaveLength(1000);
    // An empty page that says more follows ends it too.
    mailboxAt(TWO, () => ({ items: [], next: "more" }));
    expect((await bob.mind.receive()).sources[0]?.items).toBe(0);
  });

  it("has failed where what it serves is no page of a mailbox", async () => {
    const bob = await at_(TWO);
    const served: unknown[] = [
      "items",
      [],
      {},
      { items: 5 },
      { items: [5] },
      { items: [{ cursor: 1, record: {} }] },
      { items: [{ cursor: "a" }] },
    ];
    for (const page of served) {
      mailboxAt(TWO, () => page);
      expect((await bob.mind.receive()).sources, JSON.stringify(page)).toStrictEqual([
        { mailbox: mailboxOf(TWO, bob.mind), items: undefined, failure: "not-oip" },
      ]);
    }
  });
});

describe(`${clause("L1 12.6")} what is sealed to a mind and is no packet for it`, () => {
  it("is refused: what does not open, what opens to no record, and a packet of a sender nobody knows", async () => {
    const ada = await at_(ONE);
    const bob = await at_(TWO);
    const { decodeX25519Multikey, hpkeSeal, utf8, bytesToBase64url } = await import("@oip/core");
    const [key = ""] = bob.mind.state.agreement;
    const to = bob.mind.address;
    const publicKey = decodeX25519Multikey(key);
    const sealing = async (plaintext: string) => {
      const made = await hpkeSeal({
        recipientPublicKey: publicKey.ok ? publicKey.value : new Uint8Array(32),
        info: utf8("oip/1 sealed"),
        aad: utf8(to),
        plaintext: utf8(plaintext),
        randomness: new Uint8Array(32).fill(3),
      });
      return {
        oip: "1",
        type: "Sealed",
        to,
        key,
        suite: "hpke-base-x25519-sha256-chacha20poly1305",
        enc: bytesToBase64url(made?.enc ?? new Uint8Array()),
        ciphertext: bytesToBase64url(made?.ciphertext ?? new Uint8Array()),
      };
    };
    const garbage = await sealing("not a record");
    // One character of the ciphertext is another: it does not open.
    const [first = ""] = garbage.ciphertext;
    const spoiled = {
      ...garbage,
      ciphertext: `${first === "A" ? "B" : "A"}${garbage.ciphertext.slice(1)}`,
    };
    // A broker's record that names no broker.
    const brokerless = { oip: "1", type: "Forwarded", broker: 7, to, packet: { from: 7 } };
    // A packet, well made and sealed, by a mind whose log no resolver holds.
    const stranger = new KeyMind("stranger");
    const unknown = await sealing(
      JSON.stringify(
        stranger.sign({
          oip: "1",
          type: "Packet",
          from: stranger.address,
          to: [to],
          created: T(100),
          expires: T(3700),
          nonce: "nonce-0001",
          purpose: { verb: "inform" },
          content: { mediaType: "text/plain", body: "Hello." },
        }),
      ),
    );
    const good = await ada.mind.send(hello([to]));
    const held = [garbage, spoiled, unknown, brokerless];
    const removed = mailboxAt(TWO, () => ({
      items: held.map((record, index) => ({ cursor: String(index), record })),
    }));
    const inbox = await bob.mind.receive();
    expect(inbox.received).toStrictEqual([]);
    expect(inbox.waiting).toBe(0);
    expect(inbox.refused.map((refused) => `${refused.clause}: ${refused.message}`)).toStrictEqual([
      "L1 12.6: the record does not open to the canonical form of a packet",
      "L1 12.6: the record does not open with the key it names",
      "L1 12.4: the packet carries no proof that counts by its sender's own authority",
      "L1 18.5: must have required property 'created'",
    ]);
    expect(removed).toStrictEqual(["0", "1", "2", "3"]);
    expect(good.deliveries[0]?.stored).toBe(true);
  });
});

describe(`${clause("L1 18.5")} a packet for whoever a query finds`, () => {
  const X = "https://indexer-x.example";

  it(`${clause("L1 12.4")} goes in the clear to the indexers the client names, and reaches a mind that matches inside a broker's record`, async () => {
    const indexer = world.indexer(X);
    expect(await world.publish(A, indexer.mind)).toBe(202);
    const ada = await at_(ONE, { indexers: [X] });
    const made = await freshKeystore(world, [A], { indexers: [X] });
    const bob = await Mind.create(made.options, { kind: "agent", homes: [TWO] });
    await bob.publishProfile({
      name: "Bob",
      capabilities: [{ id: "translate", summary: "Translation", tags: ["lang:pt"] }],
    });
    world.clock.at = at(200);
    const sent = await ada.mind.send({
      to: { query: { tags: ["lang:pt"] } },
      verb: "request",
      content: { mediaType: "text/plain", body: "Who translates into Portuguese?" },
      expiresIn: 600,
    });
    expect(sent.packet.to).toStrictEqual({ query: { tags: ["lang:pt"] } });
    expect(sent.deliveries).toStrictEqual([
      { to: X, sealed: false, stored: true, endpoint: `${X}/oip/v1/inbox` },
    ]);
    await indexer.broker.idle();
    const inbox = await bob.receive();
    expect(inbox.refused).toStrictEqual([]);
    expect(inbox.received).toStrictEqual([
      {
        id: sent.id,
        packet: sent.packet,
        from: ada.mind.address,
        sealed: false,
        broker: indexer.mind.address,
        time: at(200),
      },
    ]);
    // The sender matches its own query no more than anyone: it is not forwarded its own packet.
    expect((await ada.mind.receive()).received).toStrictEqual([]);
  });

  it("is refused by an indexer that is not a broker of it, and is not sent where no indexer is named", async () => {
    const indexer = world.indexer(X);
    expect(await world.publish(A, indexer.mind)).toBe(202);
    const ada = await at_(ONE, { indexers: [X, "https://indexer-gone.example"] });
    const sent = await ada.mind.send({
      to: { query: {}, brokers: [new KeyMind("another-broker").address] },
      verb: "request",
      content: { mediaType: "text/plain", body: "Anyone?" },
    });
    expect(sent.deliveries).toStrictEqual([
      { to: X, sealed: false, stored: false, failure: "forbidden" },
      {
        to: "https://indexer-gone.example",
        sealed: false,
        stored: false,
        failure: "unreachable",
      },
    ]);
    const alone = await at_(ONE);
    await expect(
      alone.mind.send({ to: { query: {} }, verb: "request", content: { parts: [] } }),
    ).rejects.toThrow(/names the indexers it asks/u);
  });
});

describe("the edges of sending and receiving", () => {
  it(`${clause("L1 15.1")} an endpoint that takes no posted packet is passed over`, async () => {
    const ada = await at_(ONE);
    const bob = await at_(TWO);
    const inbox = inboxOf(TWO, bob.mind).replace(/\/inbox$/u, "");
    await bob.mind.publishLocation({
      endpoints: [
        { binding: "wss", url: "wss://host-two.example/socket", priority: 0 },
        { binding: "https", url: `${inbox}?v=1`, priority: 1 },
        { binding: "iroh", url: "iroh://node", priority: 2 },
        { binding: "https", url: inbox, priority: 3 },
      ],
    });
    const before = world.asked.length;
    const sent = await ada.mind.send(hello([bob.mind.address]));
    expect(sent.deliveries[0]).toMatchObject({ stored: true, endpoint: `${inbox}/inbox` });
    expect(world.asked.slice(before).filter((asked) => asked.startsWith("POST"))).toStrictEqual([
      `POST ${inbox}/inbox`,
    ]);
    // A recipient with no endpoint that takes one.
    await bob.mind.publishLocation({ endpoints: [] });
    expect((await ada.mind.send(hello([bob.mind.address]))).deliveries[0]).toStrictEqual({
      to: bob.mind.address,
      sealed: true,
      stored: false,
      failure: "not-found",
    });
  });

  it("a failure that is nobody's answer reaches the caller as it is, whatever was being asked", async () => {
    const ada = await at_(ONE);
    const bob = await at_(TWO);
    const again = async (of: typeof ada, when: (request: Request) => boolean) => {
      of.mind.close();
      of.mind = await Mind.open({ ...of.options, fetch: broken(when) });
      return of.mind;
    };
    // The inbox's answer to a packet, and an indexer's to one for a query.
    let sender = await again(ada, (request) => request.method === "POST");
    await expect(sender.send(hello([bob.mind.address]))).rejects.toThrow(RangeError);
    ada.options = { ...ada.options, indexers: ["https://indexer.example"] };
    sender = await again(ada, (request) => request.method === "POST");
    await expect(
      sender.send({ to: { query: {} }, verb: "request", content: { parts: [] } }),
    ).rejects.toThrow(RangeError);
    // A resolver's, when an acknowledgement is judged.
    const real = world.at(TWO);
    world.put(TWO, async (request) => {
      if (request.method !== "POST") return real(request);
      const packet = contentId(await request.json());
      const ack = await bob.mind.sign({
        oip: "1",
        type: "Ack",
        author: bob.mind.address,
        packet,
        received: T(100),
        created: T(100),
      });
      return new Response(JSON.stringify(ack), {
        status: 202,
        headers: { "content-type": MEDIA_TYPE },
      });
    });
    let posted = false;
    world.before = (request) => {
      if (request.method === "POST") posted = true;
    };
    sender = await again(ada, (request) => posted && request.url.startsWith(A));
    await expect(sender.send(hello([bob.mind.address], { seal: false }))).rejects.toThrow(
      RangeError,
    );
    world.before = undefined;
    world.put(TWO, real);
    // A mailbox's, when it is drained; a resolver's, for a sender; a mailbox's, when an item is removed.
    sender = await again(ada, () => false);
    await sender.send(hello([bob.mind.address]));
    let reader = await again(bob, (request) => request.url.includes("/mailbox"));
    await expect(reader.receive()).rejects.toThrow(RangeError);
    const from = mindId(ada.mind.address) ?? "";
    reader = await again(bob, (request) => request.url.endsWith(from));
    await expect(reader.receive()).rejects.toThrow(RangeError);
    reader = await again(bob, (request) => request.method === "DELETE");
    await expect(reader.receive()).rejects.toThrow(RangeError);
  });

  it("what is remembered of the packets accepted is forgotten when they can no longer arrive, and is damaged if it cannot be read", async () => {
    const ada = await at_(ONE);
    const bob = await at_(TWO);
    const sent = await ada.mind.send(hello([bob.mind.address], { expiresIn: 60 }));
    expect((await bob.mind.receive()).received).toHaveLength(1);
    const remembered = async (): Promise<unknown> => {
      const held = await bob.memory.get("client-accepted");
      return JSON.parse(new TextDecoder().decode(held?.value));
    };
    expect(await remembered()).toMatchObject({ ids: { [sent.id]: String(at(160 + 300)) } });
    // Until 300 seconds after it expires a copy could still be accepted: it is remembered until then.
    world.clock.at = at(160 + 300);
    await bob.mind.receive();
    expect(await remembered()).toMatchObject({ ids: { [sent.id]: String(at(460)) } });
    world.clock.at = at(461);
    await bob.mind.receive();
    expect(await remembered()).toMatchObject({ ids: {} });
    // A memory that cannot be read is not gone by.
    bob.mind.close();
    for (const stored of [
      {},
      { ids: [] },
      { ids: { [sent.id]: 460 } },
      { ids: { [sent.id]: "soon" } },
    ]) {
      const memory = memoryStorage();
      await memory.put(
        "client-accepted",
        new TextEncoder().encode(JSON.stringify({ ...stored, mind: bob.mind.address })),
        undefined,
      );
      const reader = await Mind.open({ ...bob.options, memory });
      expect(await refusal(() => reader.receive()), JSON.stringify(stored)).toBe(
        "keystore: damaged",
      );
      reader.close();
    }
  });
});
