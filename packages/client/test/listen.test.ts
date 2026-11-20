// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { MEDIA_TYPE, mindId } from "@oip/core";
import { KeystoreError } from "@oip/keystore";
import { clause } from "@oip/testkit";
import { at, KeyMind, T } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  type Inbox,
  type Message,
  Mind,
  type MindOptions,
  type SocketLike,
  type SocketState,
} from "../src/index.ts";
import { freshKeystore } from "./helpers.ts";
import { World } from "./world.ts";

const A = "https://resolver-a.example";
const ONE = "https://host-one.example";
const TWO = "https://host-two.example";

let world: World;
let open: { close: () => Promise<void> }[];
beforeEach(() => {
  world = new World(100);
  world.resolver(A);
  world.host(ONE);
  world.host(TWO);
  open = [];
});
afterEach(async () => {
  for (const listening of open) await listening.close();
  world.close();
});

/** Waits a test ends when it chooses: each is kept until it is woken. */
function sleeper() {
  const waits: { ms: number; wake: () => void }[] = [];
  return {
    waits,
    sleep: (ms: number) =>
      new Promise<void>((resolve) => {
        waits.push({ ms, wake: resolve });
      }),
  };
}

/** A mind at a home, which has said where it takes packets, and opens sockets in this world. */
async function at_(home: string | undefined, more: Partial<MindOptions> = {}) {
  const slept = sleeper();
  const made = await freshKeystore(world, [A], {
    webSocket: world.socket,
    sleep: slept.sleep,
    ...more,
  });
  const mind = await Mind.create(made.options, {
    kind: "agent",
    ...(home === undefined ? {} : { homes: [home] }),
  });
  if (home !== undefined) await mind.publishLocation();
  return { ...made, mind, ...slept };
}

async function pair(more: Partial<MindOptions> = {}) {
  const ada = await at_(ONE);
  const bob = await at_(TWO, more);
  world.clock.at = at(160);
  return { ada, bob };
}

const hello = (to: string, body = "Hello.", more: Partial<Message> = {}): Message => ({
  to: [to],
  verb: "inform",
  content: { mediaType: "text/plain", body },
  ...more,
});

/** Lets what is under way go on, until something holds or a second has passed. */
async function until(holds: () => boolean): Promise<void> {
  for (let turn = 0; turn < 1000 && !holds(); turn++) {
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  if (!holds()) throw new Error("it never came about");
}

/** A mind that listens, with what it was told. */
function listening(mind: Mind, more: { retryMs?: number; maxRetryMs?: number } = {}) {
  const inboxes: Inbox[] = [];
  const states: SocketState[] = [];
  const handle = mind.listen({
    received: (inbox) => {
      inboxes.push(inbox);
    },
    changed: (state) => states.push(state),
    ...more,
  });
  open.push(handle);
  return {
    handle,
    inboxes,
    states,
    isOpen: () => states.at(-1)?.state === "open",
    bodies: () =>
      inboxes.flatMap((inbox) =>
        inbox.received.map(({ packet }) => {
          const parts = "parts" in packet.content ? packet.content.parts : [packet.content];
          const text = parts.find((part) => part.mediaType === "text/plain");
          return text !== undefined && "body" in text ? text.body : packet.purpose.verb;
        }),
      ),
  };
}

const socketOf = (home: string, mind: Mind): string =>
  `${home.replace("https://", "wss://")}/oip/v1/minds/${mindId(mind.address) ?? ""}/ws`;
const mailboxOf = (home: string, mind: Mind): string =>
  `${home}/oip/v1/minds/${mindId(mind.address) ?? ""}/mailbox`;
const parsed = (texts: readonly string[]) =>
  texts.map((text) => JSON.parse(text) as Record<string, unknown>);

describe(`${clause("L1 13.4")} a socket to the mind's own host`, () => {
  it(`${clause("L1 13.3")} is opened where its location says, and the mind answers the host's challenge for the origin it connected to`, async () => {
    const { bob } = await pair();
    const heard = listening(bob.mind);
    await until(heard.isOpen);
    expect(world.sockets).toHaveLength(1);
    const [socket] = world.sockets;
    expect(socket?.url).toBe(socketOf(TWO, bob.mind));
    const [challenge, welcome] = parsed(socket?.fromHost ?? []);
    expect(challenge).toMatchObject({ type: "Challenge", domain: TWO });
    const [answer] = parsed(socket?.fromClient ?? []);
    expect(answer).toMatchObject({
      oip: "1",
      type: "Hello",
      author: bob.mind.address,
      created: T(160),
      proof: [
        {
          proofPurpose: "authentication",
          challenge: challenge?.["nonce"],
          domain: TWO,
        },
      ],
    });
    expect(welcome).toStrictEqual({ type: "Welcome", mind: bob.mind.address });
    expect(heard.states).toStrictEqual([
      { state: "connecting", url: socketOf(TWO, bob.mind) },
      { state: "open", url: socketOf(TWO, bob.mind) },
    ]);
    // Nothing waited, and nothing was told.
    expect(heard.inboxes).toStrictEqual([]);
  });

  it(`${clause("L1 13.5")} brings what waited in the mailbox and what arrives, and each is the host's to forget once the mind says it has it`, async () => {
    const { ada, bob } = await pair();
    const one = await ada.mind.send(hello(bob.mind.address, "One."));
    const two = await ada.mind.send(hello(bob.mind.address, "Two.", { seal: false }));
    world.clock.at = at(170);
    const heard = listening(bob.mind);
    await until(() => heard.bodies().length === 2);
    expect(heard.bodies()).toStrictEqual(["One.", "Two."]);
    expect(heard.inboxes[0]).toMatchObject({ refused: [], waiting: 0, sessions: [], sources: [] });
    expect(heard.inboxes.flatMap((inbox) => inbox.received)).toMatchObject([
      { id: one.id, packet: one.packet, from: ada.mind.address, sealed: true, time: at(170) },
      { id: two.id, sealed: false },
    ]);
    // The mind's own acknowledgements, over the socket: for a sealed record by the record's ID.
    const [socket] = world.sockets;
    await until(() => (socket?.fromClient.length ?? 0) >= 3);
    const acks = parsed(socket?.fromClient ?? []).slice(1);
    expect(acks).toMatchObject([
      { type: "Ack", author: bob.mind.address, packet: one.id, received: T(170) },
      { type: "Ack", author: bob.mind.address, packet: two.id },
    ]);
    expect(typeof acks[0]?.["sealed"]).toBe("string");
    expect(acks[1]).not.toHaveProperty("sealed");
    // What arrives while the socket is open comes at once.
    const three = await ada.mind.send(hello(bob.mind.address, "Three."));
    await until(() => heard.bodies().length === 3);
    expect(heard.inboxes.at(-1)?.received[0]?.id).toBe(three.id);
    await until(() => (socket?.fromClient.length ?? 0) >= 4);
    await heard.handle.close();
    // The host kept none of them.
    expect((await bob.mind.receive()).sources).toStrictEqual([
      { mailbox: mailboxOf(TWO, bob.mind), items: 0 },
    ]);
  });

  it("returns a packet once: one it has already is acknowledged again, and not told again", async () => {
    const { ada, bob } = await pair();
    await ada.mind.send(hello(bob.mind.address));
    world.clock.at = at(170);
    // The mailbox is read, and the host cannot be told to remove what was read.
    world.before = (request) => {
      if (request.method === "DELETE") throw new TypeError("fetch failed");
    };
    expect((await bob.mind.receive()).received).toHaveLength(1);
    world.before = undefined;
    const heard = listening(bob.mind);
    await until(() => (world.sockets[0]?.fromClient.length ?? 0) >= 2);
    expect(parsed(world.sockets[0]?.fromClient ?? [])[1]).toMatchObject({ type: "Ack" });
    expect(heard.inboxes).toStrictEqual([]);
    await heard.handle.close();
    expect((await bob.mind.receive()).sources[0]?.items).toBe(0);
  });

  it(`${clause("L1 12.4")} judges what the host sends as it judges a mailbox, and what is refused is removed by reading the mailbox`, async () => {
    const { ada, bob } = await pair();
    const eve = new KeyMind("eve");
    expect(await world.publish(A, eve)).toBe(202);
    // A packet that says it is Ada's, and that Eve signed.
    const forged = eve.sign({
      oip: "1",
      type: "Packet",
      from: ada.mind.address,
      to: [bob.mind.address],
      created: T(160),
      expires: T(3000),
      nonce: "eve-nonce-1",
      purpose: { verb: "inform" },
      content: { mediaType: "text/plain", body: "From Ada, honestly." },
    });
    const posted = await world.direct(
      new Request(mailboxOf(TWO, bob.mind), {
        method: "POST",
        headers: { "content-type": MEDIA_TYPE },
        body: JSON.stringify(forged),
      }),
    );
    expect(posted.status).toBe(202);
    await ada.mind.send(hello(bob.mind.address, "From Ada."));
    world.clock.at = at(170);
    const heard = listening(bob.mind);
    await until(() => heard.bodies().length === 1);
    expect(heard.bodies()).toStrictEqual(["From Ada."]);
    // Told once, though it was judged twice: over the socket, and when the mailbox was read.
    await until(() => world.asked.some((request) => request.startsWith("DELETE ")));
    expect(heard.inboxes.flatMap((inbox) => inbox.refused)).toMatchObject([{ clause: "L1 12.4" }]);
    await heard.handle.close();
    // Whichever way the packet that counts was read first, the host no longer keeps it.
    expect((await bob.mind.receive()).sources[0]?.items).toBe(0);
  });

  it("says nothing to a host whose connection ended while it judged, and the host sends again", async () => {
    const { ada, bob } = await pair();
    const heard = listening(bob.mind);
    await until(heard.isOpen);
    world.clock.at = at(170);
    // The connection drops while Bob asks a resolver for Ada's log.
    const sent = await ada.mind.send(hello(bob.mind.address, "Heard, and not yet said so."));
    world.before = (request) => {
      if (!request.url.startsWith(A) || request.method !== "GET") return;
      world.before = undefined;
      world.cut(TWO);
    };
    await until(() => heard.bodies().length === 1);
    expect(parsed(world.sockets[0]?.fromClient ?? []).some((said) => said["type"] === "Ack")).toBe(
      false,
    );
    // The host still keeps it. It comes again on the next connection, and is the mind's already.
    await until(() => bob.waits.length === 1);
    bob.waits[0]?.wake();
    await until(() =>
      parsed(world.sockets[1]?.fromClient ?? []).some((said) => said["packet"] === sent.id),
    );
    expect(heard.bodies()).toStrictEqual(["Heard, and not yet said so."]);
    await heard.handle.close();
    expect((await bob.mind.receive()).sources[0]?.items).toBe(0);
  });

  it("removes what it refused by reading the mailbox, and opens again if that cannot be read", async () => {
    const { ada, bob } = await pair();
    const eve = new KeyMind("eve");
    expect(await world.publish(A, eve)).toBe(202);
    const junk = (nonce: string): Promise<Response> =>
      world.direct(
        new Request(mailboxOf(TWO, bob.mind), {
          method: "POST",
          headers: { "content-type": MEDIA_TYPE },
          body: JSON.stringify(
            eve.sign({
              oip: "1",
              type: "Packet",
              from: ada.mind.address,
              to: [bob.mind.address],
              created: T(160),
              expires: T(3000),
              nonce,
              purpose: { verb: "inform" },
              content: { mediaType: "text/plain", body: "From Ada, honestly." },
            }),
          ),
        }),
      );
    const heard = listening(bob.mind);
    await until(heard.isOpen);
    world.clock.at = at(170);
    await junk("eve-nonce-1");
    await until(() => world.asked.some((request) => request.startsWith("DELETE ")));
    // Told once, and nothing else was there to tell.
    expect(heard.inboxes).toMatchObject([{ received: [], refused: [{ clause: "L1 12.4" }] }]);
    // The next time the mind's own log cannot be asked for when the mailbox is to be read.
    world.before = (request) => {
      const own = request.url.includes(mindId(bob.mind.address) ?? "");
      if (own && request.url.startsWith(A)) throw new TypeError("fetch failed");
    };
    await junk("eve-nonce-2");
    await until(() => bob.waits.length === 1);
    world.before = undefined;
    expect(heard.states.at(-1)).toMatchObject({ state: "closed", reason: "unreachable" });
    // It is read when the connection is open again, and what was refused is told then: once.
    expect(heard.inboxes).toHaveLength(1);
    bob.waits[0]?.wake();
    await until(() => heard.inboxes.length === 2);
    expect(heard.inboxes[1]).toMatchObject({ received: [], refused: [{ clause: "L1 12.4" }] });
    await heard.handle.close();
    expect((await bob.mind.receive()).sources[0]?.items).toBe(0);
  });

  it(`${clause("L1 14.3", "L1 14.4")} keeps a session in order: a packet ahead of a gap stays with the host until the gap is filled`, async () => {
    const { ada, bob } = await pair();
    const { id } = await ada.mind.openSession([bob.mind.address]);
    const say = (body: string): Message => ({ ...hello(bob.mind.address, body), session: id });
    await ada.mind.send(say("One."));
    world.down(TWO);
    await ada.mind.send(say("Two."));
    world.up(TWO);
    await ada.mind.send(say("Three."));
    world.clock.at = at(170);
    const heard = listening(bob.mind);
    await until(() => heard.inboxes.some((inbox) => inbox.sessions.length > 0));
    expect(heard.bodies()).toStrictEqual(["One."]);
    expect(
      heard.inboxes.flatMap((inbox) => inbox.sessions.map((event) => event.kind)),
    ).toStrictEqual(["gap", "asked"]);
    // One acknowledgement so far: the third is not the mind's yet.
    const acks = () =>
      parsed(world.sockets[0]?.fromClient ?? []).filter((said) => said["type"] === "Ack");
    await until(() => acks().length === 1);
    // Ada reads the Resume and sends again, and it comes over the socket.
    world.clock.at = at(180);
    expect((await ada.mind.receive()).sessions).toMatchObject([{ kind: "sent-again" }]);
    await until(() => heard.bodies().length === 3);
    expect(heard.bodies()).toStrictEqual(["One.", "Two.", "Three."]);
    // The third is acknowledged twice: as it first arrived, and as it was sent again.
    await until(() => acks().length === 4);
    await heard.handle.close();
    expect((await bob.mind.receive()).sources[0]?.items).toBe(0);
  });
});

describe("a mind that listens, and has packets that wait to be sent", () => {
  it("tries them again when its connection opens, if they are due, and is told what came of them", async () => {
    const { ada, bob } = await pair();
    world.down(TWO);
    const sent = await ada.mind.send(hello(bob.mind.address, "When you are back."));
    world.up(TWO);
    expect(sent.deliveries).toMatchObject([{ queued: true }]);
    // Not due yet: opening a connection sends nothing.
    const early = listening(ada.mind);
    await until(early.isOpen);
    await early.handle.close();
    expect(early.inboxes).toStrictEqual([]);
    expect(await ada.mind.outbox()).toHaveLength(1);
    // Due: it goes when the connection is open again.
    world.clock.at = at(200);
    const heard = listening(ada.mind);
    await until(() => heard.inboxes.length === 1);
    expect(heard.inboxes[0]).toMatchObject({
      received: [],
      retried: [{ id: sent.id, deliveries: [{ stored: true }], waiting: 0, expired: false }],
    });
    expect(await ada.mind.outbox()).toStrictEqual([]);
    world.clock.at = at(210);
    expect((await bob.mind.receive()).received).toHaveLength(1);
  });
});

describe("a connection that ends", () => {
  it(`${clause("L1 13.4")} is opened again after a wait, and nothing that arrived meanwhile is lost`, async () => {
    const { ada, bob } = await pair();
    const heard = listening(bob.mind);
    await until(heard.isOpen);
    world.cut(TWO);
    await until(() => bob.waits.length === 1);
    const closed = heard.states.at(-1);
    expect(closed).toMatchObject({ state: "closed", url: socketOf(TWO, bob.mind), code: 1006 });
    const retryIn = closed?.state === "closed" ? closed.retryIn : 0;
    expect(retryIn).toBeGreaterThanOrEqual(500);
    expect(retryIn).toBeLessThanOrEqual(1000);
    expect(bob.waits[0]?.ms).toBe(retryIn);
    // A packet arrives while nothing listens.
    await ada.mind.send(hello(bob.mind.address, "While you were away."));
    expect(heard.inboxes).toStrictEqual([]);
    bob.waits[0]?.wake();
    await until(() => heard.bodies().length === 1);
    expect(heard.bodies()).toStrictEqual(["While you were away."]);
    expect(world.sockets).toHaveLength(2);
    expect(heard.states.map(({ state }) => state)).toStrictEqual([
      "connecting",
      "open",
      "closed",
      "connecting",
      "open",
    ]);
  });

  it("waits twice as long each time it cannot be opened, up to a longest wait, and starts over once it is welcomed", async () => {
    const { bob } = await pair();
    world.down(TWO);
    const heard = listening(bob.mind, { retryMs: 100, maxRetryMs: 350 });
    const bounds = [100, 200, 350, 350];
    for (const [turn, most] of bounds.entries()) {
      await until(() => bob.waits.length === turn + 1);
      const { ms } = bob.waits[turn] ?? { ms: 0 };
      expect(ms).toBeGreaterThanOrEqual(most / 2);
      expect(ms).toBeLessThanOrEqual(most);
      expect(heard.states.at(-1)).toMatchObject({ state: "closed", retryIn: ms });
      if (turn === bounds.length - 1) world.up(TWO);
      bob.waits[turn]?.wake();
    }
    await until(heard.isOpen);
    world.cut(TWO);
    await until(() => bob.waits.length === bounds.length + 1);
    expect(bob.waits.at(-1)?.ms).toBeLessThanOrEqual(100);
  });

  it("is not opened again once the mind stops listening, in the middle of a wait or of a connection", async () => {
    const { bob } = await pair();
    const heard = listening(bob.mind);
    await until(heard.isOpen);
    await heard.handle.close();
    await heard.handle.closed;
    expect(world.sockets).toHaveLength(1);
    expect(bob.waits).toStrictEqual([]);
    // In the middle of a wait: the wait is not sat out.
    world.down(TWO);
    const again = listening(bob.mind);
    await until(() => bob.waits.length === 1);
    await again.handle.close();
    expect(world.sockets).toHaveLength(2);
    // Closing twice is closing once.
    await again.handle.close();
  });

  it("waits by the platform's own timer where it is given none", async () => {
    const made = await freshKeystore(world, [A], { webSocket: world.socket });
    const mind = await Mind.create(made.options, { kind: "agent", homes: [TWO] });
    await mind.publishLocation();
    world.clock.at = at(160);
    const heard = listening(mind, { retryMs: 2, maxRetryMs: 4 });
    await until(heard.isOpen);
    world.cut(TWO);
    await until(() => world.sockets.length === 2 && heard.isOpen());
    expect(heard.states.map(({ state }) => state)).toStrictEqual([
      "connecting",
      "open",
      "closed",
      "connecting",
      "open",
    ]);
  });

  it(`${clause("L1 15.1")} tries each socket the mind names, in the order of their priority, one after another`, async () => {
    const { bob } = await pair();
    const id = mindId(bob.mind.address) ?? "";
    const elsewhere = `wss://host-three.example/oip/v1/minds/${id}/ws`;
    await bob.mind.publishLocation({
      endpoints: [
        { binding: "https", url: `${TWO}/oip/v1/minds/${id}`, priority: 2 },
        // Nothing answers at the one it prefers. One that states no priority has priority 0.
        { binding: "wss", url: elsewhere },
        { binding: "mailbox", url: mailboxOf(TWO, bob.mind), priority: 1 },
      ],
    });
    world.clock.at = at(170);
    const heard = listening(bob.mind);
    await until(() => bob.waits.length === 1);
    expect(heard.states).toMatchObject([
      { state: "connecting", url: elsewhere },
      { state: "closed", url: elsewhere, code: 1006 },
    ]);
    bob.waits[0]?.wake();
    await until(heard.isOpen);
    expect(heard.states.at(-1)).toStrictEqual({ state: "open", url: socketOf(TWO, bob.mind) });
  });

  it("is tried again where a socket could not even be made", async () => {
    let failed = false;
    const { bob } = await pair({
      webSocket: (url, protocol) => {
        if (!failed) {
          failed = true;
          throw new Error("no such scheme");
        }
        return world.socket(url, protocol);
      },
    });
    const heard = listening(bob.mind);
    await until(() => bob.waits.length === 1);
    const closed = heard.states.at(-1);
    expect(closed).toMatchObject({
      state: "closed",
      reason: "the connection could not be opened",
    });
    expect(closed).not.toHaveProperty("code");
    bob.waits[0]?.wake();
    await until(heard.isOpen);
  });

  it("is not opened again by a mind that stops listening when it is told the connection ended", async () => {
    const { bob } = await pair();
    const states: SocketState[] = [];
    const handle = bob.mind.listen({
      received: () => undefined,
      changed: (state) => {
        states.push(state);
        if (state.state === "closed") void handle.close();
      },
    });
    open.push(handle);
    await until(() => states.at(-1)?.state === "open");
    world.cut(TWO);
    await handle.closed;
    expect(states.map(({ state }) => state)).toStrictEqual(["connecting", "open", "closed"]);
    // And one that stops before it has even found where to connect opens nothing.
    const sockets = world.sockets.length;
    const brief = bob.mind.listen({ received: () => undefined });
    await brief.close();
    expect(world.sockets).toHaveLength(sockets);
  });

  it("ends when the mind is closed: with its keys locked it could acknowledge nothing", async () => {
    const { ada, bob } = await pair();
    const heard = listening(bob.mind);
    const other = listening(bob.mind);
    await until(() => heard.isOpen() && other.isOpen());
    await other.handle.close();
    bob.mind.close();
    await heard.handle.closed;
    expect(world.sockets).toHaveLength(2);
    // What is sent now waits with the host, for the mind that is opened again.
    await ada.mind.send(hello(bob.mind.address, "For the next time."));
    expect(heard.inboxes).toStrictEqual([]);
    world.clock.at = at(170);
    const again = await Mind.open(bob.options);
    expect((await again.receive()).received).toHaveLength(1);
    // One that ended by itself is not closed a second time.
    const failing = again.listen({
      received: () => {
        throw new Error("the application's own");
      },
    });
    await ada.mind.send(hello(bob.mind.address, "Once more."));
    await expect(failing.closed).rejects.toThrow("the application's own");
    again.close();
  });

  it("takes a wait for a whole number of milliseconds", async () => {
    const { bob } = await pair();
    const received = (): void => undefined;
    expect(() => bob.mind.listen({ received, retryMs: 0 })).toThrow(TypeError);
    expect(() => bob.mind.listen({ received, maxRetryMs: 1.5 })).toThrow(
      "a wait is a whole number of milliseconds, of at least 1",
    );
  });
});

describe("a mind with nowhere to listen", () => {
  it("looks again after a wait: it may have published where it is by then", async () => {
    world.host(ONE);
    const cyd = await at_(undefined);
    world.clock.at = at(160);
    const heard = listening(cyd.mind, { retryMs: 100 });
    await until(() => cyd.waits.length === 1);
    expect(heard.states).toMatchObject([{ state: "nowhere", retryIn: cyd.waits[0]?.ms }]);
    expect(world.sockets).toStrictEqual([]);
    // The resolver cannot be asked: that is nowhere too, for now.
    world.down(A);
    cyd.waits[0]?.wake();
    await until(() => cyd.waits.length === 2);
    expect(heard.states.at(-1)).toMatchObject({ state: "nowhere" });
    expect(cyd.waits[1]?.ms).toBeGreaterThanOrEqual(100);
    world.up(A);
    // And so is a resolver that serves what is no log of the mind.
    const real = world.at(A);
    world.put(
      A,
      () =>
        new Response(
          JSON.stringify({ oip: "1", type: "Bundle", mind: cyd.mind.address, log: [] }),
          {
            headers: { "content-type": MEDIA_TYPE },
          },
        ),
    );
    cyd.waits[1]?.wake();
    await until(() => cyd.waits.length === 3);
    expect(heard.states.at(-1)).toMatchObject({ state: "nowhere" });
    world.put(A, real);
  });

  it("ends the listening where what fails is nobody's answer", async () => {
    const made = await freshKeystore(world, [A], { webSocket: world.socket });
    const mind = await Mind.create(made.options, { kind: "agent", homes: [TWO] });
    mind.close();
    let opened = false;
    const again = await Mind.open({
      ...made.options,
      fetch: (request) =>
        opened
          ? Promise.resolve({
              status: 200,
              body: null,
              headers: {
                get: () => {
                  throw new RangeError("not a response");
                },
              },
            } as unknown as Response)
          : world.fetch(request),
    });
    opened = true;
    const handle = again.listen({ received: () => undefined });
    await expect(handle.closed).rejects.toThrow(RangeError);
  });

  it("listens while it is paused: its status is for those who send to it", async () => {
    const { ada, bob } = await pair();
    await bob.mind.publishLocation({ status: "paused" });
    world.clock.at = at(170);
    await ada.mind.send(hello(bob.mind.address, "For when you are back."));
    const heard = listening(bob.mind);
    await until(() => heard.bodies().length === 1);
    expect(world.sockets[0]?.url).toBe(socketOf(TWO, bob.mind));
  });
});

describe(`${clause("L1 13.4")} a host that does not keep to the binding`, () => {
  /** A socket whose other end is the test: what the client sends is kept, and the test speaks. */
  function staged() {
    const sent: string[] = [];
    const closed: { code: number | undefined; reason: string | undefined }[] = [];
    let socket: SocketLike | undefined;
    const webSocket = (): SocketLike => {
      const made: SocketLike = {
        onopen: null,
        onmessage: null,
        onclose: null,
        onerror: null,
        send: (text) => sent.push(text),
        close: (code, reason) => closed.push({ code, reason }),
      };
      socket = made;
      return made;
    };
    return {
      webSocket,
      sent,
      closed,
      say: (data: unknown) => socket?.onmessage?.({ data }),
      connected: () => socket !== undefined,
    };
  }
  const challenge = JSON.stringify({ type: "Challenge", nonce: "n".repeat(32), domain: TWO });

  it("is left where it does not begin with a challenge, or says what is no message", async () => {
    for (const [first, why] of [
      [JSON.stringify({ type: "Welcome" }), "the host did not begin with a challenge"],
      [JSON.stringify({ type: "Challenge" }), "the host did not begin with a challenge"],
      [JSON.stringify({ type: "Challenge", nonce: "" }), "the host did not begin with a challenge"],
      ["[1]", "the message is no JSON object"],
      ["not JSON", "the message is no JSON object"],
      [new Uint8Array(4), "the message is no text"],
      [" ".repeat(8 * 2 ** 20 + 1), "the message is larger than the client reads"],
    ] as const) {
      const stage = staged();
      const bob = await at_(TWO, { webSocket: stage.webSocket });
      const heard = listening(bob.mind);
      await until(stage.connected);
      stage.say(first);
      await until(() => bob.waits.length === 1);
      expect(stage.closed, why).toMatchObject([{ reason: why }]);
      expect(heard.states.at(-1)).toMatchObject({ state: "closed", reason: why });
      expect(stage.sent).toStrictEqual([]);
      await heard.handle.close();
    }
  }, 30_000);

  it(`${clause("L1 13.3")} is answered for the origin the client connected to, whatever it says its own is`, async () => {
    const stage = staged();
    const bob = await at_(TWO, { webSocket: stage.webSocket });
    listening(bob.mind);
    await until(stage.connected);
    stage.say(JSON.stringify({ type: "Challenge", nonce: "n".repeat(32), domain: ONE }));
    await until(() => stage.sent.length === 1);
    expect(parsed(stage.sent)[0]).toMatchObject({
      type: "Hello",
      proof: [{ challenge: "n".repeat(32), domain: TWO }],
    });
  });

  it("is left where it welcomes another mind, or none", async () => {
    for (const welcome of [
      { type: "Welcome", mind: new KeyMind("eve").address },
      { type: "Welcome" },
      { type: "Packet" },
    ]) {
      const stage = staged();
      const bob = await at_(TWO, { webSocket: stage.webSocket });
      const heard = listening(bob.mind);
      await until(stage.connected);
      stage.say(challenge);
      await until(() => stage.sent.length === 1);
      stage.say(JSON.stringify(welcome));
      await until(() => bob.waits.length === 1);
      expect(stage.closed).toMatchObject([
        { code: 1002, reason: "the host did not welcome the mind" },
      ]);
      expect(heard.states.map(({ state }) => state)).toStrictEqual(["connecting", "closed"]);
      await heard.handle.close();
    }
  }, 30_000);

  it("may end the connection without a word, or with an empty one", async () => {
    for (const [event, told] of [
      [{}, {}],
      [{ code: 1000, reason: "" }, { code: 1000 }],
      [{ code: 4401, reason: "the Hello does not authenticate a mind" }, { code: 4401 }],
    ] as const) {
      let socket: SocketLike | undefined;
      const bob = await at_(TWO, {
        webSocket: () => {
          socket = {
            onopen: null,
            onmessage: null,
            onclose: null,
            onerror: null,
            send: () => undefined,
            close: () => undefined,
          };
          return socket;
        },
      });
      const heard = listening(bob.mind);
      await until(() => socket !== undefined);
      socket?.onerror?.({});
      socket?.onclose?.(event);
      await until(() => bob.waits.length === 1);
      const closed = heard.states.at(-1);
      expect(closed).toMatchObject({ state: "closed", ...told });
      expect(closed !== undefined && "code" in closed).toBe("code" in told);
      expect(closed !== undefined && "reason" in closed).toBe(event.code === 4401);
      // A second close of the same connection is one too many, and changes nothing.
      socket?.onclose?.(event);
      expect(bob.waits).toHaveLength(1);
      await heard.handle.close();
    }
  }, 30_000);

  it("is left where the mind has no key to answer its challenge with", async () => {
    const stage = staged();
    const bob = await at_(TWO, { webSocket: stage.webSocket });
    const heard = listening(bob.mind);
    await until(stage.connected);
    // The mind is retired while the socket is open: its keys sign nothing more.
    await bob.mind.retire({ control: bob.lock });
    stage.say(challenge);
    await until(() => bob.waits.length === 1);
    expect(stage.closed).toMatchObject([
      { code: 1011, reason: "the mind has no key to answer with" },
    ]);
    expect(stage.sent).toStrictEqual([]);
    await heard.handle.close();
    // The same, where the connection has ended by the time that is known.
    const again = staged();
    const cyd = await at_(TWO, { webSocket: again.webSocket });
    const second = listening(cyd.mind);
    await until(again.connected);
    await cyd.mind.retire({ control: cyd.lock });
    again.say(challenge);
    again.say("not JSON");
    await until(() => cyd.waits.length === 1);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(again.closed).toMatchObject([{ reason: "the message is no JSON object" }]);
    await second.handle.close();
  });

  it("is told nothing after the connection has ended: an answer that comes late is not sent", async () => {
    const stage = staged();
    const bob = await at_(TWO, { webSocket: stage.webSocket });
    const heard = listening(bob.mind);
    await until(stage.connected);
    stage.say(challenge);
    // The connection ends while the Hello is being signed.
    stage.say("not JSON");
    await until(() => bob.waits.length === 1);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(stage.sent).toStrictEqual([]);
    await heard.handle.close();
  });
});

describe("what goes wrong on the mind's own side", () => {
  it("ends the listening where the application's own code throws, and says so", async () => {
    const { ada, bob } = await pair();
    await ada.mind.send(hello(bob.mind.address));
    world.clock.at = at(170);
    const handle = bob.mind.listen({
      received: () => {
        throw new Error("the application's own");
      },
    });
    await expect(handle.closed).rejects.toThrow("the application's own");
    // Nothing is opened again.
    expect(world.sockets).toHaveLength(1);
    await handle.close();
  });

  it("ends the listening with an error, whatever the application threw", async () => {
    const { ada, bob } = await pair();
    await ada.mind.send(hello(bob.mind.address));
    world.clock.at = at(170);
    const handle = bob.mind.listen({
      received: () => {
        // eslint-disable-next-line @typescript-eslint/only-throw-error -- An application may.
        throw "a word, and no error";
      },
    });
    await expect(handle.closed).rejects.toThrow("a word, and no error");
  });

  it("ends the listening where the client fails in a way it does not know", async () => {
    const { ada, bob } = await pair();
    const heard = listening(bob.mind);
    await until(heard.isOpen);
    // The client's memory fails when the packet arrives, and not as a storage says it fails.
    bob.memory.put = () => Promise.reject(new Error("the disk is gone"));
    world.clock.at = at(170);
    await ada.mind.send(hello(bob.mind.address));
    await expect(heard.handle.closed).rejects.toThrow("the disk is gone");
    expect(bob.waits).toStrictEqual([]);
  });

  it("opens the connection again where another process of the mind was ahead, and reads afresh", async () => {
    const { ada, bob } = await pair();
    const { id } = await ada.mind.openSession([bob.mind.address]);
    const heard = listening(bob.mind);
    await until(heard.isOpen);
    // Where the session stands was written by another process since this one read it, once.
    const put = bob.memory.put.bind(bob.memory);
    bob.memory.put = (name, value, expected) => {
      if (!name.startsWith("client-ses-")) return put(name, value, expected);
      bob.memory.put = put;
      return Promise.reject(new KeystoreError("changed", "another process wrote it"));
    };
    world.clock.at = at(170);
    await ada.mind.send({ ...hello(bob.mind.address, "Read twice, told once."), session: id });
    await until(() => bob.waits.length === 1);
    expect(heard.states.at(-1)).toMatchObject({ state: "closed", reason: "changed" });
    expect(heard.inboxes).toStrictEqual([]);
    // The host was not told the mind has the packet, and sends it again.
    bob.waits[0]?.wake();
    await until(() => heard.bodies().length === 1);
    expect(heard.bodies()).toStrictEqual(["Read twice, told once."]);
  });

  it("opens the connection again where a resolver could not be asked for its own location", async () => {
    const { ada, bob } = await pair();
    const heard = listening(bob.mind);
    await until(heard.isOpen);
    // What the session asks for needs the resolver, which is gone when the packets come.
    const { id } = await ada.mind.openSession([bob.mind.address]);
    await ada.mind.send({ ...hello(bob.mind.address, "One."), session: id });
    await until(() => heard.bodies().length === 1);
    world.down(TWO);
    await ada.mind.send({ ...hello(bob.mind.address, "Two."), session: id });
    world.up(TWO);
    world.down(A);
    world.clock.at = at(170);
    const posted = await world.direct(
      new Request(mailboxOf(TWO, bob.mind), {
        method: "POST",
        headers: { "content-type": MEDIA_TYPE },
        body: JSON.stringify(
          await ada.mind.sign({
            oip: "1",
            type: "Packet",
            from: ada.mind.address,
            to: [bob.mind.address],
            created: T(170),
            nonce: "a-nonce-of-ada",
            session: id,
            seq: 2,
            prev: (await ada.mind.sessions())[0]?.id,
            purpose: { verb: "inform" },
            content: { mediaType: "text/plain", body: "Three." },
          }),
        ),
      }),
    );
    expect(posted.status).toBe(202);
    await until(() => heard.inboxes.some((inbox) => inbox.waiting > 0));
    world.up(A);
  });

  it("needs a WebSocket: the platform's, or one it is given", async () => {
    const platform = (globalThis as { WebSocket?: unknown }).WebSocket;
    const made = await freshKeystore(world, [A], {});
    const mind = await Mind.create(made.options, { kind: "agent", homes: [TWO] });
    try {
      (globalThis as { WebSocket?: unknown }).WebSocket = undefined;
      const handle = mind.listen({ received: () => undefined });
      await expect(handle.closed).rejects.toThrow(
        "this platform has no WebSocket: give the client one, as `webSocket`",
      );
      // The platform's own is used where there is one.
      const opened: string[][] = [];
      (globalThis as { WebSocket?: unknown }).WebSocket = class {
        onclose: ((event: object) => void) | null = null;
        constructor(url: string, protocol: string) {
          opened.push([url, protocol]);
        }
        close(): void {
          // Nothing to close.
        }
      };
      const again = mind.listen({ received: () => undefined });
      await until(() => opened.length === 1);
      expect(opened).toStrictEqual([[socketOf(TWO, mind), "oip.v1"]]);
      await again.close();
    } finally {
      (globalThis as { WebSocket?: unknown }).WebSocket = platform;
    }
  });
});
