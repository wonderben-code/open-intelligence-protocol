// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The Host profile over the wire (Layer 1, Section 13): the well-known
 * resources, the inbox, the WebSocket binding and, where the host keeps
 * one, the mailbox.
 */

import {
  base64urlToBytes,
  contentId,
  formatRecordRef,
  type JsonObject,
  problemCode,
} from "@oip/core";
import { sealPacket, verifyAck } from "@oip/net";

import { authenticationChecks } from "./authentication.ts";
import type { WireAnswer, WireFrame, WireOptions, WireSocket } from "./client.ts";
import { describe, expectProblem, expectRefused, expectStatus, WireClient } from "./client.ts";
import { second, WireMind, word } from "./minds.ts";
import {
  expect,
  Failed,
  need,
  NotApplicable,
  present,
  Recorder,
  Skipped,
  type WireReport,
} from "./report.ts";
import { expectLog, isObject, recordOf, same, verifies } from "./shapes.ts";
import { Verifier } from "./verifier.ts";

/**
 * What a host does in a way of its own, because the specification leaves it
 * to the host: how a mind comes to be served, where its endpoints are, and
 * how it brings the host the records the host serves for it.
 */
export interface HostSetup {
  /**
   * Has the host serve a mind: its bundle at the well-known path, and its
   * endpoints.
   *
   * @throws If the host does not take the mind on.
   */
  adopt(mind: WireMind, bundle: object): Promise<void>;
  /**
   * The base URL of the mind's `https` endpoint (Layer 1, 15.1), under the
   * host's own origin: the inbox is at `{url}/inbox` and the WebSocket at `{url}/ws`.
   */
  endpoint(mind: WireMind): string;
  /** The mind's mailbox URL (13.5) under the host's own origin, or `undefined` if the host keeps no mailboxes. */
  mailbox(mind: WireMind): string | undefined;
  /** Has the host serve a record at the mind's `obj/<contentId>`. */
  keep(mind: WireMind, record: object): Promise<void>;
  /** Has the host serve entries of the mind's feed, which follow the ones it has. */
  append(mind: WireMind, entries: readonly object[]): Promise<void>;
}

/** What the Host profile is given besides what every profile is. */
export interface HostOptions extends WireOptions {
  /**
   * How the suite sets the host up. Unless given, the reference host's own
   * interface: `referenceHostSetup`.
   */
  readonly setup?: (client: WireClient) => HostSetup;
}

/**
 * The interface of the reference host, `@oip/host`, which takes on any mind
 * that brings its bundle when it runs with `OIP_HOST_OPEN` set. A mind signs
 * each request (Layer 1, 13.3):
 *
 * - `PUT /oip/v1/minds/<mindId>` with its `Bundle`;
 * - `PUT /oip/v1/minds/<mindId>/obj/<contentId>` with a record;
 * - `POST /oip/v1/minds/<mindId>/feed` with a `FeedPage` of new entries.
 *
 * Its endpoint is `/oip/v1/minds/<mindId>`, and its mailbox is `mailbox` under that.
 */
export function referenceHostSetup(client: WireClient): HostSetup {
  const base = (mind: WireMind): string => `/oip/v1/minds/${mind.id}`;
  const done = (answer: WireAnswer, what: string): void => {
    if (answer.status < 200 || answer.status > 299) {
      throw new Error(`${what}: ${describe(answer)}`);
    }
  };
  return {
    adopt: async (mind, bundle) => {
      done(await client.ask("PUT", base(mind), { body: bundle, signedBy: mind }), "the bundle");
    },
    endpoint: (mind) => `${client.origin}${base(mind)}`,
    mailbox: (mind) => `${client.origin}${base(mind)}/mailbox`,
    keep: async (mind, record) => {
      const path = `${base(mind)}/obj/${contentId(record)}`;
      done(await client.ask("PUT", path, { body: record, signedBy: mind }), "a record");
    },
    append: async (mind, entries) => {
      const page = { oip: "1", type: "FeedPage", mind: mind.address, entries };
      done(
        await client.ask("POST", `${base(mind)}/feed`, { body: page, signedBy: mind }),
        "feed entries",
      );
    },
  };
}

const HOUR = 3_600_000_000_000n;
const SUBPROTOCOL = "oip.v1";

/** The message of a frame as JSON, or `undefined` if the frame is a close or no JSON object. */
function messageOf(frame: WireFrame | undefined): JsonObject | undefined {
  if (frame === undefined || !("message" in frame)) return undefined;
  try {
    const value = JSON.parse(frame.message) as unknown;
    return isObject(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

/** A frame in a line, for the detail of a failure. */
function told(frame: WireFrame | undefined): string {
  if (frame === undefined) return "nothing";
  return "message" in frame
    ? `the message ${frame.message.slice(0, 200)}`
    : `a close with code ${frame.closed} and reason "${frame.reason}"`;
}

/**
 * Runs the Host profile against a host. It has the host take on a few minds
 * of its own, so it is run against a deployment that may serve them.
 */
export async function hostProfile(options: HostOptions): Promise<WireReport> {
  const client = new WireClient(options);
  const setup = (options.setup ?? referenceHostSetup)(client);
  const suite = new Recorder("host");
  const verifier = new Verifier();
  const started = client.now();
  const stamp = (): string => second(client.now());
  const fresh = (): WireMind => WireMind.create(client.random, stamp());
  const wellKnown = (mind: WireMind): string => `/.well-known/oip/mind/${mind.id}`;
  /** A path of the host from a URL the setup gave, which is under the host's origin. */
  const pathOf = (url: string): string => {
    const path = client.pathOf(url);
    if (path === undefined) {
      throw new Skipped(`the suite asks one origin, ${client.origin}, and ${url} is at another`);
    }
    return path;
  };

  // The mind the host serves, with a log of three events; one that sends to it; one nobody knows.
  const owner = fresh();
  owner.update(stamp());
  owner.update(stamp());
  const sender = fresh();
  const stranger = fresh();
  const endpoint = (): string => pathOf(setup.endpoint(owner));

  /** A packet from one mind to others, signed by its sender. */
  const packet = (from: WireMind, to: readonly string[], more: JsonObject = {}) =>
    from.sign({
      oip: "1",
      type: "Packet",
      from: from.address,
      to,
      created: stamp(),
      expires: second(client.now() + HOUR),
      nonce: word(client.random),
      purpose: { verb: "inform" },
      content: { mediaType: "text/plain", body: `conformance ${word(client.random)}` },
      ...more,
    });
  /** The same packet with the signature of another: well formed, and not signed. */
  const forged = (from: WireMind, to: readonly string[]) => {
    const [one, other] = [packet(from, to), packet(from, to)];
    return {
      ...one,
      proof: [{ ...present(one.proof[0]), proofValue: present(other.proof[0]).proofValue }],
    };
  };
  const deliver = (record: unknown): Promise<WireAnswer> =>
    client.ask("POST", `${endpoint()}/inbox`, { body: record });

  const adopted = await suite.check(
    {
      id: "bundle",
      clauses: ["L1 13.1", "core 10.1"],
      title: "A mind the host serves has its Bundle at the well-known path",
    },
    async () => {
      try {
        await setup.adopt(owner, owner.bundle());
        await setup.adopt(sender, sender.bundle());
      } catch (error) {
        throw new Skipped(
          `the suite could not have the host take its minds on: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
      verifier.holds(owner, client.now());
      verifier.holds(sender, client.now());
      const bundle = recordOf(
        await client.ask("GET", wellKnown(owner)),
        200,
        "Bundle",
        "a mind served",
      );
      expect(bundle["mind"] === owner.address, "the bundle is of the mind asked after");
      expectLog(bundle["log"], owner.events, "a mind served");
      expect(verifies(bundle["log"], client.now()), "the log that is served verifies");
      return true as const;
    },
  );

  await suite.check(
    {
      id: "unknown-mind",
      clauses: ["L1 13.1", "core 10.2"],
      title: "A mind the host does not serve is answered 404",
    },
    async () => {
      expectProblem(await client.ask("GET", wellKnown(stranger)), "not-found", "a mind not served");
    },
  );

  await suite.check(
    {
      id: "log-page",
      clauses: ["L1 13.1"],
      title: "The log is served in pages: after is exclusive, and next leads to the following page",
    },
    async () => {
      need(adopted, "a mind the host serves");
      const page = async (query: string, when: string): Promise<JsonObject> => {
        const answer = await client.ask("GET", `${wellKnown(owner)}/log${query}`);
        const body = recordOf(answer, 200, "LogPage", when);
        expect(body["mind"] === owner.address, `${when}: the page is of the mind asked after`);
        return body;
      };
      const whole = await page("", "the log without after");
      expectLog(whole["events"], owner.events, "the log without after starts at seq 0");
      const first = await page("?limit=2", "the first page of two events");
      expectLog(first["events"], owner.events.slice(0, 2), "the first page of two events");
      expect(
        typeof first["next"] === "number" || typeof first["next"] === "string",
        `a page that is not the last gives next; got ${JSON.stringify(first["next"])}`,
      );
      const rest = await page(`?after=${String(first["next"])}&limit=2`, "the page after next");
      expectLog(rest["events"], owner.events.slice(2), "the page after next");
      expect(rest["next"] === undefined, "the last page gives no next");
      const after = await page("?after=0", "the log after seq 0");
      expectLog(after["events"], owner.events.slice(1), "after is exclusive");
    },
  );

  // Three records the mind publishes, and a feed that lists them.
  const profile = (name: string, more: JsonObject = {}) =>
    owner.sign({
      oip: "1",
      type: "Participant",
      author: owner.address,
      created: stamp(),
      name,
      kind: "agent",
      ...more,
    });
  const first = profile("Conformance mind");
  const published: object[] = [
    first,
    profile("Conformance mind, renamed", {
      supersedes: formatRecordRef(owner.address, contentId(first)),
    }),
    profile("Conformance mind, renamed again"),
  ];
  const entries: object[] = [];
  for (const [seq, record] of published.entries()) {
    entries.push(
      owner.sign({
        oip: "1",
        type: "Entry",
        author: owner.address,
        seq,
        ...(seq === 0 ? {} : { prev: contentId(present(entries[seq - 1])) }),
        created: stamp(),
        object: contentId(record),
        objectType: "Participant",
      }),
    );
  }

  const fed = await suite.check(
    {
      id: "feed-page",
      clauses: ["L1 13.1", "L1 10.1"],
      title:
        "The feed is served in pages: after is exclusive, and next leads to the following page",
    },
    async () => {
      need(adopted, "a mind the host serves");
      try {
        for (const record of published) await setup.keep(owner, record);
        await setup.append(owner, entries);
      } catch (error) {
        throw new Skipped(
          `the suite could not bring the host a feed: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
      const page = async (query: string, when: string): Promise<JsonObject> => {
        const answer = await client.ask("GET", `${wellKnown(owner)}/feed${query}`);
        const body = recordOf(answer, 200, "FeedPage", when);
        expect(body["mind"] === owner.address, `${when}: the page is of the mind asked after`);
        return body;
      };
      const whole = await page("", "the feed without after");
      expectLog(whole["entries"], entries, "the feed without after starts at seq 0");
      const one = await page("?limit=2", "the first page of two entries");
      expectLog(one["entries"], entries.slice(0, 2), "the first page of two entries");
      expect(
        typeof one["next"] === "number" || typeof one["next"] === "string",
        `a page that is not the last gives next; got ${JSON.stringify(one["next"])}`,
      );
      const rest = await page(`?after=${String(one["next"])}&limit=2`, "the page after next");
      expectLog(rest["entries"], entries.slice(2), "the page after next");
      expect(rest["next"] === undefined, "the last page gives no next");
      return true;
    },
  );

  await suite.check(
    {
      id: "object",
      clauses: ["L1 13.1", "L1 10.2"],
      title: "Every record a feed lists is served by its content ID",
    },
    async () => {
      need(fed, "a feed the host serves");
      for (const record of published) {
        const answer = await client.ask("GET", `${wellKnown(owner)}/obj/${contentId(record)}`);
        const served = recordOf(answer, 200, "Participant", "a record the feed lists");
        expect(same(served, record), "the record is served as it was signed");
      }
      expectProblem(
        await client.ask("GET", `${wellKnown(owner)}/obj/${contentId(stranger.genesis)}`),
        "not-found",
        "a record the host does not serve",
      );
    },
  );

  /**
   * Requires that an answer takes a packet: 202 with the recipient's `Ack`
   * for it, or with `{ "stored": true }` from a host that does not sign for the mind.
   */
  const expectTaken = (answer: WireAnswer, id: string, when: string, sealed?: string): void => {
    expectStatus(answer, 202, when);
    const body = answer.json;
    expect(
      isObject(body),
      `${when}: the answer is an Ack or { "stored": true }; got ${describe(answer)}`,
    );
    if (body["type"] !== "Ack") {
      expect(
        body["stored"] === true,
        `${when}: the answer is an Ack or { "stored": true }; got ${describe(answer)}`,
      );
      return;
    }
    // A verifier judges a proof by a log it obtained no earlier than its evidence for the
    // proof (core 9.4). The suite made the log, so it holds it as of now.
    const now = client.now();
    verifier.holds(owner, now);
    const ack = verifyAck(body, { view: verifier.book, seen: verifier.seen, now });
    expect(
      ack.ok && ack.value.recipient === owner.address,
      `${when}: an Ack is signed by a valid operational key of the recipient${
        ack.ok ? "" : ` (${ack.issues[0].message})`
      }; got ${describe(answer)}`,
    );
    expect(body["packet"] === id, `${when}: an Ack names the packet by its content ID`);
    if (sealed !== undefined) {
      expect(body["sealed"] === sealed, `${when}: an Ack for a Sealed record names it in sealed`);
    }
  };

  const sent = packet(sender, [owner.address]);
  const taken = await suite.check(
    {
      id: "inbox",
      clauses: ["L1 13.2"],
      title: "A packet delivered to the inbox is answered 202, with an Ack or as stored",
    },
    async () => {
      need(adopted, "a mind the host serves");
      const answer = await deliver(sent);
      expectTaken(answer, contentId(sent), "a packet to the mind");
      return answer;
    },
  );

  await suite.check(
    {
      id: "inbox-duplicate",
      clauses: ["L1 13.2", "L1 12.4"],
      title: "A packet delivered again is answered 202 with the same acknowledgement",
    },
    async () => {
      const before = need(taken, "a packet the inbox took");
      const again = await deliver(sent);
      expectStatus(again, 202, "the same packet again");
      expect(
        same(again.json, before.json),
        `a duplicate is answered as the packet was; got ${describe(again)} after ${describe(before)}`,
      );
    },
  );

  await suite.check(
    {
      id: "inbox-unsigned",
      clauses: ["L1 12.4", "core 10.2"],
      title: "A packet whose proof does not verify is refused as an invalid proof",
    },
    async () => {
      need(adopted, "a mind the host serves");
      expectProblem(
        await deliver(forged(sender, [owner.address])),
        "invalid-proof",
        "a packet with the signature of another",
      );
    },
  );

  await suite.check(
    {
      id: "inbox-of-another",
      clauses: ["L1 12.4"],
      title: "A packet that is not addressed to the mind is refused",
    },
    async () => {
      need(adopted, "a mind the host serves");
      expectRefused(
        await deliver(packet(sender, [stranger.address])),
        "a packet addressed to another mind",
      );
    },
  );

  await suite.check(
    {
      id: "inbox-expired",
      clauses: ["L1 12.4", "core 10.2"],
      title: "A packet that expired more than 300 seconds ago is refused as expired",
    },
    async () => {
      need(adopted, "a mind the host serves");
      const old = packet(sender, [owner.address], {
        created: second(client.now() - 3n * HOUR),
        expires: second(client.now() - HOUR),
      });
      expectProblem(await deliver(old), "expired", "a packet that expired an hour ago");
    },
  );

  await suite.check(
    {
      id: "inbox-dates",
      clauses: ["L1 12.4", "L1 12.1"],
      title: "A packet from the future, or one that lives more than 7 days, is refused",
    },
    async () => {
      need(adopted, "a mind the host serves");
      const ahead = packet(sender, [owner.address], {
        created: second(client.now() + HOUR),
        expires: second(client.now() + 2n * HOUR),
      });
      expectRefused(await deliver(ahead), "a packet created an hour in the future");
      const long = packet(sender, [owner.address], {
        expires: second(client.now() + 8n * 24n * HOUR),
      });
      expectRefused(await deliver(long), "a packet that expires 8 days after it was created");
    },
  );

  await suite.check(
    {
      id: "inbox-malformed",
      clauses: ["L1 13.2", "core 10.2", "core 1.6"],
      title: "What is not a Packet, a Sealed or a Forwarded record is refused as an invalid record",
    },
    async () => {
      need(adopted, "a mind the host serves");
      expectProblem(
        await deliver('{"oip":"1","type":"Packet",'),
        "invalid-record",
        "a body cut short",
      );
      expectProblem(await deliver(first), "invalid-record", "a Participant record");
      const { nonce: _, ...lacking } = packet(sender, [owner.address]);
      expectProblem(await deliver(lacking), "invalid-record", "a packet without a nonce");
      const large = {
        ...packet(sender, [owner.address]),
        content: { mediaType: "text/plain", body: "x".repeat(1024 * 1024 + 1) },
      };
      expectProblem(await deliver(large), "too-large", "a packet of more than 1 MiB");
    },
  );

  await suite.check(
    {
      id: "inbox-sealed",
      clauses: ["L1 13.2", "L1 12.6"],
      title: "A Sealed record delivered to the inbox is answered 202",
    },
    async () => {
      need(adopted, "a mind the host serves");
      const inner = packet(sender, [owner.address]);
      const sealed = await sealPacket({
        packet: inner,
        to: owner.address,
        view: verifier.book,
        randomness: client.random(32),
      });
      if (!sealed.ok) throw new TypeError("the suite could not seal a packet to its own mind");
      expectTaken(
        await deliver(sealed.value),
        contentId(inner),
        "a Sealed record to the mind",
        contentId(sealed.value),
      );
    },
  );

  await mailboxChecks(suite, client, {
    adopted,
    path: () => {
      const url = setup.mailbox(owner);
      if (url === undefined) throw new NotApplicable("the host keeps no mailboxes (13.5)");
      return pathOf(url);
    },
    owner,
    sender,
    stranger,
    packet: () => packet(sender, [owner.address]),
    forged: () => forged(sender, [owner.address]),
  });

  await socketChecks(suite, client, {
    adopted,
    path: () => `${endpoint()}/ws`,
    mailbox: () => {
      const url = setup.mailbox(owner);
      if (url === undefined) throw new NotApplicable("the host keeps no mailboxes (13.5)");
      return pathOf(url);
    },
    owner,
    sender,
    packet: () => packet(sender, [owner.address]),
    forged: () => forged(sender, [owner.address]),
    stamp,
  });

  return suite.report(client.target, started, client.now());
}

/** The items of a drained mailbox, as 13.5 gives them. */
function itemsOf(answer: WireAnswer, when: string): { cursor: string; record: unknown }[] {
  const body = answer.json;
  expect(
    answer.status === 200 && isObject(body) && Array.isArray(body["items"]),
    `${when}: required 200 with { "items": [...] }; got ${describe(answer)}`,
  );
  return (body["items"] as unknown[]).map((item) => {
    expect(
      isObject(item) && typeof item["cursor"] === "string" && isObject(item["record"]),
      `${when}: an item is { "cursor": <string>, "record": <record> }; got ${JSON.stringify(item)}`,
    );
    return { cursor: item["cursor"], record: item["record"] };
  });
}

/** The mailbox of 13.5, for a host that keeps one. */
async function mailboxChecks(
  suite: Recorder,
  client: WireClient,
  given: {
    readonly adopted: true | undefined;
    /** The path of the owner's mailbox. It throws `NotApplicable` if the host keeps none. */
    readonly path: () => string;
    readonly owner: WireMind;
    readonly sender: WireMind;
    readonly stranger: WireMind;
    readonly packet: () => object;
    readonly forged: () => object;
  },
): Promise<void> {
  const { owner } = given;
  const drain = async (query = ""): Promise<WireAnswer> =>
    client.ask("GET", `${given.path()}${query}`, { signedBy: owner });
  /** Reads the whole mailbox, page after page. */
  const everything = async (when: string): Promise<{ cursor: string; record: unknown }[]> => {
    const all: { cursor: string; record: unknown }[] = [];
    let query = "";
    for (let pages = 0; pages < 1000; pages++) {
      const answer = await drain(query);
      all.push(...itemsOf(answer, when));
      const next = (answer.json as JsonObject)["next"];
      if (typeof next !== "string") return all;
      query = `?after=${encodeURIComponent(next)}`;
    }
    throw new Failed(`${when}: the mailbox gives a next page without end`);
  };

  const [one, two] = [given.packet(), given.packet()];
  const posted = await suite.check(
    {
      id: "mailbox-post",
      clauses: ["L1 13.5"],
      title: 'A record posted to a mailbox is answered 202 with { "stored": true }',
    },
    async () => {
      const path = given.path();
      need(given.adopted, "a mind the host serves");
      for (const record of [one, two]) {
        const answer = await client.ask("POST", path, { body: record });
        expect(
          answer.status === 202 && isObject(answer.json) && answer.json["stored"] === true,
          `required 202 with { "stored": true }; got ${describe(answer)}`,
        );
      }
      return true;
    },
  );

  await suite.check(
    {
      id: "mailbox-unjudged",
      clauses: ["L1 13.5"],
      level: "SHOULD",
      title: "A mailbox does not judge what it stores: a packet it could not verify is stored",
    },
    async () => {
      const path = given.path();
      need(posted, "a mailbox that took a record");
      const answer = await client.ask("POST", path, { body: given.forged() });
      expect(
        answer.status === 202 && isObject(answer.json) && answer.json["stored"] === true,
        `a packet with the signature of another is stored for its owner to judge; got ${describe(answer)}`,
      );
    },
  );

  const drained = await suite.check(
    {
      id: "mailbox-drain",
      clauses: ["L1 13.5", "L1 13.3"],
      title:
        "The owner drains its mailbox with a signed request, and gets what was posted in order",
    },
    async () => {
      given.path();
      need(posted, "a mailbox that took a record");
      const items = await everything("the owner's signed GET");
      const at = [one, two].map((record) => items.findIndex((item) => same(item.record, record)));
      expect(
        at.every((index) => index !== -1),
        "the mailbox holds each record that was posted, as it was posted",
      );
      expect(present(at[0]) < present(at[1]), "the items are in the order they were posted");
      expect(
        new Set(items.map((item) => item.cursor)).size === items.length,
        "each item has a cursor of its own",
      );
      return items;
    },
  );

  await suite.check(
    {
      id: "mailbox-after",
      clauses: ["L1 13.5"],
      title: "A drain from a cursor gives the items after it",
    },
    async () => {
      given.path();
      const items = need(drained, "a drained mailbox");
      const at = items.findIndex((item) => same(item.record, one));
      const from = present(items[at]).cursor;
      const answer = await drain(`?after=${encodeURIComponent(from)}`);
      const rest = itemsOf(answer, "a drain after a cursor");
      expect(
        same(rest[0], items[at + 1]),
        `after cursor ${from} comes the item that followed it; got ${JSON.stringify(rest[0]?.cursor)}`,
      );
    },
  );

  if (given.adopted === true) {
    await authenticationChecks(suite, client, {
      name: "mailbox",
      what: "Draining a mailbox",
      clause: "L1 13.5",
      request: () => ({ method: "GET", path: given.path(), signer: owner }),
      taken: (answer) => answer.status === 200,
      withBody: false,
      stranger: given.stranger,
    });
  }

  await suite.check(
    {
      id: "mailbox-of-another",
      clauses: ["L1 13.5", "L1 13.3", "core 10.2"],
      title: "A mind that is not the owner may not drain the mailbox",
    },
    async () => {
      const path = given.path();
      need(posted, "a mailbox that took a record");
      expectProblem(
        await client.ask("GET", path, { signedBy: given.sender }),
        "forbidden",
        "a drain signed by another mind the host knows",
      );
    },
  );

  await suite.check(
    {
      id: "mailbox-remove",
      clauses: ["L1 13.5", "L1 13.3"],
      title: "The owner removes an item with a signed DELETE, and nobody else does",
    },
    async () => {
      const mailbox = given.path();
      const items = need(drained, "a drained mailbox");
      const item = present(items.find((held) => same(held.record, one)));
      const path = `${mailbox}/${encodeURIComponent(item.cursor)}`;
      expectProblem(await client.ask("DELETE", path), "unauthorised", "an unsigned DELETE");
      expectProblem(
        await client.ask("DELETE", path, { signedBy: given.sender }),
        "forbidden",
        "a DELETE signed by another mind",
      );
      const answer = await client.ask("DELETE", path, { signedBy: owner });
      expect(
        answer.status >= 200 && answer.status <= 299,
        `the owner's signed DELETE is taken; got ${describe(answer)}`,
      );
      const left = await everything("a drain after a DELETE");
      expect(
        !left.some((held) => held.cursor === item.cursor || same(held.record, one)),
        "an item that was removed is in the mailbox no longer",
      );
      expect(
        left.some((held) => same(held.record, two)),
        "an item that was not removed is still there",
      );
    },
  );
}

/** The WebSocket binding of 13.4. */
async function socketChecks(
  suite: Recorder,
  client: WireClient,
  given: {
    readonly adopted: true | undefined;
    /** The path of the WebSocket of the owner's endpoint. */
    readonly path: () => string;
    /** The path of the owner's mailbox. It throws `NotApplicable` if the host keeps none. */
    readonly mailbox: () => string;
    readonly owner: WireMind;
    readonly sender: WireMind;
    readonly packet: () => object;
    readonly forged: () => object;
    readonly stamp: () => string;
  },
): Promise<void> {
  const { owner, sender, stamp } = given;
  /** A `Hello` of a mind for a challenge (13.3). */
  const hello = (mind: WireMind, challenge: string, domain = client.origin): string =>
    JSON.stringify(
      mind.sign(
        { oip: "1", type: "Hello", author: mind.address, created: stamp() },
        { challenge, domain },
      ),
    );
  /** Opens the socket and reads the challenge. */
  const opened = async (): Promise<{ socket: WireSocket; nonce: string }> => {
    need(given.adopted, "a mind the host serves");
    const socket = await client.socket(given.path(), SUBPROTOCOL);
    const frame = await socket.next();
    const challenge = messageOf(frame);
    if (challenge?.["type"] !== "Challenge" || typeof challenge["nonce"] !== "string") {
      socket.close();
      throw new Failed(
        `the server's first message is a Challenge with a nonce; got ${told(frame)}`,
      );
    }
    return { socket, nonce: challenge["nonce"] };
  };
  /** Opens the socket and authenticates a mind. */
  const welcomed = async (mind: WireMind): Promise<WireSocket> => {
    const { socket, nonce } = await opened();
    socket.send(hello(mind, nonce));
    const frame = await socket.next();
    const welcome = messageOf(frame);
    if (welcome?.["type"] !== "Welcome" || welcome["mind"] !== mind.address) {
      socket.close();
      throw new Failed(
        `a Hello is answered with a Welcome that names the mind; got ${told(frame)}`,
      );
    }
    return socket;
  };
  /** Requires that the next frame is a close with a code. */
  const expectClosed = async (socket: WireSocket, code: number, when: string): Promise<string> => {
    const frame = await socket.next();
    expect(
      frame !== undefined && "closed" in frame && frame.closed === code,
      `${when}: the server closes with code ${code}; got ${told(frame)}`,
    );
    return frame.reason;
  };

  await suite.check(
    {
      id: "socket-challenge",
      clauses: ["L1 13.4"],
      title:
        "The server speaks first: a Challenge with a nonce of at least 16 bytes and its origin",
    },
    async () => {
      need(given.adopted, "a mind the host serves");
      const socket = await client.socket(given.path(), SUBPROTOCOL);
      try {
        expect(
          socket.protocol === SUBPROTOCOL,
          `the subprotocol is ${SUBPROTOCOL}; got "${socket.protocol}"`,
        );
        const frame = await socket.next();
        const challenge = messageOf(frame);
        const nonce = challenge?.["nonce"];
        expect(
          challenge?.["type"] === "Challenge" && typeof nonce === "string",
          `the server's first message is a Challenge with a nonce; got ${told(frame)}`,
        );
        const bytes = base64urlToBytes(nonce)?.length ?? 0;
        expect(bytes >= 16, `the nonce is base64url of at least 16 bytes; got "${nonce}"`);
        expect(
          challenge["domain"] === client.origin,
          `the challenge names the origin ${client.origin}; got ${JSON.stringify(challenge["domain"])}`,
        );
      } finally {
        socket.close();
      }
    },
  );

  await suite.check(
    {
      id: "socket-welcome",
      clauses: ["L1 13.4", "L1 13.3"],
      title: "A Hello that answers the challenge is welcomed, with the address of the mind",
    },
    async () => {
      (await welcomed(owner)).close();
    },
  );

  await suite.check(
    {
      id: "socket-wrong-challenge",
      clauses: ["L1 13.4", "L1 13.3"],
      title: "A Hello for a challenge the server did not issue closes the connection with 4401",
    },
    async () => {
      const { socket } = await opened();
      try {
        socket.send(hello(owner, word(client.random, 16)));
        await expectClosed(socket, 4401, "a Hello with a challenge of the client's own");
      } finally {
        socket.close();
      }
    },
  );

  await suite.check(
    {
      id: "socket-wrong-domain",
      clauses: ["L1 13.4", "L1 13.3"],
      title: "A Hello whose domain is not the server's origin closes the connection with 4401",
    },
    async () => {
      const { socket, nonce } = await opened();
      try {
        socket.send(hello(owner, nonce, "https://elsewhere.invalid"));
        await expectClosed(socket, 4401, "a Hello made for another origin");
      } finally {
        socket.close();
      }
    },
  );

  await suite.check(
    {
      id: "socket-challenge-once",
      clauses: ["L1 13.4", "L1 13.3"],
      title: "A Hello that was used before closes the connection with 4401",
    },
    async () => {
      const one = await opened();
      const two = await opened();
      try {
        const used = hello(owner, one.nonce);
        one.socket.send(used);
        const welcome = messageOf(await one.socket.next());
        expect(welcome?.["type"] === "Welcome", "a Hello that answers the challenge is welcomed");
        two.socket.send(used);
        await expectClosed(two.socket, 4401, "the same Hello on a second connection");
      } finally {
        one.socket.close();
        two.socket.close();
      }
    },
  );

  await suite.check(
    {
      id: "socket-no-hello",
      clauses: ["L1 13.4"],
      title: "A record sent before the Hello closes the connection with 4401",
    },
    async () => {
      const { socket } = await opened();
      try {
        socket.send(JSON.stringify(given.packet()));
        await expectClosed(socket, 4401, "a packet where a Hello is due");
      } finally {
        socket.close();
      }
    },
  );

  await suite.check(
    {
      id: "socket-deliver",
      clauses: ["L1 13.4", "L1 13.2"],
      title: "A packet sent over the socket is delivered as at the inbox",
    },
    async () => {
      const socket = await welcomed(sender);
      try {
        const record = given.packet();
        socket.send(JSON.stringify(record));
        // The server may send back the Ack, and need send nothing. It does not close.
        const frame = await socket.next(1000);
        expect(
          frame === undefined || "message" in frame,
          `a packet to the mind is taken; got ${told(frame)}`,
        );
        const answer = messageOf(frame);
        if (frame !== undefined) {
          expect(
            answer?.["type"] === "Ack" && answer["packet"] === contentId(record),
            `what the server sends back is the Ack for the packet; got ${told(frame)}`,
          );
        }
      } finally {
        socket.close();
      }
    },
  );

  const refused = await suite.check(
    {
      id: "socket-refused",
      clauses: ["L1 13.4"],
      title: "A record the server does not accept closes the connection with 1008",
    },
    async () => {
      const socket = await welcomed(sender);
      try {
        socket.send(JSON.stringify(given.forged()));
        return {
          reason: await expectClosed(socket, 1008, "a packet with the signature of another"),
        };
      } finally {
        socket.close();
      }
    },
  );

  await suite.check(
    {
      id: "socket-refused-reason",
      clauses: ["L1 13.4", "core 10.2"],
      level: "SHOULD",
      title: "The close of a refused record gives the error code as its reason",
    },
    () => {
      const { reason } = need(refused, "a record the server refused");
      expect(
        problemCode(`urn:oip:error:${reason}`) !== undefined,
        `the reason is a code of core 10.2; got "${reason}"`,
      );
    },
  );

  await suite.check(
    {
      id: "socket-mail",
      clauses: ["L1 13.4", "L1 13.5"],
      title:
        "The mind's own instance is sent the records kept for it, and one stays until it is acknowledged",
    },
    async () => {
      const mailbox = given.mailbox();
      need(given.adopted, "a mind the host serves");
      const record = given.packet();
      const posted = await client.ask("POST", mailbox, { body: record });
      expectStatus(posted, 202, "a record posted to the mailbox");
      /** Reads what the host sends the mind until the record comes. */
      const received = async (socket: WireSocket, when: string): Promise<void> => {
        for (;;) {
          const frame = await socket.next();
          expect(
            frame !== undefined && "message" in frame,
            `${when}: the host sends the mind the record kept for it; got ${told(frame)}`,
          );
          if (same(messageOf(frame), record)) return;
        }
      };
      const one = await welcomed(owner);
      try {
        await received(one, "over the mind's socket");
      } finally {
        one.close();
      }
      // The connection dropped before the mind said it has the record: nothing is lost.
      const held = itemsOf(
        await client.ask("GET", mailbox, { signedBy: owner }),
        "a drain after a socket that dropped",
      );
      expect(
        held.some((item) => same(item.record, record)),
        "a record that was sent and not acknowledged stays in the mailbox",
      );
      const two = await welcomed(owner);
      try {
        await received(two, "over the mind's socket, again");
        const at = stamp();
        two.send(
          JSON.stringify(
            owner.sign({
              oip: "1",
              type: "Ack",
              author: owner.address,
              packet: contentId(record),
              received: at,
              created: at,
            }),
          ),
        );
        const frame = await two.next(500);
        expect(
          frame === undefined || "message" in frame,
          `the mind's own Ack for a record is taken; got ${told(frame)}`,
        );
      } finally {
        two.close();
      }
    },
  );
}
