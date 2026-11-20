// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Packets (Layer 1, Section 12): what one mind sends another, and what it
 * finds in its mailbox.
 *
 * A packet is signed by its sender and, unless the sender says otherwise,
 * sealed to each recipient (12.6): the services it passes through carry it
 * and cannot read it. It is posted to where the recipient's current
 * location record says the recipient takes packets (15.3).
 *
 * What arrives is a stranger's until it is judged (12.4): addressed to this
 * mind, in date, signed by its sender on the evidence the client's
 * resolvers give, and not seen before. Only then is it returned. Its
 * content is data, whatever it says (12.5).
 */

import {
  bytesToBase64url,
  contentId,
  formatTimestamp,
  type Instant,
  type JsonObject,
  OipError,
  parseRecord,
} from "@oip/core";
import { judgeRecord } from "@oip/identity";
import {
  acknowledges,
  endpointsToTry,
  postUrl,
  receivePacket,
  receiveSealed,
  type SealedOpener,
  type SealedReceiver,
  sealPacket,
  verifyAck,
} from "@oip/net";
import {
  type Ack,
  type JsonValue,
  type Packet,
  type Sealed,
  validateRecordOfType,
  type Validation,
} from "@oip/schema";

import { accepted } from "./accepted.ts";
import { homeEndpoints, type Own } from "./publish.ts";
import { askJson, exchange, recordBody, refusalOf, TransportError } from "./transport.ts";

/** What a mind says to others: the members of a packet that are the sender's to choose (Layer 1, 12.1). */
export interface Message {
  /**
   * The minds it is for: 1 to 64 addresses. Or a capability query, for the
   * indexers the client names to forward it to the minds that match (18.5):
   * `{ query, brokers?, maxFanout? }`. A packet for a query is not sealed,
   * since nobody knows yet whom it is for, and may be delivered for an hour
   * at most.
   */
  readonly to: readonly string[] | Exclude<Packet["to"], readonly string[]>;
  /**
   * What kind of message it is: `inform`, `request`, `propose` and so on, or
   * a verb of the sender's own namespace (12.3). A verb binds nobody:
   * binding statements are records carried in `content`.
   */
  readonly verb: string;
  /** What it carries (12.2): a body with its media type, a reference with its digest, or parts. */
  readonly content: Packet["content"];
  /** What it is for, in at most 256 characters. */
  readonly goal?: string;
  /** How long it may be delivered, in seconds: at most seven days. Default: an hour. */
  readonly expiresIn?: number;
  /**
   * Whether it is sealed to each recipient (12.6), so that only the
   * recipient reads it. Default: `true`. A packet is not sent unsealed to a
   * recipient it cannot be sealed to.
   */
  readonly seal?: boolean;
  /** The thread it belongs to: a content ID, or another string of at most 128 characters. */
  readonly thread?: string;
  /** The packet it answers, by its content ID. */
  readonly replyTo?: string;
  /** What the recipient may do with it (12.1): retention, uses, confidentiality. */
  readonly constraints?: Packet["constraints"];
  /** What helps to read it: references, a summary, a language. */
  readonly context?: Packet["context"];
}

/** What became of a packet for one recipient. */
export interface Delivery {
  /** The recipient: a mind's address, or for a packet addressed to a query the origin of an indexer. */
  readonly to: string;
  /** Whether it went sealed. */
  readonly sealed: boolean;
  /** Whether an endpoint of the recipient took it. */
  readonly stored: boolean;
  /** The URL it was posted to, if one took it. */
  readonly endpoint?: string;
  /**
   * The recipient's acknowledgement (13.2), if the endpoint signs for the
   * recipient and the acknowledgement verified. It is evidence, at the time
   * it names, for the proofs it lists: keep it with a packet that carries
   * binding records.
   */
  readonly ack?: Ack;
  /** Why no endpoint took it: the code of a problem (core 10.2), or the failure of the transport. */
  readonly failure?: string;
}

/** A packet that was sent. */
export interface Sent {
  /** The packet, signed. */
  readonly packet: Packet;
  /** Its content ID, which is its identifier. */
  readonly id: string;
  /** What became of it for each recipient, in the order of `to`. */
  readonly deliveries: readonly Delivery[];
}

/** A packet that arrived and was accepted (12.4). Its content is data, whatever it says (12.5). */
export interface Received {
  /** The packet's content ID. */
  readonly id: string;
  /** The packet. */
  readonly packet: Packet;
  /** The sender, whose signature on it counts. */
  readonly from: string;
  /** Whether it arrived sealed to this mind. */
  readonly sealed: boolean;
  /** The broker that forwarded it, if it was addressed to a query (18.5). */
  readonly broker?: string;
  /** The evaluation time of the sender's signature. */
  readonly time: Instant;
}

/** What a mind found in its mailboxes. */
export interface Inbox {
  /** The packets accepted, each once, oldest first for each mailbox. */
  readonly received: readonly Received[];
  /** What was there and is no packet for this mind, each with the first reason. It is removed. */
  readonly refused: readonly { readonly clause: string; readonly message: string }[];
  /**
   * How many items could not be judged yet, because a resolver could not be
   * asked for the log of their sender. They stay in the mailbox.
   */
  readonly waiting: number;
  /** What each mailbox served. */
  readonly sources: readonly MailboxAnswer[];
}

/** What one mailbox served. */
export interface MailboxAnswer {
  /** The mailbox's URL. */
  readonly mailbox: string;
  /** How many items it served, or `undefined` if it could not be drained. */
  readonly items: number | undefined;
  /** Why it could not: the code of its problem, or the failure of the transport. */
  readonly failure?: string;
}

/** How long a packet may be delivered unless its sender says: an hour, in seconds. */
export const DEFAULT_EXPIRES_IN = 3600;
/** The longest a packet may be delivered (12.1): seven days, in seconds. */
export const MAX_EXPIRES_IN = 7 * 24 * 3600;
/** The longest a packet addressed to a query may be delivered (12.1): an hour, in seconds. */
export const MAX_QUERY_EXPIRES_IN = 3600;
/** The most items read of one mailbox in one call. What is left is read by the next. */
export const MAX_MAILBOX_ITEMS = 1000;

const SECOND = 1_000_000_000n;
/** How long a packet is remembered for at least, to tell a duplicate (12.4): an hour. */
const WINDOW = 3600n * SECOND;
/** The name of what is remembered of the packets accepted. */
const ACCEPTED = "client-accepted";

type Failure = OipError | TransportError;
const codeOf = (failure: Failure): string =>
  failure instanceof OipError ? failure.code : failure.failure;
const isFailure = (error: unknown): error is Failure =>
  error instanceof OipError || error instanceof TransportError;

/** An item of a mailbox (13.5). */
interface Item {
  readonly cursor: string;
  readonly record: JsonValue;
}

/** What became of an item of a mailbox. */
type Outcome =
  | { readonly kind: "received"; readonly received: Received }
  | {
      readonly kind: "refused";
      readonly why: { readonly clause: string; readonly message: string };
    }
  /** Accepted before: it is removed, and not returned again. */
  | { readonly kind: "duplicate" }
  /** Not judged yet: the log of a mind that signed it could not be asked for. */
  | { readonly kind: "waiting" };

/** A value as an object, or `undefined`. */
const objectOf = (value: unknown): JsonObject | undefined =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;

/** A page of a mailbox as it was served, or `undefined` if it is none. */
function pageOf(served: JsonValue): { items: Item[]; next: string | undefined } | undefined {
  const page = objectOf(served);
  const listed = page?.["items"];
  if (page === undefined || !Array.isArray(listed)) return undefined;
  const items: Item[] = [];
  for (const entry of listed as readonly JsonValue[]) {
    const item = objectOf(entry);
    const cursor = item?.["cursor"];
    if (item === undefined || typeof cursor !== "string" || item["record"] === undefined) {
      return undefined;
    }
    items.push({ cursor, record: item["record"] });
  }
  const next = page["next"];
  return { items, next: typeof next === "string" ? next : undefined };
}

/** What a mind sends and receives. */
export class Messaging {
  readonly #own: Own;
  /** The packets accepted, each with the time until which it is remembered. */
  #accepted: Map<string, Instant> | undefined;
  #version: string | undefined;

  constructor(own: Own) {
    this.#own = own;
  }

  /** Sends a packet: see `Mind.send`. */
  async send(message: Message): Promise<Sent> {
    const own = this.#own;
    const lasting = message.expiresIn ?? DEFAULT_EXPIRES_IN;
    if (!Number.isSafeInteger(lasting) || lasting < 1 || lasting > MAX_EXPIRES_IN) {
      throw new OipError("invalid-record", "a packet may be delivered for up to seven days", {
        clause: "L1 12.1",
      });
    }
    await own.refresh();
    const now = own.clock.now();
    const signed = await own.sign({
      oip: "1",
      type: "Packet",
      from: own.address,
      to: Array.isArray(message.to) ? [...(message.to as readonly string[])] : message.to,
      created: formatTimestamp(now),
      expires: formatTimestamp(now + BigInt(lasting) * SECOND),
      nonce: bytesToBase64url(this.#random(16)),
      purpose: {
        verb: message.verb,
        ...(message.goal === undefined ? {} : { goal: message.goal }),
      },
      content: message.content,
      ...(message.thread === undefined ? {} : { thread: message.thread }),
      ...(message.replyTo === undefined ? {} : { replyTo: message.replyTo }),
      ...(message.context === undefined ? {} : { context: message.context }),
      ...(message.constraints === undefined ? {} : { constraints: message.constraints }),
    });
    const packet = accepted(
      validateRecordOfType("Packet", signed),
      "invalid-record",
      "that is no packet",
    );
    const id = contentId(packet);
    if (!Array.isArray(packet.to)) {
      // For whoever a query finds: each indexer the client names is asked to forward it.
      if (!Object.hasOwn(packet.to, "query") || lasting > MAX_QUERY_EXPIRES_IN) {
        throw new OipError(
          "invalid-record",
          "a packet is sent to the minds it lists, or to a query for an hour at most",
          { clause: "L1 12.1" },
        );
      }
      if (own.indexers.length === 0) throw new TypeError("a client names the indexers it asks");
      const brokered = await Promise.all(
        own.indexers.map((indexer) => this.#broker(packet, indexer)),
      );
      return { packet, id, deliveries: brokered };
    }
    const seal = message.seal !== false;
    const deliveries = await Promise.all(packet.to.map((to) => this.#deliver(packet, to, seal)));
    return { packet, id, deliveries };
  }

  /** Random bytes, as many as were asked for. */
  #random(length: number): Uint8Array {
    const bytes = this.#own.randomness.bytes(length);
    if (!(bytes instanceof Uint8Array) || bytes.length !== length) {
      throw new TypeError("the source of randomness did not give what was asked");
    }
    return bytes;
  }

  /** Brings a packet addressed to a query to an indexer, which forwards it if it is a broker of it (18.5). */
  async #broker(packet: Packet, indexer: string): Promise<Delivery> {
    const url = `${indexer}/oip/v1/inbox`;
    try {
      const answer = await exchange(
        { method: "POST", url, body: recordBody(packet) },
        this.#own.transport,
      );
      if (answer.status !== 202) throw refusalOf(answer);
      return { to: indexer, sealed: false, stored: true, endpoint: url };
    } catch (error) {
      if (!isFailure(error)) throw error;
      return { to: indexer, sealed: false, stored: false, failure: codeOf(error) };
    }
  }

  /** Brings a packet to one recipient: to the first of its endpoints that takes it (15.3). */
  async #deliver(packet: Packet, to: string, seal: boolean): Promise<Delivery> {
    const own = this.#own;
    try {
      const { location } = await own.lookup.resolve(to);
      if (location === undefined) {
        throw new OipError("not-found", `${to} has published no location record`, {
          clause: "L1 15.1",
        });
      }
      const record: Packet | Sealed = seal
        ? accepted(
            await sealPacket({
              packet,
              to,
              view: own.lookup.view,
              randomness: this.#random(32),
            }),
            "invalid-record",
            `the packet cannot be sealed to ${to}`,
          )
        : packet;
      const body = recordBody(record);
      let failed: Failure = new OipError(
        "not-found",
        `${to} names no endpoint that takes a packet`,
        {
          clause: "L1 15.3",
        },
      );
      let tried = false;
      for (const endpoint of endpointsToTry(location.record)) {
        const url = postUrl(endpoint);
        if (url === undefined) continue;
        try {
          const answer = await exchange({ method: "POST", url, body }, own.transport);
          if (answer.status !== 202) throw refusalOf(answer);
          const ack = await this.#acknowledged(
            answer.body,
            packet,
            to,
            seal ? contentId(record) : undefined,
          );
          return { to, sealed: seal, stored: true, endpoint: url, ...(ack ? { ack } : {}) };
        } catch (error) {
          if (!isFailure(error)) throw error;
          // The first endpoint's failure is the one told: it is the one the recipient prefers.
          if (!tried) failed = error;
          tried = true;
        }
      }
      throw failed;
    } catch (error) {
      if (!isFailure(error)) throw error;
      return { to, sealed: seal, stored: false, failure: codeOf(error) };
    }
  }

  /**
   * The acknowledgement an endpoint answered with, if it is the recipient's
   * own for this packet (13.2). An endpoint that holds no key of the
   * recipient answers that the packet is stored, and nothing more.
   */
  async #acknowledged(
    body: Uint8Array,
    packet: Packet,
    recipient: string,
    sealed: string | undefined,
  ): Promise<Ack | undefined> {
    const own = this.#own;
    const read = parseRecord(body);
    if (!read.ok || read.value.type !== "Ack") return undefined;
    const context = { view: own.lookup.view, now: own.clock.now(), seen: own.lookup.seen };
    // First seen now. It is judged by the recipient's log as it stands no earlier (core 9.4).
    verifyAck(read.value, context);
    try {
      await own.lookup.resolve(recipient);
    } catch (error) {
      if (!isFailure(error)) throw error;
      return undefined;
    }
    const verified = verifyAck(read.value, context);
    const judged = judgeRecord(packet);
    if (!verified.ok || !judged.ok || verified.value.recipient !== recipient) return undefined;
    if (!acknowledges(verified.value, judged.value) || verified.value.ack.sealed !== sealed) {
      return undefined;
    }
    return verified.value.ack;
  }

  /** Reads the mind's mailboxes: see `Mind.receive`. */
  async receive(): Promise<Inbox> {
    const own = this.#own;
    const resolved = await own.refresh();
    const endpoints =
      resolved.location?.record.endpoints ?? homeEndpoints(own.address, resolved.state.homes);
    const mailboxes = [
      ...new Set(
        endpoints.filter((endpoint) => endpoint.binding === "mailbox").map(({ url }) => url),
      ),
    ];
    const known = await this.#remembered();
    const inbox = {
      received: [] as Received[],
      refused: [] as { clause: string; message: string }[],
      waiting: 0,
      sources: [] as MailboxAnswer[],
    };
    for (const mailbox of mailboxes) {
      let items: Item[];
      try {
        items = await this.#drain(mailbox);
      } catch (error) {
        if (!isFailure(error)) throw error;
        inbox.sources.push({ mailbox, items: undefined, failure: codeOf(error) });
        continue;
      }
      inbox.sources.push({ mailbox, items: items.length });
      const judged = await this.#judge(items, known);
      // What was accepted is remembered before it is removed from the mailbox: a process
      // that stops between the two finds a duplicate, and not a packet it never saw.
      await this.#remember(known);
      for (const { item, outcome } of judged) {
        if (outcome.kind === "waiting") {
          inbox.waiting++;
          continue;
        }
        if (outcome.kind === "received") inbox.received.push(outcome.received);
        if (outcome.kind === "refused") inbox.refused.push(outcome.why);
        await this.#remove(mailbox, item.cursor);
      }
    }
    return inbox;
  }

  /** The items of a mailbox, page by page, as many as are read in one call (13.5). */
  async #drain(mailbox: string): Promise<Item[]> {
    const own = this.#own;
    const items: Item[] = [];
    let after: string | undefined;
    for (;;) {
      const url = after === undefined ? mailbox : `${mailbox}?after=${encodeURIComponent(after)}`;
      const served = await askJson(await own.signed({ method: "GET", url }), own.transport);
      const page = pageOf(served);
      if (page === undefined) {
        throw new TransportError(
          "not-oip",
          new URL(mailbox).origin,
          "that is no page of a mailbox",
        );
      }
      items.push(...page.items);
      // A page that does not go forward ends the reading, whatever it says comes next.
      if (page.next === undefined || page.items.length === 0 || page.next === after) break;
      if (items.length >= MAX_MAILBOX_ITEMS) break;
      after = page.next;
    }
    return items.slice(0, MAX_MAILBOX_ITEMS);
  }

  /**
   * Judges what a mailbox held (12.4). Everything is first seen at one
   * reading of the clock. The logs of the minds that signed are then
   * fetched afresh, and each item is judged by them: a log held from before
   * a packet was first seen does not judge it (core 9.4).
   */
  async #judge(
    items: readonly Item[],
    known: Map<string, Instant>,
  ): Promise<{ item: Item; outcome: Outcome }[]> {
    const own = this.#own;
    const now = own.clock.now();
    const seen: { item: Item; sealed: boolean; signers: string[] }[] = [];
    const receiver = (opened?: (plaintext: Uint8Array) => void): SealedReceiver => ({
      address: own.address,
      now,
      view: own.lookup.view,
      seen: own.lookup.seen,
      accepted: (id) => known.has(id),
      window: WINDOW,
      agreementKey: (key) => {
        const open = own.opener(key);
        if (open === undefined) return undefined;
        const watched: SealedOpener = async (sealed) => {
          const plaintext = await open(sealed);
          if (plaintext !== undefined) opened?.(plaintext);
          return plaintext;
        };
        return watched;
      },
    });
    const once = (record: JsonValue, opened?: (plaintext: Uint8Array) => void) =>
      objectOf(record)?.["type"] === "Sealed"
        ? receiveSealed(record, receiver(opened))
        : Promise.resolve(receivePacket(record, receiver()));
    // The first reading: what each item is, and whose signatures it rests on.
    for (const item of items) {
      const { record } = item;
      const signers: string[] = [];
      const note = (packet: unknown): void => {
        const from = objectOf(packet)?.["from"];
        if (typeof from === "string") signers.push(from);
      };
      const sealed = objectOf(record)?.["type"] === "Sealed";
      await once(record, (plaintext) => {
        const inner = parseRecord(plaintext);
        if (inner.ok) note(inner.value);
      });
      const carried = objectOf(record);
      if (carried?.["type"] === "Forwarded") {
        if (typeof carried["broker"] === "string") signers.push(carried["broker"]);
        note(carried["packet"]);
      } else if (!sealed) {
        note(record);
      }
      seen.push({ item, sealed, signers });
    }
    // Their logs, as they stand now. One that cannot be asked for leaves its packets waiting.
    const unasked = new Set<string>();
    for (const mind of new Set(seen.flatMap(({ signers }) => signers))) {
      try {
        await own.lookup.resolve(mind);
      } catch (error) {
        if (!isFailure(error)) throw error;
        if (error instanceof TransportError) unasked.add(mind);
      }
    }
    const judged: { item: Item; outcome: Outcome }[] = [];
    for (const { item, sealed, signers } of seen) {
      const verdict: Validation<{
        id: string;
        packet: Packet;
        time: Instant;
        duplicate: boolean;
        broker: string | undefined;
        forgetAfter: Instant;
      }> = await once(item.record);
      if (!verdict.ok) {
        const [first] = verdict.issues;
        judged.push({
          item,
          outcome: signers.some((mind) => unasked.has(mind))
            ? { kind: "waiting" }
            : { kind: "refused", why: { clause: first.clause, message: first.message } },
        });
        continue;
      }
      const { id, packet, time, duplicate, broker, forgetAfter } = verdict.value;
      if (duplicate) {
        judged.push({ item, outcome: { kind: "duplicate" } });
        continue;
      }
      known.set(id, forgetAfter);
      judged.push({
        item,
        outcome: {
          kind: "received",
          received: {
            id,
            packet,
            from: packet.from,
            sealed,
            ...(broker === undefined ? {} : { broker }),
            time,
          },
        },
      });
    }
    return judged;
  }

  /** Removes an item from a mailbox (13.5). One that stays is found again, and is a duplicate then. */
  async #remove(mailbox: string, cursor: string): Promise<void> {
    const own = this.#own;
    try {
      const asking = await own.signed({
        method: "DELETE",
        url: `${mailbox}/${encodeURIComponent(cursor)}`,
      });
      await exchange(asking, own.transport);
    } catch (error) {
      if (!isFailure(error)) throw error;
    }
  }

  /** The packets accepted, as the client remembers them, without those it may forget (12.4). */
  async #remembered(): Promise<Map<string, Instant>> {
    const own = this.#own;
    if (this.#accepted === undefined) {
      const held = await own.memory.get(ACCEPTED, (stored) => {
        const ids = objectOf(stored["ids"]);
        if (ids === undefined) return undefined;
        const known = new Map<string, Instant>();
        for (const [id, until] of Object.entries(ids)) {
          if (typeof until !== "string" || !/^\d{1,30}$/u.test(until)) return undefined;
          known.set(id, BigInt(until));
        }
        return known;
      });
      this.#accepted = held.value ?? new Map<string, Instant>();
      this.#version = held.version;
    }
    const now = own.clock.now();
    for (const [id, until] of this.#accepted) if (until < now) this.#accepted.delete(id);
    return this.#accepted;
  }

  /** Writes down the packets accepted. */
  async #remember(known: Map<string, Instant>): Promise<void> {
    const ids: Record<string, string> = {};
    for (const [id, until] of known) ids[id] = String(until);
    this.#version = await this.#own.memory.put(ACCEPTED, { ids }, this.#version);
  }
}
