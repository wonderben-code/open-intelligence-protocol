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
import { authorityOf } from "@oip/delegation";
import { judgeRecord } from "@oip/identity";
import { KeystoreError } from "@oip/keystore";
import {
  acknowledges,
  type ChainEquivocation,
  endpointsToTry,
  lacking,
  postUrl,
  type ReceivedPacket,
  receivePacket,
  receiveSealed,
  recordsCarried,
  type SealedOpener,
  type SealedReceiver,
  sealPacket,
  verifyAck,
} from "@oip/net";
import {
  type Ack,
  type Delegation,
  type JsonValue,
  type Packet,
  type Sealed,
  type Session,
  validateRecordOfType,
  type Validation,
} from "@oip/schema";

import { accepted } from "./accepted.ts";
import { homeEndpoints, type Own } from "./publish.ts";
import type { Following, Place, SessionBook } from "./sessions.ts";
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
  /**
   * How long it may be delivered, in seconds: at most seven days. Default:
   * an hour, and for a packet of a session no limit, so that it can be sent
   * again whenever a participant asks (14.4).
   */
  readonly expiresIn?: number;
  /**
   * The session it is a packet of (Section 14), by the session's ID. The
   * packet takes the next place in this mind's chain in that session, and
   * `to` lists every other participant. The first packet of the chain
   * carries the `Session` record, which the client adds to its content.
   */
  readonly session?: string;
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
  /**
   * The mind it is sent for, with the chain of delegations that lets this
   * mind send on its behalf: one that covers `/oip/send` (Layer 1, 11.2).
   * The packet is still this mind's own, signed by it.
   */
  readonly onBehalfOf?: { readonly mind: string; readonly chain: readonly Delegation[] };
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
  /**
   * The mind it was sent for, if its sender's proof carries a chain of
   * delegations from that mind that covers `/oip/send` and holds (Layer 1,
   * 11.2). A packet that only says it is sent for another has no such
   * member: it is its sender's, and nobody else's.
   */
  readonly sentFor?: string;
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
  /**
   * What came of the sessions the mind is in (Section 14): chains with a
   * gap, a `Resume` sent to ask for what is missing, packets sent again to
   * a participant that asked, and senders found to have signed two packets
   * for one place.
   */
  readonly sessions: readonly SessionEvent[];
  /** What each mailbox served. */
  readonly sources: readonly MailboxAnswer[];
}

/** Something that reading the mailboxes found, or did, about a session (Layer 1, Section 14). */
export type SessionEvent =
  | {
      /**
       * Packets of a chain are missing (14.3). The packets that came after
       * them stay in the mailbox, and are returned in order once the
       * missing ones have come.
       */
      readonly kind: "gap";
      readonly session: string;
      /** The sender whose chain it is, and its instance if it names one. */
      readonly mind: string;
      readonly instance?: string;
      /** The `seq` of the first packet that is missing. */
      readonly next: number;
    }
  | {
      /**
       * A `Resume` was sent to the session's participants (14.4), for the
       * gaps found. One is sent for each gap once. `Mind.resume` asks again.
       */
      readonly kind: "asked";
      readonly session: string;
      /** The packet that carried it. */
      readonly sent: Sent;
    }
  | {
      /**
       * A participant's `Resume` showed that it lacks packets of this
       * mind's chain, and they were sent to it again, as they were (14.4).
       */
      readonly kind: "sent-again";
      readonly session: string;
      /** The participant. */
      readonly to: string;
      /** The `seq` of the first packet sent again. */
      readonly from: number;
      /** What became of each, in order. */
      readonly deliveries: readonly Delivery[];
    }
  | {
      /**
       * A `Resume` names a packet this mind did not send at that place
       * (14.4). It is not answered.
       */
      readonly kind: "invalid-resume";
      readonly session: string;
      /** The participant that sent it. */
      readonly mind: string;
      /** The packet that carried it. */
      readonly packet: string;
    }
  | {
      /**
       * What a session asked for could not be done: a `Resume` could not be
       * sent, or the packets a participant lacks could not be sent again.
       * The packets that arrived are returned all the same.
       */
      readonly kind: "failed";
      readonly session: string;
      /** What was being done. */
      readonly doing: "asked" | "sent-again";
      /** Why it failed: the code of a problem, of the keystore's error, or of the transport's failure. */
      readonly failure: string;
    }
  | ({
      /**
       * A sender signed two packets for one place of its chain (14.3). The
       * two are the evidence. Nothing of the chain is in order after that.
       */
      readonly session: string;
      /** The sender, and its instance if it names one. */
      readonly mind: string;
      readonly instance?: string;
    } & ChainEquivocation);

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
/**
 * How far back a packet that states no `expires` is taken, and remembered
 * to tell a duplicate (12.4): seven days, as long as any packet may be
 * delivered. A mind that reads its mailbox once a day finds the session
 * someone opened with it yesterday.
 */
const WINDOW = BigInt(MAX_EXPIRES_IN) * SECOND;
/** core 10.1: the media type with which a packet's content is a record (12.2). */
const RECORD = "application/oip+json";
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
  /** Accepted: this packet and, in a session, those that had waited on it. */
  | { readonly kind: "received"; readonly received: readonly Received[] }
  /** Ahead of a gap in its chain (14.3): it stays in the mailbox until the gap is filled. */
  | { readonly kind: "ahead"; readonly id: string; readonly chain: ChainOf }
  | {
      readonly kind: "refused";
      readonly why: { readonly clause: string; readonly message: string };
    }
  /** Accepted before: it is removed, and not returned again. */
  | { readonly kind: "duplicate" }
  /** Not judged yet: the log of a mind that signed it could not be asked for. */
  | { readonly kind: "waiting" };

/** Why a packet of a chain that is equivocated is refused (14.3). */
const TWO_FOR_ONE_PLACE = {
  clause: "L1 14.3",
  message: "its sender signed two packets for one place of the chain",
};

/** A sending chain of a session, as an event names it. */
interface ChainOf {
  readonly session: string;
  readonly mind: string;
  readonly instance?: string;
}

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

/** @throws OipError `invalid-record` if a message is none for the session it names (14.3). */
function inSession(message: Message, place: Place, self: string): void {
  const to: readonly unknown[] = Array.isArray(message.to) ? message.to : [];
  if (!place.session.participants.every((mind) => mind === self || to.includes(mind))) {
    throw new OipError(
      "invalid-record",
      "a packet of a session is addressed to every other participant of it",
      { clause: "L1 14.3" },
    );
  }
}

/** Content with the `Session` record of its session in it, as a part, if it is not there yet (14.2). */
function carrying(session: Session, id: string, content: Packet["content"]): Packet["content"] {
  const parts = "parts" in content ? content.parts : [content];
  const carried = parts.some((part) => {
    if (!("body" in part) || part.mediaType !== RECORD) return false;
    const record = validateRecordOfType("Session", part.body);
    return record.ok && contentId(record.value) === id;
  });
  return carried ? content : { parts: [{ mediaType: RECORD, body: session }, ...parts] };
}

/** Notes a gap in a chain, once for each place it starts at. */
function noteGap(events: SessionEvent[], gap: Extract<SessionEvent, { kind: "gap" }>): void {
  const noted = events.some(
    (event) =>
      event.kind === "gap" &&
      event.session === gap.session &&
      event.mind === gap.mind &&
      event.instance === gap.instance &&
      event.next === gap.next,
  );
  if (!noted) events.push(gap);
}

/** Notes an equivocation, once for each chain. */
function noteEquivocation(
  events: SessionEvent[],
  found: Extract<SessionEvent, { kind: "equivocation" }>,
): void {
  const noted = events.some(
    (event) =>
      event.kind === "equivocation" &&
      event.session === found.session &&
      event.mind === found.mind &&
      event.instance === found.instance,
  );
  if (!noted) events.push(found);
}

/** What a mind sends and receives. */
export class Messaging {
  readonly #own: Own;
  readonly #sessions: SessionBook;
  /** The packets accepted, each with the time until which it is remembered. */
  #accepted: Map<string, Instant> | undefined;
  #version: string | undefined;
  /** Whether each packet that waits ahead of a gap arrived sealed. */
  readonly #ahead = new Map<string, boolean>();
  /** The gaps a `Resume` was sent for. */
  readonly #asked = new Set<string>();

  constructor(own: Own, sessions: SessionBook) {
    this.#own = own;
    this.#sessions = sessions;
  }

  /** Sends a packet: see `Mind.send`. */
  send(message: Message): Promise<Sent> {
    const { session } = message;
    return session === undefined
      ? this.#send(message, undefined)
      : this.#sessions.sending(session, (place) => this.#send(message, place));
  }

  /** Sends a `Resume` for a session: see `Mind.resume`. */
  resume(session: string): Promise<Sent> {
    const own = this.#own;
    return this.#sessions.sending(session, (place) =>
      this.#send(
        {
          to: place.session.participants.filter((mind) => mind !== own.address),
          verb: "resume",
          content: {
            mediaType: RECORD,
            body: place.resume(formatTimestamp(own.clock.now())),
          },
          session,
        },
        place,
      ),
    );
  }

  /** Signs a packet and brings it to whom it is for. In a session, at the place it was given. */
  async #send(message: Message, place: Place | undefined): Promise<Sent> {
    const own = this.#own;
    const lasting = message.expiresIn ?? (place === undefined ? DEFAULT_EXPIRES_IN : undefined);
    if (
      lasting !== undefined &&
      (!Number.isSafeInteger(lasting) || lasting < 1 || lasting > MAX_EXPIRES_IN)
    ) {
      throw new OipError("invalid-record", "a packet may be delivered for up to seven days", {
        clause: "L1 12.1",
      });
    }
    if (place !== undefined) inSession(message, place, own.address);
    await own.refresh();
    const now = own.clock.now();
    const behalf = message.onBehalfOf;
    const draft = {
      oip: "1",
      type: "Packet",
      from: own.address,
      to: Array.isArray(message.to) ? [...(message.to as readonly string[])] : message.to,
      created: formatTimestamp(now),
      ...(lasting === undefined
        ? {}
        : { expires: formatTimestamp(now + BigInt(lasting) * SECOND) }),
      nonce: bytesToBase64url(this.#random(16)),
      ...(place === undefined
        ? {}
        : {
            session: place.id,
            seq: place.seq,
            ...(place.prev === undefined ? {} : { prev: place.prev }),
            ...(place.instance === undefined ? {} : { instance: place.instance }),
          }),
      purpose: {
        verb: message.verb,
        ...(message.goal === undefined ? {} : { goal: message.goal }),
      },
      // The first packet of a chain carries the Session record (14.2).
      content:
        place?.seq === 0 ? carrying(place.session, place.id, message.content) : message.content,
      ...(message.thread === undefined ? {} : { thread: message.thread }),
      ...(message.replyTo === undefined ? {} : { replyTo: message.replyTo }),
      ...(message.context === undefined ? {} : { context: message.context }),
      ...(message.constraints === undefined ? {} : { constraints: message.constraints }),
      ...(behalf === undefined ? {} : { provenance: { onBehalfOf: behalf.mind } }),
    };
    const signed = await own.sign(
      draft,
      behalf === undefined ? undefined : authorityOf(behalf.chain, "records"),
    );
    const packet = accepted(
      validateRecordOfType("Packet", signed),
      "invalid-record",
      "that is no packet",
    );
    const id = contentId(packet);
    if (!Array.isArray(packet.to)) {
      // For whoever a query finds: each indexer the client names is asked to forward it.
      if (
        !Object.hasOwn(packet.to, "query") ||
        lasting === undefined ||
        lasting > MAX_QUERY_EXPIRES_IN
      ) {
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
    // In a session the packet has its place before it leaves: a process that stops after
    // this sends the same packet again, and never another at the same place (14.3).
    await place?.keep(packet, seal);
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
    const following = await this.#sessions.ready();
    const inbox = {
      received: [] as Received[],
      refused: [] as { clause: string; message: string }[],
      waiting: 0,
      sessions: [] as SessionEvent[],
      sources: [] as MailboxAnswer[],
    };
    /** The chains of the packets that stay in a mailbox, ahead of a gap. */
    const ahead: ChainOf[] = [];
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
      const judged = await this.#judge(items, known, following, inbox.sessions);
      // What was accepted is remembered before it is removed from the mailbox: a process
      // that stops between the two finds a duplicate, and not a packet it never saw. The
      // place of each chain goes first: a packet that is remembered has its place.
      await this.#sessions.save();
      await this.#remember(known);
      for (const { item, outcome } of judged) {
        if (outcome.kind === "waiting") {
          inbox.waiting++;
          continue;
        }
        // A packet ahead of a gap stays until the gap is filled, so that nothing is lost if
        // the process stops. One that was since returned in its place is done with.
        if (outcome.kind === "ahead" && !known.has(outcome.id)) {
          if (!following.equivocated(outcome.chain)) {
            ahead.push(outcome.chain);
            continue;
          }
          // Its chain was found to be two chains while it waited: it has no place (14.3).
          inbox.refused.push(TWO_FOR_ONE_PLACE);
        }
        if (outcome.kind === "received") inbox.received.push(...outcome.received);
        if (outcome.kind === "refused") inbox.refused.push(outcome.why);
        await this.#remove(mailbox, item.cursor);
      }
    }
    for (const chain of ahead) {
      noteGap(inbox.sessions, { kind: "gap", ...chain, next: following.received(chain) });
    }
    await this.#tend(inbox, following);
    return inbox;
  }

  /**
   * What the sessions ask of the mind after its mailboxes are read (14.4):
   * to send again what a participant says it lacks, and to say what this
   * mind lacks itself.
   *
   * The packets that arrived are remembered and removed by now, so nothing
   * here stops them being returned: what cannot be done is told.
   */
  async #tend(
    inbox: { readonly received: readonly Received[]; readonly sessions: SessionEvent[] },
    following: Following,
  ): Promise<void> {
    const events = inbox.sessions;
    const attempt = async (
      session: string,
      doing: "asked" | "sent-again",
      work: () => Promise<SessionEvent>,
    ): Promise<boolean> => {
      try {
        events.push(await work());
        return true;
      } catch (error) {
        if (!isFailure(error) && !(error instanceof KeystoreError)) throw error;
        const failure = error instanceof KeystoreError ? error.code : codeOf(error);
        events.push({ kind: "failed", session, doing, failure });
        return false;
      }
    };
    for (const arrived of inbox.received) {
      const { packet } = arrived;
      const { session } = packet;
      if (session === undefined || packet.purpose.verb !== "resume") continue;
      const head = following.head(session);
      const resume = recordsCarried(packet, "Resume").find(
        (carried) => carried.session === session,
      );
      if (head === undefined || resume === undefined) continue;
      const own = following.own(head);
      const from = lacking(resume, own);
      if (!from.ok) {
        events.push({ kind: "invalid-resume", session, mind: packet.from, packet: arrived.id });
        continue;
      }
      if (from.value < own.sent.length) {
        await attempt(session, "sent-again", async () => {
          const deliveries: Delivery[] = [];
          for (const { packet: again, seal } of await this.#sessions.sent(head, from.value)) {
            deliveries.push(await this.#deliver(again, packet.from, seal));
          }
          return { kind: "sent-again", session, to: packet.from, from: from.value, deliveries };
        });
      }
      // Its sender has sent more than is held here: a gap that no later packet has shown.
      const { lastSent } = resume;
      if (lastSent !== undefined && following.against(resume, packet.from) === "behind") {
        const { instance } = lastSent;
        const chain = {
          session,
          mind: packet.from,
          ...(instance === undefined ? {} : { instance }),
        };
        noteGap(events, { kind: "gap", ...chain, next: following.received(chain) });
      }
    }
    // One Resume for each session with a gap that has not been asked about (14.3).
    const gaps = new Map<string, string[]>();
    for (const event of events) {
      if (event.kind !== "gap") continue;
      const key = JSON.stringify([event.session, event.mind, event.instance, event.next]);
      gaps.set(event.session, [...(gaps.get(event.session) ?? []), key]);
    }
    for (const [session, keys] of gaps) {
      if (keys.every((key) => this.#asked.has(key))) continue;
      const asked = await attempt(session, "asked", async () => ({
        kind: "asked",
        session,
        sent: await this.resume(session),
      }));
      if (asked) for (const key of keys) this.#asked.add(key);
    }
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
    following: Following,
    events: SessionEvent[],
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
      holdsChain: following.holdsChain,
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
      const verdict: Validation<ReceivedPacket> = await once(item.record);
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
      const { id, packet, duplicate, forgetAfter } = verdict.value;
      const asReceived = (one: ReceivedPacket, wasSealed: boolean): Received => ({
        id: one.id,
        packet: one.packet,
        from: one.packet.from,
        sealed: wasSealed,
        ...(one.broker === undefined ? {} : { broker: one.broker }),
        time: one.time,
      });
      if (packet.session !== undefined) {
        // A packet of a session is told by its place in its chain, a duplicate too (14.3).
        const outcome = this.#placed(
          verdict.value,
          packet.session,
          sealed,
          known,
          following,
          events,
          asReceived,
        );
        // A session that is not held may be one another process took up since this one read
        // its memory. The packet is then not refused: it is judged again, by what is written.
        if (
          outcome.kind === "refused" &&
          outcome.why.clause === "L1 14.2" &&
          (await this.#sessions.behind(packet.session))
        ) {
          throw new KeystoreError(
            "changed",
            "another process has followed a session since this one read its memory: read the mailbox again",
          );
        }
        judged.push({ item, outcome });
        continue;
      }
      if (duplicate) {
        judged.push({ item, outcome: { kind: "duplicate" } });
        continue;
      }
      known.set(id, forgetAfter);
      judged.push({
        item,
        outcome: { kind: "received", received: [asReceived(verdict.value, sealed)] },
      });
    }
    return judged;
  }

  /** Puts an accepted packet of a session in its place (14.2, 14.3), and says what became of it. */
  #placed(
    received: ReceivedPacket,
    session: string,
    sealed: boolean,
    known: Map<string, Instant>,
    following: Following,
    events: SessionEvent[],
    asReceived: (one: ReceivedPacket, sealed: boolean) => Received,
  ): Outcome {
    const { id, packet } = received;
    const placed = following.take(received, session);
    if (!placed.ok) {
      const [first] = placed.issues;
      return { kind: "refused", why: { clause: first.clause, message: first.message } };
    }
    const chain = {
      session,
      mind: packet.from,
      ...(packet.instance === undefined ? {} : { instance: packet.instance }),
    };
    const answer = placed.value;
    switch (answer.kind) {
      case "duplicate":
        return { kind: "duplicate" };
      case "waiting":
        this.#ahead.set(id, sealed);
        return { kind: "ahead", id, chain };
      case "equivocation":
        noteEquivocation(events, { ...chain, ...answer });
        return { kind: "refused", why: TWO_FOR_ONE_PLACE };
      case "in order": {
        if (answer.equivocation !== undefined) {
          noteEquivocation(events, { ...chain, ...answer.equivocation });
        }
        const delivered = answer.delivered.map((one) =>
          asReceived(one, one.id === id ? sealed : this.#ahead.get(one.id) === true),
        );
        for (const one of answer.delivered) {
          known.set(one.id, one.forgetAfter);
          this.#ahead.delete(one.id);
        }
        return { kind: "received", received: delivered };
      }
    }
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
