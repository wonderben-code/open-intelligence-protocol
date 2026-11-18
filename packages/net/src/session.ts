// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Sessions (Layer 1, Section 14): the packets of each sender in order.
 *
 * A session is named by a `Session` record, and each participant's packets
 * in it form a chain, one for each instance that sends: numbered from 0,
 * each naming the one before. A receiver puts every packet in its place,
 * tells a duplicate and a gap, and notices a sender that signs two packets
 * for one place.
 *
 * A chain is judged as a feed is (Section 10), so that the order packets
 * arrive in does not matter: a packet has a place only as a link. It is one
 * at `seq` 0 with no `prev`, or at the next `seq` after the link its `prev`
 * names.
 *
 * `Sessions` holds what a receiver knows. It is the caller's own state: the
 * package reads no clock and does no I/O.
 */

import { contentId } from "@oip/core";
import {
  type Branch,
  IMPLEMENTATION_LIMIT,
  type Packet,
  type Resume,
  type Session,
  type Validation,
  validateRecordOfType,
} from "@oip/schema";

import type { ReceivedPacket, SendingChain } from "./packet.ts";
import { finding, judging, no, ok } from "./result.ts";

/** core 10.1: the media type with which a packet's content is a record (Layer 1, 12.2). */
const RECORD = "application/oip+json";

/**
 * Layer 1, 12.2: the records of one type that a packet carries inline, as a
 * body or a part with the media type `application/oip+json`. A body that is
 * not a well-formed record of that type is left out.
 *
 * What a packet carries is data (12.5): a record found here has whatever
 * standing its own proofs give it, and none from the packet.
 */
export function recordsCarried<T extends "Session" | "Resume" | "Branch">(
  packet: Packet,
  type: T,
): Extract<Session | Resume | Branch, { type: T }>[] {
  const content = packet.content as {
    readonly mediaType?: string;
    readonly body?: unknown;
    readonly parts?: readonly { readonly mediaType?: string; readonly body?: unknown }[];
  };
  const carried = finding(() => {
    const found: unknown[] = [];
    // The content is one body, or has parts, each of which may be one (12.2).
    for (const part of content.parts ?? [content]) {
      if (part.mediaType !== RECORD) continue;
      // A part that names its content by reference has no body, and no record is read from it.
      const record = validateRecordOfType(type, part.body);
      if (record.ok) found.push(record.value);
    }
    return found;
  });
  return (carried ?? []) as Extract<Session | Resume | Branch, { type: T }>[];
}

/**
 * Layer 1, 14.2: the `Session` record a packet carries for the session it
 * names: the one whose content ID is the packet's `session`.
 */
export function sessionCarried(packet: Packet): Session | undefined {
  if (packet.session === undefined) return undefined;
  return finding(() =>
    recordsCarried(packet, "Session").find((record) => contentId(record) === packet.session),
  );
}

/**
 * Layer 1, 14.3: a sender signed two packets for one place in a chain. The
 * two are the evidence, as for a feed (10.3), and the chain is verified no
 * further: nothing tells which of them the sender stands by. What was in
 * order before it was found stays so.
 */
export interface ChainEquivocation {
  readonly kind: "equivocation";
  /** The place. */
  readonly seq: number;
  /** The content IDs of the two packets, in order. */
  readonly packets: readonly [string, string];
}

/** What `Sessions.take` found a packet to be. */
export type Placed =
  | {
      /** The packet is the next of its chain. */
      readonly kind: "in order";
      /** This packet, and after it those that had waited on it, in the order of the chain. */
      readonly delivered: readonly ReceivedPacket[];
      /**
       * An equivocation found among the packets that had waited, at the
       * place after the last one delivered.
       */
      readonly equivocation: ChainEquivocation | undefined;
    }
  | {
      /** The packet is one the chain already has at that `seq`. It is discarded (14.3). */
      readonly kind: "duplicate";
    }
  | {
      /**
       * The packet is ahead of its chain: there is a gap before it. It is
       * kept, and is not in order until the gap is filled (14.3). The
       * receiver should send a `Resume`.
       */
      readonly kind: "waiting";
      /** The `seq` of the first packet the receiver lacks of this chain. */
      readonly next: number;
    }
  /** The chain is equivocated. Every later packet of it gets this answer. */
  | ChainEquivocation;

/** What a receiver holds of one sending chain. */
interface Chain {
  readonly from: string;
  readonly instance: string | undefined;
  /** The content IDs of the links held in order, from `seq` 0. */
  readonly ids: string[];
  /** The packets ahead of a gap, by `seq` and then by content ID. */
  readonly waiting: Map<number, Map<string, ReceivedPacket>>;
  /** How many packets wait. */
  waits: number;
  equivocation: ChainEquivocation | undefined;
}

/** What a receiver holds of one session. */
interface Held {
  readonly session: Session;
  readonly chains: Map<string, Chain>;
  /** How many chains each sender has. */
  readonly instances: Map<string, number>;
}

/** Limits on what a `Sessions` keeps. */
export interface SessionLimits {
  /** How many sessions are held at once. Default 1,024. */
  readonly maxSessions?: number;
  /**
   * How many sending chains one participant has in one session: one for
   * each `instance` it names. Default 16.
   */
  readonly maxInstances?: number;
  /** How many packets wait ahead of a gap in one chain. Default 256. */
  readonly maxWaiting?: number;
}

const chainKey = (from: string, instance: string | undefined): string =>
  // An address has no space, so the two parts cannot run together. An absent instance is one
  // instance (14.3), and not the instance named by the empty string.
  instance === undefined ? from : `${from} ${instance}`;

/** Two packets at one place of a chain, named in the order of their content IDs. */
const equivocationAt = (seq: number, a: string, b: string): ChainEquivocation => ({
  kind: "equivocation",
  seq,
  packets: a < b ? [a, b] : [b, a],
});

/** Marks a chain as equivocated. Nothing of it is in order after that, so nothing waits for it. */
function equivocated(chain: Chain, found: ChainEquivocation): void {
  chain.equivocation = found;
  chain.waiting.clear();
  chain.waits = 0;
}

/** What `take` answers, and what it keeps once the answer stands. */
interface Plan {
  readonly answer: Validation<Placed>;
  readonly keep: (() => void) | undefined;
}

const plan = (placed: Placed, keep?: () => void): Validation<Plan> =>
  ok({ answer: ok(placed), keep });

/**
 * Layer 1, 14.2 and 14.3: the sessions one participant follows, and where
 * each sending chain in them stands.
 *
 * It follows the sessions its own mind is a participant of, and no other:
 * every packet of a session is addressed to every participant (14.3), so a
 * participant can hold every chain whole, and nobody else can.
 *
 * Give `take` each packet that `receivePacket` accepted and that names a
 * session, duplicates among them: a session packet older than the
 * receiver's window is told as a duplicate by its place here. Pass
 * `holdsChain` to the receiver, so that such a packet reaches this far.
 *
 * It keeps, for each chain, one content ID for each packet in order, and
 * the packets that wait ahead of a gap, up to a limit. Anyone whose packets
 * the receiver accepts can name it in a new session, and a `Sessions` takes
 * such sessions up to its limit: `drop` a session that is over, or that the
 * receiver wants no part of.
 */
export class Sessions {
  readonly #self: string;
  readonly #held = new Map<string, Held>();
  readonly #maxSessions: number;
  readonly #maxInstances: number;
  readonly #maxWaiting: number;

  /**
   * @param self - The address of the participant whose sessions these are.
   */
  constructor(self: string, limits: SessionLimits = {}) {
    if (typeof (self as unknown) !== "string") {
      throw new TypeError("a participant is named by its address, a string");
    }
    this.#self = self;
    this.#maxSessions = limits.maxSessions ?? 1024;
    this.#maxInstances = limits.maxInstances ?? 16;
    this.#maxWaiting = limits.maxWaiting ?? 256;
    for (const limit of [this.#maxSessions, this.#maxInstances, this.#maxWaiting]) {
      if (!Number.isSafeInteger(limit) || limit < 1) {
        throw new TypeError("a limit is a whole number of at least 1");
      }
    }
  }

  /** The `Session` record of a session held, by its ID. */
  session(id: string): Session | undefined {
    return this.#held.get(id)?.session;
  }

  /** How many sessions are held. */
  get size(): number {
    return this.#held.size;
  }

  /**
   * Whether the state of a sending chain is held. Pass it as
   * `Receiver.holdsChain` (12.4).
   */
  readonly holdsChain = (chain: SendingChain): boolean => this.#chain(chain) !== undefined;

  /** Forgets a session. @returns Whether it was held. */
  drop(id: string): boolean {
    return this.#held.delete(id);
  }

  /**
   * Layer 1, 14.2 and 14.3: puts a packet in its place in its session.
   *
   * The packet is rejected, and nothing is kept of it, if:
   *
   * - it names no session, or its `to` is no list;
   * - the receiver does not hold the session's `Session` record and the
   *   packet does not carry it (14.2), so the session ID cannot be checked;
   * - its `from` is not a participant, or its `to` does not list every
   *   other participant (14.3);
   * - this receiver is not a participant of the session;
   * - it is no link: it has `seq` 0 and a `prev`, or its `prev` is not the
   *   link before it;
   * - it is further ahead of a gap than the receiver keeps, or its sender
   *   has more chains in the session, or the receiver more sessions, than
   *   the limits allow.
   *
   * @param received - A packet from `receivePacket`. Whether the receiver
   *   accepted it before does not matter here.
   */
  take(received: ReceivedPacket): Validation<Placed> {
    // The answer and what to keep are worked out first. Nothing is kept of an answer reached
    // while a check was cut short (ADR-0004).
    const planned = judging(() => this.#place(received));
    if (!planned.ok) return planned;
    planned.value.keep?.();
    return planned.value.answer;
  }

  /** What `take` answers for a packet, and what it then keeps. It changes nothing itself. */
  #place(received: ReceivedPacket): Validation<Plan> {
    const { packet, id } = received;
    const { session: sessionId, seq, from } = packet;
    if (sessionId === undefined || seq === undefined) {
      return no("the packet names no session", "L1 14.3", "/session");
    }
    if (!Array.isArray(packet.to)) {
      return no("a packet in a session is addressed to its participants", "L1 14.3", "/to");
    }
    const held = this.#held.get(sessionId);
    const session = held?.session ?? sessionCarried(packet);
    if (session === undefined) {
      return no(
        "the receiver does not hold the Session record of this session, and the packet does not carry it",
        "L1 14.2",
        "/content",
      );
    }
    if (!session.participants.includes(from)) {
      return no("the sender is not a participant of the session", "L1 14.3", "/from");
    }
    if (!session.participants.includes(this.#self)) {
      return no("the receiver is not a participant of the session", "L1 14.3", "/session");
    }
    const to = packet.to as readonly string[];
    if (!session.participants.every((mind) => mind === from || to.includes(mind))) {
      return no("`to` does not list every other participant of the session", "L1 14.3", "/to");
    }
    if (seq === 0 && packet.prev !== undefined) {
      return no("the first packet of a chain names none before it", "L1 14.3", "/prev");
    }
    const key = chainKey(from, packet.instance);
    const chain = held?.chains.get(key);
    if (chain?.equivocation !== undefined) return plan(chain.equivocation);
    const there = chain?.ids[seq];
    if (chain !== undefined && there !== undefined) {
      // A place the chain has filled: the same packet again, another link, or no link at all.
      if (there === id) return plan({ kind: "duplicate" });
      if (seq > 0 && chain.ids[seq - 1] !== packet.prev) {
        return no("`prev` is not the packet before this one in its chain", "L1 14.3", "/prev");
      }
      const found = equivocationAt(seq, there, id);
      return plan(found, () => {
        equivocated(chain, found);
      });
    }
    const next = chain?.ids.length ?? 0;
    if (seq === next && next > 0 && chain?.ids[next - 1] !== packet.prev) {
      return no("`prev` is not the packet before this one in its chain", "L1 14.3", "/prev");
    }
    if (seq > next && chain?.waiting.get(seq)?.has(id) !== true) {
      if ((chain?.waits ?? 0) >= this.#maxWaiting) {
        return no(
          `the packet is ahead of a gap, and ${this.#maxWaiting} packets of its chain wait already`,
          IMPLEMENTATION_LIMIT,
          "/seq",
        );
      }
    }
    if (chain === undefined && (held?.instances.get(from) ?? 0) >= this.#maxInstances) {
      return no(
        `the sender has ${this.#maxInstances} sending chains in this session already`,
        IMPLEMENTATION_LIMIT,
        "/instance",
      );
    }
    if (held === undefined && this.#held.size >= this.#maxSessions) {
      return no(
        `the receiver follows ${this.#maxSessions} sessions already`,
        IMPLEMENTATION_LIMIT,
        "/session",
      );
    }
    // The packet has a place, or may have one, and something is kept of it.
    const open = (): Chain => this.#open(sessionId, session, key, from, packet.instance);
    if (seq > next) {
      return plan({ kind: "waiting", next }, () => {
        const kept = open();
        let here = kept.waiting.get(seq);
        if (here === undefined) {
          here = new Map();
          kept.waiting.set(seq, here);
        }
        if (!here.has(id)) {
          here.set(id, received);
          kept.waits++;
        }
      });
    }
    // The next link. Those that waited on it follow, for as long as exactly one fits.
    const delivered: ReceivedPacket[] = [received];
    const taken: string[] = [id];
    const consumed: number[] = [];
    let found: ChainEquivocation | undefined;
    for (let head = id, place = next + 1; ; place++) {
      const here = chain?.waiting.get(place);
      if (here === undefined) break;
      consumed.push(place);
      const links = [...here.values()].filter((waited) => waited.packet.prev === head);
      const [only, other] = links;
      // None fits: the place is open still, and what waited for it was no link.
      if (only === undefined) break;
      if (other !== undefined) {
        // The first two links at this place in the order of their content IDs, so that every
        // receiver names the same two whatever order they came in.
        const [first, second] = links.map((link) => link.id).sort() as [string, string];
        found = equivocationAt(place, first, second);
        break;
      }
      delivered.push(only);
      taken.push(only.id);
      head = only.id;
    }
    return plan({ kind: "in order", delivered, equivocation: found }, () => {
      const kept = open();
      // What waited goes first, and the links last. If anything fails on the way, the packet
      // is not yet taken, and it is taken when it comes again.
      for (const place of consumed) {
        kept.waits -= kept.waiting.get(place)?.size ?? 0;
        kept.waiting.delete(place);
      }
      kept.ids.push(...taken);
      if (found !== undefined) equivocated(kept, found);
    });
  }

  /** The chain a packet belongs to, opened if it is the first of its chain or of its session. */
  #open(
    id: string,
    session: Session,
    key: string,
    from: string,
    instance: string | undefined,
  ): Chain {
    let held = this.#held.get(id);
    if (held === undefined) {
      held = { session, chains: new Map(), instances: new Map() };
      this.#held.set(id, held);
    }
    let chain = held.chains.get(key);
    if (chain === undefined) {
      held.instances.set(from, (held.instances.get(from) ?? 0) + 1);
      chain = { from, instance, ids: [], waiting: new Map(), waits: 0, equivocation: undefined };
      held.chains.set(key, chain);
    }
    return chain;
  }

  /** Layer 1, 14.3: the equivocation found in a chain, if any. */
  equivocation(chain: SendingChain): ChainEquivocation | undefined {
    return this.#chain(chain)?.equivocation;
  }

  #chain(chain: SendingChain): Chain | undefined {
    return this.#held.get(chain.session)?.chains.get(chainKey(chain.from, chain.instance));
  }

  /**
   * Layer 1, 14.4: how the `lastSent` of a `Resume` stands against what is
   * held of its sender's chain.
   *
   * - `"level"`: the receiver holds the chain up to the packet named, and
   *   no further. Also when neither has anything.
   * - `"behind"`: the receiver lacks packets of the chain, and should send
   *   a `Resume` of its own.
   * - `"ahead"`: the receiver holds more of the chain than the `Resume`
   *   says was sent. Its sender has lost some of its own state.
   * - `"conflict"`: the receiver holds another packet at that place. One
   *   of the two is not what the sender sent there.
   *
   * @param from - The sender of the packet that carried the `Resume`.
   * @returns `undefined` if the session is not held.
   */
  against(resume: Resume, from: string): "level" | "behind" | "ahead" | "conflict" | undefined {
    if (!this.#held.has(resume.session)) return undefined;
    const last = resume.lastSent;
    const ids = this.#chain({ session: resume.session, from, instance: last?.instance })?.ids ?? [];
    if (last === undefined) return ids.length === 0 ? "level" : "ahead";
    if (last.seq >= ids.length) return "behind";
    if (ids[last.seq] !== last.packet) return "conflict";
    return last.seq === ids.length - 1 ? "level" : "ahead";
  }

  /**
   * Layer 1, 14.4: a `Resume` for a session, which says where each sending
   * chain stands for this receiver. Send it as the content of a packet with
   * the verb `resume`.
   *
   * @param lastSent - The last packet the sender of the `Resume` itself
   *   sent in the session, if it sent any. What a mind has sent is its own
   *   to keep, and is not held here.
   * @param created - The time to state, as a timestamp.
   * @returns The record, or `undefined` if the session is not held.
   */
  resume(
    id: string,
    lastSent: Resume["lastSent"] | undefined,
    created: string,
  ): Resume | undefined {
    const held = this.#held.get(id);
    if (held === undefined) return undefined;
    const lastReceived: Resume["lastReceived"][number][] = [];
    for (const chain of held.chains.values()) {
      const last = chain.ids.at(-1);
      if (last === undefined) continue;
      lastReceived.push({
        mind: chain.from,
        ...(chain.instance === undefined ? {} : { instance: chain.instance }),
        seq: chain.ids.length - 1,
        packet: last,
      });
    }
    return {
      oip: "1",
      type: "Resume",
      session: id,
      ...(lastSent === undefined ? {} : { lastSent }),
      lastReceived,
      created,
    };
  }
}

/** A mind's own sending chain in a session: what it has sent, in order. */
export interface OwnChain {
  /** The mind's address. */
  readonly address: string;
  /** The instance that sends, if it names one. */
  readonly instance?: string | undefined;
  /** The content IDs of the packets it sent in the session, from `seq` 0. */
  readonly sent: readonly string[];
}

/**
 * Layer 1, 14.4: what the sender of a `Resume` lacks of a mind's own chain.
 * The mind then sends those packets again, as they were.
 *
 * The `Resume` is checked against the chain: where it names a packet of
 * this chain, the chain has that packet at that `seq`.
 *
 * @returns The `seq` of the first packet to send again. It is the length
 *   of the chain when the sender of the `Resume` lacks nothing. A rejection
 *   if the `Resume` names a packet this chain does not have there: its
 *   sender holds something this mind did not send, or not in this place.
 */
export function lacking(resume: Resume, own: OwnChain): Validation<number> {
  const entries = resume.lastReceived.filter(
    (entry) => entry.mind === own.address && entry.instance === own.instance,
  );
  let from = 0;
  for (const [index, entry] of entries.entries()) {
    if (own.sent[entry.seq] !== entry.packet) {
      return no(
        "the Resume names a packet that this chain does not have at that place",
        "L1 14.4",
        `/lastReceived/${resume.lastReceived.indexOf(entry)}/packet`,
      );
    }
    // Entries for one chain that disagree are taken at the least: sending a packet again is harmless.
    from = index === 0 ? entry.seq + 1 : Math.min(from, entry.seq + 1);
  }
  return ok(from);
}
