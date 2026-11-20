// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Sessions (Layer 1, Section 14): the packets of each sender in order.
 *
 * A session is named by a `Session` record. Each participant numbers the
 * packets it sends in it from 0, and each packet names the one before, so
 * that a receiver tells a packet it missed, and a sender that signs two
 * packets for one place.
 *
 * What a mind has sent in a session is its own to keep, and is kept here:
 * the place of each packet before the packet leaves, so that a process that
 * stops never signs a second packet for a place, and the packets
 * themselves, to send them again to a participant that asks (14.4). What it
 * has received of each other chain is kept too, by content ID. All of it is
 * in the client's memory, one document for each session and one for each
 * packet sent.
 */

import { bytesToBase64url, contentId, formatTimestamp, type JsonObject, OipError } from "@oip/core";
import { KeystoreError } from "@oip/keystore";
import {
  type ChainEquivocation,
  type HeldChain,
  type OwnChain,
  type Placed,
  type ReceivedPacket,
  type SendingChain,
  Sessions,
} from "@oip/net";
import {
  type Packet,
  type Resume,
  type Session,
  validateRecordOfType,
  type Validation,
} from "@oip/schema";

import { accepted } from "./accepted.ts";
import type { Own } from "./publish.ts";

/** A session the mind takes part in, as the client holds it. */
export interface SessionView {
  /** The session's ID: the content ID of its `Session` record (14.1). */
  readonly id: string;
  /** The `Session` record. */
  readonly session: Session;
  /** How many packets this mind has sent in it. */
  readonly sent: number;
  /** Where the chain of each other sender stands. */
  readonly chains: readonly ChainView[];
}

/** What the client holds of one sending chain of a session (14.3). */
export interface ChainView {
  /** The sender. */
  readonly mind: string;
  /** The instance of it that sends, if it names one. */
  readonly instance?: string;
  /** How many of its packets are held in order, from `seq` 0. */
  readonly received: number;
  /**
   * Two packets its sender signed for one place. Nothing of the chain is in
   * order after that: nothing tells which of the two the sender stands by.
   */
  readonly equivocation?: ChainEquivocation;
}

/** This mind's next place in a session: where the packet it is about to send goes. */
export interface Place {
  /** The session's ID. */
  readonly id: string;
  /** The `Session` record. */
  readonly session: Session;
  /** The packet's `seq`: 0 for the first of this mind's chain. */
  readonly seq: number;
  /** The packet before it in the chain, if there is one. */
  readonly prev: string | undefined;
  /** The instance the chain was started as. A chain keeps it. */
  readonly instance: string | undefined;
  /** A `Resume` for the session (14.4), as things stand before the packet at this place. */
  resume(created: string): Resume;
  /**
   * Writes the packet down as the one at this place. Nothing leaves before
   * this has returned.
   *
   * @throws KeystoreError `changed` if another process has sent in the
   *   session since. Nothing was sent, and the next call finds the chain as
   *   it now stands.
   */
  keep(packet: Packet, seal: boolean): Promise<void>;
}

/** A sending chain of a session, by its sender. */
interface ChainName {
  readonly session: string;
  readonly mind: string;
  readonly instance?: string;
}

/** A packet this mind sent in a session, and whether it went sealed. */
interface SentPacket {
  readonly id: string;
  readonly seal: boolean;
}

/** What is held of one session. */
export interface Head {
  readonly id: string;
  readonly session: Session;
  /** The instance this mind's chain in the session was started as. */
  readonly instance: string | undefined;
  /** This mind's own chain: what it sent, in order. */
  readonly sent: SentPacket[];
  /** The version of the document in the client's memory, once it is written. */
  version: string | undefined;
}

/** The names of what is remembered of a session, and of a packet sent in one. */
const SESSION = "client-ses-";
const SENT = "client-pkt-";
/**
 * A name for a document about a record: a prefix, and 21 characters of the
 * record's content ID after the four that every content ID starts with. That
 * is 105 bits of a SHA-256, in the letters and digits a storage takes.
 */
const nameOf = (prefix: string, id: string): string => prefix + id.slice(4, 25);

const damaged = (what: string): KeystoreError =>
  new KeystoreError("damaged", `what the client remembers of ${what} cannot be read`);

/** A session as it was written down, or `undefined` if that is none. */
function readHead(stored: JsonObject): (Head & { chains: unknown }) | undefined {
  const session = validateRecordOfType("Session", stored["session"]);
  const { instance, sent, chains } = stored;
  if (!session.ok || !Array.isArray(sent)) return undefined;
  if (instance !== undefined && typeof instance !== "string") return undefined;
  const own: SentPacket[] = [];
  for (const entry of sent as readonly unknown[]) {
    const { id, seal } = (entry ?? {}) as Readonly<Record<string, unknown>>;
    if (typeof id !== "string" || typeof seal !== "boolean") return undefined;
    own.push({ id, seal });
  }
  return {
    id: contentId(session.value),
    session: session.value,
    instance,
    sent: own,
    version: undefined,
    chains,
  };
}

/** @throws TypeError if a client's name for its sending chains is none (12.1). */
export function checkInstance(instance: unknown): void {
  if (instance !== undefined && (typeof instance !== "string" || instance.length > 64)) {
    throw new TypeError("an instance is named by a string of at most 64 characters");
  }
}

/** The sessions a mind follows, as they stand while its client runs. */
export class Following {
  readonly #sessions: Sessions;
  readonly #heads: Map<string, Head>;
  readonly #self: string;
  readonly #instance: string | undefined;
  /** The sessions of which something is held that is not yet written down. */
  readonly changed = new Set<Head>();

  constructor(self: string, instance: string | undefined) {
    this.#self = self;
    this.#instance = instance;
    this.#sessions = new Sessions(self);
    this.#heads = new Map();
  }

  /** Whether the state of a sending chain is held (12.4). */
  readonly holdsChain = (chain: SendingChain): boolean => this.#sessions.holdsChain(chain);

  /** Takes up a session: one made here, or one that was written down. */
  hold(head: Head, chains: unknown): Validation<string> {
    const restored = this.#sessions.restore({
      session: head.session,
      chains: chains as readonly HeldChain[],
    });
    if (restored.ok) this.#heads.set(head.id, head);
    return restored;
  }

  /** What is held of a session. */
  head(id: string): Head | undefined {
    return this.#heads.get(id);
  }

  /** Every session held. */
  heads(): Head[] {
    return [...this.#heads.values()];
  }

  /** Where each chain of a session stands. */
  chains(id: string): readonly HeldChain[] {
    return this.#sessions.held(id)?.chains ?? [];
  }

  #chain(chain: ChainName): HeldChain | undefined {
    return this.chains(chain.session).find(
      ({ from, instance }) => from === chain.mind && instance === chain.instance,
    );
  }

  /** How many packets of a chain are held in order: the `seq` of the first that is lacking. */
  received(chain: ChainName): number {
    return this.#chain(chain)?.ids.length ?? 0;
  }

  /** Forgets a session. */
  drop(head: Head): void {
    this.#sessions.drop(head.id);
    this.#heads.delete(head.id);
    this.changed.delete(head);
  }

  /**
   * Layer 1, 14.2 and 14.3: puts a packet that was accepted in its place in
   * its session. A session first heard of is followed from here on.
   *
   * @param id - The session the packet names.
   */
  take(received: ReceivedPacket, id: string): Validation<Placed> {
    const placed = this.#sessions.take(received);
    // A packet that was placed is of a session that is held: its record is here.
    const session = this.#sessions.session(id);
    if (!placed.ok || session === undefined || placed.value.kind === "duplicate") return placed;
    let head = this.#heads.get(id);
    if (head === undefined) {
      head = { id, session, instance: this.#instance, sent: [], version: undefined };
      this.#heads.set(id, head);
    }
    this.changed.add(head);
    return placed;
  }

  /** This mind's own chain in a session (14.4). */
  own(head: Head): OwnChain {
    return { address: this.#self, instance: head.instance, sent: head.sent.map(({ id }) => id) };
  }

  /** Layer 1, 14.4: how a `Resume` stands against what is held of its sender's chain. */
  against(resume: Resume, from: string): ReturnType<Sessions["against"]> {
    return this.#sessions.against(resume, from);
  }

  /**
   * Layer 1, 14.4: a `Resume` for a session, which says where each chain
   * stands for this mind: its own, after the packets it has sent, and each
   * other of which it holds a packet in order.
   */
  resume(head: Head, created: string): Resume {
    const last = head.sent.at(-1);
    const named = <T extends object>(instance: string | undefined, position: T) =>
      instance === undefined ? position : { ...position, instance };
    return {
      oip: "1",
      type: "Resume",
      session: head.id,
      ...(last === undefined
        ? {}
        : { lastSent: named(head.instance, { seq: head.sent.length - 1, packet: last.id }) }),
      lastReceived: this.chains(head.id).flatMap((chain) => {
        const packet = chain.ids.at(-1);
        return packet === undefined
          ? []
          : [named(chain.instance, { mind: chain.from, seq: chain.ids.length - 1, packet })];
      }),
      created,
    };
  }
}

/** What a mind keeps of its sessions, between the client's memory and its work. */
export class SessionBook {
  readonly #own: Own;
  readonly #instance: string | undefined;
  readonly #left: (packets: readonly string[]) => Promise<unknown>;
  #following: Promise<Following> | undefined;
  /** What is sent in each session, one packet after another. */
  readonly #sending = new Map<string, Promise<unknown>>();

  /**
   * @param instance - The name this client gives its sending chains, for a
   *   mind that runs several clients at once (14.3).
   * @param left - Told the packets the mind sent in a session it has left:
   *   none of them is sent again.
   */
  constructor(
    own: Own,
    instance: string | undefined,
    left: (packets: readonly string[]) => Promise<unknown>,
  ) {
    this.#own = own;
    this.#instance = instance;
    this.#left = left;
  }

  /** The sessions as the client's memory has them, read once. */
  ready(): Promise<Following> {
    this.#following ??= this.#read().catch((error: unknown) => {
      this.#following = undefined;
      throw error;
    });
    return this.#following;
  }

  async #read(): Promise<Following> {
    const { memory, address } = this.#own;
    const following = new Following(address, this.#instance);
    for (const name of await memory.names(SESSION)) {
      const held = await memory.get(name, readHead);
      // A document that was removed since it was listed is a session that was left.
      if (held.value === undefined) continue;
      const { chains, ...head } = held.value;
      head.version = held.version;
      if (name !== nameOf(SESSION, head.id) || !following.hold(head, chains).ok) {
        throw damaged("a session");
      }
    }
    return following;
  }

  /** Makes a session with other minds, and remembers it. Nothing is sent. */
  async open(others: readonly string[]): Promise<{ id: string; session: Session }> {
    const own = this.#own;
    const session = accepted(
      validateRecordOfType("Session", {
        oip: "1",
        type: "Session",
        participants: [...new Set([own.address, ...others])].sort(),
        nonce: bytesToBase64url(own.randomness.bytes(16)),
        created: formatTimestamp(own.clock.now()),
      }),
      "invalid-record",
      "a session is of 2 to 256 minds, each named by its address",
    );
    const id = contentId(session);
    const following = await this.ready();
    const head: Head = { id, session, instance: this.#instance, sent: [], version: undefined };
    accepted(following.hold(head, []), "invalid-record", "the session cannot be followed");
    try {
      await this.#write(following, head);
    } catch (error) {
      following.drop(head);
      throw error;
    }
    return { id, session };
  }

  /** The sessions held. */
  async views(): Promise<SessionView[]> {
    const following = await this.ready();
    return following.heads().map((head) => ({
      id: head.id,
      session: head.session,
      sent: head.sent.length,
      chains: following.chains(head.id).map((chain) => ({
        mind: chain.from,
        ...(chain.instance === undefined ? {} : { instance: chain.instance }),
        received: chain.ids.length,
        ...(chain.equivocation === undefined ? {} : { equivocation: chain.equivocation }),
      })),
    }));
  }

  /**
   * Runs `work` with this mind's next place in a session. The packets of a
   * session are sent one after another: each has its place before the next
   * is signed.
   *
   * @throws OipError `not-found` if the mind is in no such session.
   */
  sending<T>(id: string, work: (place: Place) => Promise<T>): Promise<T> {
    return this.#inTurn(id, async () => work(await this.#place(id)));
  }

  /** Runs work on a session after what was started on it before. */
  #inTurn<T>(id: string, work: () => Promise<T>): Promise<T> {
    const next = (this.#sending.get(id) ?? Promise.resolve()).then(work);
    this.#sending.set(
      id,
      next.catch(() => undefined),
    );
    return next;
  }

  async #place(id: string): Promise<Place> {
    const following = await this.ready();
    const head = following.head(id);
    if (head === undefined) {
      throw new OipError("not-found", "the mind is in no such session", { clause: "L1 14.2" });
    }
    return {
      id,
      session: head.session,
      seq: head.sent.length,
      prev: head.sent.at(-1)?.id,
      instance: head.instance,
      resume: (created) => following.resume(head, created),
      keep: async (packet, seal) => {
        const packetId = contentId(packet);
        const { memory } = this.#own;
        // The packet first, under a name of its own. If the process stops here nothing names
        // it, and nothing was sent.
        await memory.put(nameOf(SENT, packetId), { packet }, undefined);
        head.sent.push({ id: packetId, seal });
        try {
          await this.#write(following, head);
        } catch (error) {
          // What is held may be behind what is written: it is read again before the next use.
          this.#following = undefined;
          throw error;
        }
      },
    };
  }

  /** The packets this mind sent in a session, from `seq` on, as they were sent (14.4). */
  async sent(
    head: Head,
    seq: number,
  ): Promise<{ readonly packet: Packet; readonly seal: boolean }[]> {
    const packets: { packet: Packet; seal: boolean }[] = [];
    for (const { id: packetId, seal } of head.sent.slice(seq)) {
      const held = await this.#own.memory.get(nameOf(SENT, packetId), (stored) => {
        const packet = validateRecordOfType("Packet", stored["packet"]);
        return packet.ok && contentId(packet.value) === packetId ? packet.value : undefined;
      });
      if (held.value === undefined) throw damaged("a packet it sent");
      packets.push({ packet: held.value, seal });
    }
    return packets;
  }

  /**
   * Whether the client's memory has a session that is not held here:
   * another process wrote it down since this one read. What is held is then
   * read again before its next use.
   */
  async behind(id: string): Promise<boolean> {
    const written = await this.#own.memory.get(nameOf(SESSION, id), (stored) => stored);
    if (written.version === undefined) return false;
    this.#following = undefined;
    return true;
  }

  /** Writes down where the chains of the sessions that changed now stand. */
  async save(): Promise<void> {
    const following = await this.ready();
    try {
      for (const head of [...following.changed]) {
        await this.#write(following, head);
        following.changed.delete(head);
      }
    } catch (error) {
      this.#following = undefined;
      throw error;
    }
  }

  async #write(following: Following, head: Head): Promise<void> {
    head.version = await this.#own.memory.put(
      nameOf(SESSION, head.id),
      {
        session: head.session,
        ...(head.instance === undefined ? {} : { instance: head.instance }),
        sent: head.sent,
        chains: following.chains(head.id),
      },
      head.version,
    );
  }

  /**
   * Forgets a session, and the packets sent in it.
   *
   * @returns Whether it was held.
   */
  leave(id: string): Promise<boolean> {
    return this.#inTurn(id, async () => {
      const following = await this.ready();
      const head = following.head(id);
      if (head === undefined) return false;
      const { memory } = this.#own;
      try {
        // The session first: once it is gone, nothing names the packets.
        await memory.forget(nameOf(SESSION, id), head.version);
      } catch (error) {
        // Another process has written it since: it is read again before the next use.
        this.#following = undefined;
        throw error;
      }
      following.drop(head);
      await this.#left(head.sent.map(({ id: packetId }) => packetId));
      for (const { id: packetId } of head.sent) {
        const name = nameOf(SENT, packetId);
        await memory.forget(name, (await memory.get(name, (stored) => stored)).version);
      }
      return true;
    });
  }
}
