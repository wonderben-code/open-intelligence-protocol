// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Receiving a packet (Layer 1, 12.4).
 *
 * A receiver accepts a packet only if its sender signed it, it is addressed
 * to the receiver, and its dates allow it now. It discards a packet it has
 * accepted before. The rules are one function here, with the present and
 * the receiver's memory as parameters: the package reads no clock and keeps
 * nothing of its own.
 *
 * What a packet carries is data (12.5). Nothing here reads `content`, and
 * nothing a packet says gives anyone authority.
 */

import { contentId, type Instant } from "@oip/core";
import {
  type FirstSeen,
  type IdentityView,
  type JudgedRecord,
  type JudgeOptions,
  judgeRecord,
  ownSignedTime,
  witnessRecord,
} from "@oip/identity";
import type { Forwarded, Packet, Validation } from "@oip/schema";

import { packetDates } from "./dates.ts";
import { no, ok, under } from "./result.ts";

/** A sending chain of a session (Layer 1, 14.3): one instance of one participant. */
export interface SendingChain {
  /** The session's ID. */
  readonly session: string;
  /** The participant that sends. */
  readonly from: string;
  /** The instance of it that sends, if it names one. */
  readonly instance: string | undefined;
}

/** A receiver: who it is, what time it is, and what it holds and remembers. */
export interface Receiver extends JudgeOptions {
  /** The receiver's own address. */
  readonly address: string;
  /** The present: the receiver's own clock, read by the caller. */
  readonly now: Instant;
  /** The identity logs the receiver holds, and its evidence of time. */
  readonly view: IdentityView;
  /**
   * The receiver's own record of when it first saw each proof (core 9.4),
   * which is written to: the proofs of a packet whose address and dates
   * allow it are recorded as seen at `now`. It should be part of the
   * evidence of `view`. A receiver that leaves it out records first sight
   * itself, before it calls: with no evidence for a proof, no packet counts.
   */
  readonly seen?: FirstSeen;
  /**
   * Whether a packet with this content ID was accepted before and is not
   * yet forgotten. `AcceptedPackets` is one such memory.
   */
  readonly accepted: (id: string) => boolean;
  /**
   * How far back the receiver remembers the packets it accepted that state
   * no `expires`, in nanoseconds (12.4: its duplicate-detection window).
   */
  readonly window: bigint;
  /**
   * Whether the receiver still holds the state of a sending chain (14.3).
   * A session packet older than the window is accepted only then. Default:
   * it holds none.
   */
  readonly holdsChain?: (chain: SendingChain) => boolean;
}

/** A packet a receiver may act on, or has acted on before. */
export interface ReceivedPacket {
  /** The packet's content ID, which is its identifier (12.1). */
  readonly id: string;
  /** The packet. */
  readonly packet: Packet;
  /** The packet as it was judged, with every proof that verified. */
  readonly judged: JudgedRecord;
  /** The evaluation time of its sender's signature. */
  readonly time: Instant;
  /**
   * Whether the receiver accepted this packet before. A duplicate is
   * discarded (12.4): it is not acted on again. It may be acknowledged
   * again, since the sender may not have had the first acknowledgement.
   */
  readonly duplicate: boolean;
  /**
   * The time after which the packet can no longer be accepted. Until then
   * the receiver remembers that it accepted it.
   */
  readonly forgetAfter: Instant;
  /** For a packet addressed to a query: the broker that forwarded it (18.5). */
  readonly broker: string | undefined;
}

/**
 * Layer 1, 12.4: judges a packet that has arrived, or a `Forwarded` record
 * that carries one.
 *
 * In order:
 *
 * 1. The value is a well-formed `Packet`, or a `Forwarded` record with one.
 * 2. It is addressed to the receiver: `to` lists the receiver's address. A
 *    packet addressed to a query is accepted only inside a `Forwarded`
 *    record that is addressed to the receiver and signed by its broker, and
 *    only from a broker the packet lists when it lists any. A packet
 *    addressed to a subject is reserved, and no receiver accepts one.
 * 3. Its dates allow it now (`packetDates`).
 * 4. Its sender signed it: by a valid operational key of the sender, or for
 *    a collective by its threshold (Layer 1, 6.1, 9.5), on the receiver's
 *    evidence. The receiver's own first sight is recorded first, if `seen`
 *    is given, and only for a packet that has passed 1 to 3: a stranger's
 *    packet for someone else adds nothing to what the receiver keeps.
 * 5. Whether it was accepted before is asked last, of a packet that has
 *    verified. A copy with a broken proof has the genuine packet's content
 *    ID, and is rejected for its proof.
 *
 * The caller records an accepted packet that is no duplicate
 * (`AcceptedPackets.record`), and then acts on it. Packets of a session are
 * checked further under Section 14.
 *
 * It never throws on the value. The receiver is the caller's own, and a
 * mistake in it is a `TypeError`.
 *
 * @param value - What arrived, as parsed.
 */
export function receivePacket(value: unknown, receiver: Receiver): Validation<ReceivedPacket> {
  if (typeof (receiver.now as unknown) !== "bigint") throw new TypeError("now is not a time");
  if (typeof (receiver.window as unknown) !== "bigint") {
    throw new TypeError("the window is a duration in nanoseconds, a bigint");
  }
  const options: JudgeOptions | undefined =
    receiver.understood === undefined ? undefined : { understood: receiver.understood };
  const judged = judgeRecord(value, options);
  if (!judged.ok) return judged;
  const { type } = judged.value.record;
  if (type === "Packet") return direct(judged.value, receiver);
  if (type === "Forwarded") return forwarded(judged.value, receiver, options);
  return no("the record is neither a Packet nor a Forwarded record", "L1 12.4", "/type");
}

const RESERVED = "a packet addressed to a subject is reserved: no receiver accepts one";
const NOT_FOR_RECEIVER = "the receiver is not among the packet's recipients";

/** A packet that arrived as itself. */
function direct(judged: JudgedRecord, receiver: Receiver): Validation<ReceivedPacket> {
  const packet = judged.record as Packet;
  if (!Array.isArray(packet.to)) {
    return Object.hasOwn(packet.to, "query")
      ? no(
          "a packet addressed to a query is accepted only inside a Forwarded record from a broker",
          "L1 12.4",
          "/to",
        )
      : no(RESERVED, "L1 12.1", "/to");
  }
  if (!packet.to.includes(receiver.address)) return no(NOT_FOR_RECEIVER, "L1 12.4", "/to");
  return accept(judged, packet, receiver, "", undefined);
}

/** A packet that a broker forwarded (Layer 1, 18.5). */
function forwarded(
  judged: JudgedRecord,
  receiver: Receiver,
  options: JudgeOptions | undefined,
): Validation<ReceivedPacket> {
  const wrapper = judged.record as Forwarded;
  const inner = judgeRecord(wrapper.packet, options);
  if (!inner.ok) return under("/packet", inner);
  if (inner.value.record.type !== "Packet") {
    return no("a Forwarded record carries a Packet", "L1 18.5", "/packet/type");
  }
  const packet = inner.value.record as Packet;
  if (Array.isArray(packet.to)) {
    // A packet addressed by a list stands by its own proof, however it arrived (12.4):
    // the wrapper adds nothing to it, and is not judged.
    return packet.to.includes(receiver.address)
      ? accept(inner.value, packet, receiver, "/packet", undefined)
      : no(NOT_FOR_RECEIVER, "L1 12.4", "/packet/to");
  }
  if (!Object.hasOwn(packet.to, "query")) return no(RESERVED, "L1 12.1", "/packet/to");
  if (wrapper.to !== receiver.address) {
    return no("the Forwarded record is addressed to another mind", "L1 18.5", "/to");
  }
  const brokers = (packet.to as { readonly brokers?: readonly string[] }).brokers;
  if (brokers !== undefined && !brokers.includes(wrapper.broker)) {
    return no(
      "the packet names its brokers, and the one that forwarded it is not among them",
      "L1 12.4",
      "/packet/to/brokers",
    );
  }
  return accept(inner.value, packet, receiver, "/packet", { judged, broker: wrapper.broker });
}

/**
 * The dates, the signatures and the receiver's memory, for a packet addressed to the receiver.
 *
 * @param path - Where the packet is in what arrived: what is wrong with it is wrong there.
 * @param carrier - The `Forwarded` record that carried it, for a packet addressed to a query.
 */
function accept(
  judged: JudgedRecord,
  packet: Packet,
  receiver: Receiver,
  path: string,
  carrier: { readonly judged: JudgedRecord; readonly broker: string } | undefined,
): Validation<ReceivedPacket> {
  const { session } = packet;
  const dated = packetDates(packet, {
    now: receiver.now,
    window: receiver.window,
    // It is asked only of a packet that states no `expires`, and such a packet names a
    // session (12.1).
    holdsChain: () =>
      session !== undefined &&
      receiver.holdsChain?.({ session, from: packet.from, instance: packet.instance }) === true,
  });
  if (!dated.ok) return under(path, dated);
  if (receiver.seen !== undefined) {
    witnessRecord(judged, receiver.now, receiver.seen);
    if (carrier !== undefined) witnessRecord(carrier.judged, receiver.now, receiver.seen);
  }
  if (
    carrier !== undefined &&
    ownSignedTime(carrier.judged, carrier.broker, receiver.view) === undefined
  ) {
    return no(
      "the Forwarded record is not signed by its broker's own authority",
      "L1 18.5",
      "/proof",
    );
  }
  const time = ownSignedTime(judged, packet.from, receiver.view);
  if (time === undefined) {
    return no(
      "the packet carries no proof that counts by its sender's own authority",
      "L1 12.4",
      `${path}/proof`,
    );
  }
  const id = contentId(packet);
  return ok({
    id,
    packet,
    judged,
    time,
    duplicate: receiver.accepted(id),
    forgetAfter: dated.value,
    broker: carrier?.broker,
  });
}

/**
 * Layer 1, 12.4: the packets a receiver has accepted, each remembered until
 * it can no longer be accepted.
 *
 * It grows with the packets accepted and not yet forgotten. A packet is
 * accepted only from a sender whose signature counts, addressed to the
 * receiver, so it is for the receiver to limit how many it takes from one
 * sender; call `forget` as the clock moves.
 */
export class AcceptedPackets {
  readonly #until = new Map<string, Instant>();

  /** Whether a packet with this content ID is remembered. Pass it as `Receiver.accepted`. */
  readonly has = (id: string): boolean => this.#until.has(id);

  /** How many packets are remembered. */
  get size(): number {
    return this.#until.size;
  }

  /**
   * Remembers a packet that `receivePacket` accepted. Call it before acting
   * on the packet, and only for a result of `receivePacket`: a content ID
   * is recorded only after the packet has verified (12.4), so that a
   * corrupted copy cannot cause the genuine packet to be discarded.
   */
  record(received: ReceivedPacket): void {
    const until = this.#until.get(received.id);
    if (until === undefined || until < received.forgetAfter) {
      this.#until.set(received.id, received.forgetAfter);
    }
  }

  /**
   * Forgets every packet that can no longer be accepted at `now`.
   *
   * @returns How many were forgotten.
   */
  forget(now: Instant): number {
    if (typeof (now as unknown) !== "bigint") throw new TypeError("now is not a time");
    let forgotten = 0;
    for (const [id, until] of this.#until) {
      if (until < now) {
        this.#until.delete(id);
        forgotten++;
      }
    }
    return forgotten;
  }
}
