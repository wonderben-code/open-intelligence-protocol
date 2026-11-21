// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Acknowledgements (Layer 1, 13.2).
 *
 * A recipient that takes a packet in answers with an `Ack`: a signed record
 * that names the packet and says when it was received. To the sender it
 * shows that the packet arrived. To anyone who trusts the recipient for
 * this, it is evidence of time (core 9.4, item 4) for the proofs the packet
 * carried: those of the records in its `content`, which the packet's
 * content ID covers, and those on the packet itself that the `Ack` lists by
 * digest.
 */

import { contentId, type Instant, parseTimestamp, verifyProofs } from "@oip/core";
import {
  type FirstSeen,
  type IdentityView,
  type JudgedRecord,
  type JudgeOptions,
  judgeRecord,
  ownSignedTime,
  witnessRecord,
} from "@oip/identity";
import type { Ack, Packet, Validation } from "@oip/schema";

import type { ReceivedPacket } from "./packet.ts";
import { finding, judging, no, ok } from "./result.ts";

/** core 10.1: the media type with which a packet's content is a record (Layer 1, 12.2). */
const RECORD = "application/oip+json";

/** What an `Ack` says, for the recipient to sign. */
export interface AckDraft {
  /** The packet, as `receivePacket` accepted it. */
  readonly received: ReceivedPacket;
  /** The recipient that acknowledges: one of the packet's recipients. */
  readonly recipient: string;
  /** When the recipient received the packet: its own clock, read when the packet arrived. */
  readonly at: string;
  /** The time the `Ack` is made, as a timestamp. */
  readonly created: string;
  /** The content ID of the `Sealed` record the packet arrived in, if it arrived in one. */
  readonly sealed?: string;
}

/**
 * Layer 1, 13.2: the `Ack` for a packet, not yet signed. It lists the
 * digests of the proofs on the packet that verified, so that it is evidence
 * for them. Sign it with `createProof` of `@oip/core`. A duplicate is
 * answered with the acknowledgement made the first time.
 */
export function draftAck(draft: AckDraft): Omit<Ack, "proof"> {
  return {
    oip: "1",
    type: "Ack",
    author: draft.recipient,
    packet: draft.received.id,
    ...(draft.sealed === undefined ? {} : { sealed: draft.sealed }),
    proofs: draft.received.judged.proofs.map((proof) => proof.digest),
    received: draft.at,
    created: draft.created,
  };
}

/** An acknowledgement that its recipient signed. */
export interface VerifiedAck {
  /** The `Ack`. */
  readonly ack: Ack;
  /** The recipient that acknowledges. */
  readonly recipient: string;
  /** The content ID of the packet it acknowledges. */
  readonly packet: string;
  /** When the recipient says it received the packet. */
  readonly received: Instant;
  /** The evaluation time of the recipient's signature on the `Ack`. */
  readonly time: Instant;
}

/** What an `Ack` is judged with. */
export interface AckContext extends JudgeOptions {
  /** The identity logs held, and the evidence of time. */
  readonly view: IdentityView;
  /**
   * The verifier's own record of first sight, which is written to: the
   * proofs of the `Ack` are recorded as seen at `now`. Give both or neither.
   */
  readonly seen?: FirstSeen;
  /** The present, read by the caller: when the `Ack` was obtained. */
  readonly now?: Instant;
}

/**
 * Layer 1, 13.2: judges an `Ack`: a well-formed one, signed by its author's
 * own authority (a valid operational key, or a collective's threshold).
 *
 * It says nothing yet of any packet: see `acknowledges`. It never throws
 * on the value.
 */
export function verifyAck(value: unknown, context: AckContext): Validation<VerifiedAck> {
  if ((context.seen === undefined) !== (context.now === undefined)) {
    throw new TypeError("give the record of first sight and the present together, or neither");
  }
  return judging(() => acknowledgement(value, context));
}

/** The `Ack`, as `verifyAck` answers when no check is cut short. */
function acknowledgement(value: unknown, context: AckContext): Validation<VerifiedAck> {
  const judged = judgeRecord(
    value,
    context.understood === undefined ? undefined : { understood: context.understood },
  );
  if (!judged.ok) return judged;
  if (judged.value.record.type !== "Ack") return no("the record is not an Ack", "L1 13.2", "/type");
  const ack = judged.value.record as Ack;
  const received = parseTimestamp(ack.received);
  if (received === undefined) return no("`received` is not a timestamp", "core 1.4", "/received");
  if (context.seen !== undefined && context.now !== undefined) {
    witnessRecord(judged.value, context.now, context.seen);
  }
  const time = ownSignedTime(judged.value, ack.author, context.view);
  if (time === undefined) {
    return no("the Ack is not signed by its author's own authority", "L1 13.2", "/proof");
  }
  return ok({ ack, recipient: ack.author, packet: ack.packet, received, time });
}

/**
 * Layer 1, 13.2: whether an `Ack` acknowledges this packet for one of its
 * recipients: it names the packet's content ID, and its author is among
 * the minds the packet is addressed to. A packet addressed to a query has
 * no list of recipients, and any mind may have received it from a broker.
 *
 * @param packet - The packet, from `judgeRecord`.
 */
export function acknowledges(ack: VerifiedAck, packet: JudgedRecord): boolean {
  if (packet.record.type !== "Packet") return false;
  const { to } = packet.record as Packet;
  if (Array.isArray(to) ? !to.includes(ack.recipient) : !Object.hasOwn(to, "query")) return false;
  // Where nothing can be hashed, nothing is acknowledged.
  return finding(() => ack.packet === contentId(packet.record)) === true;
}

/** Evidence of time for some proofs (core 9.4). */
export interface AckEvidence {
  /** The time the proofs are shown to have existed at: the `received` of the `Ack`. */
  readonly time: Instant;
  /** The digests of the proofs. */
  readonly proofs: readonly string[];
}

/**
 * core 9.4, item 4: what an `Ack` is evidence for, to a verifier that
 * trusts its author for this.
 *
 * The proofs are those that verify on the records the packet carries in
 * its `content`, as a body or a part: the packet's content ID covers them,
 * so the packet the recipient received had them. A proof on the packet
 * itself is not covered by the content ID. It is among the evidence only
 * if the `Ack` lists its digest in `proofs`.
 *
 * Whether to trust the recipient is the caller's decision, and nothing here
 * makes it: record the result in a `FirstSeen` only for a recipient whose
 * word on time you would take.
 *
 * @param packet - The packet as held, from `judgeRecord`.
 * @returns `undefined` if the `Ack` does not acknowledge this packet.
 */
export function ackEvidence(ack: VerifiedAck, packet: JudgedRecord): AckEvidence | undefined {
  // Evidence for some of the proofs and not for others, because a check was cut short, would
  // be kept as if it were all there is: there is none then.
  return finding(() => evidenceOf(ack, packet));
}

/** The evidence, as `ackEvidence` answers when no check is cut short. */
function evidenceOf(ack: VerifiedAck, packet: JudgedRecord): AckEvidence | undefined {
  if (!acknowledges(ack, packet)) return undefined;
  const proofs = new Set<string>();
  const listed = new Set(ack.ack.proofs ?? []);
  for (const proof of packet.proofs) if (listed.has(proof.digest)) proofs.add(proof.digest);
  const content = (packet.record as Packet).content as {
    readonly mediaType?: string;
    readonly body?: unknown;
    readonly parts?: readonly { readonly mediaType?: string; readonly body?: unknown }[];
  };
  for (const part of content.parts ?? [content]) {
    if (part.mediaType !== RECORD) continue;
    for (const proof of verifyProofs(part.body).verified) proofs.add(proof.digest);
  }
  return { time: ack.received, proofs: [...proofs] };
}
