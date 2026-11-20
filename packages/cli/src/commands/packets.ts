// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A packet as the commands show it and keep it. What a packet carries is
 * data, whatever it says (Layer 1, 12.5): it is shown, and never acted on.
 */

import type { Delivery, Received } from "@oip/client";
import { contentId, formatTimestamp, type JsonObject } from "@oip/core";
import {
  type InlineContent,
  type Packet,
  type ReferencedContent,
  validateRecord,
} from "@oip/schema";

import { quoted } from "../text.ts";
import { row } from "./describe.ts";

/** A packet that was received, as the mind's directory keeps it. */
export interface KeptPacket {
  /** The packet's content ID. */
  readonly id: string;
  /** The sender, whose signature on it counted when it was received. */
  readonly from: string;
  /** Whether it arrived sealed to this mind. */
  readonly sealed: boolean;
  /** The evaluation time of the sender's signature, as a timestamp. */
  readonly time: string;
  /** The mind it was sent for, if a chain of delegations showed it. */
  readonly sentFor?: string;
  /** The broker that forwarded it, if it was addressed to a query. */
  readonly broker?: string;
  /** The packet. */
  readonly packet: Packet;
}

/** A packet as it is kept, from one as the client returned it. */
export function keptOf(received: Received): KeptPacket {
  const { id, from, sealed, time, sentFor, broker, packet } = received;
  return {
    id,
    from,
    sealed,
    time: formatTimestamp(time),
    ...(sentFor === undefined ? {} : { sentFor }),
    ...(broker === undefined ? {} : { broker }),
    packet,
  };
}

/** A packet that is kept, read back: `undefined` for a file that holds no such thing. */
export function keptFrom(value: JsonObject): KeptPacket | undefined {
  const { id, from, sealed, time, sentFor, broker, packet } = value;
  const record = validateRecord(packet);
  if (!record.ok || record.value.type !== "Packet" || contentId(record.value) !== id) {
    return undefined;
  }
  if (typeof from !== "string" || typeof sealed !== "boolean" || typeof time !== "string") {
    return undefined;
  }
  return {
    id,
    from,
    sealed,
    time,
    ...(typeof sentFor === "string" ? { sentFor } : {}),
    ...(typeof broker === "string" ? { broker } : {}),
    packet: record.value,
  };
}

/** The lines for one part of a packet's content. */
function partLines(part: InlineContent | ReferencedContent): string[] {
  const { mediaType } = part;
  if ("ref" in part) return [row("reference", `${mediaType} at ${part.ref} (${part.digest})`)];
  const { body } = part;
  if (mediaType === "application/oip+json") {
    const record = validateRecord(body);
    return [
      row(
        "record",
        record.ok ? `${record.value.type} ${contentId(record.value)}` : "one that is no record",
      ),
    ];
  }
  if (typeof body === "string" && mediaType.startsWith("text/")) {
    return [row("text", mediaType === "text/plain" ? "" : mediaType).trimEnd(), ...quoted(body)];
  }
  return [row("content", `${mediaType}: --json has it`)];
}

/** The lines that show a packet's purpose and what it carries. */
export function packetLines(packet: Packet): string[] {
  const { purpose, content } = packet;
  const parts = "parts" in content ? content.parts : [content];
  return [
    row("verb", purpose.goal === undefined ? purpose.verb : `${purpose.verb}: ${purpose.goal}`),
    ...(packet.replyTo === undefined ? [] : [row("reply to", packet.replyTo)]),
    ...(packet.thread === undefined ? [] : [row("thread", packet.thread)]),
    ...(packet.session === undefined
      ? []
      : [row("session", `${packet.session}, packet ${String(packet.seq ?? 0)} of its sender`)]),
    ...parts.flatMap((part) => partLines(part)),
  ];
}

/** The lines that show a packet that was received. */
export function receivedLines(kept: KeptPacket): string[] {
  return [
    kept.id,
    row("from", kept.sentFor === undefined ? kept.from : `${kept.from}, for ${kept.sentFor}`),
    row("at", `${kept.time}${kept.sealed ? ", sealed to this mind" : ", not sealed"}`),
    ...(kept.broker === undefined ? [] : [row("through", kept.broker)]),
    ...packetLines(kept.packet),
  ];
}

/** The line that says what became of a packet for one recipient. */
export function deliveryLine(delivery: Delivery): string {
  const { to, stored, sealed, ack, failure, queued } = delivery;
  if (stored) {
    return row(
      "delivered",
      `${to}${sealed ? ", sealed" : ", not sealed"}${ack === undefined ? "" : ", and acknowledged"}`,
    );
  }
  const why = failure ?? "no endpoint took it";
  return queued === true
    ? row("waiting", `${to} (${why}): it is kept, and tried again`)
    : row("not sent", `${to} (${why})`);
}
