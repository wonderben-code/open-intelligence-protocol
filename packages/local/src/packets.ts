// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A packet that was received, as a mind's directory keeps it. A mailbox
 * gives a packet once, so a program that reads one writes it down before it
 * does anything else with it.
 */

import type { Received } from "@oip/client";
import { contentId, formatTimestamp, type JsonObject } from "@oip/core";
import { type Packet, validateRecord } from "@oip/schema";

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
