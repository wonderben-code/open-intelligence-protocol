// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Sending on another mind's behalf (Layer 1, 11.2). */

import { CLOCK_SKEW, type Instant } from "@oip/core";
import type { JudgedRecord } from "@oip/identity";

import { type DelegationContext, delegatedTime } from "./chain.ts";
import { SEND_COMMAND } from "./command.ts";

/**
 * Layer 1, 11.2: the earliest evaluation time at which a packet counts as
 * sent on `subject`'s behalf, or `undefined` if it never does.
 *
 * It does when the packet names the subject in `provenance.onBehalfOf`, and
 * a proof by the packet's own sender lists in `authority` a chain from the
 * subject that covers `/oip/send`. A receiver must not treat a packet as
 * sent for the subject otherwise: not for a claim in `provenance` alone, and
 * not for a chain on a proof by anyone but the sender.
 *
 * A proof evaluated more than 300 seconds after the packet's `expires` does
 * not count (core 9.6).
 *
 * @param packet - The packet, from `judgeRecord`.
 */
export function sentFor(
  packet: JudgedRecord,
  subject: string,
  context: DelegationContext,
): Instant | undefined {
  const record = packet.record as {
    readonly type: string;
    readonly from?: unknown;
    readonly provenance?: { readonly onBehalfOf?: unknown };
  };
  if (record.type !== "Packet" || typeof record.from !== "string") return undefined;
  if (record.provenance?.onBehalfOf !== subject) return undefined;
  // No time is given for a chain whose check was cut short (ADR-0010): `delegatedTime` gives none.
  const time = delegatedTime(packet, subject, context, { need: SEND_COMMAND, signer: record.from });
  if (time === undefined) return undefined;
  return packet.expires !== undefined && time > packet.expires + CLOCK_SKEW ? undefined : time;
}
