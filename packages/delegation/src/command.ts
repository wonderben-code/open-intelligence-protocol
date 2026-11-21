// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Commands: what a delegation grants (Layer 1, 11.2). */

import { OIP_COMMANDS, patterns } from "@oip/schema";

const COMMAND = new RegExp(patterns.command);
const OIP_SPACE = new RegExp(patterns.oipCommandSpace);

/**
 * Layer 1, 11.2 and Layer 2, 7.2: the types of record that can be signed
 * under delegation. Every other type is signed by its author's own
 * authority or not at all.
 */
export const DELEGABLE_TYPES = ["Intent", "Offer", "Commitment", "Receipt"] as const;

/** A type of record that can be signed under delegation. */
export type DelegableType = (typeof DELEGABLE_TYPES)[number];

/** Layer 1, 11.2: the command that grants sending packets on the subject's behalf. */
export const SEND_COMMAND = "/oip/send";

/** Whether a value is one of the delegable types. */
export function isDelegableType(type: unknown): type is DelegableType {
  return (DELEGABLE_TYPES as readonly unknown[]).includes(type);
}

/**
 * Layer 1, 11.2: whether a value is a command: `/` and a segment, any
 * number of times. A reserved command is still a command.
 */
export function isCommand(value: unknown): value is string {
  return typeof value === "string" && COMMAND.test(value);
}

/**
 * Layer 1, 11.2: whether a value is a command that a delegation or a role
 * may grant. Under `/oip` only the listed commands exist. Every other
 * command whose first segment is `oip`, `/oip` and `/oip/sign` among them,
 * is reserved, so that there are no blanket grants. A command with another
 * first segment is an extension's, and may be granted.
 */
export function isDelegableCommand(value: unknown): value is string {
  if (!isCommand(value)) return false;
  return OIP_SPACE.test(value) ? (OIP_COMMANDS as readonly string[]).includes(value) : true;
}

/**
 * Layer 1, 11.2: whether the command `granted` covers the command `needed`:
 * they are equal, or `needed` begins with `granted` and then `/`. So a
 * command covers by whole segments: `/x402/pay` covers `/x402/pay/usd` and
 * does not cover `/x402/payments`.
 *
 * It says nothing of whether either may be granted: see `isDelegableCommand`.
 */
export function covers(granted: unknown, needed: unknown): boolean {
  if (!isCommand(granted) || !isCommand(needed)) return false;
  return needed === granted || needed.startsWith(`${granted}/`);
}

/** Layer 1, 11.2: the command that grants signing records of one type for the subject. */
export function signCommand(type: DelegableType): string {
  return `/oip/sign/${type}`;
}
