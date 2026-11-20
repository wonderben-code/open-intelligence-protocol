// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What the person is asked before a Commitment is signed in their name.
 *
 * The question is written here, from the record that would be signed, and
 * from nothing the assistant says of it. An assistant that was talked into
 * a Commitment would describe it kindly: the person reads what binds them,
 * as it is, and not a description of it.
 */

import { type JsonObject, printable } from "./text.ts";

/** A Commitment as the question reads it: what a schema has already checked. */
interface Asked {
  readonly parties: readonly { readonly mind: string; readonly role: string }[];
  readonly promise: string;
  readonly terms: {
    readonly deadline?: string;
    readonly price?: {
      readonly amount: string;
      readonly currency: string;
      readonly payer: string;
      readonly payee: string;
    };
    readonly conditions?: unknown;
    readonly deliverables?: unknown;
  };
  readonly expires?: string;
  readonly closesIntent?: boolean;
  readonly resolves?: readonly string[];
}

/** The longest promise shown whole. A Commitment's promise is at most 8192 characters. */
const MOST = 2000;

/**
 * The question, as lines of plain text.
 *
 * @param record - The Commitment that would be signed, without proofs of this mind.
 * @param self - The address of the mind that would sign.
 * @param cosigning - Whether another mind wrote it, and this one is asked to sign it too.
 */
export function questionOf(record: JsonObject, self: string, cosigning: boolean): string {
  const asked = record as unknown as Asked;
  const named = (mind: string): string => (mind === self ? `${mind} (YOU)` : mind);
  const mine = asked.parties.filter(({ mind }) => mind === self).map(({ role }) => role);
  const promise = printable(asked.promise);
  const { deadline, price, conditions, deliverables } = asked.terms;
  return [
    cosigning
      ? "Your assistant asks to SIGN a Commitment that another party wrote. Signing it binds you."
      : "Your assistant asks to WRITE AND SIGN a Commitment in your name. Signing it binds you.",
    "",
    mine.length === 0
      ? "You are not named as a party in it."
      : `In it you are: ${mine.join(", ")}.`,
    "",
    "Parties:",
    ...asked.parties.map(({ mind, role }) => `  ${role}: ${named(printable(mind))}`),
    "",
    "What is promised, word for word:",
    `  ${promise.length > MOST ? `${promise.slice(0, MOST)} … (${String(promise.length - MOST)} more characters, not shown)` : promise}`,
    ...(price === undefined
      ? ["", "No price is named."]
      : [
          "",
          `Price: ${printable(price.amount)} ${printable(price.currency)}`,
          `  paid by: ${named(printable(price.payer))}`,
          `  paid to: ${named(printable(price.payee))}`,
        ]),
    ...(deadline === undefined ? [] : ["", `Deadline: ${printable(deadline)}`]),
    ...(conditions === undefined ? [] : ["", "It names conditions, which are not shown here."]),
    ...(deliverables === undefined ? [] : ["", "It names deliverables, which are not shown here."]),
    ...(asked.resolves === undefined || asked.resolves.length === 0
      ? []
      : ["", `It answers: ${asked.resolves.map((ref) => printable(ref)).join(", ")}`]),
    ...(asked.closesIntent === true ? ["Once accepted, the Intent it answers is satisfied."] : []),
    ...(asked.expires === undefined
      ? []
      : ["", `It can be signed until: ${printable(asked.expires)}`]),
    "",
    "A Commitment cannot be taken back once it is signed. Sign it?",
  ].join("\n");
}
