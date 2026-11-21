// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What the person is asked before a Commitment or a Receipt is signed in
 * their name.
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

/** A text of another's or of the assistant's, on one line, and no longer than is shown whole. */
function quoted(text: string): string {
  const line = printable(text);
  return line.length > MOST
    ? `${line.slice(0, MOST)} … (${String(line.length - MOST)} more characters, not shown)`
    : line;
}

/**
 * The question before a Commitment is signed, as lines of plain text.
 *
 * @param record - The Commitment that would be signed, without proofs of this mind.
 * @param self - The address of the mind that would sign.
 * @param cosigning - Whether another mind wrote it, and this one is asked to sign it too.
 */
export function commitmentQuestion(record: JsonObject, self: string, cosigning: boolean): string {
  const asked = record as unknown as Asked;
  const named = (mind: string): string => (mind === self ? `${mind} (YOU)` : mind);
  const mine = asked.parties.filter(({ mind }) => mind === self).map(({ role }) => role);
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
    `  ${quoted(asked.promise)}`,
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

/** What each outcome of a Receipt says, to the person who is asked to say it. */
const OUTCOMES: Readonly<Record<string, string>> = {
  accepted: "ACCEPTED: you take it on",
  progress: "IN PROGRESS: work on it has moved on",
  fulfilled: "FULFILLED: what was promised has been done",
  broken: "BROKEN: what was promised was not done",
  cancelled: "CANCELLED: it is called off",
  disputed: "DISPUTED: you contest it",
};

/**
 * The question before a Receipt is signed, as lines of plain text.
 *
 * @param receipt - The Receipt that would be signed, without its proof.
 * @param about - The record it is about, which this mind holds.
 * @param self - The address of the mind that would sign.
 */
export function receiptQuestion(receipt: JsonObject, about: JsonObject, self: string): string {
  const { outcome, statement, rating } = receipt as {
    outcome: string;
    statement?: string;
    rating?: { score?: string };
  };
  const subject = about as Partial<Asked> & { type?: string; author?: string };
  const named = (mind: string): string => (mind === self ? `${mind} (YOU)` : mind);
  const mine = (subject.parties ?? []).filter(({ mind }) => mind === self).map(({ role }) => role);
  const owed = mine.includes("creditor");
  return [
    "Your assistant asks to PUBLISH A RECEIPT in your name: a signed, public statement of what",
    "became of a record. It cannot be withdrawn.",
    "",
    `It says the record below is now ${OUTCOMES[outcome] ?? printable(outcome)}.`,
    ...(statement === undefined
      ? []
      : ["", "In your words, as the assistant wrote them:", `  ${quoted(statement)}`]),
    ...(rating?.score === undefined
      ? []
      : ["", `Your rating: ${printable(rating.score)} out of 1`]),
    "",
    `The record: a ${printable(subject.type ?? "record")}${
      typeof subject.author === "string" ? `, written by ${named(printable(subject.author))}` : ""
    }`,
    ...(subject.parties === undefined
      ? []
      : subject.parties.map(({ mind, role }) => `  ${printable(role)}: ${named(printable(mind))}`)),
    ...(typeof subject.promise === "string"
      ? ["", "What it promises, word for word:", `  ${quoted(subject.promise)}`]
      : []),
    ...(owed && outcome === "fulfilled"
      ? ["", "You are owed what it promises. Saying it is fulfilled says you have received it."]
      : []),
    "",
    "Publish it?",
  ].join("\n");
}
