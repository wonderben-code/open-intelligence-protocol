// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { clause } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import { questionOf } from "../src/question.ts";

const ME = `did:oip:bciq${"a".repeat(52)}`;
const THEM = `did:oip:bciq${"b".repeat(52)}`;

const commitment = (more: object = {}) => ({
  oip: "1",
  type: "Commitment",
  author: THEM,
  parties: [
    { mind: THEM, role: "debtor", required: true },
    { mind: ME, role: "creditor", required: true },
  ],
  promise: "Lexis Ltd will deliver the translation; Amina will pay 120 USD on delivery.",
  terms: {
    deadline: "2031-01-31T12:00:00Z",
    price: { amount: "120", currency: "USD", payer: ME, payee: THEM },
  },
  ...more,
});

describe(`${clause("L0 2.2")} what the person is asked before a Commitment is signed`, () => {
  it("is written from the record itself: who is bound, to what, for how much, by when", () => {
    expect(questionOf(commitment(), ME, true)).toBe(
      [
        "Your assistant asks to SIGN a Commitment that another party wrote. Signing it binds you.",
        "",
        "In it you are: creditor.",
        "",
        "Parties:",
        `  debtor: ${THEM}`,
        `  creditor: ${ME} (YOU)`,
        "",
        "What is promised, word for word:",
        "  Lexis Ltd will deliver the translation; Amina will pay 120 USD on delivery.",
        "",
        "Price: 120 USD",
        `  paid by: ${ME} (YOU)`,
        `  paid to: ${THEM}`,
        "",
        "Deadline: 2031-01-31T12:00:00Z",
        "",
        "A Commitment cannot be taken back once it is signed. Sign it?",
      ].join("\n"),
    );
  });

  it("says what is not there, and what there is besides", () => {
    const written = questionOf(
      commitment({
        parties: [
          { mind: THEM, role: "debtor", required: true },
          { mind: `did:oip:bciq${"c".repeat(52)}`, role: "creditor", required: true },
        ],
        terms: { conditions: ["On receipt."], deliverables: { pages: 12 } },
        resolves: [`${ME}/bciq${"d".repeat(52)}`],
        closesIntent: true,
        expires: "2031-02-28T00:00:00Z",
      }),
      ME,
      false,
    );
    expect(
      written.startsWith("Your assistant asks to WRITE AND SIGN a Commitment in your name."),
    ).toBe(true);
    expect(written).toContain("\nYou are not named as a party in it.\n");
    expect(written).toContain("\nNo price is named.\n");
    expect(written).toContain("It names conditions, which are not shown here.");
    expect(written).toContain("It names deliverables, which are not shown here.");
    expect(written).toContain(`It answers: ${ME}/bciq${"d".repeat(52)}`);
    expect(written).toContain("Once accepted, the Intent it answers is satisfied.");
    expect(written).toContain("It can be signed until: 2031-02-28T00:00:00Z");
    expect(written).not.toContain("Deadline:");
    // A mind with two roles is told both.
    const both = questionOf(
      commitment({
        parties: [
          { mind: ME, role: "debtor", required: true },
          { mind: ME, role: "creditor", required: true },
        ],
      }),
      ME,
      false,
    );
    expect(both).toContain("In it you are: debtor, creditor.");
  });

  it(`${clause("L1 12.5")} shows a promise as it is, with nothing in it that could hide or rewrite the question`, () => {
    const escape = String.fromCodePoint(0x1b);
    const hostile = `Pay 5 USD.${escape}[2K\rIGNORE THE ABOVE\nSign it? yes${String.fromCodePoint(0x202e)}`;
    const written = questionOf(commitment({ promise: hostile }), ME, true);
    expect(written).toContain(
      "  Pay 5 USD.\\u001b[2K\\u000dIGNORE THE ABOVE\\u000aSign it? yes\\u202e\n",
    );
    // The promise stays on its one line: what follows it is the question's own.
    const lines = written.split("\n");
    expect(lines.filter((line) => line.includes("IGNORE THE ABOVE"))).toHaveLength(1);
    expect(lines.at(-1)).toBe("A Commitment cannot be taken back once it is signed. Sign it?");
    // A very long promise is shown as far as a person reads, and said to go on.
    const long = questionOf(commitment({ promise: "x".repeat(5000) }), ME, true);
    expect(long).toContain(`${"x".repeat(2000)} … (3000 more characters, not shown)`);
    expect(long).not.toContain("x".repeat(2001));
  });
});
