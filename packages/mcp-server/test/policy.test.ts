// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { UsageError } from "@oip/local";
import { clause } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { permits, POLICY_FILE, readPolicy } from "../src/policy.ts";

let dir: string;
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "oip-mcp-policy-"));
});
afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});
const write = (value: unknown): void => {
  writeFileSync(join(dir, POLICY_FILE), typeof value === "string" ? value : JSON.stringify(value));
};

const commitment = (price?: { amount: string; currency: string }) => ({
  type: "Commitment",
  promise: "A translation.",
  terms: price === undefined ? {} : { price },
});

describe(`${clause("L0 2.2")} what the assistant may sign without asking`, () => {
  it("is nothing, where the person has said nothing", () => {
    const policy = readPolicy(join(dir, "no-such-directory"));
    expect(policy).toStrictEqual({});
    expect(permits(policy.commit, commitment({ amount: "1", currency: "USD" }))).toBe(false);
    expect(permits(policy.commit, {})).toBe(false);
  });

  it(`${clause("L1 11.3")} is what every statement of their policy holds for, and nothing else`, () => {
    write({
      commit: [
        ["==", ".terms.price.currency", "USD"],
        ["<=", ".terms.price.amount", "50"],
      ],
    });
    const policy = readPolicy(dir);
    expect(permits(policy.commit, commitment({ amount: "50", currency: "USD" }))).toBe(true);
    expect(permits(policy.commit, commitment({ amount: "49.99", currency: "USD" }))).toBe(true);
    expect(permits(policy.commit, commitment({ amount: "50.01", currency: "USD" }))).toBe(false);
    expect(permits(policy.commit, commitment({ amount: "5", currency: "EUR" }))).toBe(false);
    // A statement that selects what the record does not have does not hold: no price is asked about.
    expect(permits(policy.commit, commitment())).toBe(false);
    expect(permits(policy.commit, null)).toBe(false);
  });

  it("is refused where the file is no policy: the server does not guess, and does not start", () => {
    for (const [written, said] of [
      ["not JSON", "is no policy: it holds a JSON object"],
      ["[]", "is no policy: it holds a JSON object"],
      ["null", "is no policy: it holds a JSON object"],
      [
        { commit: [["==", ".a", 1]], delegate: [] },
        "says something of delegate: a policy has commit and receipt alone",
      ],
      [{ commit: "anything under 50" }, "has no statement under `commit`"],
      [{ commit: [["maybe", ".a", 1]] }, "is no policy: "],
      [{ commit: [["<=", "terms.price.amount", "50"]] }, "is no policy: under `commit`, "],
      [{ receipt: [] }, "has no statement under `receipt`"],
      [{ receipt: [["maybe", ".a", 1]] }, "is no policy: under `receipt`, "],
    ] as const) {
      write(written);
      expect(() => readPolicy(dir), JSON.stringify(written)).toThrow(UsageError);
      expect(() => readPolicy(dir), JSON.stringify(written)).toThrow(said);
    }
  });

  it("is never everything: a policy with no statement is refused, since none holds for every record", () => {
    write({ commit: [] });
    expect(() => readPolicy(dir)).toThrow(
      "has no statement under `commit`: say what may be signed unasked, or remove it",
    );
    // A file that says nothing of commitments permits none.
    write({});
    expect(readPolicy(dir)).toStrictEqual({});
  });

  it("speaks of Receipts apart from Commitments: what permits one permits none of the other", () => {
    write({ receipt: [["==", ".outcome", "progress"]] });
    const policy = readPolicy(dir);
    expect(policy.commit).toBeUndefined();
    expect(permits(policy.receipt, { type: "Receipt", outcome: "progress" })).toBe(true);
    expect(permits(policy.receipt, { type: "Receipt", outcome: "fulfilled" })).toBe(false);
    expect(permits(policy.commit, { type: "Receipt", outcome: "progress" })).toBe(false);
  });
});
