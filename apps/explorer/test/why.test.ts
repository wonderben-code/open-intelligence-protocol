// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { repoRoot } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import { anchorOf, clauseOf, WHY } from "../src/oip/why.ts";

describe("why the Explorer says what it says", () => {
  it("gives each thing a page shows a reason, with clauses the specifications have", () => {
    const reasons = Object.entries(WHY);
    expect(reasons.length).toBeGreaterThan(12);
    for (const [name, { says, clauses }] of reasons) {
      expect(says.length, name).toBeGreaterThan(40);
      expect(clauses.length, name).toBeGreaterThan(0);
      for (const clause of clauses) {
        expect(clause.id, name).toMatch(/^(?:core|L[012]) \d+(?:\.\d+)?$/u);
        expect(clause.summary.length, clause.id).toBeGreaterThan(10);
      }
    }
    // A name the specifications do not have is no clause.
    expect(clauseOf("L1 99.9")).toBeUndefined();
    expect(clauseOf("implementation limit")).toBeUndefined();
  });

  it("points at the section of the specification that each clause is in", () => {
    for (const { clauses } of Object.values(WHY)) {
      for (const { id, href, section } of clauses) {
        const [, file = "", fragment = ""] =
          /\/spec\/([a-z0-9-]+\.md)(#[a-z0-9-]+)$/u.exec(href) ?? [];
        const text = readFileSync(join(repoRoot, "spec", file), "utf8");
        const [, place = ""] = id.split(" ");
        const [number = ""] = place.split(".");
        // The heading is there, and its fragment is the one a page that shows the file gives it.
        expect(text, id).toContain(`\n## ${number}. ${section}\n`);
        expect(fragment, id).toBe(anchorOf(number, section));
      }
    }
    expect(anchorOf("2", "Mind addresses: the `did:oip` method")).toBe(
      "#2-mind-addresses-the-didoip-method",
    );
    expect(clauseOf("core 9.3")?.href).toBe(
      "https://github.com/wonderben-code/open-intelligence-protocol/blob/main/spec/core.md#9-time",
    );
  });
});
