// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The scenario of the papers, told once against a real resolver, host and
 * indexer on ports of this machine.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { clause, repoRoot } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { NotSo, Stage, tell, teller, type Told } from "../src/index.ts";

const ADDRESS = /did:oip:bciq[a-z2-7]{52}/gu;

let stage: Stage;
let told: Told;
const lines: string[] = [];

beforeAll(async () => {
  stage = await Stage.open();
  told = await tell(stage, (line) => lines.push(line));
});
afterAll(async () => {
  await stage.close();
});

describe("the telling", () => {
  it("has the nine steps of the technical paper, Section 3.4, in their order, and three more", () => {
    expect(lines.filter((line) => /^\d+\. /u.test(line))).toStrictEqual([
      "1. Identity",
      "2. Delegation",
      "3. Capability publication",
      "4. Intent",
      "5. Offer",
      "6. Commitment",
      "7. Delivery",
      "8. Receipt",
      "9. Afterwards",
      "10. The limits of the delegation",
      "11. Acting for a person",
      "12. A collective",
    ]);
  });

  it("counts what it verified, and has a check in every step", () => {
    const verified = lines.filter((line) => line.startsWith("   verified: "));
    expect(verified).toHaveLength(told.verified);
    expect(told.verified).toBe(29);
    expect(lines.at(-1)).toBe("29 things were verified in this telling.");
    // No step is words alone.
    const steps = lines
      .join("\n")
      .split(/\n\d+\. /u)
      .slice(1);
    expect(steps).toHaveLength(12);
    for (const step of steps) expect(step, step.split("\n")[0]).toContain("   verified: ");
  });

  it(`${clause("L2 8.3", "L1 11.4")} ends with a Commitment that a stranger with no key finds fulfilled, and binding on the firm`, () => {
    expect(told.status).toBe("fulfilled");
    expect(told.commitment).toMatch(/^bciq[a-z2-7]{52}$/u);
    expect(lines).toContain(
      "   verified: it works out for itself that the agent's signature binds Lexis Ltd.",
    );
    expect(lines).toContain(
      "   verified: and that the Commitment is fulfilled, by Amina's own Receipt.",
    );
  });

  it("has the cast of the papers: a person and her assistant, a firm and its agent, a researcher, and a collective", () => {
    expect(Object.keys(told.cast).sort()).toStrictEqual(
      ["amina", "amina-assistant", "lexis-agent", "lexis-ltd", "researcher"].sort(),
    );
    const addresses = [...Object.values(told.cast), told.collective];
    for (const address of addresses) expect(address).toMatch(/^did:oip:bciq[a-z2-7]{52}$/u);
    expect(new Set(addresses).size).toBe(6);
    // The minds are told of by the names their own profiles give.
    expect(lines.some((line) => line.startsWith("   Amina is did:oip:"))).toBe(true);
    expect(lines.some((line) => line.startsWith("   Lexis Ltd is did:oip:"))).toBe(true);
  });

  it("is what the README shows, but for the addresses, which are new each time", () => {
    const readme = readFileSync(
      join(repoRoot, "examples", "translation-demo", "README.md"),
      "utf8",
    );
    const shown = lines.join("\n").replace(ADDRESS, "did:oip:…");
    expect(readme).toContain(`\`\`\`\n${shown}\n\`\`\``);
  });

  it("holds no secret: nothing that opens a key is said", () => {
    const all = lines.join("\n");
    expect(all).not.toMatch(/passphrase|private|secret/iu);
    // And nothing as long as the passphrase of the telling, but an address.
    for (const word of all.replace(ADDRESS, "").split(/\s+/u)) {
      expect(word.length, word).toBeLessThan(32);
    }
  });
});

describe("a teller", () => {
  it("says a thing is verified only if it is so, and stops at the first that is not", () => {
    const said: string[] = [];
    const { step, tellOf, verify, count } = teller((line) => said.push(line));
    step(1, "A step");
    tellOf("Something happens.");
    verify(true, "it happened.");
    expect(() => {
      verify(false, "something else happened.");
    }).toThrow(NotSo);
    expect(() => {
      verify(false, "something else happened.");
    }).toThrow("not so: something else happened.");
    expect(said).toStrictEqual([
      "",
      "1. A step",
      "   Something happens.",
      "   verified: it happened.",
    ]);
    expect(count()).toBe(1);
  });

  it("stops where something that was to arrive did not, and says what", () => {
    const { need, count } = teller(() => undefined);
    expect(need("it came", "the packet reached her.")).toBe("it came");
    expect(() => need(undefined, "the packet reached her.")).toThrow(NotSo);
    expect(() => need(undefined, "the packet reached her.")).toThrow(
      "not so: the packet reached her.",
    );
    // What must be there is no check that is counted: only what is verified is.
    expect(count()).toBe(0);
  });
});

describe("a telling on a network that is slow", () => {
  it(`${clause("L1 18.5")} waits for what was sent: an indexer answers its sender before it forwards, and a host takes a moment`, async () => {
    // Every packet and every record that is posted takes a twentieth of a second longer to
    // arrive. The answer to the sender is no later for it, so each receiver looks before its
    // packet is there.
    const real = globalThis.fetch;
    let held = 0;
    const slow = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const method = init?.method ?? (input instanceof Request ? input.method : "GET");
      if (method === "POST") {
        held += 1;
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      return real(input, init);
    });
    const late = await Stage.open();
    try {
      const said: string[] = [];
      const told = await tell(late, (line) => said.push(line));
      expect(told.status).toBe("fulfilled");
      expect(said).toContain(
        "   verified: her packet reached the agent forwarded: it found her signature on the packet, and a broker's on its wrapper.",
      );
      expect(said.at(-1)).toBe("29 things were verified in this telling.");
      expect(held).toBeGreaterThan(10);
    } finally {
      slow.mockRestore();
      await late.close();
    }
  }, 120_000);
});
