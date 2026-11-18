// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The judges of this package, called with the call stack all but spent:
 * each answers from the moment it can be entered, answers nothing that is
 * true only of the moment, and is right again afterwards (ADR-0004).
 *
 * The calls are made by `spent-stack.node.ts`, in a Node.js process of its
 * own and not under the test runner: `inNode` says why. `cut-short.test.ts`
 * makes the same fault in the runner, without the engine's help.
 */

import { clause, inNode } from "@oip/testkit";
import { describe, expect, it } from "vitest";

type Tally = Readonly<Record<string, number>>;

const report = inNode(new URL("./spent-stack.node.ts", import.meta.url)) as {
  readonly sessions: {
    readonly kinds: Tally;
    readonly deliveredOnce: boolean;
    readonly delivered: number;
  };
  readonly acks: { readonly evidence: Tally; readonly after: string; readonly verified: Tally };
  readonly packets: { readonly received: Tally; readonly after: string };
  readonly feeds: { readonly verified: Tally; readonly after: string };
  readonly locations: { readonly current: Tally; readonly after: string };
  readonly hellos: {
    readonly answered: Tally;
    readonly authenticatedOnce: boolean;
    readonly open: number;
  };
};

const total = (tally: Tally) => Object.values(tally).reduce((sum, count) => sum + count, 0);
const others = (tally: Tally, ...expected: string[]) =>
  Object.keys(tally).filter((kind) => !expected.includes(kind));

describe(`${clause("core 4.4")} judging with the stack all but spent`, () => {
  it("delivers each packet of a session once, and loses none", () => {
    // Four packets, each given fifty times with the stack spent and once with room.
    expect(total(report.sessions.kinds)).toBe(204);
    expect(
      others(
        report.sessions.kinds,
        "in order",
        "duplicate",
        "not received: implementation limit",
        "not placed: implementation limit",
      ),
    ).toStrictEqual([]);
    expect(report.sessions.delivered).toBe(4);
    expect(report.sessions.deliveredOnce).toBe(true);
  });

  it("receives a packet or refuses for want of room, and never rejects it for another reason", () => {
    expect(total(report.packets.received)).toBe(200);
    expect(
      others(report.packets.received, "received", "refused: implementation limit"),
    ).toStrictEqual([]);
    expect(report.packets.after).toBe("received");
  });

  it("verifies a feed whole or refuses, and never answers with part of it", () => {
    expect(total(report.feeds.verified)).toBe(200);
    expect(
      others(report.feeds.verified, "3 entries, 0 refused", "refused: implementation limit"),
    ).toStrictEqual([]);
    expect(report.feeds.after).toBe("3 entries, 0 refused");
  });

  it("finds the current location record or none, and never an older one", () => {
    expect(total(report.locations.current)).toBe(200);
    expect(others(report.locations.current, "seq 1", "none")).toStrictEqual([]);
    expect(report.locations.after).toBe("seq 1");
  });

  it("takes an Ack as evidence for every proof it covers or for none, and never for some", () => {
    expect(total(report.acks.evidence)).toBe(200);
    expect(others(report.acks.evidence, "2 proofs", "none")).toStrictEqual([]);
    expect(report.acks.after).toBe("2 proofs");
    expect(total(report.acks.verified)).toBe(200);
    expect(others(report.acks.verified, "signed", "refused: implementation limit")).toStrictEqual(
      [],
    );
  });

  it("authenticates a Hello once, and uses its challenge up only then", () => {
    expect(total(report.hellos.answered)).toBe(200);
    expect(
      others(
        report.hellos.answered,
        "authenticated",
        "refused: implementation limit",
        // After the one that passed, the challenge is used.
        "refused: L1 13.3",
      ),
    ).toStrictEqual([]);
    expect(report.hellos.authenticatedOnce).toBe(true);
    expect(report.hellos.open).toBe(0);
  });
});
