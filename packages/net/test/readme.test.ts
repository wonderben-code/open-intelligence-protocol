// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { repoRoot } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import * as net from "../src/index.ts";

const readme = readFileSync(join(repoRoot, "packages", "net", "README.md"), "utf8");

describe("the README", () => {
  it("names only things the package exports, and every value it exports", () => {
    const table = readme.slice(readme.indexOf("## What it exports"), readme.indexOf("## Feeds"));
    // The first column of each row names exports; the second describes them.
    const named = table
      .split("\n")
      .filter((line) => line.startsWith("| `"))
      .flatMap((line) => [...(line.split("|")[1] ?? "").matchAll(/`([A-Za-z_0-9]+)/g)])
      .map((match) => match[1] ?? "");
    expect(named.length).toBeGreaterThan(40);
    // Types are not there at run time; everything else named must be.
    const values = Object.keys(net);
    const types = named.filter((name) => !values.includes(name));
    expect(types.sort()).toEqual(
      [
        "AckContext",
        "AckDraft",
        "AckEvidence",
        "Authenticated",
        "Binding",
        "ChainEquivocation",
        "CoveredFeed",
        "FeedEntry",
        "HeldLocation",
        "HeldParticipant",
        "HelloServer",
        "IssuedChallenges",
        "KnownEndpoint",
        "OwnChain",
        "PacketClock",
        "Placed",
        "ProfileSources",
        "ProposedBranch",
        "ReceivedPacket",
        "ReceivedSealed",
        "Receiver",
        "SealDraft",
        "SealedReceiver",
        "SendingChain",
        "SessionLimits",
        "VerifiedAck",
        "VerifiedFeed",
      ].sort(),
    );
    for (const value of values) expect(named, value).toContain(value);
  });

  it("gives the limits the code has", () => {
    const { maxSessions, maxInstances, maxWaiting } = net.DEFAULT_SESSION_LIMITS;
    const written = (count: number) => count.toLocaleString("en-GB");
    expect(readme).toContain(
      `at most ${written(maxSessions)} sessions, ${written(maxInstances)} chains for one sender`,
    );
    expect(readme).toContain(`${written(maxWaiting)} waiting packets for a chain`);
  });
});
