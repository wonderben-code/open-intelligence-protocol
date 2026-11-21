// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A feed as the Explorer shows it, read from the network the demo leaves
 * behind: a real resolver, host and indexer on ports of this machine, with
 * the scenario of the papers played on them.
 */

import { Reader, systemClock } from "@oip/client";
import { checkpointRoot } from "@oip/net";
import { clause } from "@oip/testkit";
import { Stage, tell, type Told } from "@oip/translation-demo";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { browse } from "../src/oip/browse.ts";
import { readFeed } from "../src/oip/feed.ts";

let stage: Stage;
let told: Told;

beforeAll(async () => {
  stage = await Stage.open();
  told = await tell(stage, () => undefined);
});
afterAll(async () => {
  await stage.close();
});

describe("a feed, as a page shows it", () => {
  it(`${clause("L1 10.1", "L2 8.1", "L2 8.3")} lists what the mind published, each record with how it stands`, async () => {
    const lookup = stage.stranger();
    const reader = new Reader({ lookup, clock: systemClock });
    const view = await readFeed(lookup, reader, told.cast["amina"] ?? "");
    expect(view).toMatchObject({ author: told.cast["amina"], equivocation: 0, refused: 0 });
    expect(
      view.entries.map(({ seq, objectType, status }) => [seq, objectType, status]),
    ).toStrictEqual([
      [0, "Intent", "satisfied"],
      [1, "Commitment", "fulfilled"],
      [2, "Receipt", undefined],
    ]);
    const [, commitment, receipt] = view.entries;
    expect(commitment?.object).toBe(told.commitment);
    expect(commitment?.record).toMatchObject({ type: "Commitment" });
    expect(receipt?.record).toMatchObject({ type: "Receipt", outcome: "fulfilled" });
    for (const entry of view.entries) {
      expect(entry.id).toMatch(/^bciq[a-z2-7]{52}$/u);
      expect(entry.missing).toBeUndefined();
    }
    expect(view.sources).toHaveLength(1);
    expect(view.sources[0]?.failure).toBeUndefined();
  });

  it(`${clause("L2 8.3")} judges a record by what the reader holds: the agent's feed alone has the promise, and not that it was kept`, async () => {
    const lookup = stage.stranger();
    const view = await readFeed(
      lookup,
      new Reader({ lookup, clock: systemClock }),
      told.cast["lexis-agent"] ?? "",
    );
    expect(view.entries.map(({ objectType, status }) => [objectType, status])).toStrictEqual([
      ["Commitment", "accepted"],
    ]);
    // A reader that has read Amina's feed too knows of her Receipt.
    const reader = new Reader({ lookup, clock: systemClock });
    await readFeed(lookup, reader, told.cast["amina"] ?? "");
    const again = await readFeed(lookup, reader, told.cast["lexis-agent"] ?? "");
    expect(again.entries.map(({ status }) => status)).toStrictEqual(["fulfilled"]);
  });

  it(`${clause("L1 10.5")} says what a checkpoint over the feed must say: its size, its last entry, and the Merkle root of them all`, async () => {
    const lookup = stage.stranger();
    const view = await readFeed(
      lookup,
      new Reader({ lookup, clock: systemClock }),
      told.cast["amina"] ?? "",
    );
    const ids = view.entries.map(({ id }) => id);
    expect(view.covering).toStrictEqual({
      size: 3,
      head: ids[2],
      root: checkpointRoot(ids),
    });
    expect(view.covering?.root).toMatch(/^bciq[a-z2-7]{52}$/u);
    // The root is of these entries in this order, and of no others.
    expect(view.covering?.root).not.toBe(checkpointRoot([...ids].reverse()));
    expect(view.covering?.root).not.toBe(checkpointRoot(ids.slice(0, 2)));
  });

  it("has nothing for a mind that published nothing", async () => {
    const lookup = stage.stranger();
    const view = await readFeed(
      lookup,
      new Reader({ lookup, clock: systemClock }),
      told.cast["lexis-ltd"] ?? "",
    );
    expect(view.entries).toStrictEqual([]);
    // A checkpoint covers at least one entry: there is none over nothing.
    expect(view.covering).toBeUndefined();
  });
});

describe("the minds an indexer lists", () => {
  it(`${clause("L1 18.2", "L1 18.3")} are those whose profiles it holds, each verified, with what the profile says`, async () => {
    const listing = await browse(stage.stranger());
    const byName = new Map(listing.minds.map((mind) => [mind.name, mind]));
    expect([...byName.keys()].sort()).toStrictEqual(
      [
        "A research agent",
        "Amina",
        "Amina's assistant",
        "Lexis Ltd",
        "Lexis translation agent",
      ].sort(),
    );
    expect(byName.get("Lexis translation agent")).toStrictEqual({
      address: told.cast["lexis-agent"],
      name: "Lexis translation agent",
      kind: "agent",
      summary: "Legal translation between Swahili and English, for Lexis Ltd.",
      capabilities: ["translate-legal-sw-en"],
      current: true,
    });
    expect(byName.get("Amina")).toMatchObject({ kind: "human", capabilities: [] });
    expect(listing.sources).toHaveLength(1);
    expect(listing.sources[0]?.failure).toBeUndefined();
  });

  it(`${clause("L1 18.2")} are narrowed by the tags a reader asks for`, async () => {
    const translators = await browse(stage.stranger(), ["lang:sw", "domain:legal/commercial"]);
    expect(translators.minds.map(({ name }) => name)).toStrictEqual(["Lexis translation agent"]);
    expect((await browse(stage.stranger(), ["lang:fi"])).minds).toStrictEqual([]);
  });
});
