// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A feed as the Explorer shows it, read from the network the demo leaves
 * behind: a real resolver, host and indexer on ports of this machine, with
 * the scenario of the papers played on them.
 */

import { Reader, systemClock } from "@oip/client";
import { clause } from "@oip/testkit";
import { Stage, tell, type Told } from "@oip/translation-demo";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

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

  it("has nothing for a mind that published nothing", async () => {
    const lookup = stage.stranger();
    const view = await readFeed(
      lookup,
      new Reader({ lookup, clock: systemClock }),
      told.cast["lexis-ltd"] ?? "",
    );
    expect(view.entries).toStrictEqual([]);
  });
});
