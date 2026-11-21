// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A feed as the Explorer shows it, read from the network the demo leaves
 * behind: a real resolver, host and indexer on ports of this machine, with
 * the scenario of the papers played on them.
 */

import { LOCAL } from "@oip/cli";
import { Reader, systemClock } from "@oip/client";
import { checkpointRoot } from "@oip/net";
import { clause } from "@oip/testkit";
import { Stage, tell, type Told } from "@oip/translation-demo";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { browse } from "../src/oip/browse.ts";
import { readFeed } from "../src/oip/feed.ts";
import { pageClient } from "./page-client.ts";

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
    const page = pageClient(stage);
    const listing = await browse(page.lookup, page.asked);
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
    // An indexer lists Offers and Intents too: the minds are those of its results that are profiles.
    const [source] = listing.sources;
    expect(listing.sources).toHaveLength(1);
    expect(source?.indexer).toBe(LOCAL.indexer);
    expect(source?.failure).toBeUndefined();
    expect(source?.results).toBeGreaterThanOrEqual(listing.minds.length);
    expect(listing).toMatchObject({ answered: true, unlisted: 0, notAsked: [] });
    // Nobody was asked but the indexer and the resolver: every profile listed is the one the
    // resolver serves with its mind's log.
    expect(new Set(page.made)).toStrictEqual(new Set([LOCAL.indexer, LOCAL.resolver]));
  });

  it(`${clause("L1 18.2")} are narrowed by the tags a reader asks for`, async () => {
    const page = pageClient(stage);
    const translators = await browse(page.lookup, page.asked, [
      "lang:sw",
      "domain:legal/commercial",
    ]);
    expect(translators.minds.map(({ name }) => name)).toStrictEqual(["Lexis translation agent"]);
    const none = await browse(page.lookup, page.asked, ["lang:fi"]);
    // An indexer answered, and has none: which is another thing than no answer.
    expect(none).toMatchObject({ minds: [], answered: true });
  });

  it("are none that the page can say of, where no indexer answered: which is not that there are none", async () => {
    const page = pageClient(stage, {}, [LOCAL.indexer]);
    const listing = await browse(page.lookup, page.asked);
    expect(listing).toMatchObject({ minds: [], answered: false, unlisted: 0 });
    expect(listing.sources).toStrictEqual([{ indexer: LOCAL.indexer, failure: "unreachable" }]);
    // One of two that answers is an answer, and the page has what the other said.
    const SECOND = "https://indexer-b.oip.localhost";
    const two = pageClient(stage, { indexers: [SECOND, LOCAL.indexer] }, [SECOND]);
    const partly = await browse(two.lookup, two.asked);
    expect(partly.answered).toBe(true);
    expect(partly.minds.length).toBeGreaterThan(0);
    expect(partly.sources.map(({ indexer, failure }) => [indexer, failure])).toStrictEqual([
      [SECOND, "unreachable"],
      [LOCAL.indexer, undefined],
    ]);
  });

  it(`${clause("L1 18.4")} are listed without asking any host the reader did not choose: a profile that could only be verified at its mind's home is not listed, and the page says whom it did not ask`, async () => {
    // A mind that an indexer lists by a profile the resolver no longer serves with its log: it
    // has changed its keys since, and has not said its profile again.
    const moved = await stage.cast("moved", "agent", { name: "A mind that moved on" });
    const [first = ""] = moved.mind.state.keys;
    await moved.mind.addKey({ control: moved.lock, label: "second" });
    await moved.mind.revokeKey(first, { control: moved.lock });
    const page = pageClient(stage);
    const listing = await browse(page.lookup, page.asked);
    expect(new Set(page.made)).toStrictEqual(new Set([LOCAL.indexer, LOCAL.resolver]));
    expect(listing.minds.map(({ address }) => address)).not.toContain(moved.mind.address);
    expect(listing).toMatchObject({ answered: true, unlisted: 1, notAsked: [LOCAL.host] });
    // The other minds are listed as before.
    expect(listing.minds.map(({ name }) => name)).toContain("Amina");
  });
});
