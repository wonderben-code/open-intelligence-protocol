// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { contentId, type JsonObject, mindId } from "@oip/core";
import { judgeRecord, ownSignedTime } from "@oip/identity";
import { type Bundle, noteCutShort } from "@oip/schema";
import { Database, LogArchive, Unavailable } from "@oip/server";
import { clause } from "@oip/testkit";
import { at, intentBy, KeyMind, locationBy, type Mind, T } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Indexer, INDEXER_MIGRATIONS, type IndexerOptions } from "../src/index.ts";

let directory: string;
let db: Database;
let clock: { at: bigint; now: () => bigint };
let archive: LogArchive;

const ian = new KeyMind("ian");
const ada = new KeyMind("ada");
const bob = new KeyMind("bob");
const eve = new KeyMind("eve");

const open = (): Database =>
  Database.open({ path: join(directory, "indexer.db"), durable: false }, INDEXER_MIGRATIONS, clock);
const idOf = (mind: Mind): string => mindId(mind.address) ?? "";
const bundleOf = (mind: Mind, more: JsonObject = {}): Bundle =>
  ({
    oip: "1",
    type: "Bundle",
    mind: mind.address,
    log: mind.events,
    ...more,
  }) as unknown as Bundle;

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "oip-indexer-"));
  clock = { at: at(110), now: () => clock.at };
  db = open();
});
afterEach(() => {
  vi.restoreAllMocks();
  db.close();
  rmSync(directory, { recursive: true, force: true });
});

/** An indexer that is the mind Ian, and holds the logs of Ada and Bob besides its own. */
function indexing(more: Partial<IndexerOptions> = {}): Indexer {
  archive = new LogArchive({ db, clock });
  for (const mind of [ian, ada, bob]) archive.publish(idOf(mind), bundleOf(mind));
  return new Indexer({
    db,
    archive,
    clock,
    address: ian.address,
    signer: ian.operational(),
    ...more,
  });
}

type Signed = JsonObject & { proof: JsonObject[] };

/** A profile of a mind, with capabilities that each have a summary and tags. */
const profile = (
  mind: Mind,
  name: string,
  capabilities: Record<string, [summary: string, ...tags: string[]]>,
  more: JsonObject = {},
  by: Mind = mind,
): Signed =>
  by.sign({
    oip: "1",
    type: "Participant",
    author: mind.address,
    created: T(100),
    name,
    kind: "agent",
    capabilities: Object.entries(capabilities).map(([id, [summary, ...tags]]) => ({
      id,
      summary,
      tags,
    })),
    ...more,
  }) as Signed;

const offer = (mind: Mind, provides: string, more: JsonObject = {}): Signed =>
  mind.sign({
    oip: "1",
    type: "Offer",
    author: mind.address,
    created: T(100),
    provides,
    terms: { summary: "By the hour." },
    ...more,
  }) as Signed;

const translator = profile(ada, "Ada", {
  translate: [
    "Translates leases from Dutch to English",
    "domain:legal",
    "lang:nl",
    "oasf:nlp/translation",
  ],
  review: ["Reviews contracts for small firms", "domain:legal"],
});
const baker = profile(bob, "Bob the baker", {
  bake: ["Bakes sourdough bread to order", "domain:food"],
});

/** What a query answers, as the places it names: `mind record-kind capability`. */
function found(indexer: Indexer, query: JsonObject): string[] {
  const names = new Map([
    [ada.address, "ada"],
    [bob.address, "bob"],
    [eve.address, "eve"],
  ]);
  return indexer
    .query(query)
    .results.map(
      (result) =>
        `${names.get(result.mind) ?? "?"}${result.capability === undefined ? "" : ` ${result.capability}`}`,
    );
}

function problem(work: () => unknown): string {
  try {
    work();
  } catch (error) {
    return (error as { code?: string }).code ?? String(error);
  }
  return "none";
}

describe(`${clause("L1 18.1")} records submitted to an indexer`, () => {
  it("are listed if their author's own authority signed them, each judged by itself", () => {
    const indexer = indexing();
    const submission = indexer.submit([
      translator,
      baker,
      offer(ada, "Translation of a lease within a day"),
      ada.sign(intentBy(ada, 100, { want: "A notary in Rotterdam" })),
    ]);
    expect(submission).toStrictEqual({ taken: 4, refused: [] });
    expect(found(indexer, { want: "translate a lease" })).toStrictEqual(["ada translate"]);
    expect(found(indexer, { want: "lease", kinds: ["Offer"] })).toStrictEqual(["ada"]);
    expect(found(indexer, { want: "notary", kinds: ["Intent"] })).toStrictEqual(["ada"]);
    // The first sight of each proof was recorded with the record it stood on.
    expect(db.prepare("SELECT COUNT(*) AS n FROM seen_proofs").get()).toEqual({ n: 4 });
    // Submitted again, they are held already: taken, and listed once.
    expect(indexer.submit([translator, baker]).taken).toBe(2);
    expect(found(indexer, { want: "lease dutch contracts bread" })).toHaveLength(3);
  });

  it("are refused, each with its problem, where they do not verify, and the rest are taken", () => {
    const indexer = indexing();
    const submission = indexer.submit([
      translator,
      profile(eve, "Eve", { spy: ["Listens"] }),
      profile(bob, "Bob", { bake: ["Bakes"] }, {}, ada),
      profile(bob, "Bob", { bake: ["Bakes"] }, { kind: "collective" }),
      { ...baker, name: 7 },
      ian.sign(locationBy(ian, 100)),
      offer(ada, "For one mind only", { audience: bob.address }),
      offer(ada, "Long over", { created: T(-9000), expires: T(-8000) }),
      "not a record",
      baker,
    ]);
    expect(submission.taken).toBe(2);
    expect(
      submission.refused.map((refusal) => [refusal.index, refusal.type.split(":").at(-1)]),
    ).toStrictEqual([
      [1, "stale-version"],
      [2, "invalid-proof"],
      [3, "invalid-proof"],
      [4, "invalid-record"],
      [5, "invalid-record"],
      [6, "forbidden"],
      [7, "expired"],
      [8, "invalid-record"],
    ]);
    expect(submission.refused.every((refusal) => refusal.detail.length > 0)).toBe(true);
    // Nothing is kept of what was refused: no listing, and no first sight.
    expect(found(indexer, { want: "listens bakes mind over" })).toStrictEqual(["bob bake"]);
    expect(db.prepare("SELECT COUNT(*) AS n FROM seen_proofs").get()).toEqual({ n: 2 });
  });

  it("take a mind's Bundle, which brings its log and the profile its location record names", () => {
    const indexer = indexing();
    const mine = profile(eve, "Eve", { paint: ["Paints portraits in oil"] });
    const location = eve.sign({ ...locationBy(eve, 100), participant: contentId(mine) });
    const bundle = bundleOf(eve, { location, participant: mine } as never);
    // Before the bundle, the mind is unknown here.
    expect(indexer.submit([mine]).refused[0]?.type).toBe("urn:oip:error:stale-version");
    expect(indexer.submit([bundle, offer(eve, "A portrait from a photograph")])).toStrictEqual({
      taken: 2,
      refused: [],
    });
    expect(found(indexer, { want: "portraits" })).toStrictEqual(["eve paint"]);
    expect(found(indexer, { want: "portrait", kinds: ["Offer"] })).toStrictEqual(["eve"]);
    // A bundle whose log does not verify is refused with the problem a resolver gives.
    const broken = { ...bundleOf(ada), log: [{ ...ada.events[0], created: T(9) }] };
    expect(indexer.submit([broken]).refused[0]?.type).toBe("urn:oip:error:invalid-proof");
    expect(indexer.submit([{ ...bundleOf(ada), mind: "nobody" }]).refused[0]?.type).toBe(
      "urn:oip:error:invalid-record",
    );
  });

  it("list one profile for a mind, the one brought last, and what an Offer supersedes is gone", () => {
    const indexer = indexing();
    indexer.submit([translator]);
    const changed = profile(
      ada,
      "Ada",
      { interpret: ["Interprets at hearings", "domain:legal"] },
      { created: T(105) },
    );
    indexer.submit([changed]);
    expect(found(indexer, { want: "translates leases interprets hearings" })).toStrictEqual([
      "ada interpret",
    ]);
    const first = offer(ada, "Translation of a lease within a day");
    const second = offer(ada, "Translation of a lease within an hour", {
      created: T(105),
      supersedes: `${ada.address}/${contentId(first)}`,
    });
    indexer.submit([first]);
    expect(found(indexer, { want: "day hour", kinds: ["Offer"] })).toHaveLength(1);
    indexer.submit([second]);
    expect(
      indexer.query({ want: "day hour", kinds: ["Offer"] }).results.map((result) => result.record),
    ).toStrictEqual([contentId(second)]);
    // One that states a status closes what it supersedes, and is not listed itself.
    const withdrawn = offer(ada, "Translation of a lease within an hour", {
      created: T(108),
      supersedes: `${ada.address}/${contentId(second)}`,
      status: "withdrawn",
    });
    expect(indexer.submit([withdrawn]).taken).toBe(1);
    expect(found(indexer, { want: "translation lease", kinds: ["Offer"] })).toStrictEqual([]);
    // Another mind's record is not taken down by naming it.
    indexer.submit([baker, offer(bob, "Bread on Fridays")]);
    const hostile = offer(ada, "Nothing", {
      supersedes: `${bob.address}/${contentId(offer(bob, "Bread on Fridays"))}`,
      status: "withdrawn",
    });
    indexer.submit([hostile]);
    expect(found(indexer, { want: "bread", kinds: ["Offer"] })).toStrictEqual(["bob"]);
  });

  it("list so many Offers and Intents for one mind, and what has expired goes", () => {
    const indexer = indexing({ limits: { offers: 2, intents: 1 } });
    const offers = [1, 2, 3].map((n) => offer(ada, `Offer number ${n}`, { expires: T(1000 * n) }));
    const submission = indexer.submit([
      ...offers,
      ada.sign(intentBy(ada, 100, { want: "One thing" })),
      ada.sign(intentBy(ada, 101, { want: "Another thing" })),
      offer(bob, "Bread"),
    ]);
    expect(submission.taken).toBe(4);
    expect(submission.refused.map((refusal) => [refusal.index, refusal.type])).toStrictEqual([
      [2, "urn:oip:error:rate-limited"],
      [4, "urn:oip:error:rate-limited"],
    ]);
    // Past its `expires` an Offer is not found, and once pruned there is room again.
    clock.at = at(1500);
    expect(found(indexer, { want: "offer number", kinds: ["Offer"] })).toHaveLength(1);
    expect(indexer.prune(clock.at)).toBe(1);
    expect(indexer.prune(clock.at)).toBe(0);
    expect(indexer.submit([offers[2]]).taken).toBe(1);
  });

  it("are not called invalid where they could not be judged (ADR-0010)", () => {
    const indexer = indexing();
    const view = archive.view.bind(archive);
    vi.spyOn(archive, "view").mockImplementationOnce((now) => {
      const held = view(now);
      return {
        evidence: held.evidence,
        log: (mind) => {
          noteCutShort(new RangeError("Maximum call stack size exceeded"));
          return held.log(mind);
        },
      };
    });
    expect(() => indexer.submit([translator])).toThrow(Unavailable);
    expect(found(indexer, { want: "leases" })).toStrictEqual([]);
    expect(indexer.submit([translator]).taken).toBe(1);
  });
});

describe(`${clause("L1 18.2", "L1 18.3")} a capability query`, () => {
  function listed(more: Partial<IndexerOptions> = {}): Indexer {
    const indexer = indexing(more);
    indexer.submit([
      translator,
      baker,
      offer(ada, "Translation of a lease within a day"),
      offer(bob, "Bread to order", { capability: "bake" }),
      ada.sign(intentBy(ada, 100, { want: "A notary in Rotterdam" })),
    ]);
    return indexer;
  }

  it("is answered with a QueryResult the indexer signs, that names each record found", () => {
    const indexer = listed();
    const query = { want: "Who translates a LEASE from Dutch?", limit: 5 };
    const result = indexer.query(query);
    expect(result).toMatchObject({
      oip: "1",
      type: "QueryResult",
      author: ian.address,
      created: T(110),
      query,
      results: [
        { mind: ada.address, record: contentId(translator), capability: "translate", score: "1" },
      ],
    });
    // It is the indexer's own word: signed by an operational key of its mind.
    const judged = judgeRecord(result);
    if (!judged.ok) throw new Error(JSON.stringify(judged.issues));
    const seen = judged.value.proofs.map((proof) => proof.digest);
    const view = archive.view(clock.now());
    expect(
      ownSignedTime(judged.value, ian.address, {
        log: (mind) => view.log(mind),
        evidence: {
          eventSeen: (id) => view.evidence.eventSeen(id),
          proofSeen: (digest) => (seen.includes(digest) ? clock.at : undefined),
        },
      }),
    ).toBe(clock.at);
  });

  it("searches profiles unless it says which kinds, and finds by the words of `want`", () => {
    const indexer = listed();
    expect(found(indexer, { want: "bread" })).toStrictEqual(["bob bake"]);
    expect(found(indexer, { want: "bread", kinds: ["Offer"] })).toStrictEqual(["bob bake"]);
    expect(
      found(indexer, { want: "bread", kinds: ["Offer", "Participant", "Offer"] }).sort(),
    ).toStrictEqual(["bob bake", "bob bake"]);
    expect(found(indexer, { want: "notary" })).toStrictEqual([]);
    expect(found(indexer, { want: "notary", kinds: ["Intent"] })).toStrictEqual(["ada"]);
    // A mind's name finds its profile, which names no capability.
    expect(found(indexer, { want: "baker" })).toStrictEqual(["bob"]);
    // Accents and case make no difference, and what is no word is not read as anything.
    expect(found(indexer, { want: "BRÉAD" })).toStrictEqual(["bob bake"]);
    expect(found(indexer, { want: 'bread" OR "leases' })).toHaveLength(2);
    expect(found(indexer, { want: "* NEAR( ) -- ;" })).toStrictEqual([]);
    expect(found(indexer, { want: "zzzunheardofzzz" })).toStrictEqual([]);
    expect(found(indexer, { kinds: [] })).toStrictEqual([]);
  });

  it("ranks what matches better first, and scores each from its place, as a decimal", () => {
    const indexer = listed();
    const result = indexer.query({ want: "contracts leases legal dutch english translates" });
    expect(result.results.map((entry) => [entry.capability, entry.score])).toStrictEqual([
      ["translate", "1"],
      ["review", "0.5"],
    ]);
    const three = indexer
      .query({ want: "contracts leases bread" })
      .results.map((entry) => entry.score);
    expect(three).toStrictEqual(["1", "0.666", "0.333"]);
    for (const score of three) expect(score).toMatch(/^(?:1|0\.\d{1,3})$/u);
  });

  it("finds only what carries every tag it asks for, by the whole tag or by its prefix", () => {
    const indexer = listed();
    expect(found(indexer, { tags: ["domain:legal"] }).sort()).toStrictEqual([
      "ada review",
      "ada translate",
    ]);
    expect(found(indexer, { tags: ["domain:legal", "lang:nl"] })).toStrictEqual(["ada translate"]);
    expect(found(indexer, { tags: ["domain:legal", "domain:food"] })).toStrictEqual([]);
    expect(found(indexer, { tags: ["oasf:nlp/*"] })).toStrictEqual(["ada translate"]);
    expect(found(indexer, { tags: ["domain:*"] })).toStrictEqual([]);
    // The prefix is all of the tag before the star: `oasf:nl/*` is no prefix of `oasf:nlp/…`.
    expect(found(indexer, { tags: ["oasf:nl/*"] })).toStrictEqual([]);
    expect(found(indexer, { tags: ["oasf:nlp/translation/*"] })).toStrictEqual([]);
    // In a tag, what a pattern would read as anything is itself.
    expect(found(indexer, { tags: ["oasf:%/*"] })).toStrictEqual([]);
    expect(found(indexer, { tags: ["domain:lega_"] })).toStrictEqual([]);
    // With words as well, both must hold.
    expect(found(indexer, { want: "contracts", tags: ["lang:nl"] })).toStrictEqual([]);
    expect(found(indexer, { want: "contracts", tags: ["domain:legal"] })).toStrictEqual([
      "ada review",
    ]);
    // With neither, the newest come first.
    expect(found(indexer, { kinds: ["Participant"], limit: 2 })).toHaveLength(2);
  });

  it("gives as many results as its limit says, twenty unless it says, and none for a limit of none", () => {
    const indexer = indexing();
    const many = Object.fromEntries(
      Array.from({ length: 30 }, (_, n) => [`c${n}`, [`Capability number ${n} of many`]]),
    ) as Record<string, [string]>;
    indexer.submit([profile(ada, "Ada", many)]);
    expect(indexer.query({ want: "capability" }).results).toHaveLength(20);
    expect(indexer.query({ want: "capability", limit: 100 }).results).toHaveLength(30);
    expect(indexer.query({ want: "capability", limit: 3 }).results).toHaveLength(3);
    expect(indexer.query({ want: "capability", limit: 0 }).results).toHaveLength(0);
    expect(indexer.query({ want: "capability", limit: -5 }).results).toHaveLength(0);
    expect(indexer.query({ limit: 100 }).results).toHaveLength(31);
  });

  it("claims no match it did not check: a constraint or evidence it cannot weigh finds nothing", () => {
    const indexer = listed();
    expect(found(indexer, { want: "bread", constraints: {}, evidence: {} })).toStrictEqual([
      "bob bake",
    ]);
    expect(found(indexer, { want: "bread", evidence: { minReceipts: 20 } })).toStrictEqual([]);
    expect(found(indexer, { want: "bread", constraints: { region: "eu" } })).toStrictEqual([]);
  });

  it("is refused where it is not well formed, or asks for more tags than are read", () => {
    const indexer = listed({ limits: { queryTags: 2 } });
    const wrong: unknown[] = [
      7,
      null,
      [],
      { want: 7 },
      { want: "x".repeat(1025) },
      { kinds: ["Bundle"] },
      { limit: 101 },
      { limit: "3" },
      { tags: "domain:legal" },
      { tags: ["a:b", "c:d", "e:f"] },
    ];
    for (const query of wrong) {
      expect(
        problem(() => indexer.query(query)),
        JSON.stringify(query),
      ).toBe("invalid-record");
    }
    expect(found(indexer, { tags: ["domain:legal", "lang:nl"] })).toHaveLength(1);
  });

  it("gives where to fetch what it found: the homes the author's own log names", () => {
    const homed = new KeyMind("zoe", 0, {
      homes: ["https://zoe.example", "https://mirror.example"],
    });
    const indexer = indexing();
    indexer.submit([
      bundleOf(homed),
      profile(homed, "Zoe", { sing: ["Sings at weddings"] }),
      translator,
    ]);
    const [zoe] = indexer.query({ want: "weddings" }).results;
    expect(zoe?.hints).toStrictEqual([
      `https://zoe.example/.well-known/oip/mind/${idOf(homed)}`,
      `https://mirror.example/.well-known/oip/mind/${idOf(homed)}`,
    ]);
    // A mind whose log names no home has no hints.
    expect(indexer.query({ want: "leases" }).results[0]).not.toHaveProperty("hints");
  });

  it("matches minds for a broker, each once, best first", () => {
    const indexer = listed();
    expect(indexer.matching({ want: "contracts leases bread" }, 10)).toStrictEqual([
      ada.address,
      bob.address,
    ]);
    expect(indexer.matching({ want: "contracts leases bread" }, 1)).toStrictEqual([ada.address]);
    expect(indexer.matching({ want: "bread", limit: 0 }, 10)).toStrictEqual([bob.address]);
    expect(indexer.matching({ want: "zzzunheardofzzz" }, 10)).toStrictEqual([]);
    expect(indexer.address).toBe(ian.address);
  });
});

describe("an indexer's own mind", () => {
  it("is one whose log it holds, and whose operational key it signs with", () => {
    archive = new LogArchive({ db, clock });
    const make = (address: string, signer = ian.operational()) =>
      new Indexer({ db, archive, clock, address, signer });
    expect(() => make(ian.address)).toThrow("holds no log of its own mind");
    archive.publish(idOf(ian), bundleOf(ian));
    expect(() => make(ian.address, ada.operational())).toThrow(
      "no operational key of its own mind",
    );
    const indexer = make(ian.address);
    // If its key is taken out of its log, it signs nothing more.
    const rotated = new KeyMind("ian").update(105, {
      keys: [{ key: ian.operational(1).publicKey }],
    });
    archive.publish(idOf(ian), bundleOf(rotated));
    expect(() => indexer.query({})).toThrow(TypeError);
    const again = new Indexer({
      db,
      archive,
      clock,
      address: ian.address,
      signer: ian.operational(1),
    });
    expect(again.query({}).results).toStrictEqual([]);
  });
});
