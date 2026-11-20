// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, MEDIA_TYPE, type OipRecord } from "@oip/core";
import type { CapabilityQuery } from "@oip/schema";
import { clause } from "@oip/testkit";
import { at, KeyMind, T } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { Lookup, Mind, type MindOptions } from "../src/index.ts";
import { freshKeystore, refusal } from "./helpers.ts";
import { World } from "./world.ts";

const A = "https://resolver-a.example";
const HOME = "https://host.example";
const X = "https://indexer-x.example";
const Y = "https://indexer-y.example";

let world: World;
let ix: KeyMind;
let iy: KeyMind;
beforeEach(async () => {
  world = new World(100);
  world.resolver(A);
  world.host(HOME);
  ix = world.indexer(X, "indexer-x").mind;
  iy = world.indexer(Y, "indexer-y").mind;
  // The indexers' own minds are with the resolver the clients trust.
  expect(await world.publish(A, ix)).toBe(202);
  expect(await world.publish(A, iy)).toBe(202);
});
afterEach(() => {
  world.close();
});

/** A mind with a home and a profile, known to the indexers given. */
async function listed(name: string, summary: string, tags: string[], indexers = [X, Y]) {
  const made = await freshKeystore(world, [A], { indexers });
  const mind = await Mind.create(made.options, { kind: "agent", homes: [HOME] });
  const profile = await mind.publishProfile({
    name,
    capabilities: [{ id: "work", summary, tags }],
  });
  return { ...made, mind, profile };
}

const seeker = (indexers: readonly string[] = [X, Y], more: Partial<MindOptions> = {}) =>
  new Lookup({ resolvers: [A], indexers, fetch: world.fetch, clock: world.clock, ...more });

/** An indexer that answers what a test gives it, signed by its own mind unless the test signs. */
function answering(
  origin: string,
  by: KeyMind,
  results: (query: CapabilityQuery) => object[],
  change: (result: OipRecord) => object = (result) => result,
): void {
  world.put(origin, async (request) => {
    const query = (await request.json()) as CapabilityQuery;
    const result = by.sign({
      oip: "1",
      type: "QueryResult",
      author: by.address,
      created: T(100),
      query,
      results: results(query),
    }) as unknown as OipRecord;
    return new Response(JSON.stringify(change(result)), {
      status: 200,
      headers: { "content-type": MEDIA_TYPE },
    });
  });
}

describe(`${clause("L1 18.1")} a mind that publishes is listed`, () => {
  it("submits its bundle and its profile to the indexers the client names, with a request it signed", async () => {
    const signatures: (string | null)[] = [];
    world.before = (request) => {
      if (request.url.endsWith("/oip/v1/submit")) {
        signatures.push(request.headers.get("signature-input"));
      }
    };
    const { mind } = await listed("Ada", "Translation of legal texts", ["lang:pt"]);
    expect(mind.publications).toStrictEqual([
      { service: "resolver", origin: A, taken: true },
      { service: "home", origin: HOME, taken: true },
      { service: "indexer", origin: X, taken: true },
      { service: "indexer", origin: Y, taken: true },
    ]);
    expect(signatures).toHaveLength(2);
    for (const signature of signatures) expect(signature).toContain(`keyid="${mind.address}?`);
  });

  it("is told which indexer did not take it, and is published all the same", async () => {
    world.down(X);
    // An indexer that says it refused a record, in words of its own.
    world.put(
      Y,
      () =>
        new Response(
          JSON.stringify({
            taken: 1,
            refused: [{ index: 1, type: "urn:oip:error:stale-version", detail: "not\\u0000now" }],
          }),
          { status: 202, headers: { "content-type": "application/json" } },
        ),
    );
    const { mind, profile } = await listed("Ada", "Translation", ["lang:pt"]);
    expect(mind.publications.slice(2)).toStrictEqual([
      { service: "indexer", origin: X, taken: false, failure: "unreachable" },
      { service: "indexer", origin: Y, taken: false, failure: "stale-version" },
    ]);
    expect(mind.resolved.participant?.id).toBe(contentId(profile));
    // A 202 that says nothing of what became of the records, or says it in a way of its own, is a yes.
    for (const said of ['{"taken":2}', '"stored"', "[]"]) {
      world.put(
        Y,
        () => new Response(said, { status: 202, headers: { "content-type": "application/json" } }),
      );
      await mind.publishLocation();
      expect(mind.publications.at(-1), said).toStrictEqual({
        service: "indexer",
        origin: Y,
        taken: true,
      });
    }
    // One that names no code of the protocol for what it refused.
    world.put(
      Y,
      () =>
        new Response(JSON.stringify({ refused: [{ index: 0 }] }), {
          status: 202,
          headers: { "content-type": "application/json" },
        }),
    );
    await mind.publishLocation();
    expect(mind.publications.at(-1)).toStrictEqual({
      service: "indexer",
      origin: Y,
      taken: false,
      failure: "invalid-record",
    });
  });
});

describe(`${clause("L1 18.4")} what a query finds`, () => {
  it(`${clause("L1 18.2", "L1 18.3")} is fetched and verified before it is returned`, async () => {
    const ada = await listed("Ada", "Translation of legal texts", ["lang:pt", "domain:legal"]);
    await listed("Bob", "Plumbing", ["domain:plumbing"]);
    const finding = await seeker().find({ want: "legal translation", tags: ["lang:pt"] });
    expect(finding.sources).toStrictEqual([
      { indexer: X, mind: ix.address, results: 1 },
      { indexer: Y, mind: iy.address, results: 1 },
    ]);
    expect(finding.refused).toStrictEqual([]);
    expect(finding.found).toStrictEqual([
      {
        mind: ada.mind.address,
        id: contentId(ada.profile),
        record: ada.profile,
        capability: ada.profile.capabilities?.[0],
        current: true,
        by: [
          { indexer: X, score: "1" },
          { indexer: Y, score: "1" },
        ],
      },
    ]);
  });

  it("is asked of every indexer, and one that fails is said to have failed", async () => {
    const ada = await listed("Ada", "Translation", ["lang:pt"], [X]);
    world.down(Y);
    const finding = await seeker().find({ tags: ["lang:*".replace("*", "pt")] });
    expect(finding.sources).toStrictEqual([
      { indexer: X, mind: ix.address, results: 1 },
      { indexer: Y, results: undefined, failure: "unreachable" },
    ]);
    expect(finding.found.map((found) => found.mind)).toStrictEqual([ada.mind.address]);
    expect(finding.found[0]?.by).toStrictEqual([{ indexer: X, score: "1" }]);
  });

  it(`${clause("L1 18.2")} a query that states constraints finds nothing at an indexer that weighs none`, async () => {
    await listed("Ada", "Translation", ["lang:pt"]);
    const finding = await seeker([X]).find({ tags: ["lang:pt"], constraints: { maxPrice: "5" } });
    expect(finding.found).toStrictEqual([]);
    expect(finding.sources).toStrictEqual([{ indexer: X, mind: ix.address, results: 0 }]);
  });

  it("needs indexers to ask", () => {
    expect(() => seeker([]).find({})).toThrow(/names the indexers it asks/u);
    expect(() =>
      new Lookup({ resolvers: [A], fetch: world.fetch, clock: world.clock }).find({}),
    ).toThrow(TypeError);
  });
});

describe(`${clause("L1 18.3")} an indexer's answer`, () => {
  it("is taken only as its own: a result of this query, signed by a mind the resolvers hold", async () => {
    const ada = await listed("Ada", "Translation", ["lang:pt"], [X]);
    const named = [
      { mind: ada.mind.address, record: contentId(ada.profile), capability: "work", score: "0.5" },
    ];
    const stranger = new KeyMind("stranger");
    const cases: [what: string, put: () => void, failure: string][] = [
      [
        "signed by a mind no resolver holds",
        () => answering(Y, stranger, () => named),
        "not-found",
      ],
      [
        "to another query",
        () =>
          answering(
            Y,
            iy,
            () => named,
            (result) => ({ ...result, query: { want: "other" } }),
          ),
        "invalid-record",
      ],
      [
        "signed by another mind than its author",
        () =>
          answering(
            Y,
            ix,
            () => named,
            (result) => ({ ...result, author: iy.address }),
          ),
        "invalid-proof",
      ],
      [
        "with no proof",
        () =>
          answering(
            Y,
            iy,
            () => named,
            ({ proof: _, ...result }) => result,
          ),
        "invalid-record",
      ],
      [
        "that is another record",
        () =>
          answering(
            Y,
            iy,
            () => named,
            () => iy.events[0] as object,
          ),
        "invalid-record",
      ],
      [
        "that is no record",
        () =>
          world.put(
            Y,
            () =>
              new Response("{}", { status: 200, headers: { "content-type": "application/json" } }),
          ),
        "not-oip",
      ],
      [
        "that is a refusal",
        () =>
          world.put(
            Y,
            () =>
              new Response(
                JSON.stringify({
                  type: "urn:oip:error:rate-limited",
                  title: "Slow down",
                  status: 429,
                }),
                { status: 429, headers: { "content-type": "application/problem+json" } },
              ),
          ),
        "rate-limited",
      ],
    ];
    for (const [what, put, failure] of cases) {
      put();
      const finding = await seeker().find({ tags: ["lang:pt"] });
      expect(finding.sources[1], what).toStrictEqual({ indexer: Y, results: undefined, failure });
      // What the other indexer named is found as before.
      expect(
        finding.found.map((found) => found.by),
        what,
      ).toStrictEqual([[{ indexer: X, score: "1" }]]);
    }
    // Its own answer, with a reason in its own words, is taken beside the other's.
    answering(Y, iy, () => [{ ...named[0], why: "It said so." }]);
    const finding = await seeker().find({ tags: ["lang:pt"] });
    expect(finding.found[0]?.by).toStrictEqual([
      { indexer: X, score: "1" },
      { indexer: Y, score: "0.5", why: "It said so." },
    ]);
  });

  it(`${clause("L1 18.2")} is looked at as far as the query's limit, whatever it holds`, async () => {
    const minds = [];
    for (const name of ["Ada", "Bob", "Cyd"])
      minds.push(await listed(name, "Work", ["lang:pt"], []));
    const all = minds.map(({ mind, profile }) => ({
      mind: mind.address,
      record: contentId(profile),
      score: "1",
    }));
    answering(X, ix, () => all);
    expect((await seeker([X]).find({ limit: 2 })).found.map((found) => found.mind)).toStrictEqual(
      minds.slice(0, 2).map(({ mind }) => mind.address),
    );
    expect((await seeker([X]).find({})).found).toHaveLength(3);
    expect((await seeker([X]).find({ limit: 0 })).found).toStrictEqual([]);
    expect((await seeker([X]).find({ limit: -3 })).found).toStrictEqual([]);
  });
});

describe(`${clause("L1 18.4")} what an indexer names and the client does not return`, () => {
  it("is each said why: what does not exist, is another's, is not what was asked, or does not carry the tags", async () => {
    const ada = await listed("Ada", "Translation", ["lang:pt"], []);
    const bob = await listed("Bob", "Plumbing", ["domain:plumbing"], []);
    const location = ada.mind.resolved.location?.record as OipRecord;
    await ada.mind.publishRecord(location);
    await ada.mind.publishRecord(bob.profile);
    const profile = contentId(ada.profile);
    // A mind with a log of its own, which no resolver was brought.
    const nobody = new KeyMind("nobody").address;
    const named = [
      // A profile that carries none of the tags asked for.
      { mind: bob.mind.address, record: contentId(bob.profile), score: "1" },
      // A capability the profile does not have.
      { mind: ada.mind.address, record: profile, capability: "other", score: "0.9" },
      // A record the mind's homes do not serve.
      { mind: ada.mind.address, record: contentId(ix.events[0]), score: "0.8" },
      // A record of a kind no indexer lists, and one that is another mind's.
      { mind: ada.mind.address, record: contentId(location), score: "0.7" },
      { mind: ada.mind.address, record: contentId(bob.profile), score: "0.6" },
      // A mind no resolver holds.
      { mind: nobody, record: profile, score: "0.5" },
      // And one that is as the indexer says.
      { mind: ada.mind.address, record: profile, capability: "work", score: "0.4" },
    ];
    answering(X, ix, () => named);
    const finding = await seeker([X]).find({ tags: ["lang:pt"] });
    expect(finding.refused.map((refused) => refused.failure)).toStrictEqual([
      "invalid-record",
      "invalid-record",
      "not-found",
      "invalid-record",
      "invalid-proof",
      "not-found",
    ]);
    expect(finding.refused[0]).toStrictEqual({
      indexer: X,
      mind: bob.mind.address,
      record: contentId(bob.profile),
      failure: "invalid-record",
    });
    expect(finding.found).toStrictEqual([
      {
        mind: ada.mind.address,
        id: profile,
        record: ada.profile,
        capability: ada.profile.capabilities?.[0],
        current: true,
        by: [{ indexer: X, score: "0.4" }],
      },
    ]);
    expect(finding.sources).toStrictEqual([{ indexer: X, mind: ix.address, results: 7 }]);
  });

  it(`${clause("L1 18.2")} a tag that ends in a star is carried by any tag that begins so, and by no other`, async () => {
    const ada = await listed("Ada", "Translation", ["oasf:nlp/translation"], []);
    answering(X, ix, () => [
      { mind: ada.mind.address, record: contentId(ada.profile), score: "1" },
    ]);
    const found = async (tag: string) => (await seeker([X]).find({ tags: [tag] })).found.length;
    expect(await found("oasf:nlp/*")).toBe(1);
    expect(await found("oasf:nlp/translation")).toBe(1);
    expect(await found("oasf:nlp")).toBe(0);
    expect(await found("oasf:nlpx/*")).toBe(0);
    expect(await found("oasf:*")).toBe(0);
  });

  it(`${clause("L1 18.2")} a profile with no capability, or a capability with no tag, carries no tag that is asked for`, async () => {
    const plain = await freshKeystore(world, [A]);
    const mind = await Mind.create(plain.options, { kind: "agent", homes: [HOME] });
    const bare = await mind.publishProfile({ name: "Bare" });
    answering(X, ix, () => [{ mind: mind.address, record: contentId(bare), score: "1" }]);
    expect((await seeker([X]).find({})).found.map((found) => found.id)).toStrictEqual([
      contentId(bare),
    ]);
    expect(
      (await seeker([X]).find({ tags: ["lang:pt"] })).refused.map((refused) => refused.failure),
    ).toStrictEqual(["invalid-record"]);
    world.clock.at = at(200);
    const untagged = await mind.publishProfile({
      name: "Bare",
      capabilities: [{ id: "work", summary: "Work" }],
    });
    answering(X, ix, () => [
      { mind: mind.address, record: contentId(untagged), capability: "work", score: "1" },
    ]);
    expect((await seeker([X]).find({})).found.map((found) => found.capability?.id)).toStrictEqual([
      "work",
    ]);
    expect(
      (await seeker([X]).find({ tags: ["lang:pt"] })).refused.map((refused) => refused.failure),
    ).toStrictEqual(["invalid-record"]);
  });

  it(`${clause("L1 16.4")} a profile the mind has replaced is found only if its homes still serve it, and is said to be not current`, async () => {
    const ada = await listed("Ada", "Translation", ["lang:pt"], []);
    const old = ada.profile;
    answering(X, ix, () => [{ mind: ada.mind.address, record: contentId(old), score: "1" }]);
    world.clock.at = at(200);
    await ada.mind.publishProfile({ name: "Ada", capabilities: [] });
    // Nobody serves the old profile.
    const gone = await seeker([X]).find({});
    expect(gone.found).toStrictEqual([]);
    expect(gone.refused.map((refused) => refused.failure)).toStrictEqual(["not-found"]);
    // The mind keeps it on its feed: it is the mind's own, and not its current one.
    await ada.mind.publishRecord(old);
    const kept = await seeker([X]).find({});
    expect(kept.found).toMatchObject([{ id: contentId(old), record: old, current: false }]);
  });
});

describe(`${clause("L1 18.4")} Offers and Intents`, () => {
  /** A mind with an Intent on its feed, signed at 100. */
  async function asking(more: object = {}) {
    const ada = await listed("Ada", "Translation", ["lang:pt"], []);
    const intent = (await ada.mind.sign({
      oip: "1",
      type: "Intent",
      author: ada.mind.address,
      created: T(100),
      want: "A lease translated into Portuguese.",
      ...more,
    })) as unknown as OipRecord;
    await ada.mind.publishRecord(intent);
    return { ...ada, intent };
  }

  it("are fetched from the homes their author names, and returned if they are the author's own", async () => {
    const { mind, intent } = await asking();
    // The real indexer is brought the mind and its Intent, and finds it.
    const submitted = await world.fetch(
      new Request(`${X}/oip/v1/submit`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          records: [
            {
              oip: "1",
              type: "Bundle",
              mind: mind.address,
              log: mind.resolved.log.entries.map((entry) => entry.event),
            },
            intent,
          ],
        }),
      }),
    );
    expect(await submitted.json()).toStrictEqual({ taken: 2, refused: [] });
    world.clock.at = at(300);
    const finding = await seeker([X]).find({ want: "lease", kinds: ["Intent"] });
    expect(finding.refused).toStrictEqual([]);
    expect(finding.found).toStrictEqual([
      {
        mind: mind.address,
        id: contentId(intent),
        record: intent,
        current: true,
        by: [{ indexer: X, score: "1" }],
      },
    ]);
    // Asked for profiles, the same record is not what was asked for.
    answering(X, ix, () => [{ mind: mind.address, record: contentId(intent), score: "1" }]);
    expect((await seeker([X]).find({})).refused.map((refused) => refused.failure)).toStrictEqual([
      "invalid-record",
    ]);
    // And it names no capability.
    answering(X, ix, () => [
      { mind: mind.address, record: contentId(intent), capability: "work", score: "1" },
    ]);
    expect(
      (await seeker([X]).find({ kinds: ["Intent"] })).refused.map((refused) => refused.failure),
    ).toStrictEqual(["invalid-record"]);
  });

  it("are not returned where their author's key did not sign them, or once they have expired", async () => {
    const { mind, intent } = await asking({ expires: T(500) });
    const named = (record: OipRecord) => () => [
      { mind: mind.address, record: contentId(record), score: "1" },
    ];
    // An Intent in the mind's name that another mind signed, which the mind's feed lists.
    const eve = await listed("Eve", "Mischief", [], []);
    const forged = (await eve.mind.sign({
      oip: "1",
      type: "Intent",
      author: mind.address,
      created: T(100),
      want: "Everything Ada has.",
    })) as unknown as OipRecord;
    await mind.publishRecord(forged);
    answering(X, ix, named(forged));
    const judged = await seeker([X]).find({ kinds: ["Intent"] });
    expect(judged.found).toStrictEqual([]);
    expect(judged.refused.map((refused) => refused.failure)).toStrictEqual(["invalid-proof"]);
    // The mind's own, until the moment it expires.
    answering(X, ix, named(intent));
    world.clock.at = at(499);
    expect((await seeker([X]).find({ kinds: ["Intent"] })).found).toHaveLength(1);
    world.clock.at = at(500);
    const late = await seeker([X]).find({ kinds: ["Intent"] });
    expect(late.found).toStrictEqual([]);
    expect(late.refused.map((refused) => refused.failure)).toStrictEqual(["expired"]);
  });
});

describe("a failure that is nobody's answer", () => {
  it("reaches the caller as it is, whatever was being asked", async () => {
    const ada = await listed("Ada", "Translation", ["lang:pt"], [X]);
    await ada.mind.publishRecord(ada.profile);
    ada.mind.close();
    // What stands in for `fetch` is broken for some requests: its answer has headers that cannot be read.
    const broken =
      (when: (request: Request) => boolean): typeof world.fetch =>
      (request) =>
        when(request)
          ? Promise.resolve({
              status: 200,
              body: null,
              headers: {
                get: () => {
                  throw new RangeError("not a response");
                },
              },
            } as unknown as Response)
          : world.fetch(request);
    // The indexer's answer; a resolver's, for the mind a result names; a home's; an indexer's, to a submission.
    await expect(
      seeker([X], { fetch: broken((request) => request.url.startsWith(X)) }).find({}),
    ).rejects.toThrow(RangeError);
    const named = ada.mind.address.slice("did:oip:".length);
    await expect(
      seeker([X], { fetch: broken((request) => request.url.endsWith(named)) }).find({}),
    ).rejects.toThrow(RangeError);
    await expect(
      seeker([X], { fetch: broken((request) => request.url.includes("/obj/")) }).record(
        ada.mind.address,
        contentId(ada.profile),
      ),
    ).rejects.toThrow(RangeError);
    const again = await Mind.open({
      ...ada.options,
      fetch: broken((request) => request.url.endsWith("/submit")),
    });
    await expect(again.publishLocation()).rejects.toThrow(RangeError);
  });
});

describe(`${clause("L1 13.1")} a record fetched from a mind's homes by its content ID`, () => {
  it("is that record, whoever served it: a home that serves another has failed, and the next is asked", async () => {
    const TWO = "https://host-two.example";
    world.host(TWO);
    const made = await freshKeystore(world, [A]);
    const mind = await Mind.create(made.options, { kind: "agent", homes: [HOME, TWO] });
    const profile = await mind.publishProfile({ name: "Ada" });
    const location = mind.resolved.location?.record as OipRecord;
    await mind.publishRecord(profile);
    await mind.publishRecord(location);
    const reader = new Lookup({ resolvers: [A], fetch: world.fetch, clock: world.clock });
    expect((await reader.record(mind.address, contentId(profile))).record).toStrictEqual(profile);
    // The first home serves the location record whatever is asked for.
    const real = world.at(HOME);
    world.put(HOME, (request) =>
      request.url.includes("/obj/")
        ? new Response(JSON.stringify(location), {
            status: 200,
            headers: { "content-type": MEDIA_TYPE },
          })
        : real(request),
    );
    expect((await reader.record(mind.address, contentId(profile))).record).toStrictEqual(profile);
    // No home serves it: the one that served another record says more than the one that has none.
    world.host(TWO);
    await mind.bringHomes();
    expect(await refusal(() => reader.record(mind.address, contentId(profile)))).toBe(
      "oip: invalid-record",
    );
    // A record neither home has.
    world.put(HOME, real);
    const unknown = contentId(ix.events[0]);
    expect(await refusal(() => reader.record(mind.address, unknown))).toBe("oip: not-found");
    // A home that cannot be reached may have it: that is said, and not that there is none.
    world.down(TWO);
    expect(await refusal(() => reader.record(mind.address, unknown))).toBe(
      "transport: unreachable",
    );
    expect((await reader.record(mind.address, contentId(profile))).record).toStrictEqual(profile);
  });

  it("is not to be had of a mind that names no home", async () => {
    const made = await freshKeystore(world, [A]);
    const mind = await Mind.create(made.options, { kind: "agent" });
    const reader = new Lookup({ resolvers: [A], fetch: world.fetch, clock: world.clock });
    expect(await refusal(() => reader.record(mind.address, contentId(ix.events[0])))).toBe(
      "oip: not-found",
    );
  });
});
