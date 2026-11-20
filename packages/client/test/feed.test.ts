// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, MEDIA_TYPE, type OipRecord } from "@oip/core";
import type { Entry } from "@oip/schema";
import { clause } from "@oip/testkit";
import { T } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { Lookup, Mind } from "../src/index.ts";
import { freshKeystore, refusal } from "./helpers.ts";
import { World } from "./world.ts";

const A = "https://resolver-a.example";
const ONE = "https://host-one.example";
const TWO = "https://host-two.example";

let world: World;
beforeEach(() => {
  world = new World(100);
  world.resolver(A);
  // Hosts that serve a feed two entries at a time.
  world.host(ONE, { maxPage: 2 });
  world.host(TWO, { maxPage: 2 });
});
afterEach(() => {
  world.close();
});

/** A mind with homes, a profile, and entries for it on its feed. */
async function writer(entries: number, homes: readonly string[] = [ONE, TWO]) {
  const made = await freshKeystore(world, [A]);
  const mind = await Mind.create(made.options, { kind: "agent", homes });
  const profile = await mind.publishProfile({ name: "Ada" });
  const written: Entry[] = [];
  for (let n = 0; n < entries; n++) written.push(await mind.publishRecord(profile));
  return { ...made, mind, profile, written };
}

const reader = (more: object = {}) =>
  new Lookup({ resolvers: [A], fetch: world.fetch, clock: world.clock, ...more });

/** A page of a feed, as a home answers. */
const page = (mind: string, entries: readonly unknown[], next?: number): Response =>
  new Response(
    JSON.stringify({
      oip: "1",
      type: "FeedPage",
      mind,
      entries,
      ...(next === undefined ? {} : { next }),
    }),
    { status: 200, headers: { "content-type": MEDIA_TYPE } },
  );

/** Puts something in front of a home that answers for its feed, and lets every other request through. */
function feedAt(home: string, answer: (asked: URL) => Response): void {
  const real = world.at(home);
  world.put(home, (request) => {
    const asked = new URL(request.url);
    return request.method === "GET" && asked.pathname.endsWith("/feed")
      ? answer(asked)
      : real(request);
  });
}

/** An entry the mind signs, which it brings to no home. */
const entryBy = (mind: Mind, seq: number, prev: string | undefined, record: OipRecord) =>
  mind.sign({
    oip: "1",
    type: "Entry",
    author: mind.address,
    seq,
    ...(prev === undefined ? {} : { prev }),
    created: T(100),
    object: contentId(record),
    objectType: record.type,
  }) as Promise<Entry>;

describe("a feed read from a mind's homes", () => {
  it(`${clause("L1 13.1")} is read page by page, from each home, to its end`, async () => {
    const { mind, written } = await writer(5);
    const before = world.asked.length;
    const { feed, sources } = await reader().feed(mind.address);
    expect(feed.entries.map((entry) => entry.entry)).toStrictEqual(written);
    expect(sources).toStrictEqual([
      { home: ONE, entries: 5 },
      { home: TWO, entries: 5 },
    ]);
    const asked = world.asked
      .slice(before)
      .filter((request) => request.startsWith(`GET ${ONE}`))
      .map((request) => new URL(request.slice(4)).search);
    expect(asked).toStrictEqual(["?limit=100", "?limit=100&after=1", "?limit=100&after=3"]);
  });

  it(`${clause("L1 13.1")} a home that serves another mind's feed, or what is no page of one, has failed, and the others are read`, async () => {
    const { mind } = await writer(1);
    const other = await writer(0, []);
    const answers: [answer: () => Response, failure: string][] = [
      [() => page(other.mind.address, []), "invalid-record"],
      [() => page(mind.address, [{ oip: "1", type: "Entry" }]), "invalid-record"],
      [
        () =>
          new Response(JSON.stringify(mind.resolved.log.entries[0]?.event), {
            status: 200,
            headers: { "content-type": MEDIA_TYPE },
          }),
        "invalid-record",
      ],
      [
        () => new Response("<html>", { status: 200, headers: { "content-type": "text/html" } }),
        "not-oip",
      ],
      [
        () => new Response(null, { status: 302, headers: { location: `${TWO}/feed` } }),
        "unreachable",
      ],
    ];
    const real = world.at(ONE);
    for (const [answer, failure] of answers) {
      world.put(ONE, real);
      feedAt(ONE, answer);
      const { feed, sources } = await reader().feed(mind.address);
      expect(sources, failure).toStrictEqual([
        { home: ONE, entries: undefined, failure },
        { home: TWO, entries: 1 },
      ]);
      expect(feed.entries).toHaveLength(1);
    }
  });

  it(`${clause("L1 13.1")} is not read past what a client reads of one feed`, async () => {
    const { mind } = await writer(3);
    expect(await refusal(() => reader({ maxFeedEntries: 2 }).feed(mind.address))).toBe(
      "oip: too-large",
    );
    expect((await reader({ maxFeedEntries: 3 }).feed(mind.address)).feed.entries).toHaveLength(3);
  });

  it(`${clause("L1 13.1")} a home that says more follows and does not go forward is read no further`, async () => {
    const { mind, written } = await writer(3);
    // The same first page, whatever is asked, with more said to follow.
    let asked = 0;
    feedAt(ONE, () => {
      asked++;
      return page(mind.address, written.slice(0, 1), 0);
    });
    const { feed, sources } = await reader().feed(mind.address);
    expect(asked).toBe(2);
    expect(sources[0]).toStrictEqual({ home: ONE, entries: 2 });
    expect(feed.entries).toHaveLength(3);
    // An empty page that says more follows.
    let empty = 0;
    feedAt(TWO, () => {
      empty++;
      return page(mind.address, [], 7);
    });
    expect((await reader().feed(mind.address)).sources[1]).toStrictEqual({ home: TWO, entries: 0 });
    expect(empty).toBe(1);
  });

  it(`${clause("L1 10.1", "L1 10.4")} what a home serves that is no entry of the mind's takes no place in the feed`, async () => {
    const { mind, written, profile } = await writer(1);
    const eve = await writer(0, []);
    const [first] = written;
    // By another mind in this one's name; out of place; and one this client may not rely on.
    const forged = {
      ...(await entryBy(eve.mind, 1, contentId(first), profile)),
      author: mind.address,
    };
    const detached = await entryBy(mind, 5, contentId(profile), profile);
    const beyond = await mind.sign({
      oip: "1",
      type: "Entry",
      author: mind.address,
      seq: 1,
      prev: contentId(first),
      created: T(100),
      object: contentId(profile),
      objectType: "Participant",
      ext: { "ext.example": { rule: "new" } },
      critical: ["ext.example"],
    });
    feedAt(ONE, () => page(mind.address, [first, forged, detached, beyond]));
    const { feed, sources } = await reader().feed(mind.address);
    expect(sources[0]).toStrictEqual({ home: ONE, entries: 4 });
    expect(feed.entries.map((entry) => entry.id)).toStrictEqual([contentId(first)]);
    expect(feed.equivocation).toStrictEqual([]);
    // The one that depends on an extension this client does not implement is not judged (core 8.3).
    expect(feed.refused.map((refused) => refused.issues[0]?.clause)).toStrictEqual(["core 8.3"]);
  });

  it(`${clause("L1 10.3")} two valid entries for one position, each from another home, are found, and the feed is verified up to the entry before`, async () => {
    const { mind, written, profile } = await writer(1);
    const [first] = written;
    const location = mind.resolved.location?.record as OipRecord;
    const one = await entryBy(mind, 1, contentId(first), profile);
    const other = await entryBy(mind, 1, contentId(first), location);
    feedAt(ONE, () => page(mind.address, [first, one]));
    feedAt(TWO, () => page(mind.address, [first, other]));
    const { feed } = await reader().feed(mind.address);
    expect(feed.entries.map((entry) => entry.id)).toStrictEqual([contentId(first)]);
    expect(feed.equivocation.map((entry) => entry.id)).toStrictEqual(
      [contentId(one), contentId(other)].sort(),
    );
  });

  it(`${clause("L1 13.1")} is not to be had where no home serves it, and the first failure says why`, async () => {
    const { mind } = await writer(1);
    world.down(ONE);
    feedAt(TWO, () => page("did:oip:another", []));
    expect(await refusal(() => reader().feed(mind.address))).toBe("transport: unreachable");
    world.down(TWO);
    world.up(ONE);
    expect((await reader().feed(mind.address)).feed.entries).toHaveLength(1);
  });

  it(`${clause("L1 3.13")} a home that is no URL is asked nothing`, async () => {
    // The grammar of an HTTPS origin bounds its characters, and does not make it a URL.
    const made = await freshKeystore(world, [A]);
    const mind = await Mind.create(made.options, { kind: "agent", homes: ["https://:::"] });
    expect(mind.publications).toStrictEqual([
      { service: "resolver", origin: A, taken: true },
      { service: "home", origin: "https://:::", taken: false, failure: "url" },
    ]);
    const before = world.asked.length;
    expect(await refusal(() => reader().feed(mind.address))).toBe("transport: url");
    expect(world.asked.slice(before).every((asked) => asked.startsWith(`GET ${A}`))).toBe(true);
  });

  it("a failure that is nobody's answer reaches the caller as it is", async () => {
    const { mind } = await writer(1);
    // What stands in for `fetch` is broken for the homes: its answer has headers that cannot be read.
    const broken: typeof world.fetch = (request) =>
      request.url.startsWith(A)
        ? world.fetch(request)
        : Promise.resolve({
            status: 200,
            body: null,
            headers: {
              get: () => {
                throw new RangeError("not a response");
              },
            },
          } as unknown as Response);
    await expect(reader({ fetch: broken }).feed(mind.address)).rejects.toThrow(RangeError);
  });
});
