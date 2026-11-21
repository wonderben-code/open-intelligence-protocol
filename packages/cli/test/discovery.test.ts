// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { writeFileSync } from "node:fs";
import { join } from "node:path";

import { clause } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { LOCAL } from "../src/index.ts";
import { Place } from "./harness.ts";

let place: Place;
let ada: string;
let bob: string;
const mindOf = async (dir: string): Promise<string> =>
  ((await place.oip(["show", "--dir", dir, "--json"])).json() as { mind: string }).mind;

beforeAll(async () => {
  place = new Place();
  await place.network();
  ada = place.dir("ada");
  bob = place.dir("bob");
  expect((await place.oip(["init", "--local", "--dir", ada])).code).toBe(0);
  expect((await place.oip(["init", "--local", "--kind", "human", "--dir", bob])).code).toBe(0);
});
afterAll(async () => {
  await place.close();
});

describe("oip publish profile", () => {
  it(`${clause("L1 16.1")} publishes what the mind is and can do, and ${clause("L1 16.4")} it is the mind's current profile`, async () => {
    const published = await place.oip([
      "publish",
      "profile",
      "--name",
      "Ada",
      "--summary",
      "Translates legal texts between English and German.",
      "--capability",
      "translate=Translates legal texts",
      "--capability",
      "review = Reviews a translation",
      "--tag",
      "domain:legal",
      "--tag",
      "lang:de",
      "--dir",
      ada,
    ]);
    expect(published.err).toBe("");
    expect(published.code).toBe(0);
    expect(place.plain(published.out)).toMatchSnapshot();
    const shown = (await place.oip(["show", "--dir", ada, "--json"])).json();
    expect(shown).toMatchObject({
      participant: {
        type: "Participant",
        name: "Ada",
        kind: "agent",
        summary: "Translates legal texts between English and German.",
        capabilities: [
          { id: "translate", summary: "Translates legal texts", tags: ["domain:legal", "lang:de"] },
          { id: "review", summary: "Reviews a translation", tags: ["domain:legal", "lang:de"] },
        ],
      },
    });
    expect((await place.oip(["show", "--dir", ada])).out).toContain(
      "  profile    Ada, 2 capabilities\n",
    );
  });

  it("takes the whole profile from a file, and an option in place of the file's part", async () => {
    const file = join(place.home, "profile.json");
    writeFileSync(
      file,
      JSON.stringify({
        name: "Robert",
        summary: "Signs leases.",
        languages: ["en", "de"],
        interfaces: { mcp: "https://bob.example/mcp" },
      }),
    );
    const published = await place.oip([
      "publish",
      "profile",
      "--file",
      file,
      "--name",
      "Bob",
      "--dir",
      bob,
      "--json",
    ]);
    expect(published.code).toBe(0);
    const said = published.json() as { id: string; record: Record<string, unknown> };
    expect(said.record).toMatchObject({
      name: "Bob",
      kind: "human",
      summary: "Signs leases.",
      languages: ["en", "de"],
      interfaces: { mcp: "https://bob.example/mcp" },
    });
    expect(said).toMatchObject({
      mind: await mindOf(bob),
      publications: [
        { service: "resolver", origin: LOCAL.resolver, taken: true },
        { service: "home", origin: LOCAL.host, taken: true },
        { service: "indexer", origin: LOCAL.indexer, taken: true },
      ],
    });
    expect(said.id).toMatch(/^bciq/u);
  });

  it("says what is wrong with what it was given, and publishes nothing", async () => {
    const file = join(place.home, "bad-profile.json");
    writeFileSync(file, JSON.stringify({ name: "Ada", summary: 5 }));
    for (const [argv, code, said] of [
      [[], 2, "a profile has a name: give one with --name"],
      [["--name", ""], 2, "a profile has a name"],
      [["--name", "Ada", "--capability", "translate"], 2, "translate names no capability"],
      [["--name", "Ada", "--capability", "=Translates"], 2, "names no capability"],
      [["--name", "Ada", "--tag", "domain:legal"], 2, "--tag is a tag of the capabilities named"],
      [["--file", join(place.home, "none.json")], 2, "there is no such file to read"],
      // What makes no record is the client's to refuse, with the code of the problem.
      [["--file", file], 1, "oip: "],
      [["--name", "Ada", "--capability", "a=b", "--tag", "no namespace"], 1, "oip: "],
    ] as const) {
      const refused = await place.oip(["publish", "profile", ...argv, "--dir", ada]);
      expect(refused.code, said).toBe(code);
      expect(refused.err).toContain(said);
      expect(refused.out).toBe("");
    }
    // The profile is as it was.
    expect((await place.oip(["show", "--dir", ada])).out).toContain(
      "  profile    Ada, 2 capabilities\n",
    );
  });
});

describe("oip publish location", () => {
  it(`${clause("L1 15.1")} publishes where the mind takes packets, and whether it does now`, async () => {
    const paused = await place.oip([
      "publish",
      "location",
      "--status",
      "paused",
      "--resume-after",
      "2031-01-31T12:00:00Z",
      "--ttl",
      "600",
      "--dir",
      bob,
    ]);
    expect(paused.err).toBe("");
    expect(paused.out).toBe(
      "The mind is paused, at 2 endpoints, for 600 seconds.\nServices that took it: 3 of 3.\n",
    );
    expect((await place.oip(["show", "--dir", bob])).out).toContain(
      "  location   paused, 2 endpoints\n",
    );
    // With nothing said, it is as before, but for when it means to be back.
    const again = await place.oip(["publish", "location", "--dir", bob, "--json"]);
    expect(again.json()).toMatchObject({ record: { status: "paused", ttl: 600 } });
    expect((again.json() as { record: object }).record).not.toHaveProperty("resumeAfter");
    const active = await place.oip(["publish", "location", "--status", "active", "--dir", bob]);
    expect(active.out).toContain("The mind is active, at 2 endpoints, for 600 seconds.\n");
  });

  it("says what is wrong with what it was given", async () => {
    for (const [argv, said] of [
      [["--status", "asleep"], "asleep is no status: it is active, paused or migrating"],
      [["--resume-after", "soon"], "soon is no time"],
      [["--ttl", "an hour"], "an hour is no number of seconds from 60 to 86400"],
      [["--ttl", "5"], "5 is no number of seconds"],
    ] as const) {
      const refused = await place.oip(["publish", "location", ...argv, "--dir", bob]);
      expect(refused.code, said).toBe(2);
      expect(refused.err).toContain(said);
    }
    // A number that is one, and is out of range, is the record's own fault.
    const long = await place.oip(["publish", "location", "--ttl", "99999", "--dir", bob]);
    expect(long.code).toBe(1);
  });
});

describe("oip publish record", () => {
  it(`${clause("L1 10.1")} puts a record on the mind's feed, one entry after another`, async () => {
    // A record the mind holds: its own profile, as it was published.
    const profile = await place.oip([
      "publish",
      "profile",
      "--name",
      "Bob",
      "--dir",
      bob,
      "--json",
    ]);
    const { id, record } = profile.json() as { id: string; record: object };
    const file = join(place.home, "record.json");
    writeFileSync(file, JSON.stringify(record, undefined, 2));
    const first = await place.oip(["publish", "record", file, "--dir", bob, "--json"]);
    expect(first.code).toBe(0);
    const { entry } = first.json() as { entry: { seq: number; object: string } };
    expect(entry).toMatchObject({ type: "Entry", object: id, objectType: "Participant" });
    // Another mind's record goes on a feed as well (10.2): here, Ada's on Bob's.
    const hers = await place.oip(["show", "--dir", ada, "--json"]);
    writeFileSync(file, JSON.stringify((hers.json() as { participant: object }).participant));
    const second = await place.oip(["publish", "record", file, "--dir", bob]);
    expect(second.err).toBe("");
    expect(place.plain(second.out)).toBe(
      `The record is on the mind's feed, at position ${String(entry.seq + 1)}: <id>\nServices that took it: 1 of 1.\n`,
    );
  });

  it("takes one file that holds a record, and nothing else", async () => {
    const file = join(place.home, "no-record.json");
    writeFileSync(file, JSON.stringify({ type: "Offer" }));
    for (const [argv, code, said] of [
      [[], 2, "publish record takes one file"],
      [[file, file], 2, "publish record takes one file"],
      [[join(place.home, "none.json")], 2, "there is no such file to read"],
      [[file], 1, "oip: "],
    ] as const) {
      const refused = await place.oip(["publish", "record", ...argv, "--dir", bob]);
      expect(refused.code, said).toBe(code);
      expect(refused.err).toContain(said);
    }
  });
});

describe("oip resolve", () => {
  it(`${clause("L1 17.1")} resolves any mind by its address, with no mind of one's own`, async () => {
    const address = await mindOf(ada);
    const resolved = await place.oip(["resolve", address, "--local"]);
    expect(resolved.err).toBe("");
    expect(resolved.code).toBe(0);
    expect(place.plain(resolved.out)).toMatchSnapshot();
    const asJson = (await place.oip(["resolve", address, "--local", "--json"])).json();
    expect(asJson).toMatchObject({
      mind: address,
      kind: "agent",
      retired: false,
      duplicitous: false,
      homes: [LOCAL.host],
      parents: [],
      children: [],
      participant: { name: "Ada" },
      location: { status: "active" },
      did: { didDocument: { id: address } },
      sources: [{ resolver: LOCAL.resolver, events: 1 }],
    });
    // From a mind's directory, the resolvers asked are that mind's.
    const fromBob = await place.oip(["resolve", address, "--dir", bob, "--json"]);
    expect(fromBob.json()).toStrictEqual(asJson);
  });

  it(`${clause("L1 5.3")} checks the other names a mind lists, when asked to`, async () => {
    const address = await mindOf(ada);
    const checked = await place.oip(["resolve", address, "--aliases", "--local", "--json"]);
    expect(checked.code).toBe(0);
    // It lists none: there is nothing to check, and that is said.
    expect(checked.json()).toMatchObject({ aliases: [], alsoKnownAs: [] });
    expect((await place.oip(["resolve", address, "--local", "--json"])).json()).not.toHaveProperty(
      "aliases",
    );
  });

  it("says so where there is no such mind, or nothing to ask", async () => {
    const nobody = "did:oip:bciq" + "a".repeat(52);
    const unknown = await place.oip(["resolve", nobody, "--local"]);
    expect(unknown.code).toBe(1);
    expect(unknown.out).toBe("");
    expect(unknown.err).toMatch(/^oip: /u);
    expect((await place.oip(["resolve", nobody, "--local", "--json"])).json()).toMatchObject({
      error: { code: "not-found" },
    });
    for (const argv of [["resolve"], ["resolve", nobody, nobody]]) {
      const refused = await place.oip([...argv, "--local"]);
      expect(refused.code).toBe(2);
      expect(refused.err).toContain("resolve takes one address: did:oip:…");
    }
    // With no mind in the directory and no network named, there is no resolver to ask.
    const nowhere = await place.oip(["resolve", nobody, "--dir", place.dir("nobody")]);
    expect(nowhere.code).toBe(2);
    expect(nowhere.err).toContain("there is no mind in");
    const stopped = await place.oip([
      "resolve",
      nobody,
      "--local",
      "--network",
      place.dir("no-network"),
    ]);
    expect(stopped.code).toBe(2);
    expect(stopped.err).toContain("no network is running from");
  });
});

describe("oip find", () => {
  it(`${clause("L1 18.4")} finds a mind by what it can do, and shows only what it verified`, async () => {
    const address = await mindOf(ada);
    const found = await place.oip(["find", "--tag", "domain:legal", "--local"]);
    expect(found.err).toBe("");
    expect(found.code).toBe(0);
    expect(
      place.plain(found.out).replace(/ranked {5}[0-9.]+ by/gu, "ranked     <score> by"),
    ).toMatchSnapshot();
    expect(found.out).toContain(`1. ${address}\n`);
    const asJson = await place.oip([
      "find",
      "--want",
      "translate a lease",
      "--tag",
      "lang:de",
      "--kind",
      "participant",
      "--limit",
      "5",
      "--dir",
      bob,
      "--json",
    ]);
    expect(asJson.code).toBe(0);
    expect(asJson.json()).toMatchObject({
      query: { want: "translate a lease", tags: ["lang:de"], kinds: ["Participant"], limit: 5 },
      found: [
        { mind: address, current: true, record: { name: "Ada" } },
        { mind: address, current: true, record: { name: "Ada" } },
      ],
      refused: [],
      sources: [{ indexer: LOCAL.indexer }],
    });
  });

  it("says that nothing was found, where nothing was", async () => {
    const none = await place.oip(["find", "--tag", "domain:astronomy", "--local"]);
    expect(none.code).toBe(0);
    expect(none.out).toBe("0 found. Indexers that answered: 1 of 1.\n");
  });

  it("says what is wrong with what it was given", async () => {
    for (const [argv, said] of [
      [["translation"], "find takes options alone"],
      [["--kind", "robot"], "robot is nothing to find: it is participant, offer or intent"],
      [["--limit", "0"], "0 is no number of results from 1 to 100"],
      [["--limit", "101"], "101 is no number of results"],
      [["--limit", "many"], "many is no number of results"],
    ] as const) {
      const refused = await place.oip(["find", ...argv, "--local"]);
      expect(refused.code, said).toBe(2);
      expect(refused.err).toContain(said);
    }
  });

  it("needs an indexer to ask", async () => {
    const dir = place.dir("unlisted");
    // No resolver answers there: the mind is not made, but its directory says which services it asks.
    await place.oip(["init", "--dir", dir, "--resolver", "https://resolver.invalid"]);
    const refused = await place.oip(["find", "--tag", "domain:legal", "--dir", dir]);
    expect(refused.code).toBe(2);
    expect(refused.err).toContain("the mind names no indexer to ask");
  });
});
