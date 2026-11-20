// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import {
  contentId,
  formatRecordRef,
  MEDIA_TYPE,
  mindId,
  type OipRecord,
  proofDigest,
} from "@oip/core";
import { judgeRecord } from "@oip/identity";
import { Keystore, KeystoreError, type KeyStorage, memoryStorage } from "@oip/keystore";
import { committedProofs } from "@oip/net";
import type { Bundle } from "@oip/schema";
import { clause } from "@oip/testkit";
import { at, T } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { askRecord, homeEndpoints, Lookup, Mind } from "../src/index.ts";
import { copyOf, freshKeystore, refusal } from "./helpers.ts";
import { World } from "./world.ts";

const A = "https://resolver-a.example";
const B = "https://resolver-b.example";
const ONE = "https://host-one.example";
const TWO = "https://host-two.example";

let world: World;
beforeEach(() => {
  world = new World(100);
  world.resolver(A);
  world.resolver(B);
  world.host(ONE);
  world.host(TWO);
});
afterEach(() => {
  world.close();
});

const fresh = () => freshKeystore(world, [A, B]);

/** A mind with two homes, and what it was made with. */
async function atHome(homes: readonly string[] = [ONE, TWO]) {
  const made = await fresh();
  const mind = await Mind.create(made.options, { kind: "agent", homes });
  return { ...made, mind };
}

/** Another client's view of the world. */
const reader = (resolvers: readonly string[] = [A, B]) =>
  new Lookup({ resolvers, fetch: world.direct, clock: world.clock });

/** What a home serves for a mind at its well-known place. */
const served = (home: string, mind: string, rest = ""): Promise<OipRecord> =>
  askRecord(
    { method: "GET", url: `${home}/.well-known/oip/mind/${mindId(mind) ?? ""}${rest}` },
    { fetch: world.direct },
  );

const taken = (service: "resolver" | "home", origin: string) => ({ service, origin, taken: true });
const everywhere = [
  taken("resolver", A),
  taken("resolver", B),
  taken("home", ONE),
  taken("home", TWO),
];

describe("where a mind can be reached", () => {
  it(`${clause("L1 15.1", "L1 13.3")} a location record goes to every resolver and to every home, with a request the mind signed`, async () => {
    const { mind } = await atHome();
    // The homes took the mind on when it was made: they serve its log.
    expect(mind.publications).toStrictEqual([
      taken("resolver", A),
      taken("resolver", B),
      taken("home", ONE),
      taken("home", TWO),
    ]);
    const signatures: (string | null)[] = [];
    world.before = (request) => {
      if (request.method === "PUT") signatures.push(request.headers.get("signature-input"));
    };
    const location = await mind.publishLocation();
    world.before = undefined;
    expect(location).toMatchObject({
      type: "Location",
      author: mind.address,
      seq: 0,
      created: T(100),
      ttl: 3600,
      status: "active",
      endpoints: homeEndpoints(mind.address, [ONE, TWO]),
    });
    expect(location.participant).toBeUndefined();
    expect(location.feed).toBeUndefined();
    expect(mind.publications).toStrictEqual(everywhere);
    expect(signatures).toHaveLength(4);
    for (const signature of signatures) {
      expect(signature).toContain(`keyid="${mind.address}?versionId=`);
      expect(signature).toContain('"@method" "@target-uri" "content-digest"');
    }
    // The mind's own view, and that of another client, each from the resolvers.
    expect(mind.resolved.location?.id).toBe(contentId(location));
    const other = await reader().resolve(mind.address);
    expect(other.location?.record).toStrictEqual(location);
    expect(other.location?.time).toBe(at(100));
    expect(other.stale).toBe(false);
    // And each home serves it with the mind's log (13.1).
    for (const home of [ONE, TWO]) {
      const bundle = (await served(home, mind.address)) as unknown as Bundle;
      expect(bundle.location).toStrictEqual(location);
      expect(bundle.log).toHaveLength(1);
    }
  });

  it(`${clause("L1 15.1")} the endpoints of a mind at its homes are an inbox and a mailbox at each, the first home first`, async () => {
    const { mind } = await atHome();
    const id = mindId(mind.address) ?? "";
    expect(homeEndpoints(mind.address, [ONE, TWO])).toStrictEqual([
      { binding: "https", url: `${ONE}/oip/v1/minds/${id}`, priority: 0 },
      { binding: "mailbox", url: `${ONE}/oip/v1/minds/${id}/mailbox`, priority: 0 },
      { binding: "https", url: `${TWO}/oip/v1/minds/${id}`, priority: 1 },
      { binding: "mailbox", url: `${TWO}/oip/v1/minds/${id}/mailbox`, priority: 1 },
    ]);
    expect(homeEndpoints(mind.address, [])).toStrictEqual([]);
    expect(() => homeEndpoints("did:web:example.com", [ONE])).toThrow(/not the address of a mind/u);
  });

  it(`${clause("L1 15.1", "L1 15.2")} each record has the next number, and what is left out stays as it was`, async () => {
    const { mind } = await atHome();
    const endpoints = [{ binding: "https", url: "https://mind.example/oip", priority: 3 }];
    const first = await mind.publishLocation({ endpoints, ttl: 600 });
    expect(first).toMatchObject({ seq: 0, endpoints, ttl: 600, status: "active" });
    world.clock.at = at(200);
    const second = await mind.publishLocation({ status: "paused", resumeAfter: T(5000) });
    expect(second).toMatchObject({
      seq: 1,
      created: T(200),
      endpoints,
      ttl: 600,
      status: "paused",
      resumeAfter: T(5000),
    });
    // When the mind means to be back is said each time, or not at all.
    const third = await mind.publishLocation({ status: "active" });
    expect(third).toMatchObject({ seq: 2, endpoints, ttl: 600, status: "active" });
    expect(third.resumeAfter).toBeUndefined();
    expect((await reader().resolve(mind.address)).location?.record.seq).toBe(2);
  });

  it(`${clause("L1 15.2")} a client that remembers nothing takes the number after the one the resolvers serve`, async () => {
    const { mind, options } = await atHome();
    await mind.publishLocation();
    await mind.publishLocation();
    mind.close();
    const again = await Mind.open({ ...options, memory: memoryStorage() });
    expect((await again.publishLocation()).seq).toBe(2);
  });

  it(`${clause("L1 15.2")} a number is used once, also for a record no resolver took`, async () => {
    const { mind } = await atHome();
    await mind.publishLocation();
    // The resolvers serve the mind, and then cannot be reached when the record is brought.
    world.before = (request) => {
      if (request.method === "PUT" && request.url.startsWith("https://resolver-")) {
        throw new TypeError("fetch failed");
      }
    };
    // The record with number 1 is signed, and reaches the homes and no resolver.
    expect(await refusal(() => mind.publishLocation({ ttl: 120 }))).toBe("transport: unreachable");
    world.before = undefined;
    expect(mind.publications).toStrictEqual([
      { service: "resolver", origin: A, taken: false, failure: "unreachable" },
      { service: "resolver", origin: B, taken: false, failure: "unreachable" },
      taken("home", ONE),
      taken("home", TWO),
    ]);
    const bundle = (await served(ONE, mind.address)) as unknown as Bundle;
    expect(bundle.location).toMatchObject({ seq: 1, ttl: 120 });
    const next = await mind.publishLocation({ ttl: 300 });
    expect(next.seq).toBe(2);
    expect(mind.publications).toStrictEqual(everywhere);
  });

  it(`${clause("L1 15.2")} a record past its time is still served, and is said to be stale`, async () => {
    const { mind } = await atHome();
    await mind.publishLocation({ ttl: 60 });
    world.clock.at = at(100 + 61);
    const other = await reader().resolve(mind.address);
    expect(other.location?.record.seq).toBe(0);
    expect(other.stale).toBe(true);
    expect((await reader().resolve((await atHome()).mind.address)).stale).toBe(false);
  });

  it(`${clause("L1 15.1")} what makes no location record is refused before anything is signed away`, async () => {
    const { mind } = await atHome();
    const before = world.asked.length;
    expect(await refusal(() => mind.publishLocation({ ttl: 5 }))).toBe("oip: invalid-record");
    expect(
      await refusal(() => mind.publishLocation({ endpoints: [{ binding: "https" } as never] })),
    ).toBe("oip: invalid-record");
    // The mind was resolved, and nothing was published.
    expect(world.asked.slice(before).filter((asked) => !asked.startsWith("GET "))).toStrictEqual(
      [],
    );
    // No number was used up.
    expect((await mind.publishLocation()).seq).toBe(0);
  });

  it(`${clause("L1 15.1")} a mind with no home publishes to the resolvers, with no endpoints unless it names some`, async () => {
    const { mind } = await atHome([]);
    expect(mind.publications).toStrictEqual([taken("resolver", A), taken("resolver", B)]);
    const location = await mind.publishLocation();
    expect(location.endpoints).toStrictEqual([]);
    expect(mind.publications).toStrictEqual([taken("resolver", A), taken("resolver", B)]);
  });

  it(`${clause("L1 13.1")} a home that could not be reached is brought the mind's records later`, async () => {
    world.down(TWO);
    const { mind } = await atHome();
    expect(mind.publications).toStrictEqual([
      taken("resolver", A),
      taken("resolver", B),
      taken("home", ONE),
      { service: "home", origin: TWO, taken: false, failure: "unreachable" },
    ]);
    const location = await mind.publishLocation();
    expect(mind.publications.at(-1)).toStrictEqual({
      service: "home",
      origin: TWO,
      taken: false,
      failure: "unreachable",
    });
    world.up(TWO);
    expect(await mind.bringHomes()).toStrictEqual([taken("home", ONE), taken("home", TWO)]);
    const bundle = (await served(TWO, mind.address)) as unknown as Bundle;
    expect(bundle.location).toStrictEqual(location);
  });

  it(`${clause("L1 13.1")} a home that does not admit the mind says so, and the others serve it`, async () => {
    world.host(TWO, { admits: () => false });
    const { mind } = await atHome();
    expect(mind.publications).toStrictEqual([
      taken("resolver", A),
      taken("resolver", B),
      taken("home", ONE),
      { service: "home", origin: TWO, taken: false, failure: "forbidden" },
    ]);
  });

  it(`${clause("L1 13.1", "L1 6.1")} the homes are brought every identity event, and take requests signed with a key it adds`, async () => {
    const { mind, lock } = await atHome();
    const [old] = mind.state.keys;
    const added = await mind.addKey({ control: lock });
    expect(mind.publications).toStrictEqual(everywhere);
    await mind.revokeKey(old ?? "", { control: lock });
    expect(mind.publications).toStrictEqual(everywhere);
    expect(mind.signingKey()).toBe(added);
    for (const home of [ONE, TWO]) {
      const bundle = (await served(home, mind.address)) as unknown as Bundle;
      expect(bundle.log).toHaveLength(3);
    }
    await mind.publishLocation();
    expect(mind.publications).toStrictEqual(everywhere);
  });

  it(`${clause("L1 3.10", "L1 17.3")} a mind that retires brings its homes the event, signed as it was before, and signs nothing after`, async () => {
    const { mind, lock } = await atHome();
    await mind.publishLocation();
    world.down(TWO);
    await mind.retire({ control: lock });
    expect(mind.publications).toStrictEqual([
      taken("resolver", A),
      taken("resolver", B),
      taken("home", ONE),
      { service: "home", origin: TWO, taken: false, failure: "unreachable" },
    ]);
    const bundle = (await served(ONE, mind.address)) as unknown as Bundle;
    expect(bundle.log).toHaveLength(2);
    // The location record of a mind that has retired counts no longer, and is not served.
    expect(bundle.location).toBeUndefined();
    // The home that was away holds the log so far, and is brought the retirement later.
    // The home that holds the retirement takes no more requests from the mind.
    world.up(TWO);
    expect(await mind.bringHomes()).toStrictEqual([
      { service: "home", origin: ONE, taken: false, failure: "unauthorised" },
      taken("home", TWO),
    ]);
    expect(((await served(TWO, mind.address)) as unknown as Bundle).log).toHaveLength(2);
    expect(await refusal(() => mind.publishLocation())).toBe("oip: forbidden");
    expect(await refusal(() => mind.publishRecord(bundle.log[0] as object))).toBe("oip: forbidden");
  });
});

describe("a resolver that takes a bundle only with a signed request", () => {
  const C = "https://resolver-c.example";
  const strict = async () => {
    world.resolver(C, true);
    const made = await freshKeystore(world, [C]);
    const mind = await Mind.create(made.options, { kind: "agent" });
    return { ...made, mind };
  };

  it(`${clause("L1 17.3")} takes a mind's first log, signed with a key the genesis lists`, async () => {
    const { mind } = await strict();
    expect(mind.publications).toStrictEqual([taken("resolver", C)]);
    // The same bundle without a signature is refused.
    const [genesis] = mind.resolved.log.entries.map((entry) => entry.event);
    expect(await world.publish(C, { address: mind.address, events: [genesis] } as never)).toBe(401);
  });

  it(`${clause("L1 17.3", "L1 6.1")} takes an event that removes the key the mind signed with, signed with one that stays`, async () => {
    const { mind, lock } = await strict();
    const [old] = mind.state.keys;
    await mind.addKey({ control: lock });
    expect(mind.publications).toStrictEqual([taken("resolver", C)]);
    // The first key is the one the mind signs with, and the one that goes.
    expect(mind.signingKey()).toBe(old);
    const state = await mind.revokeKey(old ?? "", { control: lock });
    expect(state.keys).toHaveLength(1);
    expect(mind.publications).toStrictEqual([taken("resolver", C)]);
    await mind.publishLocation({ endpoints: [] });
    expect(mind.publications).toStrictEqual([taken("resolver", C)]);
  });
});

describe("a mind that retires, before a resolver that takes a bundle only with a signed request", () => {
  it(`${clause("L1 17.3", "L1 3.10")} publishes the event that retires it`, async () => {
    const C = "https://resolver-c.example";
    world.resolver(C, true);
    const made = await freshKeystore(world, [C]);
    const mind = await Mind.create(made.options, { kind: "agent" });
    const state = await mind.retire({ control: made.lock });
    expect(state.retired).toBe(true);
    expect(mind.publications).toStrictEqual([taken("resolver", C)]);
    expect((await reader([C]).resolve(mind.address)).state.retired).toBe(true);
  });
});

describe("what a mind is and can do", () => {
  it(`${clause("L1 16.1", "L1 16.4")} a profile is published with a location record that names it`, async () => {
    const { mind } = await atHome();
    const profile = await mind.publishProfile({
      name: "Ada",
      summary: "Translates between French and English.",
      capabilities: [{ id: "translate", summary: "Translation", tags: ["lang:fr", "lang:en"] }],
      interfaces: { a2a: "https://ada.example/a2a" },
      languages: ["en", "fr"],
      attestations: ["https://ada.example/credential"],
    });
    expect(profile).toMatchObject({
      type: "Participant",
      author: mind.address,
      created: T(100),
      name: "Ada",
      kind: "agent",
      languages: ["en", "fr"],
    });
    expect(profile.supersedes).toBeUndefined();
    expect(mind.publications).toStrictEqual(everywhere);
    expect(mind.resolved.location?.record).toMatchObject({
      seq: 0,
      participant: contentId(profile),
      endpoints: homeEndpoints(mind.address, [ONE, TWO]),
    });
    const other = await reader().resolve(mind.address);
    expect(other.participant?.record).toStrictEqual(profile);
    expect(other.participant?.time).toBe(at(100));
    const bundle = (await served(ONE, mind.address)) as unknown as Bundle;
    expect(bundle.participant).toStrictEqual(profile);
  });

  it(`${clause("L1 16.1")} the next profile supersedes the one before, and a later location record goes on naming it`, async () => {
    const { mind } = await atHome();
    const first = await mind.publishProfile({ name: "Ada" });
    world.clock.at = at(200);
    const second = await mind.publishProfile({
      name: "Ada Lovelace",
      actsFor: [],
    });
    expect(second.supersedes).toBe(formatRecordRef(mind.address, contentId(first)));
    expect(mind.resolved.participant?.id).toBe(contentId(second));
    const location = await mind.publishLocation({ status: "paused" });
    expect(location).toMatchObject({ seq: 2, participant: contentId(second) });
    expect((await reader().resolve(mind.address)).participant?.record.name).toBe("Ada Lovelace");
  });

  it(`${clause("L1 16.1")} what makes no profile is refused, and nothing is published`, async () => {
    const { mind } = await atHome();
    const before = world.asked.length;
    expect(await refusal(() => mind.publishProfile({ name: "x".repeat(129) }))).toBe(
      "oip: invalid-record",
    );
    expect(world.asked.slice(before).filter((asked) => !asked.startsWith("GET "))).toStrictEqual(
      [],
    );
    expect(mind.resolved.participant).toBeUndefined();
  });

  it(`${clause("L1 16.4")} a profile the location record names and no resolver serves is no current profile`, async () => {
    const { mind } = await atHome();
    const profile = await mind.publishProfile({ name: "Ada" });
    // A resolver that serves the location record without the profile.
    const real = world.at(A);
    world.put(A, async (request) => {
      const response = await real(request);
      if (request.method !== "GET") return response;
      const { participant: _, ...bundle } = (await response.json()) as Record<string, unknown>;
      return new Response(JSON.stringify(bundle), {
        status: response.status,
        headers: { "content-type": MEDIA_TYPE },
      });
    });
    const other = await reader([A]).resolve(mind.address);
    expect(other.location?.record.participant).toBe(contentId(profile));
    expect(other.participant).toBeUndefined();
  });
});

describe("a mind's public feed", () => {
  it(`${clause("L1 10.1", "L1 10.2", "L1 13.1")} a record is put on the feed with an entry that names it and its proofs, and the homes serve both`, async () => {
    const { mind } = await atHome();
    const profile = await mind.publishProfile({ name: "Ada" });
    const first = await mind.publishRecord(profile);
    expect(first).toMatchObject({
      type: "Entry",
      author: mind.address,
      seq: 0,
      created: T(100),
      object: contentId(profile),
      objectType: "Participant",
      proofs: profile.proof.map((proof) => proofDigest(proof)),
    });
    expect(first.prev).toBeUndefined();
    expect(mind.publications).toStrictEqual([taken("home", ONE), taken("home", TWO)]);
    const location = mind.resolved.location?.record as OipRecord;
    const second = await mind.publishRecord(location);
    expect(second).toMatchObject({ seq: 1, prev: contentId(first), objectType: "Location" });

    // Another client reads the feed from the homes, and verifies it.
    const { feed, sources } = await reader().feed(mind.address);
    expect(sources).toStrictEqual([
      { home: ONE, entries: 2 },
      { home: TWO, entries: 2 },
    ]);
    expect(feed.entries.map((entry) => entry.entry)).toStrictEqual([first, second]);
    expect(feed.entries.map((entry) => entry.time)).toStrictEqual([at(100), at(100)]);
    expect(feed.equivocation).toStrictEqual([]);
    expect(feed.refused).toStrictEqual([]);
    // Each home serves the record an entry lists (10.2).
    for (const home of [ONE, TWO]) {
      const record = await served(home, mind.address, `/obj/${first.object}`);
      expect(record).toStrictEqual(profile);
      const judged = judgeRecord(record);
      expect(judged.ok && committedProofs(first, judged.value)).toStrictEqual(first.proofs);
    }
  });

  it(`${clause("L1 10.1")} an entry counts for a reader whose clock moves between what it asks`, async () => {
    const { mind } = await atHome();
    await mind.publishRecord(await mind.publishProfile({ name: "Ada" }));
    let now = at(300);
    const ticking = new Lookup({
      resolvers: [A, B],
      fetch: world.direct,
      clock: { now: () => (now += 1_000_000n) },
    });
    world.clock.at = at(400);
    const { feed } = await ticking.feed(mind.address);
    expect(feed.entries).toHaveLength(1);
    expect(feed.entries[0]?.time).toBeGreaterThan(at(300));
  });

  it(`${clause("L1 10.2")} a feed lists the records of other minds`, async () => {
    const { mind } = await atHome();
    const other = await atHome([]);
    const theirs = await other.mind.sign({
      oip: "1",
      type: "Participant",
      author: other.mind.address,
      created: T(100),
      name: "Bob",
      kind: "agent",
    });
    const entry = await mind.publishRecord(theirs);
    expect(entry).toMatchObject({ seq: 0, object: contentId(theirs), objectType: "Participant" });
    expect(await served(ONE, mind.address, `/obj/${entry.object}`)).toStrictEqual(theirs);
  });

  it(`${clause("L1 10.3")} calls are taken one after another: a feed has one writer`, async () => {
    const { mind } = await atHome();
    const profile = await mind.publishProfile({ name: "Ada" });
    const location = mind.resolved.location?.record as OipRecord;
    const [first, second, third] = await Promise.all([
      mind.publishRecord(profile),
      mind.publishRecord(location),
      mind.publishRecord(profile),
    ]);
    expect([first.seq, second.seq, third.seq]).toStrictEqual([0, 1, 2]);
    expect(second.prev).toBe(contentId(first));
    expect(third.prev).toBe(contentId(second));
    expect(third.object).toBe(first.object);
    expect((await reader().feed(mind.address)).feed.entries).toHaveLength(3);
  });

  it(`${clause("L1 10.3")} an entry no home took is brought again by the next call, and no other is signed for its position`, async () => {
    const { mind, options } = await atHome();
    const profile = await mind.publishProfile({ name: "Ada" });
    const location = mind.resolved.location?.record as OipRecord;
    await mind.publishRecord(profile);
    world.down(ONE);
    world.down(TWO);
    // The entry at 1 is signed, and remembered, and reaches no home.
    expect(await refusal(() => mind.publishRecord(location))).toBe("transport: unreachable");
    expect(mind.publications).toStrictEqual([
      { service: "home", origin: ONE, taken: false, failure: "unreachable" },
      { service: "home", origin: TWO, taken: false, failure: "unreachable" },
    ]);
    // The process ends. The next one remembers the entry, with the record it lists.
    mind.close();
    const again = await Mind.open(options);
    world.clock.at = at(200);
    expect(await refusal(() => again.publishRecord(profile))).toBe("transport: unreachable");
    world.up(ONE);
    world.up(TWO);
    // The entry that waited is brought first, as it was signed, and then the one asked for.
    const third = await again.publishRecord(profile);
    expect(third).toMatchObject({ seq: 2, created: T(200), objectType: "Participant" });
    const { feed } = await reader().feed(mind.address);
    expect(
      feed.entries.map(({ entry }) => [entry.seq, entry.objectType, entry.created]),
    ).toStrictEqual([
      [0, "Participant", T(100)],
      [1, "Location", T(100)],
      [2, "Participant", T(200)],
    ]);
    expect(third.prev).toBe(feed.entries[1]?.id);
    expect(await served(ONE, mind.address, `/obj/${contentId(location)}`)).toStrictEqual(location);
  });

  it(`${clause("L1 10.3")} a call for the record of the entry that waited brings that entry, and signs no second one for the record`, async () => {
    const { mind } = await atHome();
    const profile = await mind.publishProfile({ name: "Ada" });
    const location = mind.resolved.location?.record as OipRecord;
    await mind.publishRecord(location);
    world.down(ONE);
    world.down(TWO);
    // The entry at 1 is signed for the profile, and reaches no home.
    expect(await refusal(() => mind.publishRecord(profile))).toBe("transport: unreachable");
    world.up(ONE);
    world.up(TWO);
    world.clock.at = at(200);
    // Asked for again: the entry that was signed for it is brought, and is the answer.
    const entry = await mind.publishRecord(profile);
    expect(entry).toMatchObject({ seq: 1, created: T(100), object: contentId(profile) });
    const listed = async () =>
      (await reader().feed(mind.address)).feed.entries.map(({ entry: one }) => [
        one.seq,
        one.objectType,
        one.created,
      ]);
    expect(await listed()).toStrictEqual([
      [0, "Location", T(100)],
      [1, "Participant", T(100)],
    ]);
    // With nothing waiting, to list a record again is the caller's to decide.
    expect(await mind.publishRecord(profile)).toMatchObject({ seq: 2, created: T(200) });
    expect(await listed()).toHaveLength(3);
  });

  it(`${clause("L1 10.3")} one home is enough for an entry, and the other is told which it lacks`, async () => {
    const { mind } = await atHome();
    const profile = await mind.publishProfile({ name: "Ada" });
    world.down(TWO);
    const first = await mind.publishRecord(profile);
    expect(mind.publications).toStrictEqual([
      taken("home", ONE),
      { service: "home", origin: TWO, taken: false, failure: "unreachable" },
    ]);
    world.up(TWO);
    // The second home lacks the first entry, and takes no second before it.
    const second = await mind.publishRecord(profile);
    expect(second.prev).toBe(contentId(first));
    expect(mind.publications).toStrictEqual([
      taken("home", ONE),
      { service: "home", origin: TWO, taken: false, failure: "invalid-record" },
    ]);
    // A reader has the whole feed from the home that holds it.
    const { feed, sources } = await reader().feed(mind.address);
    expect(feed.entries).toHaveLength(2);
    expect(sources).toStrictEqual([
      { home: ONE, entries: 2 },
      { home: TWO, entries: 0 },
    ]);
  });

  it(`${clause("L1 10.3")} a client that remembers nothing goes on from where the homes' feed ends`, async () => {
    const { mind, options } = await atHome();
    const profile = await mind.publishProfile({ name: "Ada" });
    const first = await mind.publishRecord(profile);
    const second = await mind.publishRecord(profile);
    mind.close();
    const again = await Mind.open({ ...options, memory: memoryStorage() });
    const third = await again.publishRecord(profile);
    expect(third).toMatchObject({ seq: 2, prev: contentId(second) });
    expect(second.prev).toBe(contentId(first));
  });

  it(`${clause("L1 10.3", "L1 15.1")} a location record says where the feed stands, and homes that serve less are not gone by`, async () => {
    const { mind, options } = await atHome();
    const profile = await mind.publishProfile({ name: "Ada" });
    await mind.publishRecord(profile);
    const second = await mind.publishRecord(profile);
    const location = await mind.publishLocation();
    expect(location.feed).toStrictEqual({ seq: 1, head: contentId(second) });
    mind.close();
    // A new device, which remembers nothing. One home is away, and the other has lost the feed.
    world.down(ONE);
    world.host(TWO);
    const again = await Mind.open({ ...options, memory: memoryStorage() });
    expect(await again.bringHomes()).toStrictEqual([
      { service: "home", origin: ONE, taken: false, failure: "unreachable" },
      taken("home", TWO),
    ]);
    const before = world.asked.length;
    expect(await refusal(() => again.publishRecord(profile))).toBe("oip: not-found");
    // Nothing was signed away: no entry reached the home that would have taken one at seq 0.
    expect(world.asked.slice(before).filter((asked) => !asked.startsWith("GET "))).toStrictEqual(
      [],
    );
    // With the home that holds the feed, it goes on.
    world.up(ONE);
    expect(await again.publishRecord(profile)).toMatchObject({ seq: 2, prev: contentId(second) });
    // A later location record carries the feed's place on, though this client did not write it all.
    expect((await again.publishLocation()).feed?.seq).toBe(2);
  });

  it(`${clause("L1 10.3")} no home that answers and no memory: no entry is signed`, async () => {
    const { mind, options } = await atHome();
    const profile = await mind.publishProfile({ name: "Ada" });
    await mind.publishRecord(profile);
    mind.close();
    world.down(ONE);
    world.down(TWO);
    const again = await Mind.open({ ...options, memory: memoryStorage() });
    expect(await refusal(() => again.publishRecord(profile))).toBe("transport: unreachable");
  });

  it(`${clause("L1 10.3")} a client whose memory is behind is told of the entry it did not know, signs no further, and reads the feed afresh`, async () => {
    const { mind, options, memory } = await atHome();
    const profile = await mind.publishProfile({ name: "Ada" });
    const first = await mind.publishRecord(profile);
    // A second device is set up from the first, and then the first writes on.
    const behind = await copyOf(memory);
    const second = await mind.publishRecord(profile);
    mind.close();
    const other = await Mind.open({ ...options, memory: behind });
    world.clock.at = at(200);
    expect(await refusal(() => other.publishRecord(profile))).toBe("oip: duplicity");
    expect(other.publications).toStrictEqual([
      { service: "home", origin: ONE, taken: false, failure: "duplicity" },
      { service: "home", origin: TWO, taken: false, failure: "duplicity" },
    ]);
    // The homes kept the entry they had: the feed a reader sees has no fork.
    const { feed } = await reader().feed(mind.address);
    expect(feed.entries.map((entry) => entry.id)).toStrictEqual([
      contentId(first),
      contentId(second),
    ]);
    expect(feed.equivocation).toStrictEqual([]);
    // The next call goes on from the feed as the homes serve it.
    expect(await other.publishRecord(profile)).toMatchObject({ seq: 2, prev: contentId(second) });
  });

  it(`${clause("L1 10.3")} two processes that write as one mind find each other out in what they remember`, async () => {
    // A memory that lets both processes read where the feed stands before either writes.
    const base = memoryStorage();
    let reads = 0;
    let release: () => void = () => undefined;
    let both = Promise.resolve();
    const shared: KeyStorage = {
      list: () => base.list(),
      delete: (name, expected) => base.delete(name, expected),
      get: async (name) => {
        const held = await base.get(name);
        if (name === "client-feed" && ++reads === 2) release();
        return held;
      },
      put: async (name, value, expected) => {
        if (name === "client-feed") await both;
        return base.put(name, value, expected);
      },
    };
    const made = await freshKeystore(world, [A, B], { memory: shared });
    const mind = await Mind.create(made.options, { kind: "agent", homes: [ONE, TWO] });
    const profile = await mind.publishProfile({ name: "Ada" });
    const first = await mind.publishRecord(profile);
    const twin = await Mind.open({
      ...made.options,
      keystore: await Keystore.open({ storage: made.storage }),
    });
    reads = 0;
    both = new Promise<void>((resolve) => {
      release = resolve;
    });
    const location = mind.resolved.location?.record as OipRecord;
    const outcomes = await Promise.allSettled([
      mind.publishRecord(profile),
      twin.publishRecord(location),
    ]);
    // One wrote what it remembers first. The other is told, before its entry left.
    const done = outcomes.flatMap((outcome) =>
      outcome.status === "fulfilled" ? [outcome.value] : [],
    );
    const failed = outcomes.flatMap((outcome) =>
      outcome.status === "rejected" ? [outcome.reason as unknown] : [],
    );
    expect(done).toHaveLength(1);
    expect(failed).toHaveLength(1);
    expect(failed[0]).toBeInstanceOf(KeystoreError);
    expect((failed[0] as KeystoreError).code).toBe("changed");
    const { feed } = await reader().feed(mind.address);
    expect(feed.entries.map((entry) => entry.id)).toStrictEqual([
      contentId(first),
      contentId(done[0]!),
    ]);
    expect(feed.equivocation).toStrictEqual([]);
    expect(feed.refused).toStrictEqual([]);
  });

  it(`${clause("L1 13.1")} a mind with no home has no feed, and what is no record is put on none`, async () => {
    const homeless = await atHome([]);
    const profile = await homeless.mind.sign({
      oip: "1",
      type: "Participant",
      author: homeless.mind.address,
      created: T(100),
      name: "Ada",
      kind: "agent",
    });
    expect(await refusal(() => homeless.mind.publishRecord(profile))).toBe("oip: forbidden");
    expect(await refusal(() => reader().feed(homeless.mind.address))).toBe("oip: not-found");
    const { mind } = await atHome();
    expect(await refusal(() => mind.publishRecord({ type: "Participant" }))).toBe(
      "oip: invalid-record",
    );
    expect(await refusal(() => mind.publishRecord("a record" as never))).toBe(
      "oip: invalid-record",
    );
  });

  it(`${clause("L1 13.1")} a home that serves the mind no longer is brought its bundle, and then the entry`, async () => {
    const { mind } = await atHome();
    const profile = await mind.publishProfile({ name: "Ada" });
    // Both homes start again with nothing.
    world.host(ONE);
    world.host(TWO);
    const entry = await mind.publishRecord(profile);
    expect(entry.seq).toBe(0);
    expect(mind.publications).toStrictEqual([taken("home", ONE), taken("home", TWO)]);
    expect((await reader().feed(mind.address)).feed.entries).toHaveLength(1);
  });

  it(`${clause("L1 13.1")} a home that takes no mind on takes no entry, and the mind is told`, async () => {
    world.host(ONE, { admits: () => false });
    const { mind } = await atHome([ONE]);
    const profile = await mind.sign({
      oip: "1",
      type: "Participant",
      author: mind.address,
      created: T(100),
      name: "Ada",
      kind: "agent",
    });
    expect(await refusal(() => mind.publishRecord(profile))).toBe("oip: not-found");
  });
});

describe("a feed, where what is remembered or served is not as it should be", () => {
  it(`${clause("L1 10.1")} a record with no proof that verifies is listed with none`, async () => {
    const { mind } = await atHome();
    const bundle = {
      oip: "1",
      type: "Bundle",
      mind: mind.address,
      log: mind.resolved.log.entries.map((entry) => entry.event),
    };
    const entry = await mind.publishRecord(bundle);
    expect(entry).toMatchObject({ seq: 0, objectType: "Bundle", object: contentId(bundle) });
    expect(entry.proofs).toBeUndefined();
  });

  it(`${clause("L1 10.3")} a client that remembers nothing writes no entry on a feed that has forked`, async () => {
    const { mind, options } = await atHome();
    const profile = await mind.publishProfile({ name: "Ada" });
    const location = mind.resolved.location?.record as OipRecord;
    const first = await mind.publishRecord(profile);
    const entryFor = (record: OipRecord) =>
      mind.sign({
        oip: "1",
        type: "Entry",
        author: mind.address,
        seq: 1,
        prev: contentId(first),
        created: T(100),
        object: contentId(record),
        objectType: record.type,
      });
    const forks = [await entryFor(profile), await entryFor(location)];
    mind.close();
    for (const [index, home] of [ONE, TWO].entries()) {
      const real = world.at(home);
      world.put(home, (request) =>
        request.method === "GET" && request.url.includes("/feed")
          ? new Response(
              JSON.stringify({
                oip: "1",
                type: "FeedPage",
                mind: mind.address,
                entries: [first, forks[index]],
              }),
              { status: 200, headers: { "content-type": MEDIA_TYPE } },
            )
          : real(request),
      );
    }
    const again = await Mind.open({ ...options, memory: memoryStorage() });
    const before = world.asked.length;
    expect(await refusal(() => again.publishRecord(profile))).toBe("oip: duplicity");
    expect(world.asked.slice(before).filter((asked) => !asked.startsWith("GET "))).toStrictEqual(
      [],
    );
  });

  it(`${clause("L1 10.3")} where one home takes an entry and another holds a different one there, the mind is told that its feed has forked`, async () => {
    const { mind, options, memory } = await atHome();
    const profile = await mind.publishProfile({ name: "Ada" });
    const location = mind.resolved.location?.record as OipRecord;
    const first = await mind.publishRecord(profile);
    const behind = await copyOf(memory);
    // The second home is away while the first device writes on.
    world.down(TWO);
    const second = await mind.publishRecord(profile);
    world.up(TWO);
    mind.close();
    // A second device, whose memory is behind, writes another entry at that position.
    const other = await Mind.open({ ...options, memory: behind });
    expect(await refusal(() => other.publishRecord(location))).toBe("oip: duplicity");
    expect(other.publications).toStrictEqual([
      { service: "home", origin: ONE, taken: false, failure: "duplicity" },
      taken("home", TWO),
    ]);
    // Both entries are signed and served: a reader holds the two, and the feed up to the entry before.
    const { feed } = await reader().feed(mind.address);
    expect(feed.entries.map((entry) => entry.id)).toStrictEqual([contentId(first)]);
    expect(feed.equivocation).toHaveLength(2);
    expect(feed.equivocation.map((entry) => entry.id)).toContain(contentId(second));
    // The entry stays the one this device has for the position: it signs no third.
    expect(await refusal(() => other.publishRecord(profile))).toBe("oip: duplicity");
    expect((await reader().feed(mind.address)).feed.equivocation).toHaveLength(2);
  });

  it(`${clause("L1 10.3")} a first entry that reached no home waits, and is the first entry still`, async () => {
    const { mind } = await atHome();
    const profile = await mind.publishProfile({ name: "Ada" });
    // The homes serve the feed, which is empty, and then cannot be reached with the entry.
    world.before = (request) => {
      if (request.method !== "GET" && request.url.includes("/obj/")) {
        throw new TypeError("fetch failed");
      }
    };
    expect(await refusal(() => mind.publishRecord(profile))).toBe("transport: unreachable");
    world.before = undefined;
    world.clock.at = at(200);
    const location = mind.resolved.location?.record as OipRecord;
    const second = await mind.publishRecord(location);
    expect(second).toMatchObject({ seq: 1, created: T(200) });
    const { feed } = await reader().feed(mind.address);
    expect(
      feed.entries.map(({ entry }) => [entry.seq, entry.objectType, entry.created]),
    ).toStrictEqual([
      [0, "Participant", T(100)],
      [1, "Location", T(200)],
    ]);
  });

  it("what is remembered and cannot be read is said to be damaged, and nothing is signed by guess", async () => {
    const { mind, options } = await atHome();
    const profile = await mind.publishProfile({ name: "Ada" });
    const entry = await mind.publishRecord(profile);
    mind.close();
    const head = { seq: 0, id: contentId(entry) };
    const damaged: object[] = [
      { head: "the first" },
      { head: { seq: -1, id: head.id } },
      { head: { seq: 0.5, id: head.id } },
      { head: { seq: 0, id: 7 } },
      { head: [0, head.id] },
      { head, pending: 5 },
      { head, pending: { entry: { type: "Entry" }, record: profile } },
      { head, pending: { entry, record: "a record" } },
    ];
    for (const stored of damaged) {
      const memory = memoryStorage();
      await memory.put(
        "client-feed",
        new TextEncoder().encode(JSON.stringify({ ...stored, mind: mind.address })),
        undefined,
      );
      const again = await Mind.open({ ...options, memory });
      const before = world.asked.length;
      expect(await refusal(() => again.publishRecord(profile)), JSON.stringify(stored)).toBe(
        "keystore: damaged",
      );
      expect(world.asked.slice(before).filter((asked) => !asked.startsWith("GET "))).toStrictEqual(
        [],
      );
      again.close();
    }
    // The number of the last location record, likewise.
    const memory = memoryStorage();
    await memory.put(
      "client-location",
      new TextEncoder().encode(JSON.stringify({ seq: "one", mind: mind.address })),
      undefined,
    );
    const again = await Mind.open({ ...options, memory });
    expect(await refusal(() => again.publishLocation())).toBe("keystore: damaged");
  });

  it("a memory that says the feed is empty is gone by, and the homes are not asked", async () => {
    const { mind, options } = await atHome();
    const profile = await mind.publishProfile({ name: "Ada" });
    mind.close();
    const memory = memoryStorage();
    await memory.put(
      "client-feed",
      new TextEncoder().encode(JSON.stringify({ mind: mind.address })),
      undefined,
    );
    const again = await Mind.open({ ...options, memory });
    const before = world.asked.length;
    expect((await again.publishRecord(profile)).seq).toBe(0);
    expect(world.asked.slice(before).filter((asked) => asked.includes("/feed?"))).toStrictEqual([]);
  });

  it("a failure that is nobody's answer reaches the caller as it is", async () => {
    const { mind, options } = await atHome();
    mind.close();
    // What stands in for `fetch` is broken for what is brought: its answer has headers that cannot be read.
    const broken: typeof world.fetch = (request) =>
      request.method === "GET"
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
    const again = await Mind.open({ ...options, fetch: broken });
    await expect(again.publishLocation()).rejects.toThrow(RangeError);
  });
});

describe("a mind whose keystore holds none of its operational keys", () => {
  it(`${clause("L1 17.3", "L1 13.3")} publishes its log unsigned, which a service that asks for no signature takes, and signs again with a key it adds`, async () => {
    const made = await freshKeystore(world, [A, B]);
    // The genesis is signed, and no resolver can be reached with it.
    world.down(A);
    world.down(B);
    expect(await refusal(() => Mind.create(made.options, { kind: "agent", homes: [ONE] }))).toBe(
      "transport: unreachable",
    );
    world.up(A);
    world.up(B);
    // The one operational key the genesis lists is lost before the genesis is published.
    const operational = await made.keystore.unlock("operational", made.lock);
    for (const key of operational.keys()) await operational.remove(key.publicKey);
    operational.lock();
    const mind = await Mind.create(made.options, { kind: "agent", homes: [ONE] });
    // The resolvers ask for no signature. The home does.
    expect(mind.publications).toStrictEqual([
      taken("resolver", A),
      taken("resolver", B),
      { service: "home", origin: ONE, taken: false, failure: "unauthorised" },
    ]);
    expect(() => mind.signingKey()).toThrow(/holds none of the mind's current operational keys/u);
    expect(await refusal(() => mind.publishLocation())).toBe("oip: forbidden");
    // Its identity is still its own to change: that takes the control keys.
    const state = await mind.update({}, { control: made.lock });
    expect(state.seq).toBe(1);
    expect(mind.publications.at(-1)?.failure).toBe("unauthorised");
    const added = await mind.addKey({ control: made.lock });
    expect(mind.signingKey()).toBe(added);
    expect(mind.publications).toStrictEqual([
      taken("resolver", A),
      taken("resolver", B),
      taken("home", ONE),
    ]);
    expect((await mind.publishLocation()).seq).toBe(0);
  });

  it(`${clause("L1 3.10")} a retirement that cannot be signed leaves the mind as it was, and no key behind`, async () => {
    const { mind, lock, keystore } = await atHome();
    expect(await refusal(() => mind.retire({ control: lock, successor: "nobody" }))).toBe(
      "oip: invalid-record",
    );
    expect(mind.state.retired).toBe(false);
    const control = await keystore.unlock("control", lock);
    expect(control.pending()).toStrictEqual([]);
    expect(control.keys()).toHaveLength(1);
    control.lock();
    expect((await mind.retire({ control: lock })).retired).toBe(true);
  });
});
