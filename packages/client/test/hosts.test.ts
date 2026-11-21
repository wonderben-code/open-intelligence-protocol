// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import {
  contentId,
  createProofSync,
  formatKeyRef,
  MEDIA_TYPE,
  mindId,
  type OipRecord,
  signerFromPrivateKey,
} from "@oip/core";
import { memoryStorage } from "@oip/keystore";
import type { Bundle } from "@oip/schema";
import { clause } from "@oip/testkit";
import { at, T } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { askRecord, homeEndpoints, Lookup, Mind } from "../src/index.ts";
import { freshKeystore, refusal } from "./helpers.ts";
import { World } from "./world.ts";

const A = "https://resolver-a.example";
const ONE = "https://host-one.example";
const TWO = "https://host-two.example";
const THREE = "https://host-three.example";

let world: World;
beforeEach(() => {
  world = new World(100);
  world.resolver(A);
  world.host(ONE);
  world.host(TWO);
  world.host(THREE);
});
afterEach(() => {
  world.close();
});

/** A mind at homes, with a profile and a location record. */
async function settled(homes: readonly string[] = [ONE]) {
  const made = await freshKeystore(world, [A]);
  const mind = await Mind.create(made.options, { kind: "agent", homes });
  const profile = await mind.publishProfile({ name: "Ada" });
  return { ...made, mind, profile };
}

const reader = () => new Lookup({ resolvers: [A], fetch: world.fetch, clock: world.clock });

/** What a home serves for a mind at its well-known place. */
const served = (home: string, mind: string, rest = ""): Promise<OipRecord> =>
  askRecord(
    { method: "GET", url: `${home}/.well-known/oip/mind/${mindId(mind) ?? ""}${rest}` },
    { fetch: world.direct },
  );

const publishing = (asked: readonly string[]): string[] =>
  asked.filter((request) => !request.startsWith("GET "));

describe(`${clause("L1 15.4")} a mind that changes hosts`, () => {
  it(`${clause("L1 13.1", "L1 10.2")} brings the new host its log, its records and its whole feed, and then names it`, async () => {
    const { mind, lock, profile } = await settled();
    const other = await settled([]);
    const first = mind.resolved.location?.record as OipRecord;
    const entries = [
      await mind.publishRecord(profile),
      await mind.publishRecord(first),
      await mind.publishRecord(other.profile),
      await mind.publishRecord(profile),
    ];
    world.clock.at = at(200);
    const state = await mind.moveHomes([TWO], { control: lock });
    expect(state).toMatchObject({ seq: 1, homes: [TWO] });
    expect(mind.resolved.location?.record).toMatchObject({
      seq: 1,
      created: T(200),
      endpoints: homeEndpoints(mind.address, [TWO]),
      participant: contentId(profile),
      feed: { seq: 3, head: contentId(entries[3]) },
    });
    // The new home serves everything the old one did.
    const bundle = (await served(TWO, mind.address)) as unknown as Bundle;
    expect(bundle.log).toHaveLength(2);
    expect(bundle.location).toStrictEqual(mind.resolved.location?.record);
    expect(bundle.participant).toStrictEqual(profile);
    const { feed, sources } = await reader().feed(mind.address);
    expect(sources).toStrictEqual([{ home: TWO, entries: 4 }]);
    expect(feed.entries.map((entry) => entry.entry)).toStrictEqual(entries);
    for (const record of [profile, first, other.profile]) {
      expect(await served(TWO, mind.address, `/obj/${contentId(record)}`)).toStrictEqual(record);
    }
    // The feed goes on there, and packets come there.
    expect(await mind.publishRecord(profile)).toMatchObject({
      seq: 4,
      prev: contentId(entries[3]),
    });
    expect(mind.publications).toStrictEqual([{ service: "home", origin: TWO, taken: true }]);
    const sent = await other.mind.send({
      to: [mind.address],
      verb: "inform",
      content: { mediaType: "text/plain", body: "Found you." },
    });
    expect(sent.deliveries[0]?.endpoint).toContain(TWO);
    expect((await mind.receive()).received.map((received) => received.id)).toStrictEqual([sent.id]);
  });

  it(`${clause("L1 15.2")} removes a key the host it leaves held, and what that host signs counts no longer`, async () => {
    const { mind, lock } = await settled();
    // The first host was given a key, to sign acknowledgements for the mind.
    const hostKey = signerFromPrivateKey(new Uint8Array(32).fill(5));
    await mind.update(
      {
        keys: [
          ...mind.state.keys.map((key) => ({ key })),
          { key: hostKey.publicKey, label: "host" },
        ],
      },
      { control: lock },
    );
    const own = mind.resolved.location?.record;
    /** A location record the old host makes for the mind, with a number far ahead. */
    const byHost = (seconds: number): object => {
      const record = {
        oip: "1",
        type: "Location",
        author: mind.address,
        seq: 1_000_000,
        created: T(seconds),
        ttl: 86_400,
        status: "active",
        endpoints: [{ binding: "https", url: `${ONE}/oip/v1/kept` }],
      };
      const proof = createProofSync(
        record,
        {
          verificationMethod: formatKeyRef(mind.address, mind.state.versionId, hostKey.publicKey),
          created: T(seconds),
        },
        hostKey,
      );
      return { ...record, proof: [proof] };
    };
    const published = async (location: object): Promise<number> =>
      (
        await world.direct(
          new Request(`${A}/oip/v1/resolve/${mindId(mind.address) ?? ""}`, {
            method: "PUT",
            headers: { "content-type": MEDIA_TYPE },
            body: JSON.stringify({
              oip: "1",
              type: "Bundle",
              mind: mind.address,
              log: mind.resolved.log.entries.map((entry) => entry.event),
              location,
            }),
          }),
        )
      ).status;
    // While the host holds a key of the mind's, what it signs is the mind's (15.4).
    expect(await published(byHost(110))).toBe(202);
    expect((await reader().resolve(mind.address)).location?.record.seq).toBe(1_000_000);
    world.clock.at = at(200);
    const state = await mind.moveHomes([TWO], { control: lock, revoke: [hostKey.publicKey] });
    expect(state.keys).not.toContain(hostKey.publicKey);
    expect(mind.resolved.log.entries.at(-1)?.event).toMatchObject({
      type: "Update",
      homes: [TWO],
      revoked: [{ key: hostKey.publicKey }],
    });
    // The record the host made counts no longer, however high its number: the mind's own is current.
    const resolved = await reader().resolve(mind.address);
    expect(resolved.location?.record.endpoints).toStrictEqual(homeEndpoints(mind.address, [TWO]));
    expect(resolved.location?.record.seq).toBe((own?.seq ?? 0) + 1);
    // And nothing the host signs from now on is taken for the mind's.
    world.clock.at = at(300);
    expect(await published(byHost(300))).toBe(400);
    expect((await reader().resolve(mind.address)).location?.id).toBe(resolved.location?.id);
  });

  it("revokes with the move a key of its own, which the keystore then holds no longer", async () => {
    const { mind, lock, keystore, options } = await settled();
    const [first = ""] = mind.state.keys;
    const second = await mind.addKey({ control: lock });
    const state = await mind.moveHomes([ONE, TWO], { control: lock, revoke: [first] });
    expect(state.keys).toStrictEqual([second]);
    expect(state.homes).toStrictEqual([ONE, TWO]);
    expect(mind.signingKey()).toBe(second);
    mind.close();
    const operational = await keystore.unlock("operational", lock);
    expect(operational.keys().map((key) => key.publicKey)).toStrictEqual([second]);
    operational.lock();
    // A mind is not left with no key to sign with.
    const again = await Mind.open(options);
    expect(await refusal(() => again.moveHomes([TWO], { control: lock, revoke: [second] }))).toBe(
      "oip: forbidden",
    );
    expect(again.state.homes).toStrictEqual([ONE, TWO]);
  });

  it("is stopped, with nothing of it changed, by a host that will not take it on or cannot be brought its feed", async () => {
    world.host(TWO, { admits: () => false });
    const { mind, lock, profile } = await settled();
    await mind.publishRecord(profile);
    const before = world.asked.length;
    expect(await refusal(() => mind.moveHomes([TWO], { control: lock }))).toBe("oip: forbidden");
    expect(mind.state).toMatchObject({ seq: 0, homes: [ONE] });
    // The host was asked to take the mind on, and nothing else was published.
    expect(publishing(world.asked.slice(before))).toStrictEqual([
      `PUT ${TWO}/oip/v1/minds/${mindId(mind.address) ?? ""}`,
    ]);
    // A host that takes the mind on, and then no record of its feed, or no entry.
    for (const refused of ["/obj/", "/feed"]) {
      world.host(THREE);
      const real = world.at(THREE);
      world.put(THREE, (request) =>
        request.method !== "GET" && request.url.includes(refused)
          ? new Response(
              JSON.stringify({ type: "urn:oip:error:too-large", title: "No room", status: 413 }),
              { status: 413, headers: { "content-type": "application/problem+json" } },
            )
          : real(request),
      );
      expect(await refusal(() => mind.moveHomes([ONE, THREE], { control: lock })), refused).toBe(
        "oip: too-large",
      );
      expect(mind.state).toMatchObject({ seq: 0, homes: [ONE] });
    }
    // With a host that takes all of it, the move is made.
    world.host(THREE);
    expect((await mind.moveHomes([ONE, THREE], { control: lock })).homes).toStrictEqual([
      ONE,
      THREE,
    ]);
    expect((await reader().feed(mind.address)).sources).toStrictEqual([
      { home: ONE, entries: 1 },
      { home: THREE, entries: 1 },
    ]);
  });

  it(`${clause("L1 10.3")} does not carry a feed that has forked, or less of a feed than it remembers`, async () => {
    const { mind, lock, options, profile } = await settled();
    const first = await mind.publishRecord(profile);
    await mind.publishRecord(profile);
    // The home has lost the feed: it serves the mind, and none of its entries.
    world.host(ONE);
    await mind.bringHomes();
    expect(await refusal(() => mind.moveHomes([TWO], { control: lock }))).toBe("oip: not-found");
    expect(mind.state.homes).toStrictEqual([ONE]);
    // A home that serves two entries for one position.
    const fork = await mind.sign({
      oip: "1",
      type: "Entry",
      author: mind.address,
      seq: 0,
      created: T(100),
      object: contentId(mind.resolved.location?.record),
      objectType: "Location",
    });
    const real = world.at(ONE);
    world.put(ONE, (request) =>
      request.method === "GET" && request.url.includes("/feed")
        ? new Response(
            JSON.stringify({
              oip: "1",
              type: "FeedPage",
              mind: mind.address,
              entries: [first, fork],
            }),
            { status: 200, headers: { "content-type": MEDIA_TYPE } },
          )
        : real(request),
    );
    mind.close();
    const again = await Mind.open({ ...options, memory: memoryStorage() });
    expect(await refusal(() => again.moveHomes([TWO], { control: lock }))).toBe("oip: duplicity");
    expect(again.state.homes).toStrictEqual([ONE]);
  });

  it("has nothing to carry where it had no home, or no feed, and leaves a home by naming it no longer", async () => {
    const made = await freshKeystore(world, [A]);
    const mind = await Mind.create(made.options, { kind: "agent" });
    // Its first home.
    expect((await mind.moveHomes([ONE], { control: made.lock })).homes).toStrictEqual([ONE]);
    expect(((await served(ONE, mind.address)) as unknown as Bundle).log).toHaveLength(2);
    // A second, with no feed yet to carry: the first entry is taken by both.
    await mind.moveHomes([ONE, TWO], { control: made.lock });
    const profile = await mind.publishProfile({ name: "Ada" });
    expect(await mind.publishRecord(profile)).toMatchObject({ seq: 0 });
    expect(mind.publications).toStrictEqual([
      { service: "home", origin: ONE, taken: true },
      { service: "home", origin: TWO, taken: true },
    ]);
    // It leaves the first: nothing is brought anywhere, and its endpoints are at the one it keeps.
    const before = world.asked.length;
    const state = await mind.moveHomes([TWO], { control: made.lock });
    expect(state.homes).toStrictEqual([TWO]);
    expect(
      publishing(world.asked.slice(before)).filter((asked) => asked.includes("/obj/")),
    ).toStrictEqual([]);
    expect(mind.resolved.location?.record.endpoints).toStrictEqual(
      homeEndpoints(mind.address, [TWO]),
    );
  });

  it("has no feed to carry where the home it has serves it no longer, and is brought there again with the move", async () => {
    const made = await freshKeystore(world, [A]);
    const mind = await Mind.create(made.options, { kind: "agent", homes: [ONE] });
    // The home starts again with nothing.
    world.host(ONE);
    const state = await mind.moveHomes([ONE, TWO], { control: made.lock });
    expect(state.homes).toStrictEqual([ONE, TWO]);
    for (const home of [ONE, TWO]) {
      expect(((await served(home, mind.address)) as unknown as Bundle).log).toHaveLength(2);
    }
  });
});
