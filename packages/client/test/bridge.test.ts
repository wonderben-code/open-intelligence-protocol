// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A gateway and the minds it bridges (Layer 0, Section 1), through the
 * client: what a gateway does to make a bridged mind, and what any client
 * finds when it asks how far such a mind is what it says.
 */

import { contentId, formatRecordRef, type JsonObject } from "@oip/core";
import { clause } from "@oip/testkit";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { Lookup, Mind } from "../src/index.ts";
import { freshKeystore } from "./helpers.ts";
import { World } from "./world.ts";

const A = "https://resolver-a.example";
const ONE = "https://host-one.example";

let world: World;
beforeEach(() => {
  world = new World(100);
  world.resolver(A);
  world.host(ONE);
});
afterEach(() => {
  world.close();
});

const reader = () => new Lookup({ resolvers: [A], fetch: world.fetch, clock: world.clock });

/** A mind with a home, made and located. */
async function made(kind: string, ext?: Readonly<Record<string, JsonObject>>): Promise<Mind> {
  const { options } = await freshKeystore(world, [A]);
  const mind = await Mind.create(options, {
    kind,
    homes: [ONE],
    ...(ext === undefined ? {} : { ext }),
  });
  await mind.publishLocation();
  return mind;
}

/** What a gateway writes of itself into a mind it bridges. */
const blockOf = (gateway: Mind): JsonObject => ({
  protocol: "a2a",
  endpoint: "https://agent.example/a2a",
  gateway: gateway.address,
  assurance: "bridged",
});

/** A gateway, and a mind it made for an agent that is not on the network, attested and described. */
async function bridged() {
  const gateway = await made("service");
  const block = blockOf(gateway);
  const mind = await made("service", { "oip.bridge": block });
  const genesis = mind.resolved.log.entries[0].event;
  // The gateway's own word: an entry of its feed that names the genesis.
  const entry = await gateway.publishRecord(genesis);
  const attestation = formatRecordRef(gateway.address, contentId(entry));
  const profile = await mind.publishProfile({
    name: "An agent of another protocol",
    ext: { "oip.bridge": { ...block, attestation } },
  });
  return { gateway, mind, genesis, entry, profile, block };
}

describe("a gateway and the minds it bridges", () => {
  it(`${clause("L0 1.2")} names itself in the mind's genesis, attests the genesis in its own feed, and is named with that entry in the mind's profile`, async () => {
    const { gateway, mind, genesis, entry, profile, block } = await bridged();
    expect(genesis.ext).toStrictEqual({ "oip.bridge": block });
    expect(mind.state.kind).toBe("service");
    expect(entry).toMatchObject({
      type: "Entry",
      author: gateway.address,
      object: contentId(genesis),
      objectType: "Genesis",
    });
    expect(profile.ext).toStrictEqual({
      "oip.bridge": { ...block, attestation: `${gateway.address}/${contentId(entry)}` },
    });
    mind.close();
    gateway.close();
  });

  it(`${clause("L0 1.3")} is found \`bridged\` by a client that resolves the mind and reads the gateway's feed`, async () => {
    const { gateway, mind } = await bridged();
    expect(await reader().assurance(mind.address)).toStrictEqual({
      level: "bridged",
      gateway: gateway.address,
      protocol: "a2a",
      endpoint: "https://agent.example/a2a",
    });
    // The gateway itself was made by nobody but itself.
    expect(await reader().assurance(gateway.address)).toStrictEqual({ level: "native" });
    mind.close();
    gateway.close();
  });

  it(`${clause("L0 1.3")} is \`claimed\` where the mind attests itself, or names an entry that is not in the gateway's feed`, async () => {
    const gateway = await made("service");
    const block = blockOf(gateway);
    const mind = await made("service", { "oip.bridge": block });
    const genesis = mind.resolved.log.entries[0].event;
    // Its own entry, in its own feed.
    const own = await mind.publishRecord(genesis);
    await mind.publishProfile({
      name: "Self-attested",
      ext: {
        "oip.bridge": { ...block, attestation: formatRecordRef(mind.address, contentId(own)) },
      },
    });
    expect(await reader().assurance(mind.address)).toMatchObject({
      level: "claimed",
      gateway: gateway.address,
    });
    // The gateway's name on an entry the gateway never wrote.
    await mind.publishProfile({
      name: "Self-attested",
      ext: {
        "oip.bridge": { ...block, attestation: formatRecordRef(gateway.address, contentId(own)) },
      },
    });
    expect((await reader().assurance(mind.address)).level).toBe("claimed");
    mind.close();
    gateway.close();
  });

  it(`${clause("L0 1.3")} is \`claimed\` where the genesis names a gateway and the mind has no profile, or one that leaves the gateway out`, async () => {
    const gateway = await made("service");
    const mind = await made("service", { "oip.bridge": blockOf(gateway) });
    expect(await reader().assurance(mind.address)).toStrictEqual({
      level: "claimed",
      gateway: gateway.address,
      protocol: "a2a",
      endpoint: "https://agent.example/a2a",
    });
    await mind.publishProfile({ name: "Says nothing of a gateway" });
    expect((await reader().assurance(mind.address)).level).toBe("claimed");
    mind.close();
    gateway.close();
  });

  it("is `claimed` where the gateway's feed cannot be read: nothing was shown", async () => {
    const { mind } = await bridged();
    const lookup = reader();
    world.down(ONE);
    await expect(lookup.assurance(mind.address)).resolves.toMatchObject({ level: "claimed" });
    mind.close();
  });

  it("says what the block names only where it names it rightly", async () => {
    const mind = await made("service", {
      "oip.bridge": { gateway: "the best gateway", protocol: 7, endpoint: ["x"] },
    });
    expect(await reader().assurance(mind.address)).toStrictEqual({ level: "claimed" });
    mind.close();
  });
});
