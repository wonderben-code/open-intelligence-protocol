// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A mind a gateway makes and holds, and the packets that wait for a mind,
 * against a real resolver, host and indexer on ports of this machine.
 */

import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { LOCAL, type Network, startNetwork } from "@oip/cli";
import { Lookup, Mind } from "@oip/client";
import { contentId } from "@oip/core";
import { type Keychain, Keystore, SCRYPT_MIN_N } from "@oip/keystore";
import { fileStorage } from "@oip/keystore/node";
import { clause } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  Arrivals,
  type Config,
  fileNameOf,
  Home,
  lockOf,
  lookupOptions,
  type Machine,
  NETWORK_FILE,
  openMind,
  optionsOf,
  Store,
  UsageError,
  type Where,
  withBridged,
  withMind,
} from "../src/index.ts";

const PASSPHRASE = "correct horse battery staple";
const SYSTEM = { protocol: "mcp", endpoint: "https://tools.example/mcp" };

let root: string;
let network: Network;
let config: Config;
const keychain: Keychain = {
  get: () => Promise.resolve(undefined),
  set: () => Promise.resolve(),
  delete: () => Promise.resolve(),
};
const machine: Machine = {
  env: { OIP_PASSPHRASE: PASSPHRASE },
  get home() {
    return root;
  },
  keychain: () => Promise.resolve(keychain),
  scryptN: SCRYPT_MIN_N,
};
const where = (name: string): Where => ({ edges: machine, dir: join(root, name) });
const reader = (): Lookup => new Lookup(lookupOptions(where("nobody"), config));

/** Makes a mind in a directory, as `oip init` does, and closes it. */
async function make(name: string, homes: readonly string[] = [LOCAL.host]): Promise<string> {
  const at = where(name);
  const home = new Home(at.dir);
  const lock = await lockOf(at, config.lock, true);
  const keystore = await Keystore.create({ storage: fileStorage(home.keys), locks: lock });
  home.write(config);
  const mind = await Mind.create(optionsOf(at, home, config, keystore, lock), {
    kind: "service",
    ...(homes.length === 0 ? {} : { homes }),
  });
  if (homes.length > 0) await mind.publishLocation();
  mind.close();
  return mind.address;
}

let gateway: string;
const bridgedDir = (): string => join(root, "gateway", "systems", fileNameOf(SYSTEM.endpoint));

beforeAll(async () => {
  root = mkdtempSync(join(tmpdir(), "oip-local-bridged-"));
  const directory = join(root, "network");
  network = await startNetwork({ directory });
  writeFileSync(
    join(directory, NETWORK_FILE),
    JSON.stringify({ ...LOCAL, routes: network.routes }),
  );
  config = {
    resolvers: [LOCAL.resolver],
    indexers: [LOCAL.indexer],
    lock: "passphrase",
    network: directory,
  };
  gateway = await make("gateway");
});
afterAll(async () => {
  await network.stop();
  rmSync(root, { recursive: true, force: true });
});

describe("a mind a gateway makes for a system outside the network", () => {
  it(`${clause("L0 1.2")} names its gateway in its genesis, and is named by an entry of the gateway's feed`, async () => {
    const made = await withBridged(where("gateway"), bridgedDir(), SYSTEM, async (held) => {
      await held.mind.publishProfile({ name: "Tools", ext: { "oip.bridge": { ...held.block } } });
      return { address: held.mind.address, block: held.block };
    });
    const resolved = await reader().resolve(made.address);
    const genesis = resolved.log.entries[0].event as { ext?: Record<string, unknown> };
    expect(genesis.ext?.["oip.bridge"]).toStrictEqual({
      ...SYSTEM,
      gateway,
      assurance: "bridged",
    });
    expect(resolved.state.kind).toBe("service");
    // The gateway holds the mind's keys: the mind is nobody's by membership.
    expect(resolved.state.controller.kind).toBe("key");
    const { feed } = await reader().feed(gateway);
    const attested = feed.entries.filter(({ entry }) => entry.object === contentId(genesis));
    expect(attested).toHaveLength(1);
    expect(made.block).toStrictEqual({
      ...SYSTEM,
      gateway,
      assurance: "bridged",
      attestation: `${gateway}/${attested[0]?.id ?? ""}`,
    });
    // Its keys are sealed in a directory of its own, as the gateway's are.
    expect(existsSync(new Home(bridgedDir()).keys)).toBe(true);
  });

  it(`${clause("L0 1.3")} is \`bridged\` to a client that asks, once its profile carries the block`, async () => {
    const address = await withBridged(where("gateway"), bridgedDir(), SYSTEM, ({ mind }) =>
      Promise.resolve(mind.address),
    );
    expect(await reader().assurance(address)).toStrictEqual({
      level: "bridged",
      gateway,
      ...SYSTEM,
    });
  });

  it("is made once: a later run goes on with the same mind, and attests nothing again", async () => {
    const before = (await reader().feed(gateway)).feed.entries.length;
    const first = await withBridged(where("gateway"), bridgedDir(), SYSTEM, (held) =>
      Promise.resolve({ address: held.mind.address, attestation: held.block.attestation }),
    );
    // With the attestation written down by an earlier run, the feed is not asked for it.
    const second = await withBridged(
      where("gateway"),
      bridgedDir(),
      { ...SYSTEM, attestation: first.attestation },
      (held) =>
        Promise.resolve({ address: held.mind.address, attestation: held.block.attestation }),
    );
    expect(second).toStrictEqual(first);
    expect((await reader().feed(gateway)).feed.entries).toHaveLength(before);
  });

  it("is gone on with after a run that stopped, with the same keys", async () => {
    const dir = join(root, "gateway", "systems", fileNameOf("https://other.example/mcp"));
    const system = { protocol: "mcp", endpoint: "https://other.example/mcp" };
    let address = "";
    await expect(
      withBridged(where("gateway"), dir, system, (held) => {
        address = held.mind.address;
        return Promise.reject(new Error("the run stopped"));
      }),
    ).rejects.toThrow("the run stopped");
    const again = await withBridged(where("gateway"), dir, system, (held) =>
      Promise.resolve(held.mind.address),
    );
    expect(again).toBe(address);
    // The mind is open to the next program, too: nothing of the stopped run holds it.
    await withMind({ edges: machine, dir }, ({ mind }) => {
      expect(mind.address).toBe(address);
      return Promise.resolve();
    });
  });

  it("is not made by a gateway that has no home: it has no feed to attest in", async () => {
    await make("homeless", []);
    const dir = join(root, "homeless", "systems", "one");
    await expect(
      withBridged(where("homeless"), dir, SYSTEM, () => Promise.resolve()),
    ).rejects.toThrow(UsageError);
    expect(existsSync(dir)).toBe(false);
  });
});

describe("the packets that wait for a mind", () => {
  it(`${clause("L1 12.4")} are written down as they are read, and wait until they are done with`, async () => {
    const receiver = await make("receiver");
    await make("sender");
    const send = (body: string): Promise<unknown> =>
      withMind(where("sender"), ({ mind }) =>
        mind.send({ to: [receiver], verb: "request", content: { mediaType: "text/plain", body } }),
      );
    await send("One.");
    await send("Two.");
    const dir = join(root, "receiver", "work");
    const bodies = (kept: readonly { packet: { content: unknown } }[]): unknown[] =>
      kept.map(({ packet }) => (packet.content as { body: unknown }).body);

    let opened = await openMind(where("receiver"));
    const first = await new Arrivals(opened, dir).waiting();
    opened.mind.close();
    // Oldest first.
    expect(bodies(first)).toStrictEqual(["One.", "Two."]);
    expect(first.every(({ from, sealed }) => from !== receiver && sealed)).toBe(true);

    // The mailbox gave them once. A program that stopped here finds them again.
    opened = await openMind(where("receiver"));
    const arrivals = new Arrivals(opened, dir);
    const again = await arrivals.waiting();
    expect(again).toStrictEqual(first);
    arrivals.done(first[0]?.id ?? "");
    expect(bodies(await arrivals.waiting())).toStrictEqual(["Two."]);

    // What is written there and is no packet is nothing to wait for, now or later.
    const pending = new Store<unknown>(join(dir, "pending"));
    pending.put("no-packet", { id: "no-packet" });
    expect(readdirSync(join(dir, "pending"))).toHaveLength(2);
    expect(bodies(await arrivals.waiting())).toStrictEqual(["Two."]);
    expect(readdirSync(join(dir, "pending"))).toHaveLength(1);
    arrivals.done(first[1]?.id ?? "");
    expect(await arrivals.waiting()).toStrictEqual([]);
    opened.mind.close();
  });
});

describe("a name for a file", () => {
  it("is forty hexadecimal digits, whatever the text", () => {
    expect(fileNameOf("https://agent.example")).toMatch(/^[0-9a-f]{40}$/u);
    expect(fileNameOf("../../etc/passwd")).toMatch(/^[0-9a-f]{40}$/u);
    expect(fileNameOf("a")).not.toBe(fileNameOf("b"));
    expect(fileNameOf("a")).toBe(fileNameOf("a"));
  });
});
