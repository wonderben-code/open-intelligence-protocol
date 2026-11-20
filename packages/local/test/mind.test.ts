// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** A mind in a directory, against a real resolver, host and indexer on ports of this machine. */

import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { LOCAL, type Network, startNetwork } from "@oip/cli";
import { Mind } from "@oip/client";
import { contentId } from "@oip/core";
import { type Keychain, Keystore, SCRYPT_MIN_N } from "@oip/keystore";
import { fileStorage } from "@oip/keystore/node";
import { clause } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  backupLockOf,
  type Config,
  Home,
  Kept,
  keptFrom,
  keptOf,
  lockOf,
  lookupOptions,
  type Machine,
  NETWORK_FILE,
  openMind,
  optionsOf,
  recordOf,
  refOf,
  servicesOf,
  statusOf,
  UsageError,
  type Where,
  withMind,
} from "../src/index.ts";

const PASSPHRASE = "correct horse battery staple";

let root: string;
let network: Network;
let config: Config;
const kept = new Map<string, string>();
const keychain: Keychain = {
  get: (service, account) => Promise.resolve(kept.get(`${service}\n${account}`)),
  set: (service, account, secret) => {
    kept.set(`${service}\n${account}`, secret);
    return Promise.resolve();
  },
  delete: (service, account) => {
    kept.delete(`${service}\n${account}`);
    return Promise.resolve();
  },
};
const machine = (more: Partial<Machine> = {}): Machine => ({
  env: { OIP_PASSPHRASE: PASSPHRASE },
  home: root,
  keychain: () => Promise.resolve(keychain),
  scryptN: SCRYPT_MIN_N,
  ...more,
});
const where = (name: string, more: Partial<Machine> = {}): Where => ({
  edges: machine(more),
  dir: join(root, name),
});

/** Makes a mind in a directory, as a program that sets one up does, and closes it. */
async function make(name: string): Promise<{ at: Where; address: string }> {
  const at = where(name);
  const home = new Home(at.dir);
  const lock = await lockOf(at, config.lock, true);
  const keystore = await Keystore.create({ storage: fileStorage(home.keys), locks: lock });
  home.write(config);
  const mind = await Mind.create(optionsOf(at, home, config, keystore, lock), {
    kind: "agent",
    homes: [LOCAL.host],
  });
  await mind.publishLocation();
  mind.close();
  return { at, address: mind.address };
}

beforeAll(async () => {
  root = mkdtempSync(join(tmpdir(), "oip-local-mind-"));
  const directory = join(root, "network");
  network = await startNetwork({ directory });
  // What `oip demo` writes, for the minds made with it to read.
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
});
afterAll(async () => {
  await network.stop();
  rmSync(root, { recursive: true, force: true });
});

describe("the mind of a directory", () => {
  it("is opened from what the directory holds, with its keys unlocked", async () => {
    const { at, address } = await make("ada");
    const opened = await openMind(at);
    try {
      expect(opened.mind.address).toBe(address);
      expect(opened.config).toStrictEqual(config);
      expect(opened.keystore.mind).toBe(address);
      expect(opened.mind.records()).toStrictEqual([]);
      expect(opened.mind.signingKey()).toMatch(/^z6Mk/u);
    } finally {
      opened.mind.close();
    }
    await expect(openMind(where("nobody"))).rejects.toThrow("there is no mind in");
  });

  it(`${clause("core 9.4")} keeps what it holds, with when each proof first came, from one run to the next`, async () => {
    const { at } = await make("bea");
    const intent = await withMind(at, ({ mind }) => mind.intent({ want: "A hall." }));
    const id = contentId(intent);
    const home = new Home(at.dir);
    expect(readdirSync(home.records)).toStrictEqual([`${id}.json`]);
    const file = JSON.parse(readFileSync(join(home.records, `${id}.json`), "utf8")) as {
      record: object;
      seen: Record<string, string>;
    };
    expect(file.record).toStrictEqual(intent);
    const [first = ""] = Object.values(file.seen);
    expect(first).toMatch(/^[0-9]{19}$/u);
    // A file there that is no record is not held, and nothing else is wrong with the run.
    writeFileSync(
      join(home.records, `bciq${"a".repeat(52)}.json`),
      '{"record":{"no":"record"},"seen":{}}',
    );
    await new Promise((resolve) => setTimeout(resolve, 5));
    const again = await withMind(at, ({ mind }) =>
      Promise.resolve({
        held: mind.records().map((record) => contentId(record)),
        seen: mind.sightings(id),
      }),
    );
    expect(again.held).toStrictEqual([id]);
    // First seen when the first run saw it, and not when the second held it again.
    expect(Object.values(again.seen).map(String)).toStrictEqual([first]);
    // What a run signed before it failed is kept all the same.
    let signed = "";
    await expect(
      withMind(at, async ({ mind }) => {
        signed = contentId(await mind.intent({ want: "Chairs." }));
        throw new Error("the run failed after it signed");
      }),
    ).rejects.toThrow("the run failed after it signed");
    expect(readdirSync(home.records)).toContain(`${signed}.json`);
  });

  it("names a record by the ID of one it holds or by a file, and says how one stands", async () => {
    const { at, address } = await make("cy");
    const opened = await openMind(at);
    try {
      const { mind } = opened;
      const intent = await mind.intent({ want: "A hall." });
      const id = contentId(intent);
      expect(recordOf(opened, id, "the record")).toStrictEqual(intent);
      const file = join(root, "intent.json");
      writeFileSync(file, JSON.stringify(intent));
      expect(recordOf(opened, file, "the record")).toStrictEqual(intent);
      const absent = `bciq${"b".repeat(52)}`;
      expect(() => recordOf(opened, absent, "the record")).toThrow(
        `the mind holds no record ${absent}`,
      );
      expect(() => recordOf(opened, join(root, "none.json"), "the record")).toThrow(UsageError);
      expect(refOf(intent as never)).toBe(`${address}/${id}`);
      expect(() => refOf({ type: "Intent" })).toThrow("it names no author");
      expect(await statusOf(mind, intent)).toBe("open");
      // A record of a type that has no status has none: that is no failure.
      const mandate = await mind.delegate({
        delegate: `did:oip:bciq${"a".repeat(52)}`,
        command: "/oip/sign/Offer",
        expires: "2031-01-31T12:00:00Z",
      });
      expect(await statusOf(mind, mandate)).toBeUndefined();
      await expect(statusOf(mind, { no: "record" })).resolves.toBeUndefined();
    } finally {
      opened.mind.close();
    }
  });

  it(`${clause("L1 12.4")} keeps a packet it received as that packet, and reads it back as nothing else`, async () => {
    const sender = await make("dan");
    const receiver = await make("eve");
    await withMind(sender.at, ({ mind }) =>
      mind.send({
        to: [receiver.address],
        verb: "inform",
        content: { mediaType: "text/plain", body: "Hello." },
      }),
    );
    const [received] = await withMind(
      receiver.at,
      async ({ mind }) => (await mind.receive()).received,
    );
    expect(received).toBeDefined();
    if (received === undefined) return;
    const packet = keptOf(received);
    expect(packet).toMatchObject({ id: received.id, from: sender.address, sealed: true });
    expect(packet.time).toMatch(/^[0-9]{4}-[0-9]{2}-[0-9]{2}T/u);
    const inbox = new Kept(new Home(receiver.at.dir).inbox);
    inbox.put(packet.id, packet);
    expect(keptFrom(inbox.get(packet.id) ?? {})).toStrictEqual(packet);
    // Under another name, or changed, it is not the packet the name says.
    expect(keptFrom({ ...packet, id: `bciq${"c".repeat(52)}` } as never)).toBeUndefined();
    expect(keptFrom({ ...packet, sealed: "yes" } as never)).toBeUndefined();
  });
});

describe("what opens a mind's keys", () => {
  it("is a passphrase from the environment, or typed where one can be: twice when it is new", async () => {
    const asked: string[] = [];
    const typing = (answers: string[]): Partial<Machine> => ({
      env: {},
      secret: (question) => {
        asked.push(question);
        return Promise.resolve(answers.shift() ?? "");
      },
    });
    await lockOf(where("x"), "passphrase");
    await lockOf(where("x", typing([PASSPHRASE])), "passphrase");
    await lockOf(where("x", typing([PASSPHRASE, PASSPHRASE])), "passphrase", true);
    expect(asked).toStrictEqual([
      "Passphrase: ",
      "A passphrase for the keys: ",
      "The same again: ",
    ]);
    await expect(
      lockOf(where("x", typing([PASSPHRASE, "another"])), "passphrase", true),
    ).rejects.toThrow("the two passphrases are not the same");
    await expect(lockOf(where("x", typing([""])), "passphrase")).rejects.toThrow(
      "no passphrase was typed",
    );
    await expect(lockOf(where("x", { env: {} }), "passphrase")).rejects.toThrow(
      "set OIP_PASSPHRASE, or run this where one can be typed",
    );
    // An empty variable is no passphrase.
    await expect(lockOf(where("x", { env: { OIP_PASSPHRASE: "" } }), "passphrase")).rejects.toThrow(
      UsageError,
    );
  });

  it("is a key in the machine's keychain, which asks for nothing", async () => {
    const lock = await lockOf(where("x", { env: {} }), "keychain");
    expect(typeof lock.fresh).toBe("function");
  });

  it("is a passphrase of its own for a backup", async () => {
    await expect(backupLockOf(where("x"), true)).rejects.toThrow("set OIP_BACKUP_PASSPHRASE");
    await backupLockOf(where("x", { env: { OIP_BACKUP_PASSPHRASE: "kept apart" } }), true);
    const asked: string[] = [];
    await backupLockOf(
      where("x", {
        env: {},
        secret: (question) => {
          asked.push(question);
          return Promise.resolve("kept apart");
        },
      }),
      false,
    );
    expect(asked).toStrictEqual(["The backup's passphrase: "]);
  });
});

describe("the services a program asks", () => {
  it("are those of the directory's mind, or of the network on this machine where that is asked for", async () => {
    const { at } = await make("fay");
    expect(servicesOf(at, undefined)).toStrictEqual(config);
    expect(servicesOf(where("nobody"), config.network)).toStrictEqual({
      resolvers: [LOCAL.resolver],
      indexers: [LOCAL.indexer],
      lock: "passphrase",
      network: config.network,
    });
    expect(() => servicesOf(where("nobody"), undefined)).toThrow("there is no mind in");
    expect(() => servicesOf(where("nobody"), join(root, "no-network"))).toThrow(
      "no network is running from",
    );
  });

  it("are asked through the routes of that network, by the clock the program was given", () => {
    const clock = { now: () => 5n };
    const options = lookupOptions(where("x", { clock }), config);
    expect(options).toMatchObject({
      resolvers: config.resolvers,
      indexers: config.indexers,
      clock,
    });
    expect(lookupOptions(where("x"), config)).not.toHaveProperty("clock");
    // A mind whose services are real ones has no route: its requests go where they say.
    const { network: _network, ...real } = config;
    expect(typeof lookupOptions(where("x"), real).fetch).toBe("function");
  });
});
