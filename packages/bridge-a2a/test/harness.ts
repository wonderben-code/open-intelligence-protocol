// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What the tests of the gateway share: a network on this machine, minds in
 * directories of their own, and A2A agents that are functions.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { LOCAL, type Network, startNetwork } from "@oip/cli";
import { Lookup, Mind, type ProfileFields } from "@oip/client";
import { type Keychain, Keystore, SCRYPT_MIN_N } from "@oip/keystore";
import { fileStorage } from "@oip/keystore/node";
import {
  type Config,
  Home,
  lockOf,
  lookupOptions,
  type Machine,
  NETWORK_FILE,
  type Opened,
  openMind,
  optionsOf,
  type Where,
} from "@oip/local";

/** The passphrase the tests' minds are sealed with. */
export const PASSPHRASE = "correct horse battery staple 9c1e";

/** A place for one test file: a network that runs while its tests do, and the minds made on it. */
export class Place {
  readonly root = mkdtempSync(join(tmpdir(), "oip-bridge-"));
  #network: Network | undefined;
  #config: Config | undefined;

  readonly keychain: Keychain = {
    get: () => Promise.resolve(undefined),
    set: () => Promise.resolve(),
    delete: () => Promise.resolve(),
  };

  /** Starts the network: a resolver, a host and an indexer on ports of this machine. */
  async start(): Promise<this> {
    const directory = join(this.root, "network");
    this.#network = await startNetwork({ directory });
    writeFileSync(
      join(directory, NETWORK_FILE),
      JSON.stringify({ ...LOCAL, routes: this.#network.routes }),
    );
    this.#config = {
      resolvers: [LOCAL.resolver],
      indexers: [LOCAL.indexer],
      lock: "passphrase",
      network: directory,
    };
    return this;
  }

  get config(): Config {
    if (this.#config === undefined) throw new Error("the place was not started");
    return this.#config;
  }

  machine(more: Partial<Machine> = {}): Machine {
    return {
      env: { OIP_PASSPHRASE: PASSPHRASE },
      home: this.root,
      keychain: () => Promise.resolve(this.keychain),
      scryptN: SCRYPT_MIN_N,
      ...more,
    };
  }

  /** Where a program works for the mind of a name. */
  where(name: string, more: Partial<Machine> = {}): Where {
    return { edges: this.machine(more), dir: join(this.root, name) };
  }

  /**
   * Makes a mind in a directory, as `oip init` does, and closes it.
   *
   * @param homes - Its homes. None, for a mind that has no feed.
   * @returns Its address.
   */
  async make(
    name: string,
    options: { kind?: string; homes?: readonly string[]; profile?: ProfileFields } = {},
  ): Promise<string> {
    const at = this.where(name);
    const home = new Home(at.dir);
    const lock = await lockOf(at, this.config.lock, true);
    const keystore = await Keystore.create({ storage: fileStorage(home.keys), locks: lock });
    home.write(this.config);
    const homes = options.homes ?? [LOCAL.host];
    const mind = await Mind.create(optionsOf(at, home, this.config, keystore, lock), {
      kind: options.kind ?? "agent",
      ...(homes.length === 0 ? {} : { homes }),
    });
    if (homes.length > 0) await mind.publishLocation();
    if (options.profile !== undefined) await mind.publishProfile(options.profile);
    mind.close();
    return mind.address;
  }

  /** The mind of a name, opened. The test closes it. */
  mind(name: string): Promise<Opened> {
    return openMind(this.where(name));
  }

  /** A client that reads, and holds no key: as anyone on the network is. */
  reader(): Lookup {
    return new Lookup(lookupOptions(this.where("nobody"), this.config));
  }

  async close(): Promise<void> {
    await this.#network?.stop();
    rmSync(this.root, { recursive: true, force: true });
  }
}

/** A card, as an agent serves one. */
export const cardOf = (
  origin: string,
  more: Record<string, unknown> = {},
): Record<string, unknown> => ({
  name: "Lexis translation agent",
  description: "Translates legal texts between Swahili and English.",
  supportedInterfaces: [
    { url: `${origin}/a2a/v1`, protocolBinding: "JSONRPC", protocolVersion: "1.0" },
  ],
  version: "1.0.0",
  capabilities: { streaming: false, pushNotifications: false },
  defaultInputModes: ["text/plain"],
  defaultOutputModes: ["text/plain"],
  skills: [
    {
      id: "translate",
      name: "Translate",
      description: "Translates a lease.",
      tags: ["translation", "legal"],
    },
  ],
  ...more,
});

/** The bytes of a card as served. */
export const served = (card: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(card));
