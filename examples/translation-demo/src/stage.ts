// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Where the scenario is played: a network on this machine, and a
 * directory for each mind of the cast, as `oip init` makes one.
 *
 * The keys are made for one telling and thrown away with the directory.
 * They are sealed all the same, with a passphrase that is made here, kept
 * in this process, and never shown.
 */

import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { LOCAL, type Network, startNetwork } from "@oip/cli";
import { Lookup, Mind, type ProfileFields } from "@oip/client";
import { type Keychain, Keystore, type Lock, SCRYPT_MIN_N } from "@oip/keystore";
import { fileStorage } from "@oip/keystore/node";
import {
  type Config,
  Home,
  lockOf,
  lookupOptions,
  type Machine,
  NETWORK_FILE,
  optionsOf,
  type Where,
} from "@oip/local";

/** One of the cast: a mind, open, and what opens its invocation keys. */
export interface Player {
  /** Its name in the directory of the telling. */
  readonly name: string;
  /** Its name as its profile gives it. */
  readonly label: string;
  readonly mind: Mind;
  readonly lock: Lock;
}

/** A keychain that keeps nothing: the keys of the cast are opened by the passphrase. */
const NO_KEYCHAIN: Keychain = {
  get: () => Promise.resolve(undefined),
  set: () => Promise.resolve(),
  delete: () => Promise.resolve(),
};

/** The place of one telling. */
export class Stage {
  readonly root: string;
  readonly #network: Network;
  readonly #config: Config;
  readonly #machine: Machine;
  readonly #players: Player[] = [];

  private constructor(root: string, network: Network, config: Config) {
    this.root = root;
    this.#network = network;
    this.#config = config;
    this.#machine = {
      // For this telling alone. It is never written anywhere, and never said.
      env: { OIP_PASSPHRASE: randomBytes(24).toString("base64url") },
      home: root,
      keychain: () => Promise.resolve(NO_KEYCHAIN),
      // The keys last as long as the telling does: the least work that seals them will do.
      scryptN: SCRYPT_MIN_N,
    };
  }

  /** Starts a resolver, a host and an indexer on ports of this machine. */
  static async open(): Promise<Stage> {
    const root = mkdtempSync(join(tmpdir(), "oip-translation-demo-"));
    const directory = join(root, "network");
    const network = await startNetwork({ directory });
    writeFileSync(
      join(directory, NETWORK_FILE),
      JSON.stringify({ ...LOCAL, routes: network.routes }),
    );
    return new Stage(root, network, {
      resolvers: [LOCAL.resolver],
      indexers: [LOCAL.indexer],
      lock: "passphrase",
      network: directory,
    });
  }

  #where(name: string): Where {
    return { edges: this.#machine, dir: join(this.root, name) };
  }

  /**
   * Makes a mind: its keys, its genesis, where it is reached, and what it
   * says of itself.
   *
   * @param name - Its name in the telling, and its directory's.
   */
  async cast(name: string, kind: string, profile: ProfileFields): Promise<Player> {
    const at = this.#where(name);
    const home = new Home(at.dir);
    const lock = await lockOf(at, this.#config.lock, true);
    const keystore = await Keystore.create({ storage: fileStorage(home.keys), locks: lock });
    home.write(this.#config);
    const mind = await Mind.create(optionsOf(at, home, this.#config, keystore, lock), {
      kind,
      homes: [LOCAL.host],
    });
    await mind.publishLocation();
    await mind.publishProfile(profile);
    const player = { name, label: profile.name, mind, lock };
    this.#players.push(player);
    return player;
  }

  /** A client that holds no key and no record: anyone on the network. */
  stranger(): Lookup {
    return new Lookup(lookupOptions(this.#where("a-stranger"), this.#config));
  }

  /** Ends the telling: the minds are closed, the network stopped, and the directory removed. */
  async close(): Promise<void> {
    for (const { mind } of this.#players) mind.close();
    await this.#network.stop();
    rmSync(this.root, { recursive: true, force: true });
  }
}
