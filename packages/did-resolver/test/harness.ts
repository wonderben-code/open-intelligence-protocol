// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** What the tests of the resolver share: a network on this machine, and minds on it. */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { LOCAL, type Network, startNetwork } from "@oip/cli";
import { type LookupOptions, Mind } from "@oip/client";
import { Keystore, SCRYPT_MIN_N } from "@oip/keystore";
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

/** A place for one test file: a network that runs while its tests do, and the minds made on it. */
export class Place {
  readonly root = mkdtempSync(join(tmpdir(), "oip-did-"));
  #network: Network | undefined;
  #config: Config | undefined;

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

  where(name: string, more: Partial<Machine> = {}): Where {
    const edges: Machine = {
      // For minds that live as long as a test file does.
      env: { OIP_PASSPHRASE: "a passphrase of the resolver's tests 7d2a" },
      home: this.root,
      keychain: () => Promise.reject(new Error("these minds are kept under a passphrase")),
      scryptN: SCRYPT_MIN_N,
      ...more,
    };
    return { edges, dir: join(this.root, name) };
  }

  /** Makes a mind in a directory, as `oip init` does, and closes it. Its address. */
  async make(name: string, kind = "agent"): Promise<string> {
    const at = this.where(name);
    const home = new Home(at.dir);
    const lock = await lockOf(at, this.config.lock, true);
    const keystore = await Keystore.create({ storage: fileStorage(home.keys), locks: lock });
    home.write(this.config);
    const mind = await Mind.create(optionsOf(at, home, this.config, keystore, lock), {
      kind,
      homes: [LOCAL.host],
    });
    await mind.publishLocation();
    mind.close();
    return mind.address;
  }

  /** The mind of a name, opened. The test closes it. */
  mind(name: string): Promise<Opened> {
    return openMind(this.where(name));
  }

  /** How anyone on this network asks its resolver: what a `Lookup`, and so the driver, takes. */
  options(more: Partial<Machine> = {}): LookupOptions {
    return lookupOptions(this.where("nobody", more), this.config);
  }

  async close(): Promise<void> {
    await this.#network?.stop();
    rmSync(this.root, { recursive: true, force: true });
  }
}
