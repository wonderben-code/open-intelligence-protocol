// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What the tests of the server share: a network on this machine, minds in
 * directories of their own, and a tool called as a host calls it.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { LOCAL, type Network, startNetwork } from "@oip/cli";
import { Mind, type ProfileFields } from "@oip/client";
import type { JsonObject } from "@oip/core";
import { type Keychain, Keystore, SCRYPT_MIN_N } from "@oip/keystore";
import { fileStorage } from "@oip/keystore/node";
import {
  type Config,
  Home,
  lockOf,
  type Machine,
  NETWORK_FILE,
  type Opened,
  openMind,
  optionsOf,
  type Where,
} from "@oip/local";

import {
  type Confirming,
  type Given,
  type Policy,
  type Question,
  TOOLS,
  Work,
} from "../src/index.ts";

/** The passphrase the tests' minds are sealed with. No result may ever hold it. */
export const PASSPHRASE = "correct horse battery staple 7f3a";

/** A host that cannot put a question to anyone. */
export const SILENT: Confirming = { canAsk: false, answer: () => undefined };

/** A host that can ask, and has not been answered. */
export const ASKING: Confirming = { canAsk: true, answer: () => undefined };

/** A host through which the person answered the question with this digest. */
export const answering = (digest: string, answer: "yes" | "no"): Confirming => ({
  canAsk: true,
  answer: (asked) => (asked === digest ? answer : undefined),
});

/** A place for one test file: a network that runs while its tests do, and the minds made on it. */
export class Place {
  readonly root = mkdtempSync(join(tmpdir(), "oip-mcp-"));
  #network: Network | undefined;
  #config: Config | undefined;
  readonly #kept = new Map<string, string>();

  /** A keychain that is a map. */
  readonly keychain: Keychain = {
    get: (service, account) => Promise.resolve(this.#kept.get(`${service}\n${account}`)),
    set: (service, account, secret) => {
      this.#kept.set(`${service}\n${account}`, secret);
      return Promise.resolve();
    },
    delete: (service, account) => {
      this.#kept.delete(`${service}\n${account}`);
      return Promise.resolve();
    },
  };

  /** Starts the network: a resolver, a host and an indexer on ports of this machine. */
  async start(): Promise<this> {
    const directory = join(this.root, "network");
    this.#network = await startNetwork({ directory });
    // What `oip demo` writes, for the minds made with it to read.
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

  /** The directory of the network, for a process that is started apart. */
  get networkDirectory(): string {
    return join(this.root, "network");
  }

  /** The machine, as a program of this place sees it. */
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
   * Makes a mind in a directory, as `oip init` does, with a profile if one
   * is given, and closes it.
   *
   * @returns Its address.
   */
  async make(name: string, profile?: ProfileFields, kind = "agent"): Promise<string> {
    if (this.#config === undefined) throw new Error("the place was not started");
    const at = this.where(name);
    const home = new Home(at.dir);
    const lock = await lockOf(at, this.#config.lock, true);
    const keystore = await Keystore.create({ storage: fileStorage(home.keys), locks: lock });
    home.write(this.#config);
    const mind = await Mind.create(optionsOf(at, home, this.#config, keystore, lock), {
      kind,
      homes: [LOCAL.host],
    });
    await mind.publishLocation();
    if (profile !== undefined) await mind.publishProfile(profile);
    mind.close();
    return mind.address;
  }

  /** The mind of a name, opened: for what a test does that no tool does. The test closes it. */
  mind(name: string): Promise<Opened> {
    return openMind(this.where(name));
  }

  /** The work of a server for the mind of a name. */
  work(name: string, policy: Policy = {}, more: Partial<Machine> = {}): Work {
    return new Work(this.where(name, more), policy);
  }

  /** Stops the network, and removes everything of this place. */
  async close(): Promise<void> {
    await this.#network?.stop();
    rmSync(this.root, { recursive: true, force: true });
  }
}

/** A tool, by its name. */
export function toolOf(name: string): (typeof TOOLS)[number] {
  const tool = TOOLS.find((one) => one.name === name);
  if (tool === undefined) throw new Error(`there is no tool ${name}`);
  return tool;
}

/**
 * Calls a tool, as a host that cannot ask unless the test says otherwise.
 *
 * @returns What it said.
 * @throws If it came back with a question.
 */
export async function call(
  work: Work,
  name: string,
  given: Given = {},
  confirming: Confirming = SILENT,
): Promise<JsonObject> {
  const said = await toolOf(name).run(work, given, confirming);
  if ("ask" in said) throw new Error(`${name} asked: ${said.ask.text}`);
  return said.result;
}

/** Calls a tool that is expected to come back with a question for the person. */
export async function asked(work: Work, name: string, given: Given): Promise<Question> {
  const said = await toolOf(name).run(work, given, ASKING);
  if (!("ask" in said)) throw new Error(`${name} did not ask: ${JSON.stringify(said.result)}`);
  return said.ask;
}
