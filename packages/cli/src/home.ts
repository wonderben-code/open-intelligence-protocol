// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A mind's directory: where the command keeps its keys, what its client
 * remembers, the records it holds, and which services it asks.
 *
 * One directory is one mind. It is `~/.oip` unless `--dir` or `OIP_DIR`
 * names another. Its keys are sealed, and the directory is the user's alone.
 */

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { httpsOrigin } from "@oip/client";

import { UsageError } from "./command.ts";
import type { Edges } from "./edges.ts";

/** What a mind's directory says of how the mind is reached and kept. */
export interface Config {
  /** The HTTPS origins of the resolvers the mind trusts. */
  readonly resolvers: readonly string[];
  /** The HTTPS origins of the indexers it lists itself at, and asks. */
  readonly indexers: readonly string[];
  /** What its keys are sealed under: a passphrase, or a key the machine's keychain keeps. */
  readonly lock: "passphrase" | "keychain";
  /**
   * The directory of a network that runs on this machine (`oip demo`), if
   * the mind's services are of one. Where each is really reached is read
   * from there each time, since it changes when the network starts again.
   * It is the user's own setting: nothing a service or a record says is
   * ever put here.
   */
  readonly network?: string;
}

/** What a local network says of itself, in `network.json` in its directory. */
export interface NetworkFile {
  readonly resolver: string;
  readonly host: string;
  readonly indexer: string;
  /** Where each origin is really reached: `http://127.0.0.1:<port>`. */
  readonly routes: Readonly<Record<string, string>>;
}

/** The name of the file a running network writes in its directory. */
export const NETWORK_FILE = "network.json";

/**
 * Reads what a local network says of itself.
 *
 * @throws UsageError if none is running there, or the file is not one this command wrote.
 */
export function readNetwork(directory: string): NetworkFile {
  let text: string;
  try {
    text = readFileSync(join(directory, NETWORK_FILE), "utf8");
  } catch {
    throw new UsageError(
      `no network is running from ${directory}: start one with \`oip demo\`, in another terminal`,
    );
  }
  let read: unknown;
  try {
    read = JSON.parse(text);
  } catch {
    read = undefined;
  }
  const { resolver, host, indexer, routes } = (read ?? {}) as Readonly<Record<string, unknown>>;
  const places = Object.entries((routes ?? {}) as Readonly<Record<string, unknown>>);
  if (
    !isOrigins([resolver, host, indexer]) ||
    !places.every(([origin, place]) => httpsOrigin(origin) === origin && isLocal(place))
  ) {
    throw new UsageError(`${join(directory, NETWORK_FILE)} is not what a running network wrote`);
  }
  return {
    resolver: String(resolver),
    host: String(host),
    indexer: String(indexer),
    routes: Object.fromEntries(places) as Record<string, string>,
  };
}

/** The directory a command works in: the one named, or `OIP_DIR`, or `.oip` under the user's home. */
export function directoryOf(named: string | undefined, edges: Edges): string {
  return resolve(named ?? edges.env["OIP_DIR"] ?? join(edges.home, ".oip"));
}

const isOrigins = (value: unknown): value is string[] =>
  Array.isArray(value) &&
  value.every((origin) => typeof origin === "string" && httpsOrigin(origin) === origin);

/** A configuration as it was read, or `undefined` if it is none. */
function configOf(read: unknown): Config | undefined {
  if (typeof read !== "object" || read === null) return undefined;
  const { resolvers, indexers, lock, network } = read as Readonly<Record<string, unknown>>;
  if (!isOrigins(resolvers) || !isOrigins(indexers)) return undefined;
  if (lock !== "passphrase" && lock !== "keychain") return undefined;
  if (network === undefined) return { resolvers, indexers, lock };
  return typeof network === "string" ? { resolvers, indexers, lock, network } : undefined;
}

/**
 * Whether a route leads to this machine, over plain HTTP: `http://127.0.0.1:<port>`.
 * A route is for a network that runs here. Anywhere else is reached by HTTPS, at its own origin.
 */
export function isLocal(place: unknown): place is string {
  return typeof place === "string" && /^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/u.test(place);
}

/** A mind's directory. */
export class Home {
  /** The directory. */
  readonly dir: string;

  constructor(dir: string) {
    this.dir = dir;
  }

  /** Where the keys are kept, sealed. */
  get keys(): string {
    return join(this.dir, "keys");
  }

  /** Where the client remembers its own work. */
  get memory(): string {
    return join(this.dir, "memory");
  }

  /** Where the records the mind holds are kept, each under its content ID. */
  get records(): string {
    return join(this.dir, "records");
  }

  /** Where the packets the mind has received are kept, each under its content ID. */
  get inbox(): string {
    return join(this.dir, "inbox");
  }

  get #file(): string {
    return join(this.dir, "config.json");
  }

  /** Whether the directory has a configuration: whether `init` has been here. */
  get exists(): boolean {
    return existsSync(this.#file);
  }

  /**
   * The configuration.
   *
   * @throws UsageError if there is none, or what is there is not one.
   */
  read(): Config {
    let text: string;
    try {
      text = readFileSync(this.#file, "utf8");
    } catch {
      throw new UsageError(`there is no mind in ${this.dir}: make one with \`oip init\``);
    }
    let read: unknown;
    try {
      read = JSON.parse(text);
    } catch {
      read = undefined;
    }
    const config = configOf(read);
    if (config === undefined) {
      throw new UsageError(`${this.#file} is not a configuration this command wrote`);
    }
    return config;
  }

  /** Writes the configuration, in the place of any that was there. The directory is made the user's alone. */
  write(config: Config): void {
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    const next = `${this.#file}.next`;
    writeFileSync(next, `${JSON.stringify(config, undefined, 2)}\n`, { mode: 0o600 });
    // In one step: a reader finds the old configuration or the new one, and never half of one.
    renameSync(next, this.#file);
  }
}
