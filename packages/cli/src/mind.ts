// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The mind a command works for: opened from its directory, with its keys
 * unlocked for as long as the command runs.
 */

import {
  type Fetch,
  type LookupOptions,
  Mind,
  type MindOptions,
  type OpenSocket,
  type SocketLike,
} from "@oip/client";
import { keychainLock, Keystore, type Lock, passphrase } from "@oip/keystore";
import { fileStorage } from "@oip/keystore/node";

import { type Context, UsageError } from "./command.ts";
import { type Config, Home, readNetwork } from "./home.ts";
import { routed, routedSocket } from "./network.ts";

/** The name the command's keys are kept under in a keychain. */
const SERVICE = "oip";

const platformFetch: Fetch = (request) => fetch(request);
// The platform's WebSocket is one the client takes. Its own types say more of it than that.
const platformSocket: OpenSocket = (url, protocol) =>
  new WebSocket(url, protocol) as unknown as SocketLike;

/**
 * What opens the mind's keys: the key in the machine's keychain, or a
 * passphrase from `OIP_PASSPHRASE` or typed at the terminal.
 *
 * A passphrase is never taken from the command line: what is typed there is
 * shown to every user of the machine, and kept in the shell's history.
 *
 * @param fresh - Whether the lock is to seal keys for the first time: a
 *   passphrase that is typed is then asked for twice.
 * @throws UsageError if there is no passphrase to be had.
 */
export async function lockOf(context: Context, kind: Config["lock"], fresh = false): Promise<Lock> {
  const { edges } = context;
  if (kind === "keychain") return keychainLock(await edges.keychain(), SERVICE);
  const options = edges.scryptN === undefined ? {} : { n: edges.scryptN };
  const given = edges.env["OIP_PASSPHRASE"];
  if (given !== undefined && given !== "") return passphrase(given, options);
  if (edges.secret === undefined) {
    throw new UsageError(
      "the keys are sealed with a passphrase: set OIP_PASSPHRASE, or run this where one can be typed",
    );
  }
  const typed = await edges.secret(fresh ? "A passphrase for the keys: " : "Passphrase: ");
  if (fresh && (await edges.secret("The same again: ")) !== typed) {
    throw new UsageError("the two passphrases are not the same");
  }
  if (typed === "") throw new UsageError("no passphrase was typed");
  return passphrase(typed, options);
}

/** How the services of a mind's configuration are asked: for reading, with no key. */
export function lookupOptions(context: Context, config: Config): LookupOptions {
  const { edges } = context;
  // A network on this machine says where it is each time: it may have started again since.
  const routes = config.network === undefined ? {} : readNetwork(config.network).routes;
  return {
    resolvers: config.resolvers,
    indexers: config.indexers,
    fetch: routed(routes, edges.fetch ?? platformFetch),
    ...(edges.clock === undefined ? {} : { clock: edges.clock }),
  };
}

/** How a mind in a directory is made or opened: its keystore, its memory, and its network. */
export function optionsOf(
  context: Context,
  home: Home,
  config: Config,
  keystore: Keystore,
  lock: Lock,
): MindOptions {
  const { edges } = context;
  const routes = config.network === undefined ? {} : readNetwork(config.network).routes;
  return {
    ...lookupOptions(context, config),
    keystore,
    lock,
    memory: fileStorage(home.memory),
    webSocket: routedSocket(routes, edges.webSocket ?? platformSocket),
  };
}

/** A mind that is open, with what the commands need besides. */
export interface Opened {
  readonly mind: Mind;
  readonly home: Home;
  readonly config: Config;
  readonly keystore: Keystore;
  /** What opens the keys of everyday work, and the control keys unless told otherwise. */
  readonly lock: Lock;
}

/**
 * Opens the mind of the command's directory.
 *
 * @throws UsageError if there is none there.
 */
export async function openMind(context: Context): Promise<Opened> {
  const home = new Home(context.dir);
  const config = home.read();
  const keystore = await Keystore.open({ storage: fileStorage(home.keys) });
  const lock = await lockOf(context, config.lock);
  const mind = await Mind.open(optionsOf(context, home, config, keystore, lock));
  return { mind, home, config, keystore, lock };
}
