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
import { contentId, OipError } from "@oip/core";
import { keychainLock, Keystore, type Lock, passphrase } from "@oip/keystore";
import { fileStorage } from "@oip/keystore/node";

import { type Context, UsageError } from "./command.ts";
import { type Config, Home, readNetwork } from "./home.ts";
import { routed, routedSocket } from "./network.ts";
import { Kept, KeptRecords } from "./records.ts";

/** The name the command's keys are kept under in a keychain. */
const SERVICE = "oip";

const platformFetch: Fetch = (request) => fetch(request);
// The platform's WebSocket is one the client takes. Its own types say more of it than that.
const platformSocket: OpenSocket = (url, protocol) =>
  new WebSocket(url, protocol) as unknown as SocketLike;

/**
 * A passphrase: from a variable of the environment, or typed at the
 * terminal, where what is typed is not shown.
 *
 * A passphrase is never taken from the command line: what is typed there is
 * shown to every user of the machine, and kept in the shell's history.
 *
 * @param from.variable - The variable it is read from, if it is set.
 * @param from.what - What it opens, for the message: "the keys".
 * @param from.question - What is asked where it is typed.
 * @param from.fresh - Whether it is to seal something for the first time:
 *   typed, it is then asked for twice.
 * @throws UsageError if there is no passphrase to be had.
 */
export async function passphraseOf(
  context: Context,
  from: { variable: string; what: string; question: string; fresh: boolean },
): Promise<Lock> {
  const { edges } = context;
  const options = edges.scryptN === undefined ? {} : { n: edges.scryptN };
  const given = edges.env[from.variable];
  if (given !== undefined && given !== "") return passphrase(given, options);
  if (edges.secret === undefined) {
    throw new UsageError(
      `${from.what} are sealed with a passphrase: set ${from.variable}, or run this where one can be typed`,
    );
  }
  const typed = await edges.secret(from.question);
  if (from.fresh && (await edges.secret("The same again: ")) !== typed) {
    throw new UsageError("the two passphrases are not the same");
  }
  if (typed === "") throw new UsageError("no passphrase was typed");
  return passphrase(typed, options);
}

/**
 * What opens the mind's keys: the key in the machine's keychain, or a
 * passphrase from `OIP_PASSPHRASE` or typed at the terminal.
 *
 * @param fresh - Whether the lock is to seal keys for the first time: a
 *   passphrase that is typed is then asked for twice.
 * @throws UsageError if there is no passphrase to be had.
 */
export async function lockOf(context: Context, kind: Config["lock"], fresh = false): Promise<Lock> {
  if (kind === "keychain") return keychainLock(await context.edges.keychain(), SERVICE);
  return passphraseOf(context, {
    variable: "OIP_PASSPHRASE",
    what: "the keys",
    question: fresh ? "A passphrase for the keys: " : "Passphrase: ",
    fresh,
  });
}

/**
 * What a backup of the keys is sealed under: a passphrase of its own, from
 * `OIP_BACKUP_PASSPHRASE` or typed. Kept apart from the one the keys are
 * sealed with, it is what makes a backup worth having.
 */
export function backupLockOf(context: Context, fresh: boolean): Promise<Lock> {
  return passphraseOf(context, {
    variable: "OIP_BACKUP_PASSPHRASE",
    what: "the keys of a backup",
    question: fresh ? "A passphrase for the backup, of its own: " : "The backup's passphrase: ",
    fresh,
  });
}

/** How a service of a mind's configuration is reached: where its route says, if it has one. */
export function fetchOf(context: Context, config: Config): Fetch {
  // A network on this machine says where it is each time: it may have started again since.
  const routes = config.network === undefined ? {} : readNetwork(config.network).routes;
  return routed(routes, context.edges.fetch ?? platformFetch);
}

/** How the services of a mind's configuration are asked: for reading, with no key. */
export function lookupOptions(context: Context, config: Config): LookupOptions {
  const { edges } = context;
  return {
    resolvers: config.resolvers,
    indexers: config.indexers,
    fetch: fetchOf(context, config),
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
  /** The records the mind held when the command before this one ended. It holds them again. */
  readonly records: KeptRecords;
  /** The packets the mind has received. */
  readonly inbox: Kept;
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
  const records = new KeptRecords(home.records);
  for (const { record, seen } of records.all()) {
    try {
      mind.hold(record, seen);
    } catch (error) {
      // A file there that is no record is not one the mind holds. Nothing else is wrong.
      if (!(error instanceof OipError)) {
        mind.close();
        throw error;
      }
    }
  }
  return { mind, home, config, keystore, lock, records, inbox: new Kept(home.inbox) };
}

/** Writes down the records a mind holds, each with when its proofs were first obtained. */
export function keepRecords({ mind, records }: Pick<Opened, "mind" | "records">): void {
  for (const record of mind.records()) records.keep(record, mind.sightings(contentId(record)));
}

/**
 * Opens the mind of the command's directory for one piece of work. After
 * it, the records the mind holds are written down, whether the work came
 * to an end or failed part of the way: what the mind signed, it signed.
 * Then its keys are locked.
 */
export async function withMind<T>(
  context: Context,
  work: (opened: Opened) => Promise<T>,
): Promise<T> {
  const opened = await openMind(context);
  try {
    return await work(opened);
  } finally {
    try {
      keepRecords(opened);
    } finally {
      opened.mind.close();
    }
  }
}

/**
 * The services a command asks that reads and signs nothing: those of the
 * directory's mind if there is one, or the local network's where `--local`
 * says so.
 *
 * @throws UsageError if there is neither.
 */
export function servicesOf(context: Context, local: string | undefined): Config {
  if (local !== undefined) {
    const network = readNetwork(local);
    return {
      resolvers: [network.resolver],
      indexers: [network.indexer],
      lock: "passphrase",
      network: local,
    };
  }
  return new Home(context.dir).read();
}
