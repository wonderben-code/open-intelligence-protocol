// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `oip keys backup` and `oip keys restore`: the one way a mind's private
 * keys leave its directory, sealed, and the way back from it.
 */

import { existsSync, readFileSync, renameSync, rmdirSync, statSync, writeFileSync } from "node:fs";

import { Mind } from "@oip/client";
import { keyHash, OipError } from "@oip/core";
import { KEY_ROLES, Keystore, KeystoreError, type RoleKeys } from "@oip/keystore";
import { fileStorage } from "@oip/keystore/node";

import { type Command, has, many, one, UsageError } from "../command.ts";
import { type Config, Home, readNetwork } from "../home.ts";
import { backupLockOf, lockOf, optionsOf } from "../mind.ts";
import { counted } from "../text.ts";
import { row } from "./describe.ts";
import { networkDirectory, origins } from "./init.ts";

/** The most bytes of a file that is read as a backup: the keys of one mind are far fewer. */
const MAX_BACKUP_BYTES = 4 * 1024 * 1024;

export const keysBackup: Command = {
  name: "keys backup",
  summary: "Writes the mind's keys to a file, sealed with a passphrase of its own",
  positionals: "<file>",
  flags: {
    replace: { type: "boolean", describes: "Write over a file that is there" },
  },
  notes: [
    "A backup is the one form in which private keys leave the mind's directory. Nothing in it",
    "can be read without its passphrase: from OIP_BACKUP_PASSPHRASE, or typed. Choose one of its",
    "own, and keep it and the file apart from this machine.",
    "Back up again after every change of the mind's identity (`oip rotate`, `add-key`,",
    "`revoke-key`, `fork`): each makes a control key the change after it will need. If that key",
    "is lost, the mind's identity can never change again.",
  ],
  example: "oip keys backup ~/safe/oip-keys.backup",
  async run(context, given) {
    const [file, ...more] = given.positionals;
    if (file === undefined || more.length > 0) {
      throw new UsageError("keys backup takes one file to write the backup to");
    }
    if (existsSync(file) && !has(given, "replace")) {
      throw new UsageError(
        `${file} is there already: name another, or write over it with --replace`,
      );
    }
    const home = new Home(context.dir);
    const config = home.read();
    const keystore = await Keystore.open({ storage: fileStorage(home.keys) });
    const lock = await lockOf(context, config.lock);
    const sealing = await backupLockOf(context, true);
    const unlocked: RoleKeys[] = [];
    try {
      // Each role that is unlocked is locked again, whichever of them fails to open.
      for (const role of KEY_ROLES) unlocked.push(await keystore.unlock(role, lock));
      const [control, operational, invocation, agreement] = unlocked;
      const backup = await keystore.backup(
        { control, operational, invocation, agreement } as Parameters<Keystore["backup"]>[0],
        sealing,
      );
      // Whole, or not at all, and the user's alone: then read back before it is said to be kept.
      const partial = `${file}.partial`;
      writeFileSync(partial, backup.bytes, { mode: 0o600 });
      renameSync(partial, file);
      if (!Buffer.from(backup.bytes).equals(readFileSync(file))) {
        throw new KeystoreError("changed", `${file} does not hold what was written to it`);
      }
      await backup.saved();
      const held = unlocked.reduce((count, keys) => count + keys.keys().length, 0);
      return {
        lines: [
          `The backup is in ${file}`,
          row(
            "holds",
            `${counted(held, "key")}, of ${keystore.mind ?? "a mind not yet published"}`,
          ),
          row("sealed", "with the backup's own passphrase: without it, nothing of it can be read"),
          "Keep the file and its passphrase apart from this machine, and from each other.",
        ],
        json: { file, mind: keystore.mind ?? null, keys: held, bytes: backup.bytes.length },
      };
    } finally {
      for (const keys of unlocked) keys.lock();
    }
  },
};

export const keysRestore: Command = {
  name: "keys restore",
  summary: "Makes the mind's directory again from a backup of its keys",
  positionals: "<file>",
  flags: {
    resolver: {
      type: "string",
      multiple: true,
      value: "origin",
      describes:
        "A resolver the mind trusts, as an HTTPS origin. Name two, run by different people",
    },
    indexer: {
      type: "string",
      multiple: true,
      value: "origin",
      describes: "An indexer the mind lists itself at, and asks",
    },
    local: {
      type: "boolean",
      describes: "Use the network `oip demo` runs on this machine, for what is not named",
    },
    network: {
      type: "string",
      value: "path",
      describes: "The directory of that network. Default: ~/.oip-demo",
    },
    keychain: {
      type: "boolean",
      describes: "Seal the keys with a key in this machine's keychain, in place of a passphrase",
    },
  },
  notes: [
    "The directory must hold no keys yet. The backup is opened with its own passphrase, from",
    "OIP_BACKUP_PASSPHRASE or typed, and the keys are sealed afresh for this machine.",
    "A backup holds the keys as they were when it was made. If the mind's identity has changed",
    "since, the control keys it needs now are not in it: this says so, and the mind then signs",
    "and reads as before, but its identity can change no more. A later backup would mend that.",
    "What the mind's client remembered is not in a backup: its sessions do not go on.",
  ],
  example: "oip keys restore ~/safe/oip-keys.backup --resolver https://resolver.example",
  async run(context, given) {
    const [file, ...more] = given.positionals;
    if (file === undefined || more.length > 0) {
      throw new UsageError("keys restore takes one file: the backup");
    }
    let bytes: Uint8Array;
    try {
      if (statSync(file).size > MAX_BACKUP_BYTES) throw new UsageError(`${file} is no backup`);
      bytes = readFileSync(file);
    } catch (error) {
      if (error instanceof UsageError) throw error;
      throw new UsageError(
        `the backup could not be read from ${file}: there is no such file to read`,
      );
    }
    const home = new Home(context.dir);
    if (existsSync(home.keys)) {
      throw new UsageError(
        `${home.dir} holds keys already: a backup is restored to a directory of its own (--dir)`,
      );
    }
    const network = has(given, "local")
      ? networkDirectory(context.edges.home, one(given, "network"))
      : undefined;
    const local = network === undefined ? undefined : readNetwork(network);
    const named = (flag: string, what: string, fallback: string | undefined): string[] => {
      const listed = origins(many(given, flag), what);
      return listed.length > 0 || fallback === undefined ? listed : [fallback];
    };
    const resolvers = named("resolver", "a resolver", local?.resolver);
    if (resolvers.length === 0) {
      throw new UsageError(
        "a mind needs a resolver: name one with --resolver, or use --local while `oip demo` runs",
      );
    }
    const config: Config = {
      resolvers,
      indexers: named("indexer", "an indexer", local?.indexer),
      lock: has(given, "keychain") ? "keychain" : "passphrase",
      ...(network === undefined ? {} : { network }),
    };
    // Both locks are had before anything is written: a passphrase mistyped leaves no trace.
    const opening = await backupLockOf(context, false);
    const lock = await lockOf(context, config.lock, true);
    let keystore: Keystore;
    try {
      keystore = await Keystore.restore({
        storage: fileStorage(home.keys),
        locks: lock,
        backup: bytes,
        backupLock: opening,
      });
    } catch (error) {
      // Nothing was restored: the directories made for it are not left behind, empty.
      for (const made of [home.keys, home.dir]) {
        try {
          rmdirSync(made);
        } catch {
          // It holds something, or was never made: either way it stays as it is.
        }
      }
      if (error instanceof KeystoreError && error.code === "damaged") {
        throw new UsageError(`${file} is no backup of a mind's keys`);
      }
      throw error;
    }
    home.write(config);
    const address = keystore.mind;
    if (address === undefined) {
      return {
        lines: [
          `The keys are restored to ${home.keys}`,
          "They are of a mind that was never published: `oip init` goes on to make it.",
        ],
        json: { directory: home.dir, mind: null },
      };
    }
    const mind = await Mind.open(optionsOf(context, home, config, keystore, lock));
    let signs: boolean;
    let events: number;
    let committed: readonly string[];
    try {
      const { state } = mind;
      events = state.seq + 1;
      committed = state.retired || state.controller.kind !== "key" ? [] : state.controller.next;
      try {
        mind.signingKey();
        signs = true;
      } catch (error) {
        if (!(error instanceof OipError)) throw error;
        signs = false;
      }
    } finally {
      mind.close();
    }
    // Whether the backup holds the control keys the log commits to now: without them, no
    // event can follow the one the log ends with.
    const control = await keystore.unlock("control", lock);
    let changes: boolean;
    try {
      changes = control.keys().some((key) => committed.includes(keyHash(key.publicKey)));
    } finally {
      control.lock();
    }
    return {
      lines: [
        `The mind is ${address}`,
        row("keys", `restored to ${home.keys}, and sealed afresh`),
        row("log", counted(events, "event")),
        row(
          "signs",
          signs
            ? "yes: the backup holds a key the mind signs with now"
            : "no: the mind's keys have changed since this backup was made",
        ),
        row(
          "identity",
          changes
            ? "can change: the backup holds the control keys the log commits to"
            : "can change no more from this backup: its control keys were used since. A later backup holds the next",
        ),
        "What the mind's client remembered is not restored: publish where it is with `oip publish location`.",
      ],
      json: { directory: home.dir, mind: address, events, signs, identity: changes },
    };
  },
};
