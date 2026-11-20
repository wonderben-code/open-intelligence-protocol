// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { existsSync } from "node:fs";
import { join } from "node:path";

import { httpsOrigin, Mind } from "@oip/client";
import { Keystore, KeystoreError } from "@oip/keystore";
import { fileStorage } from "@oip/keystore/node";

import { type Command, type Context, has, many, one, UsageError } from "../command.ts";
import { type Config, Home, readNetwork } from "../home.ts";
import { lockOf, optionsOf } from "../mind.ts";

/** Each of the origins given, or what is wrong with the first that is none. */
export function origins(given: readonly string[], what: string): string[] {
  for (const origin of given) {
    if (httpsOrigin(origin) !== origin) {
      throw new UsageError(`${origin} is no HTTPS origin: ${what} is named as https://example.org`);
    }
  }
  return [...new Set(given)];
}

/** Where a local network keeps its files, unless told otherwise. */
export const networkDirectory = (home: string, named?: string): string =>
  named ?? join(home, ".oip-demo");

/** What a new mind is made with, besides its directory and its services. */
export interface Making {
  readonly kind: string;
  /** The hosts that will serve it. With none, it takes no packets. */
  readonly homes: readonly string[];
  /** The minds it is forked from, each at a version (Layer 1, 8.1). */
  readonly parents?: readonly { readonly mind: string; readonly at: string }[];
}

/**
 * Makes a mind in a directory: its keys, sealed there, its first event with
 * its resolvers, and where it takes packets.
 *
 * Nothing is written until there is a lock to seal with: a passphrase
 * mistyped leaves no trace. Once the keys are there, a run that fails is
 * gone on with by the next, with the same keys.
 *
 * @returns The mind, open: the caller closes it. And how many resolvers have its first event.
 * @throws UsageError if a mind lives in the directory already.
 */
export async function makeMind(
  context: Context,
  home: Home,
  config: Config,
  making: Making,
): Promise<{ mind: Mind; took: number }> {
  const begun = existsSync(home.keys);
  let keystore: Keystore | undefined;
  if (begun) {
    try {
      keystore = await Keystore.open({ storage: fileStorage(home.keys) });
    } catch (error) {
      if (!(error instanceof KeystoreError && error.code === "not-found")) throw error;
    }
  }
  if (keystore?.mind !== undefined) {
    throw new UsageError(
      `a mind lives in ${home.dir} already: \`oip show\` says which. Another needs a directory of its own (--dir)`,
    );
  }
  const lock = await lockOf(context, config.lock, keystore === undefined);
  keystore ??= await Keystore.create({ storage: fileStorage(home.keys), locks: lock });
  // The keys are there. If what follows fails, the next run goes on from here.
  home.write(config);
  const mind = await Mind.create(optionsOf(context, home, config, keystore, lock), {
    kind: making.kind,
    ...(making.homes.length === 0 ? {} : { homes: making.homes }),
    ...(making.parents === undefined ? {} : { parents: making.parents }),
  });
  try {
    // Where it takes packets: an inbox and a mailbox at each of its homes.
    if (making.homes.length > 0) await mind.publishLocation();
  } catch (error) {
    mind.close();
    throw error;
  }
  const took = mind.publications.filter(({ service, taken }) => service === "resolver" && taken);
  return { mind, took: took.length };
}

export const init: Command = {
  name: "init",
  summary:
    "Makes a mind: its keys, sealed in its directory, and its first event with its resolvers",
  flags: {
    kind: {
      type: "string",
      value: "kind",
      describes: "What the mind says it is: agent, human, institution, service. Default: agent",
    },
    resolver: {
      type: "string",
      multiple: true,
      value: "origin",
      describes:
        "A resolver the mind trusts, as an HTTPS origin. Name two, run by different people",
    },
    host: {
      type: "string",
      multiple: true,
      value: "origin",
      describes: "A host that serves the mind's records and takes its packets",
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
    "The keys are sealed with a passphrase: from OIP_PASSPHRASE, or typed. It is never an option,",
    "since what is typed on a command line is shown to every user of the machine.",
    "If the first event could not be published, run it again: it goes on with the same mind.",
  ],
  example: "oip init --local",
  async run(context, given) {
    const { edges } = context;
    const home = new Home(context.dir);
    const network = has(given, "local")
      ? networkDirectory(edges.home, one(given, "network"))
      : undefined;
    const local = network === undefined ? undefined : readNetwork(network);
    const named = (flag: string, what: string, fallback: string | undefined): string[] => {
      const listed = origins(many(given, flag), what);
      return listed.length > 0 || fallback === undefined ? listed : [fallback];
    };
    const resolvers = named("resolver", "a resolver", local?.resolver);
    const homes = named("host", "a host", local?.host);
    const indexers = named("indexer", "an indexer", local?.indexer);
    if (resolvers.length === 0) {
      throw new UsageError(
        "a mind needs a resolver: name one with --resolver, or use --local while `oip demo` runs",
      );
    }
    const config: Config = {
      resolvers,
      indexers,
      lock: has(given, "keychain") ? "keychain" : "passphrase",
      ...(network === undefined ? {} : { network }),
    };
    const { mind, took } = await makeMind(context, home, config, {
      kind: one(given, "kind") ?? "agent",
      homes,
    });
    try {
      return {
        lines: [
          `Your mind is ${mind.address}`,
          `Its keys are in ${home.keys}, sealed with ${
            config.lock === "keychain" ? "a key in this machine's keychain" : "your passphrase"
          }.`,
          `Resolvers that have its first event: ${String(took)} of ${String(resolvers.length)}.`,
          ...(homes.length === 0
            ? ["It names no host yet, so it takes no packets."]
            : [`It takes packets at ${homes.join(", ")}.`]),
          "Back the keys up before you rely on it: oip keys backup <file>",
        ],
        json: {
          mind: mind.address,
          directory: home.dir,
          resolvers,
          homes,
          indexers,
          lock: config.lock,
          published: took,
        },
      };
    } finally {
      mind.close();
    }
  },
};
