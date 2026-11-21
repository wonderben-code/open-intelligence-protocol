// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The indexer's own mind, made once before the indexer first starts.
 *
 * An indexer signs what it answers, so it is a mind (Layer 1, 18.3). This
 * makes one that is controlled by a key: a genesis, the operational key the
 * indexer signs with, and the control key that the mind's next event will
 * need. The keys are written to files that only their owner can read, and
 * go nowhere else: nothing here returns one, logs one or puts one in an error.
 */

import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { bytesToBase64url, contentId, keyHash, mindAddress, signerFromPrivateKey } from "@oip/core";
import { draftGenesis, signEventSync } from "@oip/identity";
import { ConfigError, type Randomness } from "@oip/server";

/** What the mind is made from. */
export interface InitOptions {
  /** Where the files are written. It is made if it is not there, for its owner alone. */
  readonly directory: string;
  /** The `created` of the genesis: the present, as a timestamp. */
  readonly created: string;
  /** Where the keys come from. */
  readonly randomness: Randomness;
  /** HTTPS origins that serve the mind's records (Layer 1, 3.13), if it has any yet. */
  readonly homes?: readonly string[];
}

/** The mind that was made, and where its files are. Nothing of a key is here. */
export interface Initialised {
  /** The mind's address. */
  readonly address: string;
  /** The mind's `Bundle`: what `OIP_INDEXER_BUNDLE_FILE` names. */
  readonly bundleFile: string;
  /** The operational key: what `OIP_INDEXER_KEY_FILE` names. */
  readonly keyFile: string;
  /**
   * The control key that signs the mind's next identity event. The indexer
   * never reads it. Whoever runs the indexer moves it somewhere safer than
   * the machine the indexer runs on.
   */
  readonly nextControlKeyFile: string;
}

/** The names of the files in the directory. */
export const INIT_FILES = {
  bundle: "bundle.json",
  key: "operational.key",
  nextControlKey: "next-control.key",
} as const;

/**
 * Makes the indexer's mind and writes its files.
 *
 * The control key that signs the genesis is used once and kept nowhere, as
 * Layer 1, 3.11 asks. The genesis commits to the next control key, which is
 * written beside the operational key.
 *
 * @throws ConfigError if one of the files is there already: a key is never
 *   written over. Nothing is written then.
 * @throws OipError if a home is no HTTPS origin: nothing is written then either.
 */
export function init(options: InitOptions): Initialised {
  const { directory, randomness } = options;
  const at = (name: string): string => join(directory, name);
  const files: Initialised = {
    address: "",
    bundleFile: at(INIT_FILES.bundle),
    keyFile: at(INIT_FILES.key),
    nextControlKeyFile: at(INIT_FILES.nextControlKey),
  };
  for (const file of [files.bundleFile, files.keyFile, files.nextControlKeyFile]) {
    if (existsSync(file)) {
      throw new ConfigError([
        `${file} is there already: a mind is made once, and its keys are not written over`,
      ]);
    }
  }
  const [control, operational, next] = [
    randomness.bytes(32),
    randomness.bytes(32),
    randomness.bytes(32),
  ];
  const genesis = signEventSync(
    draftGenesis(options.created, {
      kind: "service",
      controller: {
        keys: [signerFromPrivateKey(control).publicKey],
        next: [keyHash(signerFromPrivateKey(next).publicKey)],
      },
      keys: [{ key: signerFromPrivateKey(operational).publicKey }],
      ...(options.homes === undefined || options.homes.length === 0
        ? {}
        : { homes: [...options.homes] }),
    }),
    [{ control: signerFromPrivateKey(control) }],
  );
  const address = mindAddress(contentId(genesis));
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  // `wx`: a file that appeared meanwhile is not written over.
  const secret = { mode: 0o600, flag: "wx" } as const;
  writeFileSync(files.keyFile, `${bytesToBase64url(operational)}\n`, secret);
  writeFileSync(files.nextControlKeyFile, `${bytesToBase64url(next)}\n`, secret);
  const bundle = { oip: "1", type: "Bundle", mind: address, log: [genesis] };
  writeFileSync(files.bundleFile, `${JSON.stringify(bundle, undefined, 2)}\n`, {
    mode: 0o644,
    flag: "wx",
  });
  return { ...files, address };
}

/** How `oip-indexer init` is used. */
export const INIT_USAGE = `Usage: oip-indexer init <directory> [--if-missing] [--home <https origin>]...

Makes the indexer's own mind, once, and writes into <directory>:

  ${INIT_FILES.bundle}        the mind's Bundle: set OIP_INDEXER_BUNDLE_FILE to it
  ${INIT_FILES.key}    the key the indexer signs with: set OIP_INDEXER_KEY_FILE to it
  ${INIT_FILES.nextControlKey}   the control key for the mind's next identity event:
                     the indexer never reads it, so keep it somewhere safer

The keys are files that only their owner can read. Nothing is written over: where the
mind is there already the command ends with 1, or with 0 if --if-missing is given.
`;

/**
 * The command `oip-indexer init`.
 *
 * @param args - The arguments after `init`.
 * @param edges - The clock's reading as a timestamp, the randomness, and where to write.
 * @returns The exit code: 0 if the mind was made, 1 if it was not, 2 for wrong arguments.
 */
export function initCommand(
  args: readonly string[],
  edges: {
    readonly created: string;
    readonly randomness: Randomness;
    readonly out: (text: string) => void;
    readonly err: (text: string) => void;
  },
): number {
  const homes: string[] = [];
  const positional: string[] = [];
  let ifMissing = false;
  for (let at = 0; at < args.length; at++) {
    const arg = args[at] ?? "";
    if (arg === "--help" || arg === "-h") {
      edges.out(INIT_USAGE);
      return 0;
    }
    if (arg === "--if-missing") ifMissing = true;
    else if (arg === "--home") {
      const home = args[++at];
      if (home === undefined) return wrong(edges, "--home takes an HTTPS origin");
      homes.push(home);
    } else if (arg.startsWith("--")) return wrong(edges, `${arg} is no option of this command`);
    else positional.push(arg);
  }
  const [directory, ...more] = positional;
  if (directory === undefined || more.length > 0) return wrong(edges, "give one directory");
  // What starts the indexer each time can ask for the mind each time: it is made the first.
  const there = [INIT_FILES.bundle, INIT_FILES.key].every((name) =>
    existsSync(join(directory, name)),
  );
  if (ifMissing && there) {
    edges.out(`The mind in ${directory} is there already: nothing was made.\n`);
    return 0;
  }
  try {
    const made = init({ directory, created: edges.created, randomness: edges.randomness, homes });
    edges.out(
      [
        `Made the mind ${made.address}`,
        `  OIP_INDEXER_BUNDLE_FILE=${made.bundleFile}`,
        `  OIP_INDEXER_KEY_FILE=${made.keyFile}`,
        `The control key for its next identity event is in ${made.nextControlKeyFile}.`,
        "The indexer never reads that file: keep it somewhere safer than this machine.",
        "",
      ].join("\n"),
    );
    return 0;
  } catch (error) {
    // What went wrong is said without anything a key file holds: an error here never has it.
    edges.err(
      `oip-indexer init: ${error instanceof Error ? error.message : "the mind could not be made"}\n`,
    );
    return 1;
  }
}

function wrong(edges: { readonly err: (text: string) => void }, why: string): number {
  edges.err(`oip-indexer init: ${why}\n\n${INIT_USAGE}`);
  return 2;
}
