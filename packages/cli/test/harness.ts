// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What the tests of the command share: a home directory of their own, a
 * network on this machine, and `oip` run in the test's process with what it
 * printed kept.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { type Keychain, SCRYPT_MIN_N } from "@oip/keystore";

import { type Context, type Edges, type ExitCode, type Network, run } from "../src/index.ts";
import { type Opened, openMind } from "../src/mind.ts";

/** What a run of the command came to. */
export interface Ran {
  readonly code: ExitCode;
  /** What it wrote to standard output, and to standard error. */
  readonly out: string;
  readonly err: string;
  /** What it wrote to standard output, read as JSON. */
  readonly json: () => unknown;
}

/** The passphrase the tests' minds are sealed with. */
export const PASSPHRASE = "correct horse battery staple";

/** A place for one test file: a home directory, and a network that runs while its tests do. */
export class Place {
  /** The user's home directory, in which `.oip` and `.oip-demo` are. */
  readonly home = mkdtempSync(join(tmpdir(), "oip-cli-"));
  #network: Network | undefined;
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

  /** The directory of a mind of this place, by a name. */
  dir(name: string): string {
    return join(this.home, name);
  }

  /** The edges of a run in this place, which writes to what it is given. */
  #edges(written: { out: string; err: string }, more: Partial<Edges>): Edges {
    return {
      env: { OIP_PASSPHRASE: PASSPHRASE },
      home: this.home,
      out: (text) => {
        written.out += text;
      },
      err: (text) => {
        written.err += text;
      },
      keychain: () => Promise.resolve(this.keychain),
      // Nothing of a test runs until it is stopped, unless the test says when.
      stopped: () => Promise.resolve(),
      scryptN: SCRYPT_MIN_N,
      ...more,
    };
  }

  /** Runs `oip` with these arguments, as the user of this place. */
  async oip(argv: readonly string[], more: Partial<Edges> = {}): Promise<Ran> {
    const written = { out: "", err: "" };
    const code = await run(argv, this.#edges(written, more));
    return { code, ...written, json: () => JSON.parse(written.out) as unknown };
  }

  /**
   * The mind of a directory, opened as a command opens it: for what a test
   * does that no command does. The test closes it.
   */
  mind(dir: string): Promise<Opened> {
    return openMind(this.context(dir));
  }

  /** What a command of this place is run with, for a directory: for a test that calls what a command calls. */
  context(dir: string): Context {
    return { edges: this.#edges({ out: "", err: "" }, {}), dir, say: () => undefined };
  }

  /**
   * Starts the network `oip demo` runs, in the directory `oip init --local`
   * looks in, and says where it is as `oip demo` does.
   */
  async network(): Promise<Network> {
    let stop: (() => void) | undefined;
    const stopped = new Promise<void>((resolve) => {
      stop = resolve;
    });
    let started: (() => void) | undefined;
    const running = new Promise<void>((resolve) => {
      started = resolve;
    });
    let said: Network | undefined;
    const ended = this.oip(["demo", "--json"], {
      stopped: () => stopped,
      out: (text) => {
        said ??= JSON.parse(text) as Network;
        started?.();
      },
    });
    await Promise.race([running, ended]);
    if (said === undefined) throw new Error(`the network did not start: ${(await ended).err}`);
    this.#network = {
      ...said,
      stop: async () => {
        stop?.();
        await ended;
      },
    };
    return this.#network;
  }

  /** Stops the network, and removes everything of this place. */
  async close(): Promise<void> {
    await this.#network?.stop();
    rmSync(this.home, { recursive: true, force: true });
  }

  /**
   * What was printed, with what differs from run to run made the same: the
   * addresses of minds, content IDs, keys, ports, times, and this place's own path.
   */
  plain(text: string): string {
    return text
      .replaceAll(this.home, "<home>")
      .replace(/did:oip:[a-z2-7]{56}/gu, "did:oip:<mind>")
      .replace(/\bbciq[a-z2-7]{52}\b/gu, "<id>")
      .replace(/\bz6Mk[1-9A-HJ-NP-Za-km-z]{40,48}\b/gu, "<key>")
      .replace(/127\.0\.0\.1:[0-9]+/gu, "127.0.0.1:<port>")
      .replace(/[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z/gu, "<time>");
  }
}
