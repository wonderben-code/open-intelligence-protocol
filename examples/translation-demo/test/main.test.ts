// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The demo as a program: what it takes, what it exits with, and where it plays. */

import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { LOCAL, type Network, startNetwork } from "@oip/cli";
import { Lookup, TransportError } from "@oip/client";
import { OipError } from "@oip/core";
import { Keystore } from "@oip/keystore";
import { fileStorage } from "@oip/keystore/node";
import { Home, lookupOptions, NETWORK_FILE, UsageError } from "@oip/local";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { type Edges, linesOf, main, NotSo, Stage, tell } from "../src/index.ts";

let root: string;
let network: Network;
let directory: string;

beforeAll(async () => {
  // A network that runs before the telling and after it, as `oip demo` runs one.
  root = mkdtempSync(join(tmpdir(), "oip-translation-demo-test-"));
  directory = join(root, "network");
  network = await startNetwork({ directory });
  writeFileSync(
    join(directory, NETWORK_FILE),
    JSON.stringify({ ...LOCAL, routes: network.routes }),
  );
});
afterAll(async () => {
  await network.stop();
  rmSync(root, { recursive: true, force: true });
});

/** Runs the program, and gives what it wrote. */
async function run(...argv: string[]): Promise<{ code: number; out: string; err: string }> {
  return runWith({ tell }, ...argv);
}

/** Runs the program with a telling of the test's own. */
async function runWith(
  edges: Edges,
  ...argv: string[]
): Promise<{ code: number; out: string; err: string }> {
  const written = { out: "", err: "" };
  const code = await main(
    argv,
    {
      stdout: { write: (text) => (written.out += text) },
      stderr: { write: (text) => (written.err += text) },
    },
    edges,
  );
  return { code, ...written };
}

/** The directories of tellings that are there now: each telling makes one, and removes it. */
const tellings = (): string[] =>
  readdirSync(tmpdir()).filter(
    (name) => name.startsWith("oip-translation-demo-") && !name.includes("-test-"),
  );

describe("pnpm demo", () => {
  it("says what it takes", async () => {
    const help = await run("--help");
    expect(help.code).toBe(0);
    expect(help.out).toContain("pnpm demo --network <directory>");
    expect(help.err).toBe("");
  });

  it("takes nothing it does not know, and no network that is none", async () => {
    for (const argv of [["--loudly"], ["now"], ["--network"]]) {
      const done = await run(...argv);
      expect(done.code, argv.join(" ")).toBe(2);
      expect(done.out).toBe("");
      expect(done.err).toContain("`pnpm demo --help` shows what it takes");
    }
    const before = tellings();
    const nowhere = await run("--network", join(root, "nowhere"));
    expect(nowhere.code).toBe(2);
    expect(nowhere.err).toContain("no network is running from");
    expect(nowhere.out).toBe("");
    // A file that no network wrote is said before anything is told, and is the same mistake.
    const damaged = join(root, "damaged");
    mkdirSync(damaged);
    writeFileSync(join(damaged, NETWORK_FILE), "{}");
    const odd = await run("--network", damaged);
    expect(odd.code).toBe(2);
    expect(odd.err).toContain("is not what a running network wrote");
    expect(odd.out).toBe("");
    // Nothing of a telling that could not begin is left behind.
    expect(tellings()).toStrictEqual(before);
  });

  it("tells a failed check from a network that could not be used: each has its exit code, and one line", async () => {
    const before = tellings();
    // A network that has stopped: its file is there, and nothing answers where it says.
    const stale = join(root, "stale");
    mkdirSync(stale);
    writeFileSync(
      join(stale, NETWORK_FILE),
      JSON.stringify({
        ...LOCAL,
        routes: {
          [LOCAL.resolver]: "http://127.0.0.1:9",
          [LOCAL.host]: "http://127.0.0.1:9",
          [LOCAL.indexer]: "http://127.0.0.1:9",
        },
      }),
    );
    const gone = await run("--network", stale);
    expect(gone.code).toBe(3);
    expect(gone.err).toMatch(
      /^demo: the network could not be used: https:\/\/[a-z.]+ unreachable\. Is it still running\?\n$/u,
    );
    expect(gone.out).toContain("1. Identity");
    // A check that did not hold: the telling stops, says which, and exits with 1.
    const stopped = await runWith(
      {
        tell: (_stage, say) => {
          say("1. Identity");
          return Promise.reject(new NotSo("not so: a stranger resolves that address."));
        },
      },
      "--network",
      directory,
    );
    expect(stopped).toStrictEqual({
      code: 1,
      out: "1. Identity\n",
      err: "not so: a stranger resolves that address.\n",
    });
    // What the protocol refused, and what was asked for wrongly, are told apart too.
    const refused = await runWith(
      { tell: () => Promise.reject(new OipError("rate-limited", "slow down")) },
      "--network",
      directory,
    );
    expect(refused).toMatchObject({
      code: 3,
      err: "demo: the network could not be used: it answered rate-limited\n",
    });
    const lost = await runWith(
      {
        tell: () =>
          Promise.reject(new TransportError("timeout", "https://host.example", "too slow")),
      },
      "--network",
      directory,
    );
    expect(lost.code).toBe(3);
    const usage = await runWith(
      { tell: () => Promise.reject(new UsageError("the mind was never published")) },
      "--network",
      directory,
    );
    expect(usage).toMatchObject({ code: 2, err: "demo: the mind was never published\n" });
    // What nobody foresaw is thrown as it came, once the telling's directory is gone.
    await expect(
      runWith({ tell: () => Promise.reject(new RangeError("a bug")) }, "--network", directory),
    ).rejects.toThrow(RangeError);
    expect(tellings()).toStrictEqual(before);
  });

  it("ends as a telling ends where it is interrupted: its keys and its directory are removed", async () => {
    const before = tellings();
    const heard = new Map<string, () => void>();
    const written = { out: "", err: "" };
    let during: string[] = [];
    const code = await main(
      ["--network", directory],
      {
        stdout: { write: (text) => (written.out += text) },
        stderr: { write: (text) => (written.err += text) },
        once: (signal, listener) => heard.set(signal, listener),
      },
      {
        // A telling that is at work until it is interrupted, and never ends by itself.
        tell: async (stage) => {
          await stage.cast("amina", "human", { name: "Amina" });
          during = tellings();
          heard.get("SIGINT")?.();
          return new Promise(() => undefined);
        },
      },
    );
    expect(code).toBe(130);
    expect(written.err).toBe(
      "demo: interrupted. The telling's keys and its directory are removed\n",
    );
    expect([...heard.keys()].sort()).toStrictEqual(["SIGINT", "SIGTERM"]);
    // While it was at work its directory was there, with the keys of the cast in it.
    expect(during.length).toBe(before.length + 1);
    expect(tellings()).toStrictEqual(before);
  });

  it("keeps a telling as a recording where it is asked to: a terminal session and a picture", async () => {
    const kept = join(root, "kept", "recording");
    const done = await run("--network", directory, "--record", kept);
    expect(done.code).toBe(0);
    const cast = readFileSync(join(kept, "translation-demo.cast"), "utf8");
    const svg = readFileSync(join(kept, "translation-demo.svg"), "utf8");
    const told = done.out.split("\n\n").slice(0, -1).join("\n\n");
    expect(linesOf(cast).join("\n")).toBe(told.trimEnd());
    expect(svg.startsWith("<svg")).toBe(true);
    expect(done.out.trimEnd().endsWith(`lines recorded in ${kept}`)).toBe(true);
    // A telling that stopped is not kept.
    const none = join(root, "none");
    const stopped = await runWith(
      { tell: () => Promise.reject(new NotSo("not so")) },
      "--network",
      directory,
      "--record",
      none,
    );
    expect(stopped.code).toBe(1);
    expect(existsSync(none)).toBe(false);
  });

  it("plays on a network that runs already, and leaves what the minds published there", async () => {
    const done = await run("--network", directory);
    expect(done.err).toBe("");
    expect(done.code).toBe(0);
    expect(done.out).toContain("12. A collective");
    expect(done.out.trimEnd().endsWith("29 things were verified in this telling.")).toBe(true);
    // The telling is over, and its keys are gone. The network runs on, and anyone can read
    // what was published on it: a mind's log, its profile, and its feed.
    const amina = /Amina is (did:oip:[a-z2-7]+),/u.exec(done.out)?.[1] ?? "";
    const stranger = new Lookup(
      lookupOptions(
        {
          edges: { env: {}, home: root, keychain: () => Promise.reject(new Error("none")) },
          dir: root,
        },
        {
          resolvers: [LOCAL.resolver],
          indexers: [LOCAL.indexer],
          lock: "passphrase",
          network: directory,
        },
      ),
    );
    const resolved = await stranger.resolve(amina);
    expect((resolved.participant?.record as { name?: string } | undefined)?.name).toBe("Amina");
    const { feed } = await stranger.feed(amina);
    expect(feed.entries.map(({ entry }) => entry.objectType).sort()).toStrictEqual(
      ["Commitment", "Intent", "Receipt"].sort(),
    );
    // A second telling on the same network is a second cast: new minds, and the same outcome.
    const again = await run("--network", directory);
    expect(again.code).toBe(0);
    expect(/Amina is (did:oip:[a-z2-7]+),/u.exec(again.out)?.[1]).not.toBe(amina);
  });
});

describe("the place of a telling", () => {
  it("is removed when the telling ends, with the keys of the cast: a telling's passphrase opens no other telling's keys", async () => {
    const one = await Stage.open(directory);
    const other = await Stage.open(directory);
    try {
      const amina = await one.cast("amina", "human", { name: "Amina" });
      const her = await other.cast("amina", "human", { name: "Amina" });
      expect(existsSync(one.root) && existsSync(other.root)).toBe(true);
      // Sealed, and each under what its own telling made: one telling's lock opens its own
      // keys, and not the other's.
      const keys = (stage: Stage): ReturnType<typeof fileStorage> =>
        fileStorage(new Home(join(stage.root, "amina")).keys);
      expect(amina.mind.address).not.toBe(her.mind.address);
      const kept = await Keystore.open({ storage: keys(one) });
      await expect(kept.unlock("control", her.lock)).rejects.toThrow();
    } finally {
      await one.close();
      await other.close();
    }
    expect(existsSync(one.root) || existsSync(other.root)).toBe(false);
    // Closed twice, it is closed once.
    await expect(one.close()).resolves.toBeUndefined();
  });
});
