// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The demo as a program: what it takes, what it exits with, and where it plays. */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { LOCAL, type Network, startNetwork } from "@oip/cli";
import { Lookup } from "@oip/client";
import { lookupOptions, NETWORK_FILE } from "@oip/local";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { main } from "../src/index.ts";

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
  const written = { out: "", err: "" };
  const code = await main(argv, {
    stdout: { write: (text) => (written.out += text) },
    stderr: { write: (text) => (written.err += text) },
  });
  return { code, ...written };
}

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
    const nowhere = await run("--network", join(root, "nowhere"));
    expect(nowhere.code).toBe(2);
    expect(nowhere.err).toContain("no network says where it is in");
    expect(nowhere.out).toBe("");
  });

  it("plays on a network that runs already, and leaves what the minds published there", async () => {
    const done = await run("--network", directory);
    expect(done.err).toBe("");
    expect(done.code).toBe(0);
    expect(done.out).toContain("12. A collective");
    expect(done.out.trimEnd().endsWith("27 things were verified in this telling.")).toBe(true);
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
