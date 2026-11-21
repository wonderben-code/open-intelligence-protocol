// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The Explorer on the demo network, as a program (`pnpm explorer:demo`):
 * what it takes, what it opens, and when it ends.
 *
 * What opens a browser needs one, and is skipped without: `OIP_CHROMIUM`,
 * as in `browser.test.ts`. The browser has no window here.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { LOCAL, type Network, startNetwork } from "@oip/cli";
import { NETWORK_FILE } from "@oip/local";
import { type Browser, chromium } from "playwright-core";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { type Edges, main } from "../demo/main.ts";
import { SETTINGS_KEY } from "../src/settings.ts";

const CHROMIUM = process.env["OIP_CHROMIUM"];

/** A Chromium with no window. */
const launch = (): Promise<Browser> =>
  chromium.launch(
    CHROMIUM === undefined || CHROMIUM === "installed" ? {} : { executablePath: CHROMIUM },
  );

let root: string;
let network: Network;
let directory: string;

beforeAll(async () => {
  // A network that runs before the program and after it, as `oip demo` runs one. Nobody is on it.
  root = mkdtempSync(join(tmpdir(), "oip-explorer-demo-test-"));
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

/** Runs the program, and gives what it wrote as it writes it. */
function run(argv: string[], edges: Edges = {}) {
  const written = { out: "", err: "" };
  const code = main(
    argv,
    {
      stdout: { write: (text) => (written.out += text) },
      stderr: { write: (text) => (written.err += text) },
      env: {},
    },
    edges,
  );
  return { code, written };
}

describe("pnpm explorer:demo", () => {
  it("says what it takes", async () => {
    const { code, written } = run(["--help"]);
    expect(await code).toBe(0);
    expect(written.out).toContain("pnpm explorer:demo --network <directory>");
    expect(written.out).toContain("OIP_CHROMIUM");
  });

  it("takes nothing else, and no network that is not there", async () => {
    for (const argv of [["--window"], ["somewhere"], ["--network", join(root, "nowhere")]]) {
      const { code, written } = run(argv);
      expect(await code).toBe(2);
      expect(written.err).toContain("`pnpm explorer:demo --help` shows what it takes");
      expect(written.out).toBe("");
    }
  });

  it("says so where no browser can be opened, and nothing of why", async () => {
    const { code, written } = run(["--network", directory], {
      launch: () => Promise.reject(new Error("no executable at /home/somebody/chrome")),
    });
    expect(await code).toBe(1);
    expect(written.err).toBe(
      "explorer: no browser could be opened. Set OIP_CHROMIUM to the path of a Chromium or a Chrome\n",
    );
  });

  it.skipIf(CHROMIUM === undefined)(
    "opens the Explorer on a network of its own, with the services chosen and the minds of the demo to be found",
    async () => {
      let listed: string[] = [];
      let start = "";
      const { code, written } = run([], {
        launch,
        visit: async (page) => {
          start = (await page.textContent("main")) ?? "";
          await page.getByRole("button", { name: "List the minds the indexers know" }).click();
          await page.getByRole("link", { name: "Amina", exact: true }).waitFor();
          listed = await page.locator("ul.minds > li").allTextContents();
        },
      });
      expect(await code).toBe(0);
      // A reader of this window has a resolver already.
      expect(start).not.toContain("No resolver is chosen yet.");
      expect(listed).toHaveLength(5);
      expect(written.out).toContain("The minds of the demo:");
      expect(written.out).toMatch(/\n {2}amina: did:oip:bciq[a-z2-7]{52}\n/u);
      expect(written.out).toMatch(/\n {2}the collective: did:oip:bciq[a-z2-7]{52}\n/u);
      expect(written.err).toBe("");
    },
  );

  it.skipIf(CHROMIUM === undefined)(
    "shows a network that runs already as it stands, and leaves a reader's own choice of services alone",
    async () => {
      const kept: (string | null)[] = [];
      const { code, written } = run(["--network", directory], {
        launch,
        visit: async (page) => {
          const read = () => page.evaluate((key) => localStorage.getItem(key), SETTINGS_KEY);
          kept.push(await read());
          // The reader chooses otherwise, and comes back.
          await page.evaluate(
            ([key, settings]) => {
              localStorage.setItem(key, settings);
            },
            [SETTINGS_KEY, JSON.stringify({ resolvers: [], indexers: [] })] as const,
          );
          await page.reload();
          kept.push(await read());
        },
      });
      expect(await code).toBe(0);
      expect(kept).toStrictEqual([
        JSON.stringify({ resolvers: [LOCAL.resolver], indexers: [LOCAL.indexer] }),
        JSON.stringify({ resolvers: [], indexers: [] }),
      ]);
      // Nothing was played on a network that is somebody's own.
      expect(written.out).not.toContain("The minds of the demo:");
    },
  );

  it.skipIf(CHROMIUM === undefined)("ends when its window is closed", async () => {
    const opened = launch();
    const { code, written } = run(["--network", directory], { launch: () => opened });
    await vi.waitFor(
      () => {
        expect(written.out).toContain("Close the window to end.");
      },
      { timeout: 20_000 },
    );
    const [page] = (await opened).contexts()[0]?.pages() ?? [];
    await page?.close();
    expect(await code).toBe(0);
  });
});
