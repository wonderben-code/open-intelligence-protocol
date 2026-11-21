// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The Explorer on the demo network, as a program (`pnpm explorer:demo`):
 * what it takes, what it opens, and when it ends.
 *
 * What opens a browser needs one, and is skipped without: `OIP_CHROMIUM`,
 * as in `browser.test.ts`. The browser has no window here.
 */

import { mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { LOCAL, type Network, startNetwork } from "@oip/cli";
import { NETWORK_FILE } from "@oip/local";
import { type Browser, chromium } from "playwright-core";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { type Edges, type Host, main } from "../demo/main.ts";
import { buildSite, serveTo, SITE } from "../demo/window.ts";
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

/** Runs the program, and gives what it wrote as it writes it, and what sends it a signal. */
function run(argv: string[], edges: Edges = {}, env: Host["env"] = {}) {
  const written = { out: "", err: "" };
  const signals = new Map<string, () => void>();
  const code = main(
    argv,
    {
      stdout: { write: (text) => (written.out += text) },
      stderr: { write: (text) => (written.err += text) },
      env,
      once: (signal, listener) => signals.set(signal, listener),
    },
    edges,
  );
  return { code, written, signal: (name: string) => signals.get(name)?.() };
}

/** A server on a port of this machine that notes what it is asked, and answers as it is told. */
async function listening(
  answer: (path: string) => { status: number; headers?: Record<string, string>; body?: string },
): Promise<{ at: string; asked: string[]; stop: () => Promise<void> }> {
  const asked: string[] = [];
  const server: Server = createServer((request, response) => {
    asked.push(`${request.method ?? ""} ${request.url ?? ""}`);
    const { status, headers = {}, body = "" } = answer(request.url ?? "");
    response.writeHead(status, headers).end(body);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    at: `http://127.0.0.1:${String((server.address() as AddressInfo).port)}`,
    asked,
    stop: () =>
      new Promise((resolve) => {
        server.close(() => {
          resolve();
        });
        server.closeAllConnections();
      }),
  };
}

/** The telling's directories that a run left in a directory for temporary files. */
const leftIn = (temporary: string): string[] =>
  readdirSync(temporary).filter((name) => name.startsWith("oip-translation-demo-"));

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

  it("says so where no browser can be opened, and why only to whoever asks", async () => {
    const launch = () =>
      Promise.reject(
        new Error("no executable at /home/somebody/chrome\n    at launch (file.js:1)"),
      );
    const quiet = run(["--network", directory], { launch });
    expect(await quiet.code).toBe(1);
    expect(quiet.written.err).toBe(
      "explorer: no browser could be opened. Set OIP_CHROMIUM to the path of a Chromium or a Chrome, or OIP_EXPLORER_WHY=1 to see what the browser said\n",
    );
    const asking = run(["--network", directory], { launch }, { OIP_EXPLORER_WHY: "1" });
    expect(await asking.code).toBe(1);
    // The first line of it, and no stack.
    expect(asking.written.err).toBe(
      "explorer: no browser could be opened. Set OIP_CHROMIUM to the path of a Chromium or a Chrome\n" +
        "explorer: the browser said: no executable at /home/somebody/chrome\n",
    );
  });

  it("says in one line that a network could not be used, and opens nothing", async () => {
    let opened = false;
    const { code, written } = run(["--network", directory], {
      build: () => Promise.reject(new Error("the site does not build\n    at build (file.js:1)")),
      launch: () => {
        opened = true;
        return Promise.reject(new Error("unused"));
      },
    });
    expect(await code).toBe(3);
    expect(written.err).toBe("explorer: the network could not be used: the site does not build\n");
    expect(opened).toBe(false);
  });

  it("stops the network it started and removes its directory, with the keys in it, however it ends", async () => {
    // The telling's directory is made where temporary files go: a place of this test's own.
    const temporary = mkdtempSync(join(tmpdir(), "oip-x-"));
    vi.stubEnv("TMPDIR", temporary);
    try {
      let seen: string[] = [];
      const { code } = run([], {
        build: () => Promise.resolve(new Map()),
        launch: () => {
          // The network is up, and its directory is there, when the browser is asked for.
          seen = leftIn(temporary);
          return Promise.reject(new Error("no browser"));
        },
      });
      expect(await code).toBe(1);
      expect(seen).toHaveLength(1);
      expect(leftIn(temporary)).toStrictEqual([]);
    } finally {
      vi.unstubAllEnvs();
      rmSync(temporary, { recursive: true, force: true });
    }
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

  it.skipIf(CHROMIUM === undefined)(
    "ends when it is interrupted, with the browser closed and nothing of its network left behind",
    async () => {
      const temporary = mkdtempSync(join(tmpdir(), "oip-x-"));
      vi.stubEnv("TMPDIR", temporary);
      try {
        const opened = launch();
        // A visit that never ends by itself: the window stays open.
        const { code, written, signal } = run([], {
          launch: () => opened,
          visit: () => new Promise(() => undefined),
        });
        await vi.waitFor(
          () => {
            expect(written.out).toContain("Close the window to end.");
          },
          { timeout: 60_000 },
        );
        expect(leftIn(temporary)).toHaveLength(1);
        signal("SIGINT");
        expect(await code).toBe(130);
        expect((await opened).isConnected()).toBe(false);
        expect(leftIn(temporary)).toStrictEqual([]);
      } finally {
        vi.unstubAllEnvs();
        rmSync(temporary, { recursive: true, force: true });
      }
    },
  );

  it.skipIf(CHROMIUM === undefined)(
    "tells the page that a service is down as a browser would, and goes on",
    async () => {
      // A network whose services are where nothing listens: as after `oip demo` was stopped.
      const gone = await listening(() => ({ status: 200 }));
      await gone.stop();
      const down = mkdtempSync(join(tmpdir(), "oip-explorer-down-"));
      writeFileSync(
        join(down, NETWORK_FILE),
        JSON.stringify({
          ...LOCAL,
          routes: { [LOCAL.resolver]: gone.at, [LOCAL.host]: gone.at, [LOCAL.indexer]: gone.at },
        }),
      );
      try {
        let said = "";
        const { code, written } = run(["--network", down], {
          launch,
          visit: async (page) => {
            await page.goto(`${SITE}/#/mind/did:oip:bciq${"a".repeat(52)}`);
            await page.getByText("This mind could not be shown").waitFor();
            said = (await page.textContent("main")) ?? "";
          },
        });
        expect(await code).toBe(0);
        expect(said).toContain(`${LOCAL.resolver}: the service could not be reached`);
        expect(written.err).toBe("");
      } finally {
        rmSync(down, { recursive: true, force: true });
      }
    },
  );

  it.skipIf(CHROMIUM === undefined)(
    "fetches nothing for the page from where a service points, and carries the page's requests to the network's three services only",
    async () => {
      const elsewhere = await listening(() => ({ status: 200, body: "{}" }));
      const pointing = await listening(() => ({
        status: 302,
        headers: { location: `${elsewhere.at}/admin/secret` },
      }));
      const FOURTH = "https://fourth.oip.localhost";
      const browser = await launch();
      try {
        const context = await browser.newContext();
        await serveTo(context, await buildSite(), {
          ...LOCAL,
          routes: {
            [LOCAL.resolver]: pointing.at,
            [LOCAL.host]: pointing.at,
            [LOCAL.indexer]: pointing.at,
            // A route that the network's file has, and that is none of its three services.
            [FOURTH]: elsewhere.at,
          },
        });
        const page = await context.newPage();
        await page.goto(`${SITE}/`);
        const fetched = (url: string): Promise<string> =>
          page.evaluate(
            (asked) =>
              fetch(asked, { redirect: "error" }).then(
                (answer) => `answered ${String(answer.status)}`,
                () => "failed",
              ),
            url,
          );
        // The service was asked, and its redirect came to the page, which follows none.
        expect(await fetched(`${LOCAL.resolver}/oip/v1/resolve/x`)).toBe("failed");
        expect(pointing.asked).toStrictEqual(["GET /oip/v1/resolve/x"]);
        // No origin but the three is carried anywhere.
        expect(await fetched(`${FOURTH}/x`)).toBe("failed");
        expect(elsewhere.asked).toStrictEqual([]);
        // A tab its reader opens is the Explorer too.
        const second = await context.newPage();
        await second.goto(`${SITE}/#/settings`);
        expect(await second.title()).toBe("The services to ask · OIP Explorer");
      } finally {
        await browser.close();
        await pointing.stop();
        await elsewhere.stop();
      }
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
