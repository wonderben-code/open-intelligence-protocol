// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The Explorer on the demo network, as a program: `pnpm explorer:demo`.
 *
 * It opens a window of Chromium with the Explorer in it, and the services
 * of a network on this machine already chosen. With nothing said, the
 * network is its own, with the scenario of the papers played on it: five
 * minds, their profiles, and the records of a deal. With `--network`, it is
 * one that runs already, as `oip demo` runs one, shown as it stands.
 *
 * The program ends when the window is closed.
 */

import { join } from "node:path";
import { parseArgs } from "node:util";

import { type NetworkFile, readNetwork, UsageError } from "@oip/local";
import { Stage, tell } from "@oip/translation-demo";
import { type Browser, chromium, type Page } from "playwright-core";

import { SETTINGS_KEY } from "../src/settings.ts";
import { buildSite, serveTo, SITE } from "./window.ts";

const HELP = [
  "The OIP Explorer in a window of Chromium, on a network of this machine.",
  "",
  "  pnpm explorer:demo                       On a network of its own, with the translation demo played on it",
  "  pnpm explorer:demo --network <directory> On a network that runs already: the directory of `oip demo`",
  "",
  "  --help                                   Show this",
  "",
  "The browser is Google Chrome, as it is installed. To use another Chromium,",
  "set OIP_CHROMIUM to its path, or to `installed` for the one Playwright installed.",
  "",
].join("\n");

/** What the program has of the process it runs in: `process` is one. */
export interface Host {
  readonly stdout: { write(text: string): unknown };
  readonly stderr: { write(text: string): unknown };
  readonly env: Readonly<Record<string, string | undefined>>;
}

/** What a test replaces. */
export interface Edges {
  /** Opens the browser. Default: a Chromium with a window. */
  readonly launch?: () => Promise<Browser>;
  /**
   * What is done with the page once the Explorer is open in it. The program
   * ends when this does. Default: wait until the window is closed.
   */
  readonly visit?: (page: Page) => Promise<void>;
}

/** A Chromium with a window: the one the environment names, or else the Chrome that is installed. */
function withWindow(env: Host["env"]): Promise<Browser> {
  const named = env["OIP_CHROMIUM"];
  if (named === undefined) return chromium.launch({ headless: false, channel: "chrome" });
  return chromium.launch({
    headless: false,
    ...(named === "installed" ? {} : { executablePath: named }),
  });
}

/** Until the window is closed, by its reader or with the browser. */
function untilClosed(page: Page): Promise<void> {
  return new Promise((resolve) => {
    page.once("close", () => {
      resolve();
    });
    page.context().once("close", () => {
      resolve();
    });
  });
}

/**
 * Runs the program.
 *
 * @param argv - Its arguments, without the program's own name.
 * @returns What it exits with: 0 after a visit, 1 if no browser could be
 *   opened, 2 for arguments it does not take or a network that is not there.
 */
export async function main(
  argv: readonly string[],
  host: Host,
  edges: Edges = {},
): Promise<number> {
  let directory: string | undefined;
  let stage: Stage | undefined;
  let network: NetworkFile;
  try {
    const { values, positionals } = parseArgs({
      args: [...argv],
      options: { network: { type: "string" }, help: { type: "boolean" } },
      strict: true,
      allowPositionals: true,
    });
    if (values.help === true) {
      host.stdout.write(HELP);
      return 0;
    }
    if (positionals.length > 0) throw new UsageError("it takes no argument but --network");
    directory = values.network;
    // A network that runs already says where it is. One that is not there is said so at once.
    if (directory !== undefined) readNetwork(directory);
  } catch (error) {
    host.stderr.write(
      `explorer: ${(error as Error).message}. \`pnpm explorer:demo --help\` shows what it takes\n`,
    );
    return 2;
  }

  const cast: string[] = [];
  try {
    if (directory === undefined) {
      host.stdout.write(
        "Starting a network on this machine, and playing the translation demo on it.\n",
      );
      stage = await Stage.open();
      const told = await tell(stage, () => undefined);
      for (const [name, address] of Object.entries(told.cast)) cast.push(`  ${name}: ${address}`);
      cast.push(`  the collective: ${told.collective}`);
      network = readNetwork(join(stage.root, "network"));
    } else {
      network = readNetwork(directory);
    }
    host.stdout.write("Building the Explorer.\n");
    const files = await buildSite();

    let browser: Browser;
    try {
      browser = await (edges.launch ?? (() => withWindow(host.env)))();
    } catch {
      // What a browser says of why it did not start is long, and names paths of this machine.
      host.stderr.write(
        "explorer: no browser could be opened. Set OIP_CHROMIUM to the path of a Chromium or a Chrome\n",
      );
      return 1;
    }
    try {
      // The window is the size its reader makes it.
      const context = await browser.newContext({ viewport: null });
      // The services of this network, chosen for a reader who has chosen none: it is what the
      // program is for. A reader's own choice, made in the page since, is left as it is.
      await context.addInitScript(
        ([site, key, settings]) => {
          if (location.origin === site && localStorage.getItem(key) === null) {
            localStorage.setItem(key, settings);
          }
        },
        [
          SITE,
          SETTINGS_KEY,
          JSON.stringify({ resolvers: [network.resolver], indexers: [network.indexer] }),
        ] as const,
      );
      const page = await context.newPage();
      await serveTo(page, files, network);
      await page.goto(`${SITE}/`);
      host.stdout.write(
        [
          "The Explorer is open, with this network's resolver and indexer chosen.",
          ...(cast.length === 0 ? [] : ["The minds of the demo:", ...cast]),
          "Close the window to end.",
          "",
        ].join("\n"),
      );
      await (edges.visit ?? untilClosed)(page);
      return 0;
    } finally {
      await browser.close();
    }
  } finally {
    await stage?.close();
  }
}
