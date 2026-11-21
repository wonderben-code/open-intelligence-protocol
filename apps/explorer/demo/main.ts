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
 * The program ends when the window is closed, or when it is interrupted.
 * Either way it stops the network it started, and removes that network's
 * directory with the keys in it.
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
  "If no browser opens, OIP_EXPLORER_WHY=1 shows what the browser said of it.",
  "",
  "It ends with 0 after a visit, 1 if no browser could be opened, 2 for arguments it",
  "does not take or a network that is not there, 3 if the network could not be used,",
  "and 130 when it is interrupted.",
  "",
].join("\n");

/** The signals that end a program a person runs in a terminal. */
const SIGNALS = ["SIGINT", "SIGTERM", "SIGHUP"] as const;

/** What the program has of the process it runs in: `process` is one. */
export interface Host {
  readonly stdout: { write(text: string): unknown };
  readonly stderr: { write(text: string): unknown };
  readonly env: Readonly<Record<string, string | undefined>>;
  /** Called once when the process is sent a signal. A host that has none is never interrupted. */
  once?(signal: (typeof SIGNALS)[number], listener: () => void): unknown;
}

/** What a test replaces. */
export interface Edges {
  /** Opens the browser. Default: a Chromium with a window. */
  readonly launch?: () => Promise<Browser>;
  /** Builds the site. Default: as it is shipped. */
  readonly build?: () => Promise<Map<string, string>>;
  /**
   * What is done with the page once the Explorer is open in it. The program
   * ends when this does. Default: wait until the window is closed.
   */
  readonly visit?: (page: Page) => Promise<void>;
}

/**
 * A Chromium with a window: the one the environment names, or else the Chrome that is installed.
 *
 * The browser is not left to end the process on a signal: the program ends
 * the visit itself, so that what it started is stopped and removed.
 */
function withWindow(env: Host["env"]): Promise<Browser> {
  const named = env["OIP_CHROMIUM"];
  const ours = { headless: false, handleSIGINT: false, handleSIGTERM: false, handleSIGHUP: false };
  if (named === undefined) return chromium.launch({ ...ours, channel: "chrome" });
  return chromium.launch({ ...ours, ...(named === "installed" ? {} : { executablePath: named }) });
}

/** The first line of what something said when it failed. */
const firstLine = (error: unknown): string =>
  (error instanceof Error ? error.message : String(error)).split("\n")[0] ?? "";

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
 *   opened, 2 for arguments it does not take or a network that is not there,
 *   3 if the network could not be used, 130 if it was interrupted.
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

  // A signal ends the visit, and the program then ends as after any visit: nothing is left behind.
  const interrupted = new Promise<"interrupted">((resolve) => {
    for (const signal of SIGNALS) {
      host.once?.(signal, () => {
        resolve("interrupted");
      });
    }
  });
  const cast: string[] = [];
  try {
    let files: Map<string, string>;
    try {
      if (directory === undefined) {
        host.stdout.write(
          "Starting a network on this machine, and playing the translation demo on it.\n",
        );
        stage = await Stage.open();
        const told = await tell(stage, () => undefined);
        for (const [name, address] of Object.entries(told.cast)) {
          cast.push(`  ${name}: ${address}`);
        }
        cast.push(`  the collective: ${told.collective}`);
        network = readNetwork(join(stage.root, "network"));
      } else {
        network = readNetwork(directory);
      }
      host.stdout.write("Building the Explorer.\n");
      files = await (edges.build ?? buildSite)();
    } catch (error) {
      // One line, and no stack: what failed is the network or the build, and not the reader.
      host.stderr.write(`explorer: the network could not be used: ${firstLine(error)}\n`);
      return 3;
    }

    let browser: Browser;
    try {
      browser = await (edges.launch ?? (() => withWindow(host.env)))();
    } catch (error) {
      // What a browser says of why it did not start is long, and names paths of this machine:
      // it is shown to whoever asks for it.
      host.stderr.write(
        "explorer: no browser could be opened. Set OIP_CHROMIUM to the path of a Chromium or a Chrome" +
          (host.env["OIP_EXPLORER_WHY"] === undefined
            ? ", or OIP_EXPLORER_WHY=1 to see what the browser said\n"
            : `\nexplorer: the browser said: ${firstLine(error)}\n`),
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
      await serveTo(context, files, network);
      const page = await context.newPage();
      await page.goto(`${SITE}/`);
      host.stdout.write(
        [
          "The Explorer is open, with this network's resolver and indexer chosen.",
          ...(cast.length === 0 ? [] : ["The minds of the demo:", ...cast]),
          "Close the window to end.",
          "",
        ].join("\n"),
      );
      const ended = await Promise.race([
        (edges.visit ?? untilClosed)(page).then(() => "visited" as const),
        interrupted,
      ]);
      return ended === "interrupted" ? 130 : 0;
    } finally {
      await browser.close();
    }
  } finally {
    await stage?.close();
  }
}
