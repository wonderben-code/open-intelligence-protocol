// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The Explorer in a page of Chromium, on a network of this machine.
 *
 * A network that `oip demo` runs has services with HTTPS origins that no
 * certificate stands behind: `https://resolver.oip.localhost` and its like
 * are names, which the `oip` command carries to ports of this machine. A
 * browser asked for one would find nothing there.
 *
 * So the page is given the same last step. Its requests leave it by its own
 * `fetch`, with the page's own policy applied, are caught on their way out
 * of the browser, and are carried to where the network says its services
 * are. The site itself is served to the page in the same way, built as it
 * is shipped. Nothing else is carried anywhere, and nothing is fetched for
 * the page from anywhere else: a service that answers with a redirect has
 * its redirect handed to the page, which follows none.
 */

import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { type NetworkFile, routed } from "@oip/local";
import type { BrowserContext } from "playwright-core";
import { build } from "vite";

/** Where the page believes the Explorer is. */
export const SITE = "https://explorer.oip.localhost";

const here = dirname(fileURLToPath(import.meta.url));

const TYPES: Readonly<Record<string, string>> = {
  html: "text/html; charset=utf-8",
  js: "text/javascript; charset=utf-8",
  css: "text/css; charset=utf-8",
  map: "application/json",
  json: "application/json",
  svg: "image/svg+xml",
};
/** What a file of no type the site is known to have is served as: nothing a browser runs or shows. */
const NO_TYPE = "application/octet-stream";

/**
 * Builds the site as it is shipped, and writes nothing.
 *
 * @returns Its files, by path: `/index.html`, and what that asks for.
 */
export async function buildSite(): Promise<Map<string, string>> {
  const built = await build({
    configFile: join(here, "..", "vite.config.ts"),
    root: join(here, ".."),
    logLevel: "silent",
    build: { write: false },
  });
  const [bundle] = (Array.isArray(built) ? built : [built]) as {
    output: { fileName: string; code?: string; source?: string | Uint8Array }[];
  }[];
  const files = new Map<string, string>();
  for (const file of bundle?.output ?? []) {
    const text = file.code ?? file.source ?? "";
    files.set(`/${file.fileName}`, typeof text === "string" ? text : Buffer.from(text).toString());
  }
  return files;
}

/**
 * Serves the site to the pages of a browser's context, and carries their
 * requests for the network's three services to where they are.
 *
 * Every page of the context is served: a tab its reader opens from a link
 * is the Explorer too.
 *
 * @param network - What the network says of itself: its origins, and the
 *   port of this machine behind each.
 * @param send - What makes a request once it is routed. Default: `fetch`.
 */
export async function serveTo(
  context: BrowserContext,
  files: ReadonlyMap<string, string>,
  network: NetworkFile,
  send: (request: Request) => Promise<Response> = (request) => fetch(request),
): Promise<void> {
  await context.route(`${SITE}/**`, (route) => {
    const { pathname } = new URL(route.request().url());
    const name = pathname === "/" ? "/index.html" : pathname;
    const body = files.get(name);
    if (body === undefined) return route.fulfill({ status: 404, body: "no such file" });
    const type = TYPES[name.split(".").at(-1) ?? ""] ?? NO_TYPE;
    return route.fulfill({ status: 200, contentType: type, body });
  });
  const carry = routed(network.routes, send);
  for (const origin of [network.resolver, network.host, network.indexer]) {
    await context.route(`${origin}/**`, async (route) => {
      const request = route.request();
      const body = request.postDataBuffer();
      let answer: Response;
      try {
        answer = await carry(
          new Request(request.url(), {
            method: request.method(),
            headers: request.headers(),
            // Wherever a service points, nothing is fetched there for the page.
            redirect: "manual",
            ...(body === null ? {} : { body: new Uint8Array(body) }),
          }),
        );
      } catch {
        // Nothing listens where the network said its service is: the page is told what a
        // browser tells it of any service that is down.
        await route.abort("connectionrefused");
        return;
      }
      await route.fulfill({
        status: answer.status,
        headers: Object.fromEntries(answer.headers),
        body: Buffer.from(await answer.arrayBuffer()),
      });
    });
  }
}
