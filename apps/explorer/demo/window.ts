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
 * is shipped. Nothing else is carried anywhere.
 */

import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { type NetworkFile, routed } from "@oip/local";
import type { Page } from "playwright-core";
import { build } from "vite";

/** Where the page believes the Explorer is. */
export const SITE = "https://explorer.oip.localhost";

const here = dirname(fileURLToPath(import.meta.url));

const TYPES: Readonly<Record<string, string>> = {
  html: "text/html; charset=utf-8",
  js: "text/javascript; charset=utf-8",
  css: "text/css; charset=utf-8",
};

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
 * Serves the site to a page, and carries the page's requests for the
 * network's three services to where they are.
 *
 * @param network - What the network says of itself: its origins, and the
 *   port of this machine behind each.
 */
export async function serveTo(
  page: Page,
  files: ReadonlyMap<string, string>,
  network: NetworkFile,
): Promise<void> {
  await page.route(`${SITE}/**`, (route) => {
    const { pathname } = new URL(route.request().url());
    const body = files.get(pathname === "/" ? "/index.html" : pathname);
    if (body === undefined) return route.fulfill({ status: 404, body: "no such file" });
    const type = TYPES[pathname.split(".").at(-1) ?? ""] ?? TYPES["html"] ?? "";
    return route.fulfill({ status: 200, contentType: type, body });
  });
  const carry = routed(network.routes, (request) => fetch(request));
  for (const origin of [network.resolver, network.host, network.indexer]) {
    await page.route(`${origin}/**`, async (route) => {
      const request = route.request();
      const body = request.postDataBuffer();
      const answer = await carry(
        new Request(request.url(), {
          method: request.method(),
          headers: request.headers(),
          ...(body === null ? {} : { body: new Uint8Array(body) }),
        }),
      );
      await route.fulfill({
        status: answer.status,
        headers: Object.fromEntries(answer.headers),
        body: Buffer.from(await answer.arrayBuffer()),
      });
    });
  }
}
