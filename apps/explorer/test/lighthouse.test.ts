// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The Explorer under Lighthouse (BUILD.md, M11): accessibility, performance
 * and best practices, each at 95 or more of 100.
 *
 * The site is built as it is shipped and served from this machine as a
 * static host serves one, compressed. Lighthouse loads the pages a reader
 * meets before choosing any service: the start page and the page of the
 * services. Those need no network of minds. The pages that show one are
 * walked through in `browser.test.ts`.
 *
 * It needs a browser, and is skipped without one: `OIP_CHROMIUM`, as there.
 */

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

import lighthouse from "lighthouse";
import { type Browser, chromium } from "playwright-core";
import { build } from "vite";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const CHROMIUM = process.env["OIP_CHROMIUM"];
const here = dirname(fileURLToPath(import.meta.url));
/** What BUILD.md asks of each score, of 1. */
const LEAST = 0.95;

const TYPES: Readonly<Record<string, string>> = {
  html: "text/html; charset=utf-8",
  js: "text/javascript; charset=utf-8",
  css: "text/css; charset=utf-8",
};

/** A port of this machine that nothing listens on. */
async function freePort(): Promise<number> {
  const probe = createServer();
  await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const { port } = probe.address() as AddressInfo;
  await new Promise((resolve) => probe.close(resolve));
  return port;
}

describe.skipIf(CHROMIUM === undefined)("the Explorer under Lighthouse", () => {
  let server: Server;
  let browser: Browser;
  let site: string;
  let debugging: number;

  beforeAll(async () => {
    const built = await build({
      configFile: join(here, "..", "vite.config.ts"),
      root: join(here, ".."),
      logLevel: "silent",
      build: { write: false },
    });
    const [bundle] = (Array.isArray(built) ? built : [built]) as {
      output: { fileName: string; code?: string; source?: string | Uint8Array }[];
    }[];
    const files = new Map<string, Buffer>();
    for (const file of bundle?.output ?? []) {
      const text = file.code ?? file.source ?? "";
      files.set(`/${file.fileName}`, gzipSync(Buffer.from(text)));
    }
    // A static host: each file with its type, compressed, and the built files kept by a browser.
    server = createServer((request, response) => {
      const { pathname } = new URL(request.url ?? "/", "http://localhost");
      const path = pathname === "/" ? "/index.html" : pathname;
      const body = files.get(path);
      if (body === undefined) {
        response.writeHead(404, { "content-type": "text/plain" }).end("no such file");
        return;
      }
      response
        .writeHead(200, {
          "content-type": TYPES[path.split(".").at(-1) ?? ""] ?? "application/octet-stream",
          "content-encoding": "gzip",
          "cache-control": path.startsWith("/assets/")
            ? "public, max-age=31536000, immutable"
            : "no-cache",
        })
        .end(body);
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    site = `http://127.0.0.1:${String((server.address() as AddressInfo).port)}`;
    debugging = await freePort();
    browser = await chromium.launch({
      ...(CHROMIUM === undefined || CHROMIUM === "installed" ? {} : { executablePath: CHROMIUM }),
      args: [`--remote-debugging-port=${String(debugging)}`],
    });
  });
  afterAll(async () => {
    await browser.close();
    await new Promise((resolve) => server.close(resolve));
  });

  it.each([
    ["the start page", "/"],
    ["the page of the services", "/#/settings"],
  ])(
    "scores %s at 95 or more for accessibility, performance and best practices",
    async (_, path) => {
      const run = await lighthouse(`${site}${path}`, {
        port: debugging,
        output: "json",
        logLevel: "error",
        onlyCategories: ["accessibility", "performance", "best-practices"],
      });
      const categories = run?.lhr.categories ?? {};
      const scores = Object.fromEntries(
        Object.entries(categories).map(([name, category]) => [name, category.score ?? 0]),
      );
      // What cost a point is said, so that a run that fails says why.
      const audits = run?.lhr.audits ?? {};
      const lost = Object.values(audits)
        .filter(
          (audit) =>
            audit.score !== null && audit.score < 0.9 && audit.scoreDisplayMode !== "informative",
        )
        .map((audit) => `${audit.id}: ${audit.displayValue ?? String(audit.score)}`);
      expect(Object.keys(scores).sort()).toStrictEqual([
        "accessibility",
        "best-practices",
        "performance",
      ]);
      for (const [name, score] of Object.entries(scores)) {
        expect(score, `${name}, with ${lost.join("; ")}`).toBeGreaterThanOrEqual(LEAST);
      }
    },
  );
});
