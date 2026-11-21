// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The client in a real browser (BUILD.md, M6): the scenario of the papers,
 * run in a page of Chromium, against the real resolver, host and indexer.
 *
 * The services run in this process, as in the client's other tests. The
 * page's requests leave the browser by its own `fetch`, are caught on
 * their way out, and are answered here by the services. Nothing listens on
 * a socket.
 *
 * What it shows: that the client and the keystore run in a browser as they
 * are, with its `fetch`, its `WebSocket`, its randomness, its clock and its IndexedDB, and
 * need nothing of Node.js; and that the services let a page of another
 * origin read what they answer.
 *
 * The layer that catches the requests answers a browser's preflight
 * itself, so the browser's own never reaches a service. Each test
 * therefore asks the services afterwards, for every request the page made,
 * what a browser asks first, and checks that the answer gives leave.
 *
 * It needs a browser, and is skipped without one. Set `OIP_CHROMIUM` to the
 * path of a Chromium, or to `installed` for the one Playwright installed.
 */

import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { clause } from "@oip/testkit";
import { type Browser, chromium, type Page as BrowserPage } from "playwright-core";
import { build } from "vite";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { sourceAliases } from "../../../scripts/lib/source-aliases.ts";
import type { Page } from "./browser/page.ts";
import { World } from "./world.ts";

const CHROMIUM = process.env["OIP_CHROMIUM"];
const here = dirname(fileURLToPath(import.meta.url));

const APP = "https://app.example";
const A = "https://resolver.example";
const HOME = "https://home.example";
const X = "https://indexer.example";

declare const oip: Page;

/** The headers a browser sets itself, which it asks no leave for (Fetch, "forbidden request-header"). */
const OF_THE_BROWSER =
  /^(?:accept-encoding|connection|content-length|cookie|host|origin|referer|user-agent|sec-.*)$/u;
/** The headers any page may send, with a value of the usual kind (Fetch, "CORS-safelisted request-header"). */
const ANY_PAGE_MAY = /^(?:accept|accept-language|content-language)$/u;
/** The content types a form can send. */
const OF_A_FORM =
  /^(?:application\/x-www-form-urlencoded|multipart\/form-data|text\/plain)(?:;|$)/iu;

/** The headers of a request that a browser asks leave to send to another origin, in order. */
function unsafeHeaders(headers: Readonly<Record<string, string>>): string[] {
  return Object.entries(headers)
    .filter(
      ([name, value]) =>
        !OF_THE_BROWSER.test(name) &&
        !ANY_PAGE_MAY.test(name) &&
        !(name === "content-type" && OF_A_FORM.test(value)),
    )
    .map(([name]) => name)
    .sort();
}

describe.skipIf(CHROMIUM === undefined)("the client in a browser", () => {
  let browser: Browser;
  let script: string;
  let world: World;
  let page: BrowserPage;
  /** What the page asked of other origins, as `METHOD url`. */
  let asked: string[];
  /** The same requests, with the headers they carried. */
  let sent: { method: string; url: string; headers: Record<string, string> }[];

  /**
   * The requests the page made that their service would not give a browser
   * leave to make (Fetch, "CORS-preflight request"): empty if all would pass.
   */
  async function withoutLeave(): Promise<string[]> {
    const refused: string[] = [];
    for (const { method, url, headers } of sent) {
      const wanted = unsafeHeaders(headers);
      // A request a form could make is sent without asking.
      if (wanted.length === 0 && ["GET", "HEAD", "POST"].includes(method)) continue;
      const answer = await world.direct(
        new Request(url, {
          method: "OPTIONS",
          headers: {
            origin: APP,
            "access-control-request-method": method,
            ...(wanted.length === 0 ? {} : { "access-control-request-headers": wanted.join(",") }),
          },
        }),
      );
      const listed = (name: string): string[] =>
        (answer.headers.get(name) ?? "").split(",").map((item) => item.trim().toLowerCase());
      const origin = answer.headers.get("access-control-allow-origin");
      const allowed =
        answer.ok &&
        (origin === "*" || origin === APP) &&
        listed("access-control-allow-methods").includes(method.toLowerCase()) &&
        wanted.every((name) => listed("access-control-allow-headers").includes(name));
      if (!allowed) refused.push(`${method} ${url} with ${wanted.join(", ")}`);
    }
    return refused;
  }
  const errors: string[] = [];

  beforeAll(async () => {
    // The page's script: the client and the keystore from source, as a browser would be given them.
    const built = await build({
      configFile: false,
      logLevel: "silent",
      root: join(here, ".."),
      resolve: { alias: sourceAliases },
      build: {
        write: false,
        minify: false,
        lib: { entry: join(here, "browser", "page.ts"), formats: ["iife"], name: "oipPage" },
      },
    });
    const [output] = Array.isArray(built) ? built : [built];
    script = (output as { output: { code?: string }[] }).output[0]?.code ?? "";
    expect(script.length).toBeGreaterThan(1000);
    browser = await chromium.launch(
      CHROMIUM === undefined || CHROMIUM === "installed" ? {} : { executablePath: CHROMIUM },
    );
  });
  afterAll(async () => {
    await browser.close();
  });

  beforeEach(async () => {
    world = new World(0);
    // The browser reads the machine's clock, and so do the services it talks to.
    world.clock.now = () => BigInt(Date.now()) * 1_000_000n;
    world.resolver(A);
    world.host(HOME);
    asked = [];
    sent = [];
    page = await browser.newPage();
    page.on("pageerror", (error) => errors.push(error.message));
    await page.route("**/*", async (route) => {
      const request = route.request();
      const url = new URL(request.url());
      if (url.origin === APP) {
        await route.fulfill({
          status: 200,
          contentType: "text/html; charset=utf-8",
          body: `<!doctype html><meta charset="utf-8"><title>OIP</title><script>${script}</script>`,
        });
        return;
      }
      asked.push(`${request.method()} ${request.url()}`);
      try {
        const body = request.postDataBuffer();
        const headers = await request.allHeaders();
        sent.push({ method: request.method(), url: request.url(), headers });
        const response = await world.direct(
          new Request(request.url(), {
            method: request.method(),
            headers,
            ...(body === null ? {} : { body }),
          }),
        );
        await route.fulfill({
          status: response.status,
          headers: Object.fromEntries(response.headers),
          body: Buffer.from(await response.arrayBuffer()),
        });
      } catch {
        await route.abort("connectionrefused");
      }
    });
    // A WebSocket the page opens is the browser's own. Its other end is the host's binding.
    await page.routeWebSocket(/^wss:/u, (socket) => {
      const inner = world.socket(socket.url(), "oip.v1");
      inner.onmessage = ({ data }) => {
        socket.send(String(data));
      };
      inner.onclose = ({ code, reason }) => {
        void socket.close({
          ...(code === undefined ? {} : { code }),
          ...(reason === undefined ? {} : { reason }),
        });
      };
      socket.onMessage((message) => {
        inner.send(String(message));
      });
      socket.onClose(() => {
        inner.close();
      });
    });
    await page.goto(`${APP}/`);
  });
  afterEach(async () => {
    await page.close();
    world.close();
    expect(errors).toStrictEqual([]);
  });

  it(`${clause("L2 7.3", "L2 8.3", "L1 12.6", "L1 13.3")} runs the scenario of the papers: a deal an agent signs for its firm, sealed packets and signed requests`, async () => {
    const output = await page.evaluate(([resolvers, home]) => oip.deal(resolvers, home), [
      [A],
      HOME,
    ] as const);
    expect(output).toStrictEqual([
      "Amina's Intent is open",
      "the Commitment is proposed",
      "it binds the firm: true",
      "with her proof it is accepted",
      "and her Intent is satisfied",
      "the firm says it delivered: claimed-fulfilled",
      "Amina confirms: fulfilled",
    ]);
    // It was the page that talked to the services: signed publications, and packets to an inbox.
    expect(asked.some((request) => request.startsWith(`PUT ${A}/oip/v1/resolve/`))).toBe(true);
    expect(asked.some((request) => /^POST .*\/inbox$/u.test(request))).toBe(true);
    expect(asked.some((request) => /^GET .*\/mailbox$/u.test(request))).toBe(true);
    // Signed requests carry headers a browser asks leave for, and it would have had it.
    expect(sent.some(({ headers }) => unsafeHeaders(headers).includes("signature"))).toBe(true);
    expect(await withoutLeave()).toStrictEqual([]);
  });

  it(`${clause("L1 18.1", "L1 18.4")} lists a mind at an indexer and finds it, from a page`, async () => {
    const indexer = world.indexer(X);
    expect(await world.publish(A, indexer.mind)).toBe(202);
    const output = await page.evaluate((services) => oip.find(services), {
      resolvers: [A],
      indexers: [X],
      home: HOME,
    });
    expect(output).toStrictEqual([
      "listed by 1 indexer",
      "the indexer named 1 record",
      'found: Ada, for "Translation of legal texts", score 1',
      "named and not returned: 0",
    ]);
    expect(asked.some((request) => request === `POST ${X}/oip/v1/query`)).toBe(true);
    expect(await withoutLeave()).toStrictEqual([]);
  });

  it(`${clause("L1 13.4")} listens at its host over the browser's own WebSocket, and hears what is sent`, async () => {
    const output = await page.evaluate(([resolvers, home]) => oip.listen(resolvers, home), [
      [A],
      HOME,
    ] as const);
    expect(output).toStrictEqual([
      "the socket is connecting",
      "the socket is open",
      "Bob hears from Ada: Sent while you were away.",
      "Bob hears from Ada: Sent while you listen.",
      "Bob heard 2 packets, and listens no more",
    ]);
    // The socket was the page's, and what it sent was signed there: a Hello, and its own Acks.
    expect(world.sockets).toHaveLength(1);
    const said = (world.sockets[0]?.fromClient ?? []).map(
      (text) => (JSON.parse(text) as { type: string }).type,
    );
    expect(said).toStrictEqual(["Hello", "Ack", "Ack"]);
  });

  it(`${clause("L1 3.11")} keeps a mind's keys in the browser's own storage, sealed, and opens the mind from it again`, async () => {
    const output = await page.evaluate((resolvers) => oip.kept(resolvers), [A]);
    expect(output).toStrictEqual([
      "the same mind: true",
      "it signs: 1 proof",
      "a wrong passphrase opens it: false",
    ]);
    expect(await withoutLeave()).toStrictEqual([]);
  });
});
