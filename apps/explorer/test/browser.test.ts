// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The Explorer in a real browser, against the demo network (BUILD.md,
 * M11): a resolver, a host and an indexer on ports of this machine, with
 * the scenario of the papers played on them.
 *
 * The site is built as it is shipped and served to a page of Chromium. The
 * page's requests to the three services leave it by its own `fetch`, are
 * caught on their way out, and are carried to the services as a network
 * would carry them. Every request the page makes is written down: the last
 * test reads the list.
 *
 * It needs a browser, and is skipped without one. Set `OIP_CHROMIUM` to the
 * path of a Chromium, or to `installed` for the one Playwright installed.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { LOCAL, type Network, startNetwork } from "@oip/cli";
import { NETWORK_FILE } from "@oip/local";
import { Stage, tell, type Told } from "@oip/translation-demo";
import { type Browser, chromium, type Page } from "playwright-core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { buildSite, serveTo, SITE } from "../demo/window.ts";

const CHROMIUM = process.env["OIP_CHROMIUM"];

describe.skipIf(CHROMIUM === undefined)("the Explorer in a browser", () => {
  let root: string;
  let network: Network;
  let stage: Stage;
  let told: Told;
  let browser: Browser;
  let page: Page;
  /** The origin of every request the page made, in order. */
  const asked: string[] = [];
  /** What the page wrote to its console as an error, and what it threw. */
  const errors: string[] = [];

  beforeAll(async () => {
    // The network first, then the scenario on it, as `oip demo` and `pnpm demo --network` do.
    root = mkdtempSync(join(tmpdir(), "oip-explorer-test-"));
    const directory = join(root, "network");
    network = await startNetwork({ directory });
    writeFileSync(
      join(directory, NETWORK_FILE),
      JSON.stringify({ ...LOCAL, routes: network.routes }),
    );
    stage = await Stage.open(directory);
    told = await tell(stage, () => undefined);

    // The site, built as it is shipped.
    const files = await buildSite();
    expect([...files.keys()]).toContain("/index.html");

    browser = await chromium.launch(
      CHROMIUM === undefined || CHROMIUM === "installed" ? {} : { executablePath: CHROMIUM },
    );
    page = await browser.newPage();
    page.on("console", (message) => {
      if (message.type() === "error") errors.push(message.text());
    });
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("request", (request) => asked.push(new URL(request.url()).origin));
    // The site's own files, and the three services, each reached where the network says it is.
    await serveTo(page.context(), files, { ...LOCAL, routes: network.routes });
  });
  afterAll(async () => {
    await browser.close();
    await stage.close();
    await network.stop();
    rmSync(root, { recursive: true, force: true });
  });

  it("asks nobody anything until its reader has chosen whom to ask", async () => {
    await page.goto(`${SITE}/`);
    await expect(page.getByRole("heading", { level: 1 }).textContent()).resolves.toBe(
      "OIP Explorer",
    );
    expect(await page.textContent("main")).toContain("No resolver is chosen yet.");
    expect(new Set(asked)).toStrictEqual(new Set([SITE]));
  });

  it("keeps the services its reader names, and refuses what is no HTTPS origin", async () => {
    await page.getByRole("link", { name: "Services", exact: true }).click();
    await page.getByLabel("Resolvers, one HTTPS origin to a line").fill("http://plain.example");
    await page.getByRole("button", { name: "Keep these" }).click();
    expect(await page.textContent("main")).toContain("Not an HTTPS origin");
    await page.getByLabel("Resolvers, one HTTPS origin to a line").fill(LOCAL.resolver);
    await page.getByLabel("Indexers, one HTTPS origin to a line").fill(LOCAL.indexer);
    await page.getByRole("button", { name: "Keep these" }).click();
    expect(await page.textContent("main")).toContain("Kept, in this browser.");
    expect(await page.title()).toBe("The services to ask · OIP Explorer");
  });

  it("lists the minds the indexer knows, and each is a way to its page", async () => {
    await page.getByRole("link", { name: "OIP Explorer", exact: true }).click();
    await page.getByRole("button", { name: "List the minds the indexers know" }).click();
    const amina = page.getByRole("link", { name: "Amina", exact: true });
    await amina.waitFor();
    const listed = await page.locator("ul.minds > li").allTextContents();
    expect(listed).toHaveLength(5);
    expect(listed.join("\n")).toContain("Lexis translation agent, agent");
    expect(listed.join("\n")).toContain("translate-legal-sw-en");
    // Narrowed by what a mind can do: one of the five translates Swahili.
    await page.getByLabel("Only minds that can do what these tags say (optional)").fill("lang:sw");
    await page.getByRole("button", { name: "List the minds the indexers know" }).click();
    await expect.poll(() => page.locator("ul.minds > li").count()).toBe(1);
    expect(await page.locator("ul.minds > li").textContent()).toContain("Lexis translation agent");
    await page.getByLabel("Only minds that can do what these tags say (optional)").fill("lang:xx");
    await page.getByRole("button", { name: "List the minds the indexers know" }).click();
    await page.getByText("The indexers that answered list no such mind.").waitFor();
    // Who was asked is said, with what each answered.
    expect(await page.textContent("section[aria-labelledby=browse-title]")).toContain(
      `${LOCAL.indexer}: answered, with 0 results`,
    );
    await page.getByLabel("Only minds that can do what these tags say (optional)").fill("");
    await page.getByRole("button", { name: "List the minds the indexers know" }).click();
    await amina.waitFor();
    await amina.click();
    await page.getByRole("heading", { name: "Verified in this browser" }).waitFor();
    expect(page.url()).toBe(`${SITE}/#/mind/${told.cast["amina"] ?? ""}`);
  });

  it("shows a mind: its log, its keys and what it says of itself, each verified in the page", async () => {
    const main = (await page.textContent("main")) ?? "";
    expect(main).toContain(told.cast["amina"]);
    expect(main).toContain("1 event of the identity log was verified here");
    expect(main).toContain("0. Genesis");
    expect(main).toContain("Signed by each control key it names:");
    expect(main).toContain("its own control keys");
    expect(await page.locator("ul.keys > li").count()).toBeGreaterThanOrEqual(2);
    expect(main).toContain("Still the mind's.");
    // What no signature settles is said to be the resolvers' word.
    expect(main).toContain("is the word of the resolvers you chose, as witnesses");
    // The profile's name, which is the mind's own word.
    expect(await page.locator("#said-title + p + dl dd").first().textContent()).toBe("Amina");
    expect(await page.title()).toBe("A mind · OIP Explorer");
    // Nothing was asked of the mind's home: the reader has not said to.
    expect(asked).not.toContain(LOCAL.host);
  });

  it("says why, with the clause of the specification behind each thing it shows", async () => {
    const why = page.locator("#log-title ~ details.why").first();
    await why.locator("summary").click();
    expect(await why.textContent()).toContain("Every signature was verified in this browser.");
    const links = await why
      .locator("a")
      .evaluateAll((all) => all.map((link) => [link.textContent, link.getAttribute("href")]));
    expect(links).toContainEqual([
      "core 4.4",
      "https://github.com/wonderben-code/open-intelligence-protocol/blob/main/spec/core.md#4-keys",
    ]);
    expect(await page.locator("details.why").count()).toBeGreaterThan(6);
  });

  it("reads the feed when its reader says so, and shows how each record stands", async () => {
    await page.getByRole("button", { name: "Read the feed" }).click();
    await page.locator("ol.entries").waitFor();
    const entries = await page.locator("ol.entries > li > h3").allTextContents();
    expect(entries).toStrictEqual(["0. Intent satisfied", "1. Commitment fulfilled", "2. Receipt"]);
    expect(await page.textContent("ol.entries")).toContain(told.commitment);
    // And what a checkpoint over the feed must say, worked out here.
    const feed = (await page.textContent("section[aria-labelledby=feed-title]")) ?? "";
    expect(feed).toContain("What a checkpoint over this feed says");
    expect(feed).toMatch(/Merkle rootbciq[a-z2-7]{52}/u);
    // The homes were asked now, and not before.
    expect(asked).toContain(LOCAL.host);
    // A picture of the page as it stands, where one is asked for: `OIP_EXPLORER_SHOT=<file>`.
    const shot = process.env["OIP_EXPLORER_SHOT"];
    if (shot !== undefined) await page.screenshot({ path: shot, fullPage: true });
    // The record itself can be read, as text.
    await page.locator("ol.entries > li").nth(1).locator("details > summary").first().click();
    expect(await page.locator("ol.entries > li").nth(1).locator("pre").textContent()).toContain(
      '"type": "Commitment"',
    );
  });

  it("looks up an address that is typed, and says so where what is typed is none", async () => {
    await page.getByRole("link", { name: "OIP Explorer", exact: true }).click();
    await page.getByLabel("The address of a mind").fill("did:oip:not-an-address");
    await page.getByRole("button", { name: "Look it up" }).click();
    expect(await page.textContent("main")).toContain("That is no address of a mind.");
    await page.getByLabel("The address of a mind").fill(told.collective);
    await page.getByRole("button", { name: "Look it up" }).click();
    await page.getByRole("heading", { name: "Verified in this browser" }).waitFor();
    const main = (await page.textContent("main")) ?? "";
    expect(main).toContain("its members, a collective: 2 of 3 members must sign");
    expect(main).toContain("Signed by each of its founding members:");
    for (const name of ["amina", "lexis-agent", "researcher"]) {
      expect(main, name).toContain(told.cast[name]);
    }
    // A collective signs by its members: it has no key of its own.
    expect(main).toContain("A collective signs by its members.");
    // Up to here nothing the page did failed, or was refused by its own policy.
    expect(errors).toStrictEqual([]);
    // A mind nobody knows of is said to be unknown, and nothing else is shown.
    await page.goto(`${SITE}/#/mind/did:oip:bciq${"a".repeat(52)}`);
    await page.locator("div.failed").waitFor();
    expect(await page.textContent("main")).toContain("This mind could not be shown");
    await page.goto(`${SITE}/#/elsewhere`);
    await page.getByRole("heading", { name: "No such page" }).waitFor();
  });

  it("sends nothing anywhere but to the services its reader chose, and to the homes it was told to read", () => {
    expect(new Set(asked)).toStrictEqual(
      new Set([SITE, LOCAL.resolver, LOCAL.indexer, LOCAL.host]),
    );
    // The one thing that failed is the one that was asked to: a resolver that knows of no such
    // mind says so, and the browser notes the answer.
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.every((error) => error.includes("404 (Not Found)"))).toBe(true);
  });
});
