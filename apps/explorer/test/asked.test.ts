// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Whom the page asks: the one place where the rule is kept. */

import { describe, expect, it } from "vitest";

import { Asked } from "../src/oip/asked.ts";

const RESOLVER = "https://resolver.example";
const INDEXER = "https://indexer.example";
const HOME = "https://home.example";
const OTHER = "https://tracker.example";

/** An `Asked` over something that notes each request in place of making it. */
function watched() {
  const made: string[] = [];
  const asked = new Asked([RESOLVER, INDEXER], (request) => {
    made.push(`${request.method} ${request.url}`);
    return Promise.resolve(new Response("{}"));
  });
  const ask = async (url: string, method = "GET"): Promise<string> => {
    try {
      await asked.fetch(new Request(url, { method }));
      return "asked";
    } catch (error) {
      return error instanceof TypeError ? "not asked" : "failed";
    }
  };
  return { asked, made, ask };
}

describe("whom the page asks", () => {
  it("asks the services its reader chose, at any path, and nobody else", async () => {
    const { asked, made, ask } = watched();
    expect(await ask(`${RESOLVER}/oip/v1/resolve/x`)).toBe("asked");
    expect(await ask(`${INDEXER}/oip/v1/query`, "POST")).toBe("asked");
    expect(await ask(`${HOME}/.well-known/oip/mind/x/feed`)).toBe("not asked");
    expect(await ask(`${OTHER}/pixel`)).toBe("not asked");
    // The page's own host is nobody the reader chose to ask of a mind.
    expect(await ask("https://explorer.example/index.html?looked-at=x")).toBe("not asked");
    // Another port, another scheme and a name that only begins alike are other origins.
    expect(await ask("https://resolver.example:8443/oip/v1/resolve/x")).toBe("not asked");
    expect(await ask("http://resolver.example/oip/v1/resolve/x")).toBe("not asked");
    expect(await ask("https://resolver.example.evil.example/")).toBe("not asked");
    expect(made).toStrictEqual([
      `GET ${RESOLVER}/oip/v1/resolve/x`,
      `POST ${INDEXER}/oip/v1/query`,
    ]);
    // What was not asked is said once each, and then forgotten.
    expect(asked.kept()).toStrictEqual([
      HOME,
      OTHER,
      "https://explorer.example",
      "https://resolver.example:8443",
      "what is no HTTPS origin",
      "https://resolver.example.evil.example",
    ]);
    expect(asked.kept()).toStrictEqual([]);
  });

  it("asks the homes a reading named, while the reading goes on", async () => {
    const { asked, made, ask } = watched();
    const reading = asked.reading([`${HOME}/`, HOME, "http://plain.example", "no origin"]);
    expect(reading.ended).toBe(false);
    expect(await ask(`${HOME}/.well-known/oip/mind/x/feed`)).toBe("asked");
    // A home the page did not name is not asked, whoever names it since.
    expect(await ask(`${OTHER}/.well-known/oip/mind/x/feed`)).toBe("not asked");
    expect(await ask("http://plain.example/feed")).toBe("not asked");
    reading.end();
    expect(reading.ended).toBe(true);
    expect(await ask(`${HOME}/.well-known/oip/mind/x/obj/y`)).toBe("not asked");
    expect(made).toStrictEqual([`GET ${HOME}/.well-known/oip/mind/x/feed`]);
  });

  it("keeps a home open for a reading that goes on when another of the same home ends", async () => {
    const { asked, ask } = watched();
    const first = asked.reading([HOME]);
    const second = asked.reading([HOME, OTHER]);
    first.end();
    // Ended twice, it ends once.
    first.end();
    expect(await ask(`${HOME}/feed`)).toBe("asked");
    expect(await ask(`${OTHER}/feed`)).toBe("asked");
    second.end();
    expect(await ask(`${HOME}/feed`)).toBe("not asked");
    expect(await ask(`${OTHER}/feed`)).toBe("not asked");
  });

  it("passes on what a service answers, and what goes wrong in asking it", async () => {
    const answer = new Response("{}", { status: 404 });
    const asked = new Asked([RESOLVER], (request) =>
      request.url.endsWith("/down")
        ? Promise.reject(new Error("connection refused"))
        : Promise.resolve(answer),
    );
    expect(await asked.fetch(new Request(`${RESOLVER}/x`))).toBe(answer);
    await expect(asked.fetch(new Request(`${RESOLVER}/down`))).rejects.toThrow(
      "connection refused",
    );
    expect(asked.kept()).toStrictEqual([]);
  });
});
