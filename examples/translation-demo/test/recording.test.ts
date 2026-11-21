// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { repoRoot } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import { castOf, linesOf, svgOf } from "../src/index.ts";

const directory = join(repoRoot, "examples", "translation-demo");
const ADDRESS = /did:oip:bciq[a-z2-7]{52}/gu;
const masked = (text: string): string => text.replace(ADDRESS, "did:oip:…");

const LINES = [
  "A telling",
  "",
  "1. A step",
  "   Something happens, with <angles> & an ampersand.",
  "   verified: it happened.",
];

describe("a telling as a terminal session", () => {
  it("is an asciicast: a header, and each line at its time, in order", () => {
    const cast = castOf(LINES, "A title");
    const [header = "", ...events] = cast.trimEnd().split("\n");
    expect(JSON.parse(header)).toStrictEqual({
      version: 2,
      width: 80,
      height: 40,
      title: "A title",
    });
    const read = events.map((event) => JSON.parse(event) as [number, string, string]);
    expect(read.map(([, kind]) => kind)).toStrictEqual(["o", "o", "o", "o", "o"]);
    expect(read.map(([, , text]) => text)).toStrictEqual(LINES.map((line) => `${line}\r\n`));
    const times = read.map(([time]) => time);
    expect(times).toStrictEqual([...times].sort((one, other) => one - other));
    expect(new Set(times).size).toBe(times.length);
    expect(linesOf(cast)).toStrictEqual(LINES);
    // The same lines give the same file: no clock is read.
    expect(castOf(LINES, "A title")).toBe(cast);
    // A line wider than a narrow terminal widens the session.
    expect(JSON.parse(castOf(["x".repeat(120)], "t").split("\n")[0] ?? "")).toMatchObject({
      width: 120,
    });
  });
});

describe("a telling as a picture", () => {
  it("draws each line at its time, with no script, and all at once for a reader who asked for less motion", () => {
    const svg = svgOf(LINES, "A <title>");
    expect(svg.startsWith('<svg xmlns="http://www.w3.org/2000/svg" ')).toBe(true);
    expect(svg).toContain('<title id="title">A &lt;title&gt;</title>');
    expect(svg.match(/<text /gu)).toHaveLength(LINES.length);
    // What a line holds is text, whatever it holds.
    expect(svg).toContain("Something happens, with &lt;angles&gt; &amp; an ampersand.");
    expect(svg).not.toContain("<angles>");
    expect(svg).toContain('<text class="step" ');
    expect(svg).toContain('<text class="verified" ');
    expect(svg).not.toMatch(/<script|javascript:|onload=/iu);
    expect(svg).toContain(
      "@media (prefers-reduced-motion: reduce) { text { animation: none; opacity: 1; } }",
    );
    expect(svgOf(LINES, "A <title>")).toBe(svg);
  });
});

describe("the recording that is kept", () => {
  const cast = readFileSync(join(directory, "recording", "translation-demo.cast"), "utf8");
  const svg = readFileSync(join(directory, "recording", "translation-demo.svg"), "utf8");
  const readme = readFileSync(join(directory, "README.md"), "utf8");

  it("is a telling as the README shows one, but for the addresses", () => {
    const lines = linesOf(cast);
    expect(readme).toContain(`\`\`\`\n${masked(lines.join("\n"))}\n\`\`\``);
    expect(lines.at(-1)).toBe("29 things were verified in this telling.");
  });

  it("is one telling in both its forms", () => {
    const lines = linesOf(cast);
    expect(svg).toBe(
      svgOf(lines, "The Open Intelligence Protocol: a translation, from want to Receipt"),
    );
    expect(cast).toBe(
      castOf(lines, "The Open Intelligence Protocol: a translation, from want to Receipt"),
    );
  });

  it("holds the addresses of minds, and nothing that opens a key", () => {
    expect(cast.match(ADDRESS)?.length).toBeGreaterThan(3);
    expect(cast).not.toMatch(/passphrase|private|secret/iu);
  });
});
