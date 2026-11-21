// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** What the pages rest on that needs no browser: where a reader is, whom they chose to ask, and how a stranger's words are shown. */

import { describe, expect, it } from "vitest";

import { NO_NAME, shown, shownJson, shownName } from "../src/oip/text.ts";
import { hashOf, routeOf } from "../src/route.ts";
import {
  loadSettings,
  MAX_SERVICES,
  NO_SETTINGS,
  parseOrigins,
  saveSettings,
  SETTINGS_KEY,
} from "../src/settings.ts";

const ADDRESS = `did:oip:bciq${"a".repeat(52)}`;
/** Characters written so that this file holds none of them. */
const OVERRIDE = String.fromCodePoint(0x202e);
const ZERO_WIDTH = String.fromCodePoint(0x200b);
const LINE_SEPARATOR = String.fromCodePoint(0x2028);

describe("where a reader is", () => {
  it("is what the fragment of the address says", () => {
    expect(routeOf("")).toStrictEqual({ page: "home" });
    expect(routeOf("#")).toStrictEqual({ page: "home" });
    expect(routeOf("#/")).toStrictEqual({ page: "home" });
    expect(routeOf("#/settings")).toStrictEqual({ page: "settings" });
    expect(routeOf(`#/mind/${ADDRESS}`)).toStrictEqual({ page: "mind", address: ADDRESS });
    expect(routeOf(`#/mind/${encodeURIComponent(ADDRESS)}`)).toStrictEqual({
      page: "mind",
      address: ADDRESS,
    });
  });

  it("is nowhere for a fragment that names no page, or an address that is none", () => {
    for (const hash of [
      "#/elsewhere",
      "#/mind/",
      "#/mind/did:oip:short",
      "#/mind/did:web:example.com",
      `#/mind/${ADDRESS}/more`,
      "#/mind/%E0%A4%A",
      "#/settings/more",
      `#/mind/<script>alert(1)</script>`,
    ]) {
      expect(routeOf(hash), hash).toStrictEqual({ page: "nowhere" });
    }
  });

  it("is written as the fragment that names it", () => {
    for (const route of [
      { page: "home" },
      { page: "settings" },
      { page: "mind", address: ADDRESS },
    ] as const) {
      expect(routeOf(hashOf(route))).toStrictEqual(route);
    }
    expect(hashOf({ page: "nowhere" })).toBe("#/");
  });
});

describe("the services a reader chose", () => {
  it("are HTTPS origins, each once, however they are typed", () => {
    expect(
      parseOrigins(
        "https://resolver.example\n  https://Other.Example/ , https://resolver.example\nhttps://third.example:8443",
      ),
    ).toStrictEqual({
      origins: ["https://resolver.example", "https://other.example", "https://third.example:8443"],
      wrong: [],
    });
    expect(parseOrigins("")).toStrictEqual({ origins: [], wrong: [] });
  });

  it("are none of what is no HTTPS origin", () => {
    const typed = [
      "http://plain.example",
      "resolver.example",
      "https://user:pass@host.example",
      "javascript:alert(1)",
      "ftp://x.example",
    ];
    expect(parseOrigins(typed.join("\n"))).toStrictEqual({ origins: [], wrong: typed });
  });

  it("are no more than the Explorer asks", () => {
    const many = Array.from(
      { length: MAX_SERVICES + 3 },
      (_, at) => `https://r${String(at)}.example`,
    );
    expect(parseOrigins(many.join(" ")).origins).toStrictEqual(many.slice(0, MAX_SERVICES));
  });

  it("are kept in the browser's storage, and read back as they were kept", () => {
    const kept = new Map<string, string>();
    const storage = {
      getItem: (key: string) => kept.get(key) ?? null,
      setItem: (key: string, value: string) => void kept.set(key, value),
    };
    expect(loadSettings(storage)).toBe(NO_SETTINGS);
    const chosen = {
      resolvers: ["https://resolver.example"],
      indexers: ["https://indexer.example"],
    };
    saveSettings(storage, chosen);
    expect([...kept.keys()]).toStrictEqual([SETTINGS_KEY]);
    expect(loadSettings(storage)).toStrictEqual(chosen);
  });

  it("are none where the storage holds something else, or cannot be used", () => {
    const holding = (value: string | null) => ({ getItem: () => value });
    for (const value of ["not JSON", "7", "null", "[]", '{"resolvers": "https://r.example"}']) {
      expect(loadSettings(holding(value)), value).toStrictEqual(
        value === "[]" || value.startsWith("{") ? { resolvers: [], indexers: [] } : NO_SETTINGS,
      );
    }
    // What was kept by other code, or by an older page: only HTTPS origins are taken from it.
    expect(
      loadSettings(
        holding('{"resolvers": ["https://r.example", "http://plain.example", 7], "indexers": {}}'),
      ),
    ).toStrictEqual({ resolvers: ["https://r.example"], indexers: [] });
    const broken = {
      getItem: (): string => {
        throw new Error("storage is switched off");
      },
      setItem: (): void => {
        throw new Error("storage is full");
      },
    };
    expect(loadSettings(broken)).toBe(NO_SETTINGS);
    expect(() => {
      saveSettings(broken, NO_SETTINGS);
    }).not.toThrow();
  });
});

describe("a stranger's words", () => {
  it("are shown as they are, but for the characters that act on what is around them", () => {
    expect(shown("Amina, a person")).toBe("Amina, a person");
    expect(shown("Wanjiru Kamau ✓ 日本語")).toBe("Wanjiru Kamau ✓ 日本語");
    // A character that turns the line round would make what follows read as something else.
    expect(shown(`Lexis Ltd${OVERRIDE}deifirev`)).toBe("Lexis Ltd\\u{202e}deifirev");
    expect(shown(`a${ZERO_WIDTH}b\nc\td${LINE_SEPARATOR}e\u0000`)).toBe(
      "a\\u{200b}b\\u{a}c\\u{9}d\\u{2028}e\\u{0}",
    );
  });

  it("have nothing in them that is not seen: what a display leaves out, or has no shape for, is shown as its escape", () => {
    // Each written by its number, so that this file holds none of them.
    const unseen = [
      0x034f, // a joiner of marks
      0xfe0f, // a selector of a variation
      0xe0100, // and one of the supplement
      0xe000, // private use
      0x3164, // a filler of Hangul
      0x115f,
      0x1160,
      0xffa0,
      0x2800, // the blank of the Braille patterns
      0x00ad, // a soft hyphen
      0xfeff,
      0xe0041, // a tag
      0x0085,
      0x2029,
    ];
    for (const point of unseen) {
      const escape = `\\u{${point.toString(16)}}`;
      expect(shown(`a${String.fromCodePoint(point)}b`), escape).toBe(`a${escape}b`);
    }
    // A name made of nothing but such is seen as what it is made of.
    expect(shownName(String.fromCodePoint(0x3164, 0x3164))).toBe("\\u{3164}\\u{3164}");
  });

  it("do not draw over the lines around them: marks piled on one letter are cut at four, and a mark with no letter is shown as its escape", () => {
    const mark = String.fromCodePoint(0x0301);
    // What a script puts on a letter stays: Vietnamese has two, and some have more.
    const viet = `e${String.fromCodePoint(0x0302)}${mark}`;
    expect(shown(viet)).toBe(viet);
    expect(shown(`a${mark.repeat(4)}`)).toBe(`a${mark.repeat(4)}`);
    expect(shown(`a${mark.repeat(6)}b`)).toBe(`a${mark.repeat(4)}\\u{301}\\u{301}b`);
    expect(shown(`${mark}a`)).toBe("\\u{301}a");
  });

  it("name a mind, or say that a name has nothing to see", () => {
    expect(shownName("Amina")).toBe("Amina");
    expect(shownName(" Lexis Ltd ")).toBe(" Lexis Ltd ");
    for (const blank of [
      "",
      " ",
      "\t",
      String.fromCodePoint(0x00a0).repeat(3),
      String.fromCodePoint(0x3000),
      `${String.fromCodePoint(0x2003)} ${String.fromCodePoint(0x202f)}`,
    ]) {
      // A tab is a control, and is seen as its escape. The rest is space, and no name.
      expect(shownName(blank), JSON.stringify(blank)).toBe(blank === "\t" ? "\\u{9}" : NO_NAME);
    }
    expect(NO_NAME).toBe("(no name)");
  });

  it("are shown within a record as JSON of many lines, with the same characters as escapes", () => {
    const text = shownJson({ name: `Lexis${OVERRIDE}`, list: [1, "two"] });
    expect(text).toBe('{\n  "name": "Lexis\\u{202e}",\n  "list": [\n    1,\n    "two"\n  ]\n}');
    expect(text).not.toContain(OVERRIDE);
    // What JSON writes as an escape already stays one.
    expect(shownJson({ said: "one\ntwo" })).toBe('{\n  "said": "one\\ntwo"\n}');
  });
});
