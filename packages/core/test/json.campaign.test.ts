// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The campaign of BUILD.md, M1: a million generated inputs to the parser of
 * the JSON profile, none of which may crash it, and none of which may be
 * accepted unless it is within the profile.
 *
 * Whether an input is within the profile is decided by an oracle written
 * for this test, which shares nothing with the parser: the platform's
 * `JSON.parse` for the grammar, exact integer arithmetic on each number's
 * source text, the platform's check for valid Unicode with a character class
 * for the noncharacters, and a token scan for duplicate names and depth.
 *
 * The inputs are generated from a fixed seed, so a failure reproduces.
 * `OIP_PARSER_CAMPAIGN` sets how many are generated.
 */

import { MAX_DEPTH } from "@oip/schema";
import { clause } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import { parseJson, parseJsonBytes } from "../src/index.ts";
import { textInProfile } from "./text.ts";

const INPUTS = Number(process.env["OIP_PARSER_CAMPAIGN"] ?? 1_000_000);

/** A small, fast generator of pseudo-random numbers (mulberry32), so that the campaign is reproducible. */
function generator(seed: number) {
  let state = seed >>> 0;
  const next = () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const below = (limit: number) => Math.floor(next() * limit);
  const pick = <T>(items: readonly T[]): T => items[below(items.length)] as T;
  const chance = (probability: number) => next() < probability;
  return { below, pick, chance };
}

type Random = ReturnType<typeof generator>;

// ---------------------------------------------------------------- the oracle

const SAFE = 2n ** 53n - 1n;
const NUMBER = /^(-?)([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/;

/** Whether a number, as written, is an integer within the safe range. Exact. */
function numberInProfile(source: string): boolean {
  const match = NUMBER.exec(source);
  if (match === null) return false;
  const [, , whole = "", fraction = "", exponent = "0"] = match;
  const digits = BigInt(whole + fraction);
  if (digits === 0n) return true;
  // The exponent of an input here has few digits; the cap only keeps the arithmetic small.
  const shift = BigInt(exponent) - BigInt(fraction.length);
  if (shift > 20n) return false;
  if (shift >= 0n) return digits * 10n ** shift <= SAFE;
  // Dividing by more tens than the number has digits never comes out whole.
  if (-shift > BigInt(whole.length + fraction.length)) return false;
  const divisor = 10n ** -shift;
  return digits % divisor === 0n && digits / divisor <= SAFE;
}

const TOKEN = /"(?:[^"\\]|\\.)*"|[{}[\]:,]/g;

/** For text that is valid JSON: whether any object repeats a name, and how deep it nests. */
function scan(text: string): { duplicate: boolean; depth: number } {
  const names: (Set<string> | undefined)[] = [];
  let depth = 0;
  let previous = "";
  for (const [token] of text.matchAll(TOKEN)) {
    if (token === "{") names.push(new Set());
    else if (token === "[") names.push(undefined);
    else if (token === "}" || token === "]") names.pop();
    else if (token.startsWith('"')) {
      const open = names.at(-1);
      if (open !== undefined && (previous === "{" || previous === ",")) {
        const name = JSON.parse(token) as string;
        if (open.has(name)) return { duplicate: true, depth };
        open.add(name);
      }
    }
    depth = Math.max(depth, names.length);
    previous = token;
  }
  return { duplicate: false, depth };
}

/** The value of a text if it is within the JSON profile of core Section 1, and `undefined` if not. */
function oracle(text: string): { value: unknown } | undefined {
  // A text with half a surrogate pair in it has no UTF-8 form: no record holds it.
  if (!text.isWellFormed()) return undefined;
  let inProfile = true;
  let value: unknown;
  try {
    value = JSON.parse(text, function (
      this: unknown,
      _name,
      member: unknown,
      context?: { source?: string },
    ) {
      if (typeof member === "number" && !numberInProfile(context?.source ?? "")) inProfile = false;
      if (typeof member === "string" && !textInProfile(member)) inProfile = false;
      if (typeof member === "object" && member !== null && !Array.isArray(member)) {
        for (const name of Object.keys(member)) if (!textInProfile(name)) inProfile = false;
      }
      return member;
    } as Parameters<typeof JSON.parse>[1]);
  } catch {
    return undefined;
  }
  if (!inProfile) return undefined;
  const { duplicate, depth } = scan(text);
  if (duplicate || depth > MAX_DEPTH) return undefined;
  return { value };
}

// ------------------------------------------------------------ the generators

const NAMES = [
  "a",
  "b",
  "type",
  "oip",
  "proof",
  "",
  "é",
  "__proto__",
  "constructor",
  "10",
  "2",
  "a b",
  "\u2028",
  "😀",
];
const TEXTS = [
  "",
  "x",
  "did:oip:b",
  "é€",
  "😀",
  'q"q',
  "back\\slash",
  "line\nbreak",
  "tab\t",
  "\u0000",
  "\u007f",
  "/",
  "1.5",
  "null",
];
const INTEGERS = [
  0, 1, -1, 2, 10, 100, 255, 65536, 4294967296, 9007199254740991, -9007199254740991, 123456789,
];
const SPACE = ["", "", "", " ", "\n", "\t", "\r\n", "  "];

/** A value within the profile. */
function value(random: Random, depth: number): unknown {
  const kind = random.below(depth > 3 ? 4 : 6);
  if (kind === 0) return random.pick([null, true, false]);
  if (kind === 1) return random.chance(0.5) ? random.pick(INTEGERS) : random.below(2000) - 1000;
  if (kind === 2 || kind === 3)
    return random.pick(TEXTS) + (random.chance(0.3) ? random.pick(TEXTS) : "");
  if (kind === 4) return Array.from({ length: random.below(4) }, () => value(random, depth + 1));
  const object: Record<string, unknown> = {};
  for (let i = random.below(4); i > 0; i--) {
    Object.defineProperty(object, random.pick(NAMES), {
      value: value(random, depth + 1),
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return object;
}

/** A string, written with a random choice of escapes. */
function writeString(random: Random, text: string): string {
  let out = '"';
  // By code point: a pair is written as two escapes or as itself, never half and half,
  // because a text with a raw half in it is not valid Unicode.
  for (const character of text) {
    const unit = character.charCodeAt(0);
    if (unit < 0x20 || character === '"' || character === "\\" || random.chance(0.1)) {
      const short = { '"': '\\"', "\\": "\\\\", "\n": "\\n", "\t": "\\t", "/": "\\/" }[character];
      out +=
        short !== undefined && random.chance(0.7)
          ? short
          : Array.from(
              { length: character.length },
              (_, i) => `\\u${character.charCodeAt(i).toString(16).padStart(4, "0")}`,
            )
              .join("")
              .replace(/[a-f]/g, (hex) => (random.chance(0.5) ? hex.toUpperCase() : hex));
    } else out += character;
  }
  return `${out}"`;
}

/** An integer, written in one of the ways that keep its value. */
function writeInteger(random: Random, integer: number): string {
  const plain = String(integer);
  const way = random.below(8);
  if (way === 0) return `${plain}.0`;
  if (way === 1) return `${plain}.${"0".repeat(1 + random.below(5))}`;
  if (way === 2) return `${plain}e0`;
  if (way === 3) return `${plain}E+0`;
  if (way === 4 && Math.abs(integer) < 1e12) return `${plain}00e-2`;
  if (way === 5 && integer % 10 === 0 && integer !== 0) return `${plain.slice(0, -1)}e1`;
  if (way === 6 && integer === 0) return random.pick(["-0", "0.0", "0e5", "-0.0e-3"]);
  return plain;
}

/** A value as JSON text, with a random layout. */
function write(random: Random, input: unknown): string {
  const space = () => random.pick(SPACE);
  if (typeof input === "string") return writeString(random, input);
  if (typeof input === "number") return writeInteger(random, input);
  if (typeof input !== "object" || input === null) return String(input);
  if (Array.isArray(input)) {
    return `[${space()}${input.map((item) => write(random, item) + space()).join(`,${space()}`)}]`;
  }
  const members = Object.entries(input).map(
    ([name, member]) =>
      `${writeString(random, name)}${space()}:${space()}${write(random, member)}${space()}`,
  );
  return `{${space()}${members.join(`,${space()}`)}}`;
}

/** Fragments that take a text out of the profile when they land in the right place. */
const FAULTS = [
  "1.5",
  "0.1",
  "1e-1",
  "9007199254740992",
  "-9007199254740993",
  "1e16",
  "1e400",
  "01",
  "-",
  "+1",
  ".5",
  "1.",
  "NaN",
  "Infinity",
  "undefined",
  "nul",
  "True",
  "'a'",
  String.raw`"\ud800"`,
  String.raw`"\udc00\ud800"`,
  String.raw`"\ufdd0"`,
  String.raw`"\uFFFE"`,
  String.raw`"\ud83f\udfff"`,
  '"\uffff"',
  '"\u{10ffff}"',
  '{"\ufdef":1}',
  '"\ud83d"',
  // A number too long to be read as one, in the forms that keep and that lose its value.
  `1${"0".repeat(400)}`,
  "9".repeat(5000),
  `1${"0".repeat(400)}e-400`,
  `0.${"0".repeat(500)}`,
  String.raw`"\x41"`,
  String.raw`"\u12"`,
  '"\n"',
  '"\u0001"',
  '"',
  "//c\n",
  "/**/",
  "\ufeff",
  "\u00a0",
  ",",
  ":",
  "[",
  "]",
  "{",
  "}",
  '"a":1,"a":2',
  '{"a":1,"a":1}',
  String.raw`{"a":1,"\u0061":2}`,
  '{"__proto__":1,"__proto__":2}',
  "\ud800",
];
const SOUP = '[]{}:,"\\ \n0123456789.eE-+truefalsnu/\ud83d\ude00é'.split("");

/** One input of the campaign: a text within the profile, a text with a fault, or a text edited at random. */
function input(random: Random): string {
  const text = write(random, value(random, 0));
  const kind = random.below(10);
  if (kind < 4) return text;
  const at = random.below(text.length + 1);
  if (kind < 6) return text.slice(0, at) + random.pick(FAULTS) + text.slice(at);
  if (kind < 7) {
    // Wrap it deeper than any record may nest, or exactly as deep as one may.
    const levels = random.pick([MAX_DEPTH - 6, MAX_DEPTH - 5, MAX_DEPTH, MAX_DEPTH + 1, 200]);
    return random.chance(0.5)
      ? "[".repeat(levels) + text + "]".repeat(levels)
      : '{"a":'.repeat(levels) + text + "}".repeat(levels);
  }
  let edited = text;
  for (let edits = 1 + random.below(3); edits > 0; edits--) {
    const position = random.below(edited.length + 1);
    const how = random.below(3);
    if (how === 0) edited = edited.slice(0, position) + random.pick(SOUP) + edited.slice(position);
    else if (how === 1) edited = edited.slice(0, position) + edited.slice(position + 1);
    else edited = edited.slice(0, position) + random.pick(SOUP) + edited.slice(position + 1);
  }
  return edited;
}

// -------------------------------------------------------------- the campaign

describe(`${clause("core 1.1", "core 1.2")} the campaign on the parser of the JSON profile`, () => {
  it("has an oracle that knows the profile", () => {
    for (const within of [
      "1",
      "-0",
      "1.0",
      "1e2",
      "100e-2",
      "9007199254740991",
      '{"a":1,"b":{"a":2}}',
      String.raw`"\ud83d\ude00"`,
      '"😀"',
      String.raw`"\ufffd\ufdcf\ufdf0"`,
      `1${"0".repeat(400)}e-400`,
      `0.${"0".repeat(500)}`,
      "[]",
      " [1 , 2]\n",
    ]) {
      expect(oracle(within), within).toBeDefined();
    }
    for (const outside of [
      "1.5",
      "1e-1",
      "9007199254740992",
      "1e16",
      '{"a":1,"a":2}',
      String.raw`{"a":1,"\u0061":2}`,
      String.raw`"\ud800"`,
      String.raw`{"\ud800":1}`,
      String.raw`"\ufffe"`,
      String.raw`{"\ufdd0":1}`,
      String.raw`"\udbff\udfff"`,
      '"\uffff"',
      // Half a pair written raw, beside an escape that would complete it.
      `"\ud83d\\ude00"`,
      `[\udc001]`,
      `1${"0".repeat(400)}`,
      "[1,]",
      "",
      "\ufeff1",
      `${"[".repeat(65)}${"]".repeat(65)}`,
    ]) {
      expect(oracle(outside), outside).toBeUndefined();
    }
    expect(oracle(`${"[".repeat(64)}${"]".repeat(64)}`)).toBeDefined();
    expect(oracle('{"a":[{"b":1},{"b":2}]}')).toBeDefined();
    expect(oracle('{"a":{"a":1},"b":{"a":1}}')).toBeDefined();
    expect(oracle('["a","a",{"k":"k"}]')).toBeDefined();
  });

  it(
    `${INPUTS.toLocaleString("en")} generated inputs: no crash, and nothing outside the profile accepted`,
    { timeout: 600_000 },
    () => {
      const random = generator(0x01f2026);
      let accepted = 0;
      let rejected = 0;
      for (let i = 0; i < INPUTS; i++) {
        const text = input(random);
        const expected = oracle(text);
        const parsed = parseJson(text);
        if (parsed.ok !== (expected !== undefined)) {
          throw new Error(
            `input ${i}: the parser ${parsed.ok ? "accepted" : "rejected"} what the oracle ${expected === undefined ? "rejects" : "accepts"}: ${JSON.stringify(text)}`,
          );
        }
        if (parsed.ok) {
          accepted++;
          if (JSON.stringify(parsed.value) !== JSON.stringify(expected?.value)) {
            throw new Error(`input ${i}: read as a different value: ${JSON.stringify(text)}`);
          }
        } else rejected++;
      }
      // The campaign is worth something only if it exercises both answers.
      expect(accepted).toBeGreaterThan(INPUTS / 4);
      expect(rejected).toBeGreaterThan(INPUTS / 4);
    },
  );

  it(
    "the same for inputs given as bytes, with bytes that are not UTF-8 among them",
    { timeout: 600_000 },
    () => {
      const random = generator(0x0b17e5);
      const encoder = new TextEncoder();
      const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
      const count = Math.ceil(INPUTS / 10);
      let invalid = 0;
      for (let i = 0; i < count; i++) {
        const bytes = encoder.encode(input(random).toWellFormed());
        if (random.chance(0.3) && bytes.length > 0) {
          bytes[random.below(bytes.length)] = random.pick([
            0x80, 0xbf, 0xc0, 0xc3, 0xe2, 0xed, 0xf4, 0xff,
          ]);
        }
        let text: string | undefined;
        try {
          text = decoder.decode(bytes);
        } catch {
          invalid++;
        }
        const expected = text === undefined ? undefined : oracle(text);
        const parsed = parseJsonBytes(bytes);
        if (parsed.ok !== (expected !== undefined)) {
          throw new Error(
            `input ${i}: disagreement on the bytes ${Buffer.from(bytes).toString("hex")}`,
          );
        }
        if (parsed.ok && JSON.stringify(parsed.value) !== JSON.stringify(expected?.value)) {
          throw new Error(
            `input ${i}: read as a different value: ${Buffer.from(bytes).toString("hex")}`,
          );
        }
      }
      expect(invalid).toBeGreaterThan(count / 20);
    },
  );
});
