// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { canonicalBytes, parseJson, sha256Digest } from "@oip/core";
import { clause } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import { carriedJson, digestOf, holds, jsonText, readJsonText } from "../src/index.ts";
import { sizeOf, Unsayable } from "../src/json.ts";

/** Characters written so that this file holds none of them. */
const NONCHARACTER = String.fromCodePoint(0xfffe);
const HIGH_NONCHARACTER = String.fromCodePoint(0x1fffe);
const LONE = String.fromCodePoint(0xd800);

/** A value that nests so many arrays deep. */
function nested(levels: number): unknown {
  let value: unknown = "at the bottom";
  for (let level = 0; level < levels; level += 1) value = [value];
  return value;
}

describe("JSON as MCP has it, in a record", () => {
  it(`${clause("L0 2.1", "core 1.2")} is held as it is where a record can hold it`, () => {
    const schema = {
      type: "object",
      properties: { text: { type: "string", maxLength: 1000 }, count: { type: "integer" } },
      required: ["text"],
    };
    expect(holds(schema)).toBe(true);
    // What is carried is what the parser for records read of the value's text: the value as it
    // will be signed, and not the object that was handed in.
    expect(carriedJson(schema)).toStrictEqual(schema);
    expect(carriedJson(schema)).not.toBe(schema);
    for (const value of [
      null,
      true,
      0,
      -5,
      9_007_199_254_740_991,
      "text",
      [],
      {},
      [1, [2, { a: 3 }]],
    ]) {
      expect(holds(value), JSON.stringify(value)).toBe(true);
    }
    // An integer however it was written is an integer by its value.
    expect(holds(JSON.parse("1.0"))).toBe(true);
    expect(holds(JSON.parse("1e2"))).toBe(true);
  });

  it(`${clause("L0 2.1", "core 1.2")} is carried as its JSON text where it holds a number no record has`, () => {
    for (const value of [0.5, { maximum: 0.5 }, [1, 2.25], 9_007_199_254_740_992, -1e21, 1e300]) {
      expect(holds(value), JSON.stringify(value)).toBe(false);
      const carried = carriedJson(value);
      expect(typeof carried).toBe("string");
      // Whoever parses the text reads the value.
      expect(JSON.parse(carried as string)).toStrictEqual(value);
      // And the text is a string that a record holds.
      expect(parseJson(JSON.stringify({ body: carried })).ok).toBe(true);
    }
  });

  it(`${clause("L0 2.1", "core 1.1")} is carried as text where it holds a string no record has, with the character written as its escape`, () => {
    for (const odd of [NONCHARACTER, HIGH_NONCHARACTER, LONE, String.fromCodePoint(0xfdd0)]) {
      const value = { [`a name with ${odd}`]: `a text with ${odd}` };
      expect(holds(value)).toBe(false);
      const text = jsonText(value);
      expect(text).not.toContain(odd);
      expect(text).toMatch(/\\u[0-9a-f]{4}/u);
      expect(JSON.parse(text)).toStrictEqual(value);
      expect(parseJson(JSON.stringify({ body: text })).ok).toBe(true);
    }
    // A character beyond the first plane is two escapes: one for each half.
    expect(jsonText(HIGH_NONCHARACTER)).toBe('"\\ud83f\\udffe"');
    // What a record holds is written as any JSON is.
    expect(jsonText({ a: [1, "é", String.fromCodePoint(0x1f600)] })).toBe(
      JSON.stringify({ a: [1, "é", String.fromCodePoint(0x1f600)] }),
    );
  });

  it(`${clause("L0 2.1", "core 1.9")} is carried as text where it nests deeper than its place in a record allows`, () => {
    // A value sits up to six levels down in its record, and a record nests 64 deep.
    expect(holds(nested(58))).toBe(true);
    expect(holds(nested(59))).toBe(false);
    expect(typeof carriedJson(nested(59))).toBe("string");
  });

  it("is not held where it is no JSON at all", () => {
    expect(holds(undefined)).toBe(false);
    expect(holds(() => 1)).toBe(false);
    expect(holds(10n)).toBe(false);
    const circle: Record<string, unknown> = {};
    circle["self"] = circle;
    expect(holds(circle)).toBe(false);
    expect(() => jsonText(undefined)).toThrow(TypeError);
  });
});

describe("a value with a number that is not finite", () => {
  it(`${clause("L0 2.1")} is not carried at all: JSON would write it as \`null\`, which is not what was given`, () => {
    // `1e999` on a wire is read as an infinity by the program that reads it.
    const read: unknown = JSON.parse('{"balance":1e999,"more":[1,{"low":-1e999}]}');
    for (const value of [
      Number.POSITIVE_INFINITY,
      Number.NaN,
      { a: [Number.NEGATIVE_INFINITY] },
      read,
    ]) {
      expect(() => carriedJson(value)).toThrow(Unsayable);
    }
    // What is no JSON at all has no text to carry.
    expect(() => carriedJson(undefined)).toThrow(Unsayable);
    expect(() => carriedJson(() => 1)).toThrow(Unsayable);
    // A finite number that no record has is carried, as text.
    expect(carriedJson(1e300)).toBe("1e+300");
  });
});

describe("the size of a body in the record that carries it", () => {
  it(`${clause("core 1.6")} is of its canonical form, where a text is a JSON string`, () => {
    expect(sizeOf({ b: 1, a: [true, null] })).toBe('{"a":[true,null],"b":1}'.length);
    // Each quotation mark and each backslash of a text is two bytes in the record.
    expect(sizeOf('{"a":"b"}')).toBe('"{\\"a\\":\\"b\\"}"'.length);
    expect(sizeOf("é")).toBe(4);
  });
});

describe("JSON text that a requester wrote", () => {
  it("is read as JSON is, fractions and all", () => {
    expect(
      readJsonText('{"tool":"scale","arguments":{"by":0.25,"note":"a } and a ] in \\" a string"}}'),
    ).toStrictEqual({
      value: { tool: "scale", arguments: { by: 0.25, note: 'a } and a ] in " a string' } },
    });
    expect(readJsonText("null")).toStrictEqual({ value: null });
  });

  it("is not read where it is no JSON, or nests deeper than a record", () => {
    expect(readJsonText("{not JSON")).toBeUndefined();
    expect(readJsonText("")).toBeUndefined();
    expect(readJsonText(`${"[".repeat(64)}${"]".repeat(64)}`)).toBeDefined();
    expect(readJsonText(`${"[".repeat(65)}${"]".repeat(65)}`)).toBeUndefined();
    expect(readJsonText(`${'{"a":'.repeat(65)}1${"}".repeat(65)}`)).toBeUndefined();
    // Brackets in a string are text, however many: they nest nothing.
    expect(readJsonText(JSON.stringify("[".repeat(500)))).toStrictEqual({ value: "[".repeat(500) });
    expect(readJsonText(JSON.stringify(`\\"${"{".repeat(100)}`))).toBeDefined();
    // A text that is all open brackets ends nowhere, and is not parsed.
    expect(readJsonText("[".repeat(100_000))).toBeUndefined();
  });

  it(`${clause("core 1.1")} is not read where an object names a member twice: two readers would read two calls`, () => {
    expect(readJsonText('{"tool":"harmless","tool":"send_money","arguments":{}}')).toBeUndefined();
    // However the name is written: an escape spells the same name.
    expect(readJsonText('{"tool":"a","to\\u006fl":"b"}')).toBeUndefined();
    expect(readJsonText('{"a":{"b":1,"c":[{"d":1,"d":2}]}}')).toBeUndefined();
    expect(readJsonText('{"":1,"":2}')).toBeUndefined();
    // One name in two objects is two names, and a value that reads like a name is a value.
    expect(readJsonText('{"a":{"a":1},"b":{"a":"a"},"c":["a","a"],"d":"a"}')).toStrictEqual({
      value: { a: { a: 1 }, b: { a: "a" }, c: ["a", "a"], d: "a" },
    });
    expect(readJsonText('[{"a":1},{"a":2}]')).toStrictEqual({ value: [{ a: 1 }, { a: 2 }] });
    expect(readJsonText('{"a":"x,\\"a\\":1","b":{}, "c":[] ,"e":1}')).toBeDefined();
    // `__proto__` is a name like another.
    expect(readJsonText('{"__proto__":1,"__proto__":2}')).toBeUndefined();
    expect(readJsonText('{"__proto__":{"tool":"x"}}')).toBeDefined();
  });

  it("is not read where it holds a number JSON has and a program has not", () => {
    expect(readJsonText('{"tool":"pay","arguments":{"amount":1e999}}')).toBeUndefined();
    expect(readJsonText("-1e999")).toBeUndefined();
    expect(readJsonText("1e308")).toStrictEqual({ value: 1e308 });
  });
});

describe("the digest of a body the gateway returned", () => {
  it(`${clause("L0 2.1")} is of its canonical form, or of its bytes where it is text`, () => {
    const body = { b: [2, 1], a: "é" };
    expect(digestOf(body)).toBe(sha256Digest(canonicalBytes(body)));
    // The order its members were written in is no part of a record.
    expect(digestOf({ a: "é", b: [2, 1] })).toBe(digestOf(body));
    const text = '{"b":[2,1.5],"a":"é"}';
    expect(digestOf(text)).toBe(sha256Digest(new TextEncoder().encode(text)));
    expect(digestOf(text)).not.toBe(digestOf('{"a":"é","b":[2,1.5]}'));
  });
});
