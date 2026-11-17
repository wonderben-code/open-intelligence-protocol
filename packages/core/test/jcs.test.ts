// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { MAX_CONTAINER_DEPTH, MAX_DEPTH } from "@oip/schema";
import { clause } from "@oip/testkit";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { canonicalBytes, canonicalize, contentId, OipError, parseJson } from "../src/index.ts";
import { contentIdIfAny } from "../src/content-id.ts";
import { textInProfile } from "./text.ts";
import { cases, positiveVectorRecords } from "./vectors.ts";

/**
 * RFC 8785 for the JSON profile, written independently of the library: a
 * second opinion on every byte.
 */
function reference(value: unknown): string {
  if (value === null || typeof value === "boolean") return String(value);
  if (typeof value === "number") return Object.is(value, -0) ? "0" : value.toFixed(0);
  if (typeof value === "string") {
    let out = '"';
    for (const unit of value.split("")) {
      const code = unit.charCodeAt(0);
      if (unit === '"') out += '\\"';
      else if (unit === "\\") out += "\\\\";
      else if (code === 0x08) out += "\\b";
      else if (code === 0x09) out += "\\t";
      else if (code === 0x0a) out += "\\n";
      else if (code === 0x0c) out += "\\f";
      else if (code === 0x0d) out += "\\r";
      else if (code < 0x20) out += `\\u${code.toString(16).padStart(4, "0")}`;
      else out += unit;
    }
    return `${out}"`;
  }
  if (Array.isArray(value)) return `[${value.map(reference).join(",")}]`;
  const object = value as Record<string, unknown>;
  const names = Object.keys(object).sort((a, b) => {
    // By UTF-16 code units, compared one by one.
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      const difference = a.charCodeAt(i) - b.charCodeAt(i);
      if (difference !== 0) return difference;
    }
    return a.length - b.length;
  });
  return `{${names.map((name) => `${reference(name)}:${reference(object[name])}`).join(",")}}`;
}

const wellFormed = fc.string({ unit: "binary" }).filter(textInProfile);

const json = fc.letrec((tie) => ({
  value: fc.oneof(
    { depthSize: "small" },
    fc.constant(null),
    fc.boolean(),
    fc.maxSafeInteger(),
    wellFormed,
    fc.array(tie("value"), { maxLength: 5 }),
    fc.dictionary(wellFormed, tie("value"), { maxKeys: 5 }),
  ),
})).value;

function rejected(value: unknown): OipError {
  try {
    canonicalize(value);
  } catch (error) {
    expect(error).toBeInstanceOf(OipError);
    return error as OipError;
  }
  throw new Error(`canonicalize accepted ${String(value)}`);
}

describe(`${clause("core 2.1")} canonical form is RFC 8785`, () => {
  it("reproduces the example of the vectors", () => {
    const example = cases["jcs_example"] as { input: unknown; output: string };
    expect(canonicalize(example.input)).toBe(example.output);
    expect(example.output).toBe('{"a":[1,"x"],"b":2,"é":true}');
  });

  it("sorts members by the UTF-16 code units of their names (RFC 8785, 3.2.3)", () => {
    const input = {
      "\u20ac": "Euro Sign",
      "\r": "Carriage Return",
      "\ufb33": "Hebrew Letter Dalet With Dagesh",
      "1": "One",
      "\ud83d\ude00": "Emoji: Grinning Face",
      "\u0080": "Control",
      "\u00f6": "Latin Small Letter O With Diaeresis",
    };
    expect(canonicalize(input)).toBe(
      '{"\\r":"Carriage Return","1":"One","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis","\u20ac":"Euro Sign","\ud83d\ude00":"Emoji: Grinning Face","\ufb33":"Hebrew Letter Dalet With Dagesh"}',
    );
    // Code units, not code points: U+1F600 is written D83D DE00, which sorts before U+FB33.
    expect(canonicalize({ "\ufb33": 1, "\u{1f600}": 2 })).toBe('{"\u{1f600}":2,"\ufb33":1}');
    expect(canonicalize({ b: 1, a: 2, B: 3, A: 4, aa: 5, "": 6 })).toBe(
      '{"":6,"A":4,"B":3,"a":2,"aa":5,"b":1}',
    );
    expect(canonicalize({ "10": 1, "9": 2, "1": 3 })).toBe('{"1":3,"10":1,"9":2}');
  });

  it("sorts at every level and keeps the order of arrays", () => {
    expect(canonicalize({ z: [{ b: 1, a: 2 }, [3, 1, 2]], a: { y: null, x: true } })).toBe(
      '{"a":{"x":true,"y":null},"z":[{"a":2,"b":1},[3,1,2]]}',
    );
  });

  it("emits no white space", () => {
    expect(canonicalize({ a: [1, 2, { b: "c d" }], e: {} })).toBe('{"a":[1,2,{"b":"c d"}],"e":{}}');
    expect(canonicalize([])).toBe("[]");
    expect(canonicalize({})).toBe("{}");
  });

  it("escapes strings minimally (RFC 8785, 3.2.2.2)", () => {
    expect(canonicalize('"\\/\b\f\n\r\t')).toBe(String.raw`"\"\\/\b\f\n\r\t"`);
    expect(canonicalize("\u0000\u0001\u001f\u000b")).toBe(String.raw`"\u0000\u0001\u001f\u000b"`);
    // Everything else is written as itself: DEL, the line separators, non-ASCII, astral characters.
    for (const literal of ["\u007f", "\u0080", "\u2028", "\u2029", "é", "€", "😀", "<>&'"]) {
      expect(canonicalize(literal)).toBe(`"${literal}"`);
    }
    expect(canonicalize({ "a\nb": "\u001b" })).toBe(String.raw`{"a\nb":"\u001b"}`);
  });

  it("writes the three literals", () => {
    expect(canonicalize([null, true, false])).toBe("[null,true,false]");
    expect(canonicalize(null)).toBe("null");
    expect(canonicalize(true)).toBe("true");
    expect(canonicalize("")).toBe('""');
  });

  it("gives the same text whatever order the members were written in", () => {
    fc.assert(
      fc.property(json, (value) => {
        const shuffled = (input: unknown): unknown => {
          if (Array.isArray(input)) return input.map(shuffled);
          if (typeof input !== "object" || input === null) return input;
          return Object.fromEntries(
            Object.entries(input)
              .reverse()
              .map(([name, member]) => [name, shuffled(member)]),
          );
        };
        expect(canonicalize(shuffled(value))).toBe(canonicalize(value));
      }),
      { numRuns: 500 },
    );
  });

  it("agrees with an independent serialiser on every value in the profile", () => {
    fc.assert(
      fc.property(json, (value) => {
        expect(canonicalize(value)).toBe(reference(value));
      }),
      { numRuns: 3000 },
    );
    for (const { name, record } of positiveVectorRecords()) {
      expect(canonicalize(record), name).toBe(reference(record));
    }
  });

  it("is a fixed point: the canonical form of what it parses to is itself", () => {
    fc.assert(
      fc.property(json, (value) => {
        const text = canonicalize(value);
        const parsed = parseJson(text);
        expect(parsed.ok).toBe(true);
        if (parsed.ok) expect(canonicalize(parsed.value)).toBe(text);
      }),
      { numRuns: 1000 },
    );
  });

  it("encodes the text as UTF-8", () => {
    expect([...canonicalBytes({ é: "€😀" })]).toEqual([...new TextEncoder().encode('{"é":"€😀"}')]);
    expect(canonicalBytes([1])).toBeInstanceOf(Uint8Array);
  });
});

describe(`${clause("core 2.2")} numbers in canonical form`, () => {
  it("writes an integer in its shortest decimal form", () => {
    expect(canonicalize([0, 1, -1, 10, 100, 123456789, -42])).toBe("[0,1,-1,10,100,123456789,-42]");
    expect(canonicalize(Number.MAX_SAFE_INTEGER)).toBe("9007199254740991");
    expect(canonicalize(-Number.MAX_SAFE_INTEGER)).toBe("-9007199254740991");
    expect(canonicalize(1e15)).toBe("1000000000000000");
    expect(canonicalize(1e2)).toBe("100");
    expect(canonicalize(1.0)).toBe("1");
  });

  it("writes -0 as 0", () => {
    expect(canonicalize(-0)).toBe("0");
    expect(canonicalize([-0, { a: -0 }])).toBe('[0,{"a":0}]');
  });

  it("writes integers as the parser read them, however they were spelled", () => {
    const parsed = parseJson("[1.0, 1e2, -0, 12.50e1, 9007199254740991.0]");
    expect(parsed.ok && canonicalize(parsed.value)).toBe("[1,100,0,125,9007199254740991]");
  });
});

describe(`${clause("core 1.2")} nothing outside the profile has a canonical form`, () => {
  it("refuses numbers that are not safe integers", () => {
    for (const bad of [0.5, 1e21, Number.MAX_SAFE_INTEGER + 1, Number.NaN, Infinity, -Infinity]) {
      const error = rejected([bad]);
      expect(error.code).toBe("invalid-record");
      expect(error.clause).toBe("core 1.2");
    }
    expect(rejected(1.5).detail).toBe(
      "the number 1.5 is not an integer between -(2^53-1) and 2^53-1; write decimal quantities as strings",
    );
  });

  it("refuses values that are not JSON, which a serialiser would drop or rewrite", () => {
    class Custom {
      readonly a = 1;
    }
    const withToJson = [1, 2] as number[] & { toJSON?: () => unknown };
    withToJson.toJSON = () => "rewritten";
    const cyclic: Record<string, unknown> = {};
    cyclic["self"] = cyclic;
    const sparse: unknown[] = [];
    sparse[2] = 1;
    for (const bad of [
      undefined,
      [undefined],
      { a: undefined },
      () => 1,
      Symbol("s"),
      1n,
      new Date(0),
      new Map(),
      new Set(),
      new Custom(),
      new Uint8Array(2),
      { toJSON: () => "rewritten" },
      withToJson,
      class Sub extends Array {}.from([1]),
      cyclic,
      sparse,
      Object.defineProperty({}, "hidden", { value: 1, enumerable: false }),
      Object.defineProperty({}, "getter", { get: () => 1, enumerable: true }),
      { [Symbol("s")]: 1 },
      new String("boxed"),
      new Number(1),
    ]) {
      expect(rejected(bad).code).toBe("invalid-record");
    }
  });

  it("refuses strings and names that are not valid Unicode", () => {
    for (const bad of ["\ud800", ["a\udc00"], { "\ud800": 1 }, { a: { b: "\udfff" } }]) {
      const error = rejected(bad);
      expect(error.clause).toBe("core 1.1");
    }
    expect(canonicalize("\ud83d\ude00")).toBe('"😀"');
  });

  it("refuses nesting deeper than a container may have", () => {
    // A container carries a record three levels down, and that record may nest
    // 64 deep (core 1.9). A page of such records has a canonical form; whether
    // each record in a value keeps the limit is validateRecord's question.
    expect(MAX_CONTAINER_DEPTH).toBe(MAX_DEPTH + 3);
    let nested: unknown = 1;
    for (let i = 0; i < MAX_CONTAINER_DEPTH; i++) nested = [nested];
    expect(canonicalize(nested)).toBe(
      `${"[".repeat(MAX_CONTAINER_DEPTH)}1${"]".repeat(MAX_CONTAINER_DEPTH)}`,
    );
    expect(canonicalBytes(nested)).toHaveLength(2 * MAX_CONTAINER_DEPTH + 1);
    expect(rejected([nested]).clause).toBe("core 1.9");
    expect(rejected({ a: nested }).clause).toBe("core 1.9");
    // Content IDs follow: the deepest container has one, and nothing deeper has.
    expect(contentId({ a: (nested as unknown[])[0] })).toMatch(/^bciq/);
    expect(contentIdIfAny({ a: (nested as unknown[])[0] })).toMatch(/^bciq/);
    expect(() => contentId({ a: nested })).toThrow(OipError);
    expect(contentIdIfAny({ a: nested })).toBeUndefined();
  });

  it("serialises nothing while every object or every array has a toJSON", () => {
    // The serialiser calls a toJSON wherever it finds one. Put on a prototype by
    // other code in the process, it would give every record one canonical form
    // and one content ID. Then nothing is hashed, signed or accepted.
    const record = { oip: "1", type: "Example", n: 1 };
    const expected = canonicalize(record);
    for (const prototype of [Object.prototype, Array.prototype] as object[]) {
      Object.defineProperty(prototype, "toJSON", {
        value: () => "all the same",
        configurable: true,
        writable: true,
      });
      try {
        expect(() => canonicalize(record)).toThrow("nothing can be serialised safely");
        expect(() => canonicalBytes([1, 2])).toThrow(Error);
        expect(() => contentId(record)).toThrow(Error);
        expect(contentIdIfAny(record)).toBeUndefined();
      } finally {
        delete (prototype as { toJSON?: unknown }).toJSON;
      }
    }
    expect(canonicalize(record)).toBe(expected);
  });

  it("is not fooled by members named like the things it refuses", () => {
    expect(canonicalize({ toJSON: "a string", __proto__: null, constructor: 1 })).toBe(
      '{"constructor":1,"toJSON":"a string"}',
    );
    const parsed = parseJson('{"toJSON":1,"__proto__":{"b":2},"valueOf":3}');
    expect(parsed.ok && canonicalize(parsed.value)).toBe(
      '{"__proto__":{"b":2},"toJSON":1,"valueOf":3}',
    );
    expect(canonicalize(Object.create(null))).toBe("{}");
  });
});
