// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { IMPLEMENTATION_LIMIT, MAX_DEPTH } from "@oip/schema";
import { clause } from "@oip/testkit";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { MAX_TEXT_LENGTH, parseJson, parseJsonBytes } from "../src/index.ts";

const utf8 = (text: string) => new TextEncoder().encode(text);

/** The value, or a failure that shows the issue. */
function value(text: string): unknown {
  const parsed = parseJson(text);
  if (!parsed.ok) throw new Error(`rejected: ${parsed.issues[0].message}`);
  return parsed.value;
}

/** The clause of the rejection, or a failure that shows what was accepted. */
function rejection(text: string): string {
  const parsed = parseJson(text);
  if (parsed.ok)
    throw new Error(`accepted ${text.slice(0, 80)} as ${JSON.stringify(parsed.value)}`);
  expect(parsed.issues).toHaveLength(1);
  expect(parsed.issues[0].path).toBe("");
  return parsed.issues[0].clause;
}

const message = (text: string) => {
  const parsed = parseJson(text);
  return parsed.ok ? "accepted" : parsed.issues[0].message;
};

describe("the JSON profile: what is JSON", () => {
  it("reads every kind of value", () => {
    expect(value("null")).toBeNull();
    expect(value("true")).toBe(true);
    expect(value("false")).toBe(false);
    expect(value("0")).toBe(0);
    expect(value("-12")).toBe(-12);
    expect(value('""')).toBe("");
    expect(value('"a"')).toBe("a");
    expect(value("[]")).toEqual([]);
    expect(value("{}")).toEqual({});
    expect(value('[1,"a",null,true,false,[],{}]')).toEqual([1, "a", null, true, false, [], {}]);
    expect(value('{"a":{"b":[{"c":1}]},"d":"e"}')).toEqual({ a: { b: [{ c: 1 }] }, d: "e" });
  });

  it("allows white space around every token, and only the four characters JSON names", () => {
    expect(value(' \t\r\n{ "a" : [ 1 , 2 ] , "b" : { } } \n')).toEqual({ a: [1, 2], b: {} });
    expect(value("[ ]")).toEqual([]);
    expect(value("{ }")).toEqual({});
    for (const space of ["\u00a0", "\u2028", "\ufeff", "\v", "\f", "\u0000"]) {
      expect(rejection(`${space}1`), JSON.stringify(space)).toBe("core 1.1");
      expect(rejection(`1${space}`), JSON.stringify(space)).toBe("core 1.1");
      expect(rejection(`[1,${space}2]`), JSON.stringify(space)).toBe("core 1.1");
    }
  });

  it("reads every escape, and nothing JSON does not define", () => {
    expect(value(String.raw`"\"\\\/\b\f\n\r\t"`)).toBe('"\\/\b\f\n\r\t');
    expect(value(String.raw`"\u0041\u00e9\u00E9\u20ac"`)).toBe("A\u00e9\u00e9\u20ac");
    expect(value(String.raw`"a\u0000b"`)).toBe("a\u0000b");
    expect(value(String.raw`"\ud83d\ude00"`)).toBe("😀");
    expect(value('"😀 é \u2028 \u007f"')).toBe("😀 é \u2028 \u007f");
    for (const bad of [
      String.raw`"\x41"`,
      String.raw`"\a"`,
      String.raw`"\'"`,
      String.raw`"\0"`,
      String.raw`"\u12"`,
      String.raw`"\u12g4"`,
      String.raw`"\u+123"`,
      String.raw`"\u 123"`,
      String.raw`"\U0041"`,
      String.raw`"\"`,
      String.raw`"\u00"`,
    ]) {
      expect(rejection(bad), bad).toBe("core 1.1");
    }
  });

  it("requires control characters to be escaped", () => {
    for (let code = 0; code < 0x20; code++) {
      expect(rejection(`"a${String.fromCharCode(code)}b"`), String(code)).toBe("core 1.1");
    }
    expect(value('"a\u007fb"')).toBe("a\u007fb");
    expect(value('" "')).toBe(" ");
  });

  it("rejects everything that is not one complete JSON value", () => {
    for (const bad of [
      "",
      " ",
      "nul",
      "nulll",
      "tru",
      "True",
      "fals",
      "undefined",
      "NaN",
      "Infinity",
      "-Infinity",
      "-",
      "+1",
      "01",
      "-01",
      "00",
      "1.",
      ".5",
      "1e",
      "1e+",
      "1E-",
      "0x10",
      "1_000",
      "1 2",
      "'a'",
      '"a',
      '"',
      "[",
      "]",
      "[1",
      "[1,",
      "[1,]",
      "[,1]",
      "[1 2]",
      "[1,,2]",
      "{",
      "}",
      '{"a"',
      '{"a":',
      '{"a":1',
      '{"a":1,',
      '{"a":1,}',
      '{,"a":1}',
      "{a:1}",
      "{1:1}",
      '{"a" 1}',
      '{"a":1 "b":2}',
      '{"a":1,,"b":2}',
      '{"a"}',
      '{"a":}',
      "[1]]",
      "{}{}",
      "[] []",
      "// a comment\n1",
      "/* a comment */ 1",
      "1 // a comment",
      "\ufeff{}",
      "[1}",
      '{"a":1]',
    ]) {
      expect(rejection(bad), JSON.stringify(bad)).toBe("core 1.1");
    }
  });

  it("says what is wrong and where", () => {
    expect(message("[1,")).toBe("the text ends where a value should be (at character 3)");
    expect(message("[1,x]")).toBe("not a JSON value (at character 3)");
    expect(message("nul")).toBe("not a JSON value (at character 0)");
    expect(message("1 2")).toBe("unexpected text after the JSON value (at character 2)");
    expect(message('{"a":1 "b":2}')).toBe('expected "," or "}" in an object (at character 7)');
    expect(message("[1 2]")).toBe('expected "," or "]" in an array (at character 3)');
    expect(message('{"a" 1}')).toBe('expected ":" after a member name (at character 5)');
    expect(message("{a:1}")).toBe("a member name must be a string (at character 1)");
    expect(message('{"a":1,}')).toBe("a member name must be a string (at character 7)");
    expect(message('"abc')).toBe("the text ends inside a string (at character 4)");
    expect(message('"a\nb"')).toBe(
      "a control character must be escaped in a string (at character 2)",
    );
    expect(message(String.raw`"a\qb"`)).toBe("not an escape that JSON defines (at character 2)");
    expect(message(String.raw`"a\u12"`)).toBe(
      String.raw`\u must be followed by four hexadecimal digits (at character 4)`,
    );
    expect(message("-x")).toBe("not a JSON number (at character 0)");
    expect(message("[012]")).toBe("not a JSON number (at character 1)");
    expect(message("1.x")).toBe("a digit must follow the decimal point (at character 2)");
    expect(message("1ex")).toBe("a digit must follow the exponent (at character 2)");
    expect(message("1e+")).toBe("a digit must follow the exponent (at character 3)");
  });

  it("never throws, whatever it is given", () => {
    for (const notText of [undefined, null, 1, {}, [], Symbol("x"), 1n]) {
      const parsed = parseJson(notText as string);
      expect(parsed.ok).toBe(false);
    }
    expect(parseJsonBytes("{}" as unknown as Uint8Array).ok).toBe(false);
    expect(parseJsonBytes([123, 125] as unknown as Uint8Array).ok).toBe(false);
  });
});

describe(`${clause("core 1.1")} no duplicate member names`, () => {
  it("rejects a name that appears twice in one object", () => {
    expect(rejection('{"a":1,"a":2}')).toBe("core 1.1");
    expect(rejection('{"a":1,"b":2,"a":1}')).toBe("core 1.1");
    expect(rejection('{"x":{"a":1,"a":1}}')).toBe("core 1.1");
    expect(rejection('[{"a":null,"a":null}]')).toBe("core 1.1");
    expect(rejection('{"":1,"":2}')).toBe("core 1.1");
    expect(message('{"a":1,"a":2}')).toBe(
      'the member name "a" appears twice in one object (at character 10)',
    );
  });

  it("compares names after unescaping them", () => {
    expect(rejection(String.raw`{"a":1,"\u0061":2}`)).toBe("core 1.1");
    expect(rejection(String.raw`{"é":1,"\u00e9":2}`)).toBe("core 1.1");
    expect(rejection(String.raw`{"\n":1,"\u000a":2}`)).toBe("core 1.1");
    expect(rejection(String.raw`{"\/":1,"/":2}`)).toBe("core 1.1");
    // Different strings are different names, however alike they look.
    expect(value('{"\u00e9":1,"e\u0301":2}')).toEqual({ "\u00e9": 1, "e\u0301": 2 });
    expect(value('{"a":1,"A":2}')).toEqual({ a: 1, A: 2 });
  });

  it("allows the same name in different objects", () => {
    expect(value('{"a":{"a":{"a":1}},"b":[{"a":1},{"a":2}]}')).toEqual({
      a: { a: { a: 1 } },
      b: [{ a: 1 }, { a: 2 }],
    });
  });

  it("treats names that objects inherit as ordinary names", () => {
    const parsed = value(
      '{"__proto__":{"polluted":true},"constructor":1,"toString":2,"hasOwnProperty":3,"valueOf":4}',
    ) as Record<string, unknown>;
    expect(Object.keys(parsed)).toEqual([
      "__proto__",
      "constructor",
      "toString",
      "hasOwnProperty",
      "valueOf",
    ]);
    expect(Object.getPrototypeOf(parsed)).toBe(Object.prototype);
    expect(Object.getOwnPropertyDescriptor(parsed, "__proto__")?.value).toEqual({ polluted: true });
    expect(({} as { polluted?: boolean }).polluted).toBeUndefined();
    expect(rejection('{"__proto__":1,"__proto__":2}')).toBe("core 1.1");
    expect(rejection('{"constructor":1,"constructor":2}')).toBe("core 1.1");
    expect(rejection('{"toString":1,"toString":2}')).toBe("core 1.1");
  });

  it("shows only the start of a long name", () => {
    const name = "n".repeat(5000);
    expect(message(`{"${name}":1,"${name}":2}`).length).toBeLessThan(200);
  });
});

describe(`${clause("core 1.1")} every string is valid Unicode`, () => {
  it("rejects an unpaired surrogate, written as an escape or as itself", () => {
    for (const bad of [
      String.raw`"\ud800"`,
      String.raw`"\udc00"`,
      String.raw`"\ud800a"`,
      String.raw`"a\udfff"`,
      String.raw`"\ud800\ud800"`,
      String.raw`"\udc00\ud800"`,
      String.raw`"\ud83d\u0041"`,
      String.raw`"\ud83d\ude00\ud83d"`,
      `"\ud800"`,
      `"a\udc00b"`,
      `"\udbff"`,
      String.raw`{"\ud800":1}`,
      String.raw`{"a":["\udfff"]}`,
    ]) {
      expect(rejection(bad), JSON.stringify(bad)).toBe("core 1.1");
    }
    expect(message(String.raw`"\ud800"`)).toMatch(/^a string contains an unpaired surrogate/);
  });

  it("accepts a surrogate pair however its halves are written", () => {
    expect(value(String.raw`"\ud83d\ude00"`)).toBe("😀");
    expect(value(`"\ud83d\\ude00"`)).toBe("😀");
    expect(value(String.raw`"\uD800\uDC00\udbff\udfff"`)).toBe("\u{10000}\u{10ffff}");
    expect(value(String.raw`"\ud7ff\ue000"`)).toBe("\ud7ff\ue000");
  });
});

describe(`${clause("core 1.2")} numbers are safe integers, judged by value`, () => {
  it("reads an integer however it is written", () => {
    expect(value("1.0")).toBe(1);
    expect(value("1e2")).toBe(100);
    expect(value("1E2")).toBe(100);
    expect(value("1e+2")).toBe(100);
    expect(value("100e-2")).toBe(1);
    expect(value("1.50e1")).toBe(15);
    expect(value("-2.5e1")).toBe(-25);
    expect(value("12.000")).toBe(12);
    expect(value("0.00001e5")).toBe(1);
    expect(value("123456789e-0")).toBe(123456789);
    expect(value("1e0")).toBe(1);
    expect(value("1e00002")).toBe(100);
    expect(value("5000e-3")).toBe(5);
    expect(value("9007199254740991")).toBe(Number.MAX_SAFE_INTEGER);
    expect(value("-9007199254740991")).toBe(-Number.MAX_SAFE_INTEGER);
    expect(value("9007199254740991.0")).toBe(Number.MAX_SAFE_INTEGER);
    expect(value("9.007199254740991e15")).toBe(Number.MAX_SAFE_INTEGER);
    expect(value("90071992547409910e-1")).toBe(Number.MAX_SAFE_INTEGER);
    expect(value("0.9007199254740991e16")).toBe(Number.MAX_SAFE_INTEGER);
    expect(value("9e15")).toBe(9_000_000_000_000_000);
    expect(value("1e15")).toBe(1_000_000_000_000_000);
    expect(value("123456789012345")).toBe(123456789012345);
    expect(value("1234567890123456")).toBe(1234567890123456);
  });

  it("reads zero as 0 however it is written, never as -0", () => {
    for (const zero of [
      "0",
      "-0",
      "0.0",
      "-0.000",
      "0e0",
      "0e999999999999999999999",
      "-0e-5",
      "0.0e+7",
    ]) {
      expect(Object.is(value(zero), 0), zero).toBe(true);
    }
    expect(Object.is(value("[-0]"), 0)).toBe(false);
    expect(Object.is((value("[-0]") as number[])[0], 0)).toBe(true);
  });

  it("rejects a number with a fractional part", () => {
    for (const bad of [
      "1.5",
      "0.1",
      "-0.5",
      "1e-1",
      "15e-1",
      "1.25e1",
      "100e-3",
      "0.000001",
      "5e-324",
      "1e-999999999999",
      "123456789.123456789",
      "9007199254740991.5",
      "1.0000000000000000000000001",
      "0.1e0",
    ]) {
      expect(rejection(bad), bad).toBe("core 1.2");
    }
  });

  it("rejects an integer outside the range, exactly at its edge", () => {
    for (const bad of [
      "9007199254740992",
      "-9007199254740992",
      "9007199254740993",
      "9007199254740992.0",
      "9.007199254740992e15",
      "1e16",
      "10000000000000000",
      "99999999999999999",
      "1e400",
      "-1e400",
      "1e999999999999999999999",
      "123456789012345678901234567890",
      "0.1e17",
      "18446744073709551616",
    ]) {
      expect(rejection(bad), bad).toBe("core 1.2");
    }
    expect(message("[1.5]")).toBe(
      "the number 1.5 is not an integer between -(2^53-1) and 2^53-1; write decimal quantities as strings (at character 1)",
    );
  });

  it("is exact where a float would round", () => {
    // 2^53 + 1 rounds to 2^53 as a float; both are out of range.
    expect(rejection("9007199254740993")).toBe("core 1.2");
    // A float would read these as the integer 1.
    expect(rejection("1.0000000000000001")).toBe("core 1.2");
    expect(rejection("0.99999999999999999999")).toBe("core 1.2");
    // A fraction that long digits push below any float is still a fraction.
    expect(rejection(`0.${"0".repeat(400)}1`)).toBe("core 1.2");
    // An exponent can bring a long run of digits back to an integer.
    expect(value(`0.${"0".repeat(400)}1e401`)).toBe(1);
    expect(value(`1${"0".repeat(400)}e-400`)).toBe(1);
    expect(value(`0.${"0".repeat(20000)}1e20001`)).toBe(1);
    expect(rejection(`0.${"0".repeat(20000)}1e20000`)).toBe("core 1.2");
    expect(rejection(`1${"0".repeat(20000)}e-19984`)).toBe("core 1.2");
    expect(value(`9${"0".repeat(20000)}e-19985`)).toBe(9e15);
    expect(value(`0.${"0".repeat(50)}`)).toBe(0);
  });

  it("shows only the start of a long number", () => {
    expect(message(`1${"0".repeat(5000)}`)).toBe(
      `the number 1${"0".repeat(39)} is not an integer between -(2^53-1) and 2^53-1; write decimal quantities as strings (at character 0)`,
    );
  });

  it("agrees with exact arithmetic on any number", () => {
    const digits = fc.stringMatching(/^[0-9]{1,25}$/);
    fc.assert(
      fc.property(
        fc.boolean(),
        fc.stringMatching(/^(0|[1-9][0-9]{0,24})$/),
        fc.option(digits, { nil: undefined }),
        fc.option(fc.integer({ min: -40, max: 40 }), { nil: undefined }),
        (negative, integer, fraction, exponent) => {
          const text =
            (negative ? "-" : "") +
            integer +
            (fraction === undefined ? "" : `.${fraction}`) +
            (exponent === undefined ? "" : `e${exponent}`);
          // The value as a fraction of two integers: units / 10^scale.
          const scale = (fraction?.length ?? 0) - (exponent ?? 0);
          const units = BigInt(integer + (fraction ?? "")) * (negative ? -1n : 1n);
          const numerator = scale < 0 ? units * 10n ** BigInt(-scale) : units;
          const denominator = scale > 0 ? 10n ** BigInt(scale) : 1n;
          const whole = numerator % denominator === 0n;
          const quotient = numerator / denominator;
          const inRange = quotient >= -(2n ** 53n - 1n) && quotient <= 2n ** 53n - 1n;
          const parsed = parseJson(text);
          expect(parsed.ok, text).toBe(whole && inRange);
          if (parsed.ok) expect(parsed.value, text).toBe(Number(quotient));
        },
      ),
      { numRuns: 5000 },
    );
  });
});

describe("depth and length", () => {
  const nested = (depth: number, open: string, close: string) =>
    open.repeat(depth) + close.repeat(depth);

  it(`reads arrays and objects nested ${MAX_DEPTH} deep, and no deeper`, () => {
    expect(parseJson(nested(MAX_DEPTH, "[", "]")).ok).toBe(true);
    expect(rejection(nested(MAX_DEPTH + 1, "[", "]"))).toBe(IMPLEMENTATION_LIMIT);
    const objects = (depth: number) => `${'{"a":'.repeat(depth)}1${"}".repeat(depth)}`;
    // The number inside is not a level: only arrays and objects nest.
    expect(parseJson(objects(MAX_DEPTH)).ok).toBe(true);
    expect(rejection(objects(MAX_DEPTH + 1))).toBe(IMPLEMENTATION_LIMIT);
    expect(
      parseJson(`[${nested(MAX_DEPTH - 1, "[", "]")},${nested(MAX_DEPTH - 1, "[", "]")}]`).ok,
    ).toBe(true);
    expect(message(nested(MAX_DEPTH + 1, "[", "]"))).toBe(
      `arrays and objects nest more than ${MAX_DEPTH} deep (at character ${MAX_DEPTH})`,
    );
  });

  it("is not exhausted by a text that only opens", () => {
    for (const open of ["[", '{"a":', '[[[{"a":']) {
      expect(rejection(open.repeat(200_000))).toBe(IMPLEMENTATION_LIMIT);
    }
    expect(rejection("[".repeat(10))).toBe("core 1.1");
  });

  it("reads a text up to the longest it accepts, and no longer", () => {
    const text = (length: number) => `"${"a".repeat(length - 2)}"`;
    expect(MAX_TEXT_LENGTH).toBe(8 * 1024 * 1024);
    expect(parseJson(text(MAX_TEXT_LENGTH)).ok).toBe(true);
    expect(rejection(text(MAX_TEXT_LENGTH + 1))).toBe(IMPLEMENTATION_LIMIT);
    expect(parseJson(text(100), { maxLength: 100 }).ok).toBe(true);
    expect(parseJson(text(101), { maxLength: 100 })).toEqual({
      ok: false,
      issues: [
        {
          path: "",
          message: "the text is longer than 100 characters, the most this reader accepts",
          clause: IMPLEMENTATION_LIMIT,
        },
      ],
    });
    // A caller that accepts containers of many records raises the limit.
    expect(parseJson(text(MAX_TEXT_LENGTH + 1), { maxLength: MAX_TEXT_LENGTH + 1 }).ok).toBe(true);
  });
});

describe(`${clause("core 1.1")} records are encoded as UTF-8`, () => {
  it("reads bytes as UTF-8", () => {
    expect(parseJsonBytes(utf8('{"é":"😀"}'))).toEqual({ ok: true, value: { é: "😀" } });
    expect(parseJsonBytes(new Uint8Array())).toMatchObject({ ok: false });
    expect(parseJsonBytes(Buffer.from("[1]")).ok).toBe(true);
  });

  it("rejects bytes that are not valid UTF-8", () => {
    for (const bad of [
      [0x22, 0xff, 0x22], // a byte that never appears in UTF-8
      [0x22, 0xc3, 0x22], // a sequence cut short
      [0x22, 0xc0, 0xaf, 0x22], // an overlong encoding of "/"
      [0x22, 0xed, 0xa0, 0x80, 0x22], // a surrogate, encoded
      [0x22, 0xf4, 0x90, 0x80, 0x80, 0x22], // beyond U+10FFFF
      [0x22, 0x80, 0x22], // a continuation byte on its own
    ]) {
      const parsed = parseJsonBytes(Uint8Array.from(bad));
      expect(parsed).toEqual({
        ok: false,
        issues: [{ path: "", message: "the bytes are not valid UTF-8", clause: "core 1.1" }],
      });
    }
  });

  it("does not skip a byte order mark", () => {
    const parsed = parseJsonBytes(Uint8Array.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d]));
    expect(parsed.ok).toBe(false);
  });

  it("applies the length limit to the bytes, before decoding them", () => {
    expect(parseJsonBytes(utf8('"aaaa"'), { maxLength: 6 }).ok).toBe(true);
    expect(parseJsonBytes(utf8('"aaaaa"'), { maxLength: 6 })).toEqual({
      ok: false,
      issues: [
        {
          path: "",
          message: "the text is longer than 6 bytes, the most this reader accepts",
          clause: IMPLEMENTATION_LIMIT,
        },
      ],
    });
    // Three bytes each: too long as bytes, though short as characters.
    expect(parseJsonBytes(utf8('"€€"'), { maxLength: 6 }).ok).toBe(false);
    // Invalid bytes beyond the limit are not decoded to find that out.
    expect(parseJsonBytes(new Uint8Array(7).fill(0xff), { maxLength: 6 })).toMatchObject({
      issues: [{ clause: IMPLEMENTATION_LIMIT }],
    });
  });
});

describe("the parser and the platform's agree on every value in the profile", () => {
  const json = fc.letrec((tie) => ({
    value: fc.oneof(
      { depthSize: "small" },
      fc.constant(null),
      fc.boolean(),
      fc.maxSafeInteger(),
      fc.string({ unit: "binary" }).filter((text) => text.isWellFormed()),
      fc.array(tie("value"), { maxLength: 5 }),
      fc.dictionary(
        fc.string({ unit: "binary" }).filter((text) => text.isWellFormed()),
        tie("value"),
        { maxKeys: 5 },
      ),
    ),
  })).value;

  it("reads back what the platform writes, in any layout", () => {
    fc.assert(
      fc.property(json, fc.constantFrom(undefined, 1, "\t"), (input, indent) => {
        const text = JSON.stringify(input, null, indent);
        const parsed = parseJson(text);
        expect(parsed.ok).toBe(true);
        // -0 is read as 0; nothing else differs.
        if (parsed.ok) expect(JSON.stringify(parsed.value)).toBe(JSON.stringify(input));
      }),
      { numRuns: 2000 },
    );
  });

  it("accepts nothing the platform's parser rejects, and returns the same value", () => {
    const soup = fc.string({
      unit: fc.constantFrom(...'[]{}:,"\\ \n0123456789.eE-+truefalsnu'.split("")),
      maxLength: 40,
    });
    fc.assert(
      fc.property(fc.oneof(soup, fc.string({ unit: "binary", maxLength: 40 })), (text) => {
        const parsed = parseJson(text);
        let reference: unknown;
        let valid = true;
        try {
          reference = JSON.parse(text);
        } catch {
          valid = false;
        }
        if (parsed.ok) {
          expect(valid, text).toBe(true);
          expect(JSON.stringify(parsed.value), text).toBe(JSON.stringify(reference));
        }
      }),
      { numRuns: 20000 },
    );
  });
});
