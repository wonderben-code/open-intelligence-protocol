// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The JSON profile of core Section 1: a strict parser for record text.
 *
 * `JSON.parse` cannot be used for records. It keeps the last of two members
 * with the same name, so two receivers could read one text as two different
 * records; it turns `1e400` into Infinity and `0.1` into a float. This
 * parser rejects all of those, and nests no deeper than the limit of
 * core 1.9, so no text can exhaust the stack.
 */

import {
  IMPLEMENTATION_LIMIT,
  type Issue,
  type JsonValue,
  MAX_CONTAINER_DEPTH,
  MAX_DEPTH,
  MAX_SAFE_INTEGER,
  quote,
  textFault,
  type Validation,
  judging,
  noteCutShort,
} from "@oip/schema";

import { decodeUtf8 } from "./bytes.ts";

/** What bounds the parsing of one text. */
export interface ParseOptions {
  /**
   * The longest text to parse, in UTF-16 code units for a string and in
   * bytes for bytes: a non-negative integer. Default: `MAX_TEXT_LENGTH`. A
   * service that accepts containers of many records sets its own. A value
   * that is not a non-negative integer is ignored, and the default applies:
   * a mistake in configuration must not switch the limit off.
   */
  readonly maxLength?: number;
}

/**
 * The limit on length that the options give. It is the one limit on a text
 * as a whole: a text of that length holds at most half as many values, and
 * the parser spends on each about what the platform's own parser does.
 */
function lengthLimit(options: ParseOptions | undefined): number {
  // Its own member only: a limit must not come from a prototype that other code changed.
  const from: unknown = options;
  const given: unknown =
    typeof from === "object" && from !== null && Object.hasOwn(from, "maxLength")
      ? (from as ParseOptions).maxLength
      : undefined;
  return typeof given === "number" && Number.isSafeInteger(given) && given >= 0
    ? given
    : MAX_TEXT_LENGTH;
}

/**
 * The longest text this implementation parses unless told otherwise. A
 * record's canonical form is at most 1 MiB (core 1.6), but escapes and white
 * space make the text sent longer, and the specification sets no limit on
 * that. Eight times the canonical limit is far more than any honest sender
 * needs.
 */
export const MAX_TEXT_LENGTH = 8 * 1024 * 1024;

class Rejected extends Error {
  readonly issue: Issue;
  constructor(message: string, clause: string, at: number) {
    super(message);
    this.issue = { path: "", message: `${message} (at character ${at})`, clause };
  }
}

const QUOTE = 0x22;
const BACKSLASH = 0x5c;
const MINUS = 0x2d;
const ZERO = 0x30;
const NINE = 0x39;

const isDigit = (code: number) => code >= ZERO && code <= NINE;

/**
 * The value of a number written as JSON, if it is an integer within the safe
 * range, and `undefined` otherwise. Validity depends on the value, not on how
 * it is written (core 1.2): `1.0` and `1e2` are the integers 1 and 100. The
 * check is exact: it works on the digits, never through a float.
 *
 * The number is `integer.fraction × 10^exponent`.
 */
function integerValue(
  negative: boolean,
  integer: string,
  fraction: string,
  exponent: number,
): number | undefined {
  const digits = integer + fraction;
  let first = 0;
  while (digits.charCodeAt(first) === ZERO) first++;
  // Nothing but zeros: the value is 0, whatever the exponent. -0 is 0 (core 2.2).
  if (first === digits.length) return 0;
  let last = digits.length;
  while (digits.charCodeAt(last - 1) === ZERO) last--;
  // The value is the significant digits followed by `zeros` zeros.
  const zeros = exponent - fraction.length + (digits.length - last);
  if (zeros < 0) return undefined; // a fractional part
  if (last - first + zeros > 16) return undefined; // more digits than 2^53 - 1 has
  // At most 16 digits: the conversion is exact up to 2^53, and anything
  // greater converts to at least 2^53, so the comparison is exact too.
  const value = Number(digits.slice(first, last) + "0".repeat(zeros));
  if (value > MAX_SAFE_INTEGER) return undefined;
  return negative ? -value : value;
}

const TEXT_FAULTS = {
  "unpaired surrogate": "a string contains an unpaired surrogate, which is not valid Unicode",
  noncharacter:
    "a string contains a noncharacter (U+FDD0 to U+FDEF, or a code point ending FFFE or FFFF), which a record may not contain",
} as const;

class Parser {
  readonly #text: string;
  readonly #maxDepth: number;
  readonly #elements: JsonValue[] = [];
  #at = 0;
  /** How deep the arrays and objects read so far nest. */
  deepest = 0;

  constructor(text: string, maxDepth: number) {
    this.#text = text;
    this.#maxDepth = maxDepth;
  }

  parse(): JsonValue {
    this.#space();
    const value = this.#value(1);
    this.#space();
    if (this.#at < this.#text.length)
      this.#fail("unexpected text after the JSON value", "core 1.1");
    return value;
  }

  #fail(message: string, clause: string): never {
    throw new Rejected(message, clause, this.#at);
  }

  #space(): void {
    for (;;) {
      const code = this.#text.charCodeAt(this.#at);
      if (code !== 0x20 && code !== 0x0a && code !== 0x0d && code !== 0x09) return;
      this.#at++;
    }
  }

  #value(depth: number): JsonValue {
    const code = this.#text.charCodeAt(this.#at);
    switch (code) {
      case 0x7b: // {
        return this.#object(depth);
      case 0x5b: // [
        return this.#array(depth);
      case QUOTE:
        return this.#string();
      case 0x74: // t
        return this.#literal("true", true);
      case 0x66: // f
        return this.#literal("false", false);
      case 0x6e: // n
        return this.#literal("null", null);
      default:
        if (code === MINUS || isDigit(code)) return this.#number();
        return this.#fail(
          Number.isNaN(code) ? "the text ends where a value should be" : "not a JSON value",
          "core 1.1",
        );
    }
  }

  #literal<T extends JsonValue>(word: string, value: T): T {
    if (!this.#text.startsWith(word, this.#at)) this.#fail("not a JSON value", "core 1.1");
    this.#at += word.length;
    return value;
  }

  #deeper(depth: number): void {
    if (depth > this.#maxDepth) {
      this.#fail(`arrays and objects nest more than ${MAX_DEPTH} deep`, "core 1.9");
    }
    if (depth > this.deepest) this.deepest = depth;
  }

  #object(depth: number): JsonValue {
    this.#deeper(depth);
    this.#at++;
    const object: Record<string, JsonValue> = {};
    this.#space();
    if (this.#text.charCodeAt(this.#at) === 0x7d) {
      this.#at++;
      return object;
    }
    for (;;) {
      if (this.#text.charCodeAt(this.#at) !== QUOTE)
        this.#fail("a member name must be a string", "core 1.1");
      const name = this.#string();
      if (Object.hasOwn(object, name)) {
        this.#fail(`the member name ${quote(name)} appears twice in one object`, "core 1.1");
      }
      this.#space();
      if (this.#text.charCodeAt(this.#at) !== 0x3a)
        this.#fail('expected ":" after a member name', "core 1.1");
      this.#at++;
      this.#space();
      // Assignment to "__proto__" would set the prototype instead of adding a member.
      Object.defineProperty(object, name, {
        value: this.#value(depth + 1),
        writable: true,
        enumerable: true,
        configurable: true,
      });
      this.#space();
      const next = this.#text.charCodeAt(this.#at);
      this.#at++;
      if (next === 0x7d) return object;
      if (next !== 0x2c) {
        this.#at--;
        this.#fail('expected "," or "}" in an object', "core 1.1");
      }
      this.#space();
    }
  }

  #array(depth: number): JsonValue {
    this.#deeper(depth);
    this.#at++;
    this.#space();
    if (this.#text.charCodeAt(this.#at) === 0x5d) {
      this.#at++;
      return [];
    }
    // Elements gather at the end of one shared list, and the array is made from
    // them at exactly its size. An array grown one element at a time keeps room
    // for many more, and a text of small arrays would cost several times as much.
    const base = this.#elements.length;
    for (;;) {
      this.#elements.push(this.#value(depth + 1));
      this.#space();
      const next = this.#text.charCodeAt(this.#at);
      this.#at++;
      if (next === 0x5d) return this.#cut(base);
      if (next !== 0x2c) {
        this.#at--;
        this.#fail('expected "," or "]" in an array', "core 1.1");
      }
      this.#space();
    }
  }

  /**
   * The elements gathered since `base`, as an array of their own. It is built
   * by hand: `splice` and `slice` ask the array's constructor what kind of
   * array to make, which other code in the process can change, and what the
   * parser returns must be a plain array whatever that code has done.
   */
  #cut(base: number): JsonValue[] {
    const elements = this.#elements;
    const count = elements.length - base;
    const array = new Array<JsonValue>(count);
    for (let i = 0; i < count; i++) array[i] = elements[base + i] as JsonValue;
    elements.length = base;
    return array;
  }

  #string(): string {
    const text = this.#text;
    this.#at++;
    let out = "";
    let from = this.#at;
    for (;;) {
      const code = text.charCodeAt(this.#at);
      if (code === QUOTE) {
        out += text.slice(from, this.#at);
        this.#at++;
        break;
      }
      if (code === BACKSLASH) {
        out += text.slice(from, this.#at) + this.#escape();
        from = this.#at;
        continue;
      }
      if (Number.isNaN(code)) this.#fail("the text ends inside a string", "core 1.1");
      if (code < 0x20) this.#fail("a control character must be escaped in a string", "core 1.1");
      this.#at++;
    }
    // core 1.1: every string is valid Unicode and holds no noncharacter. Either may
    // come from an escape, so the check is on the finished string.
    const fault = textFault(out);
    if (fault !== undefined) this.#fail(TEXT_FAULTS[fault], "core 1.1");
    return out;
  }

  #escape(): string {
    const text = this.#text;
    const code = text.charCodeAt(this.#at + 1);
    this.#at += 2;
    switch (code) {
      case QUOTE:
        return '"';
      case BACKSLASH:
        return "\\";
      case 0x2f:
        return "/";
      case 0x62:
        return "\b";
      case 0x66:
        return "\f";
      case 0x6e:
        return "\n";
      case 0x72:
        return "\r";
      case 0x74:
        return "\t";
      case 0x75: {
        const hex = text.slice(this.#at, this.#at + 4);
        if (hex.length !== 4 || /[^0-9a-fA-F]/.test(hex)) {
          this.#fail("\\u must be followed by four hexadecimal digits", "core 1.1");
        }
        this.#at += 4;
        return String.fromCharCode(Number.parseInt(hex, 16));
      }
      default:
        this.#at -= 2;
        return this.#fail("not an escape that JSON defines", "core 1.1");
    }
  }

  #number(): number {
    const text = this.#text;
    const start = this.#at;
    const negative = text.charCodeAt(this.#at) === MINUS;
    if (negative) this.#at++;
    const integerStart = this.#at;
    while (isDigit(text.charCodeAt(this.#at))) this.#at++;
    const integer = text.slice(integerStart, this.#at);
    if (integer === "" || (integer.length > 1 && integer.startsWith("0"))) {
      this.#at = start;
      this.#fail("not a JSON number", "core 1.1");
    }
    let fraction = "";
    if (text.charCodeAt(this.#at) === 0x2e) {
      const fractionStart = ++this.#at;
      while (isDigit(text.charCodeAt(this.#at))) this.#at++;
      fraction = text.slice(fractionStart, this.#at);
      if (fraction === "") this.#fail("a digit must follow the decimal point", "core 1.1");
    }
    let exponent = 0;
    const e = text.charCodeAt(this.#at);
    if (e === 0x65 || e === 0x45) {
      this.#at++;
      const sign = text.charCodeAt(this.#at);
      if (sign === 0x2b || sign === MINUS) this.#at++;
      const exponentStart = this.#at;
      while (isDigit(text.charCodeAt(this.#at))) this.#at++;
      const written = text.slice(exponentStart, this.#at);
      if (written === "") this.#fail("a digit must follow the exponent", "core 1.1");
      // The exponent may be any run of digits. A size too large to hold
      // exactly, or infinite, still puts the value out of range below, as it
      // should: the text is far too short to bring such a value back.
      const size = Number(written);
      exponent = sign === MINUS ? -size : size;
    }
    const value = integerValue(negative, integer, fraction, exponent);
    if (value === undefined) {
      const written = text.slice(start, Math.min(this.#at, start + 40));
      this.#at = start;
      this.#fail(
        `the number ${written} is not an integer between -(2^53-1) and 2^53-1; write decimal quantities as strings`,
        "core 1.2",
      );
    }
    return value;
  }
}

function tooLong<T>(limit: number, unit: string): Validation<T> {
  return {
    ok: false,
    issues: [
      {
        path: "",
        message: `the text is longer than ${limit} ${unit}, the most this reader accepts`,
        clause: IMPLEMENTATION_LIMIT,
      },
    ],
  };
}

function rejection<T>(message: string, clause: string): Validation<T> {
  return { ok: false, issues: [{ path: "", message, clause }] };
}

/** A value the parser built, and how deep its arrays and objects nest. */
export interface Parsed {
  readonly value: JsonValue;
  readonly deepest: number;
}

/** Parses text that is known to be a string, to a depth the caller chooses. */
function parseText(text: string, limit: number, maxDepth: number): Validation<Parsed> {
  if (text.length > limit) return tooLong(limit, "characters");
  // A record is encoded as UTF-8 (core 1.1), so its text is valid Unicode before
  // any escape is read: half a surrogate pair written raw has no encoding, even
  // if an escape beside it would complete the pair.
  if (textFault(text) === "unpaired surrogate") {
    return rejection("the text is not valid Unicode: it has an unpaired surrogate", "core 1.1");
  }
  try {
    const parser = new Parser(text, maxDepth);
    const value = parser.parse();
    return { ok: true, value: { value, deepest: parser.deepest } };
  } catch (error) {
    // Anything but a rejection is a fault in this parser, not in the text, and is not hidden.
    // Stryker disable next-line all: no test can reach it while the parser is sound.
    /* v8 ignore next -- @preserve */
    if (!(error instanceof Rejected)) throw error;
    return { ok: false, issues: [error.issue] };
  }
}

/** Parses bytes that are known to be a `Uint8Array`, to a depth the caller chooses. */
function parseBytes(bytes: Uint8Array, limit: number, maxDepth: number): Validation<Parsed> {
  if (bytes.length > limit) return tooLong(limit, "bytes");
  const text = decodeUtf8(bytes);
  if (text === undefined) return rejection("the bytes are not valid UTF-8", "core 1.1");
  return parseText(text, limit, maxDepth);
}

/**
 * Parses text or bytes as `parseJson` and `parseJsonBytes` do, to the depth
 * a container may have, and says how deep the value nests. For `parseRecord`
 * alone, which validates the value at once, as the parser built it, and
 * applies core 1.9 to each record.
 */
export function parseForRecord(
  input: unknown,
  options: ParseOptions | undefined,
): Validation<Parsed> {
  try {
    const limit = lengthLimit(options);
    if (typeof input === "string") return parseText(input, limit, MAX_CONTAINER_DEPTH);
    if (input instanceof Uint8Array) return parseBytes(input, limit, MAX_CONTAINER_DEPTH);
  } catch (error) {
    noteCutShort(error);
    // A value that cannot even be examined, such as a revoked proxy.
  }
  return rejection("a record is read from text or from bytes", "core 1.1");
}

/** The value alone, for a caller that asked for no more. */
function valueOf(parsed: Validation<Parsed>): Validation<JsonValue> {
  return parsed.ok ? { ok: true, value: parsed.value.value } : parsed;
}

/**
 * Parses JSON text under the profile of core Section 1. It rejects, and
 * says why: duplicate member names, invalid Unicode and noncharacters (1.1),
 * numbers that are not safe integers (1.2), nesting deeper than 64 (1.9),
 * and anything that is not JSON (RFC 8259), including a byte order mark. Any
 * JSON value may stand at the top; whether it is a record is `parseRecord`'s
 * question.
 *
 * The value it returns is plain data: `-0` is read as 0, and a member named
 * `__proto__` is an ordinary member. It never throws.
 */
export function parseJson(text: string, options?: ParseOptions): Validation<JsonValue> {
  return judging(() => jsonOfText(text, options));
}

/** The value, as `parseJson` answers when no check is cut short. */
function jsonOfText(text: string, options?: ParseOptions): Validation<JsonValue> {
  try {
    if (typeof text === "string") {
      return valueOf(parseText(text, lengthLimit(options), MAX_DEPTH));
    }
  } catch (error) {
    noteCutShort(error);
    // Options that cannot be read.
  }
  return rejection("not text", "core 1.1");
}

/**
 * Parses the UTF-8 bytes of JSON text under the profile of core Section 1.
 * Bytes that are not valid UTF-8 are rejected (core 1.1). It never throws.
 */
export function parseJsonBytes(bytes: Uint8Array, options?: ParseOptions): Validation<JsonValue> {
  return judging(() => jsonOfBytes(bytes, options));
}

/** The value, as `parseJsonBytes` answers when no check is cut short. */
function jsonOfBytes(bytes: Uint8Array, options?: ParseOptions): Validation<JsonValue> {
  try {
    if (bytes instanceof Uint8Array) {
      return valueOf(parseBytes(bytes, lengthLimit(options), MAX_DEPTH));
    }
  } catch (error) {
    noteCutShort(error);
    // A value that cannot even be examined, such as a revoked proxy.
  }
  return rejection("not bytes", "core 1.1");
}
