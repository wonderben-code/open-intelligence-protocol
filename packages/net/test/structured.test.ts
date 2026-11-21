// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { bytesToHex } from "@oip/core";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  type InnerList,
  type Item,
  parseDictionary,
  writeInnerList,
  writeItem,
} from "../src/index.ts";

const member = (text: string, name: string) => parseDictionary(text)?.get(name);
const item = (text: string): Item => {
  const found = member(`a=${text}`, "a");
  if (found?.kind !== "item") throw new Error(`no item: ${text}`);
  return found;
};
const list = (text: string): InnerList => {
  const found = member(`a=${text}`, "a");
  if (found?.kind !== "list") throw new Error(`no inner list: ${text}`);
  return found;
};

describe("structured field values (RFC 8941), as signatures and digests use them", () => {
  it("reads a dictionary of items, in the order written", () => {
    // RFC 8941, 3.2: members with values of several kinds, and one with none.
    const read = parseDictionary(
      'en="Applepie", da=:w4ZibGV0w6ZydGU=:, n=-42, t=text/plain, b=?0, c',
    );
    expect([...(read?.keys() ?? [])]).toStrictEqual(["en", "da", "n", "t", "b", "c"]);
    expect(read?.get("en")).toMatchObject({
      kind: "item",
      value: { kind: "string", value: "Applepie" },
    });
    const da = read?.get("da");
    expect(da?.kind === "item" && da.value.kind === "bytes" && bytesToHex(da.value.value)).toBe(
      "c386626c6574c3a67274 65".replace(" ", ""),
    );
    expect(read?.get("n")).toMatchObject({ value: { kind: "integer", value: -42 } });
    expect(read?.get("t")).toMatchObject({ value: { kind: "token", value: "text/plain" } });
    expect(read?.get("b")).toMatchObject({ value: { kind: "boolean", value: false } });
    // A member with no value is true (3.2).
    expect(read?.get("c")).toMatchObject({ value: { kind: "boolean", value: true } });
    expect(parseDictionary("")?.size).toBe(0);
    expect(parseDictionary("  a=1")?.size).toBe(1);
  });

  it("reads an inner list with its parameters, and each item's own", () => {
    const read = list(
      '("@method" "content-digest";sf "date");created=1618884473;keyid="k";tag=t;x',
    );
    expect(read.items.map((entry) => entry.value.value)).toStrictEqual([
      "@method",
      "content-digest",
      "date",
    ]);
    expect(read.items[1]?.parameters).toStrictEqual([["sf", { kind: "boolean", value: true }]]);
    expect(read.parameters.map(([name]) => name)).toStrictEqual(["created", "keyid", "tag", "x"]);
    expect(list("()").items).toStrictEqual([]);
    // Parameters may follow a space (4.2.3.2).
    expect(item("1; a=2; b").parameters).toHaveLength(2);
  });

  it("writes a value in its one writing, whatever spaces it was read with (4.1)", () => {
    const canonical =
      '("@method" "@target-uri");created=1618884473;nonce="a \\"b\\" \\\\ c";alg="ed25519";x';
    expect(writeInnerList(list(canonical))).toBe(canonical);
    expect(
      writeInnerList(
        list(
          '(  "@method"   "@target-uri" );created=1618884473; nonce="a \\"b\\" \\\\ c";alg="ed25519";x',
        ),
      ),
    ).toBe(canonical);
    expect(writeItem(item(":AQID:;a=?0;b=?1;c=tok"))).toBe(":AQID:;a=?0;b;c=tok");
    expect(writeItem(item("-0"))).toBe("0");
    // What is written reads back as it was.
    fc.assert(
      fc.property(
        fc.array(fc.stringMatching(/^[\x20-\x7e]{0,12}$/u), { maxLength: 4 }),
        fc.integer({ min: -999_999_999_999_999, max: 999_999_999_999_999 }),
        (strings, integer) => {
          const made: InnerList = {
            kind: "list",
            items: strings.map((value) => ({
              kind: "item",
              value: { kind: "string", value },
              parameters: [],
            })),
            parameters: [["n", { kind: "integer", value: integer }]],
          };
          const written = writeInnerList(made);
          expect(writeInnerList(list(written))).toBe(written);
          expect(list(written).items.map((entry) => entry.value.value)).toStrictEqual(strings);
        },
      ),
    );
  });

  it("reads no text that is not a dictionary of these kinds of value", () => {
    for (const text of [
      // A name given twice, in the dictionary and among parameters.
      "a=1, a=2",
      "a=1;x=1;x=2",
      // A comma with nothing after it, and nothing between two.
      "a=1,",
      "a=1,,b=2",
      "a=1 b=2",
      // Names that are none.
      "A=1",
      "1a=1",
      "=1",
      // Values that are none, or of a kind not read here.
      "a=",
      "a=1.5",
      "a=1234567890123456",
      "a=--1",
      'a="unterminated',
      'a="bad \\escape"',
      'a="café"',
      'a="tab\there"',
      "a=:not base64!:",
      "a=:aGVsbG8-:",
      "a=:aGVs bG8=:",
      "a=:AQID",
      // Bytes that begin and never end, with nothing after them.
      "a=:",
      // A space between a name and its value.
      "a= 1",
      "a=(1);x= 2",
      // A second text for the same bytes: bits set that encode nothing, and no padding.
      "a=:AQJ=:",
      "a=:AQI:",
      "a=?2",
      // Inner lists that are none.
      "a=(1 2",
      'a=("x""y")',
      "a=((1))",
    ]) {
      expect(parseDictionary(text), text).toBeUndefined();
    }
    for (const value of [undefined, null, 7, [], {}]) {
      expect(parseDictionary(value)).toBeUndefined();
    }
    expect(parseDictionary(`a="${"x".repeat(20_000)}"`)).toBeUndefined();
  });

  it("never throws, whatever the text", () => {
    fc.assert(
      fc.property(fc.string(), (text) => {
        const read = parseDictionary(text);
        expect(read === undefined || read instanceof Map).toBe(true);
      }),
      { numRuns: 500 },
    );
    fc.assert(
      fc.property(fc.stringMatching(/^[a-z=();:"?, 0-9*\\-]{0,40}$/u), (text) => {
        const read = parseDictionary(text);
        expect(read === undefined || read instanceof Map).toBe(true);
      }),
      { numRuns: 1000 },
    );
  });
});
