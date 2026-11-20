// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** What a tool is given, read with care: each reader takes what it should, and says what is wrong with the rest. */

import { UsageError } from "@oip/local";
import { describe, expect, it } from "vitest";

import {
  addresses,
  addressOf,
  amount,
  count,
  flag,
  only,
  part,
  recordId,
  recordIds,
  text,
  texts,
  time,
} from "../src/given.ts";

const ADDRESS = `did:oip:bciqa${"a".repeat(50)}a`;
const ID = `bciqa${"a".repeat(50)}a`;

describe("the arguments of a call", () => {
  it("are the tool's own, and no others", () => {
    expect(() => {
      only({ want: "x" }, ["want", "tags"]);
    }).not.toThrow();
    expect(() => {
      only({ want: "x", wanted: "y", ["z".repeat(100)]: 1 }, ["want", "tags"]);
    }).toThrow(
      `this tool has no argument named "wanted", "${"z".repeat(64)}": it takes want, tags`,
    );
    expect(() => {
      only({ x: 1 }, []);
    }).toThrow(UsageError);
  });

  it("are texts where a text is asked for, of no more than its length", () => {
    expect(text({ a: "word" }, "a")).toBe("word");
    expect(text({}, "a")).toBeUndefined();
    expect(text({ a: null }, "a")).toBeUndefined();
    // An empty text says nothing: it is none.
    expect(text({ a: "" }, "a")).toBeUndefined();
    expect(() => text({ a: 1 }, "a")).toThrow("`a` is a text");
    expect(() => text({ a: ["word"] }, "a")).toThrow("`a` is a text");
    expect(text({ a: "x".repeat(10) }, "a", 10)).toBe("x".repeat(10));
    expect(() => text({ a: "x".repeat(11) }, "a", 10)).toThrow("`a` is at most 10 characters long");
  });

  it("are lists of texts where a list is asked for", () => {
    expect(texts({ a: ["one", "two"] }, "a")).toStrictEqual(["one", "two"]);
    expect(texts({}, "a")).toStrictEqual([]);
    expect(texts({ a: null }, "a")).toStrictEqual([]);
    for (const wrong of ["one", [1], ["one", ""], { 0: "one" }]) {
      expect(() => texts({ a: wrong }, "a")).toThrow("`a` is a list of texts");
    }
    expect(() => texts({ a: ["1", "2", "3"] }, "a", 2)).toThrow("`a` has at most 2 items");
    // The list is the caller's to change: it is a copy.
    const given = ["one"];
    expect(texts({ a: given }, "a")).not.toBe(given);
  });

  it("are yes or no where that is asked, and no where nothing is said", () => {
    expect(flag({ a: true }, "a")).toBe(true);
    expect(flag({ a: false }, "a")).toBe(false);
    expect(flag({}, "a")).toBe(false);
    expect(flag({ a: null }, "a")).toBe(false);
    for (const wrong of ["true", 1, "yes"]) {
      expect(() => flag({ a: wrong }, "a")).toThrow("`a` is true or false");
    }
  });

  it("are whole numbers within their bounds", () => {
    expect(count({ a: 1 }, "a", 1, 3)).toBe(1);
    expect(count({ a: 3 }, "a", 1, 3)).toBe(3);
    expect(count({}, "a", 1, 3)).toBeUndefined();
    expect(count({ a: null }, "a", 1, 3)).toBeUndefined();
    for (const wrong of [0, 4, 1.5, "2", Number.NaN, 2 ** 60]) {
      expect(() => count({ a: wrong }, "a", 1, 3)).toThrow("`a` is a whole number from 1 to 3");
    }
  });

  it("are objects where arguments are nested", () => {
    expect(part({ a: { b: 1 } }, "a")).toStrictEqual({ b: 1 });
    expect(part({}, "a")).toBeUndefined();
    expect(part({ a: null }, "a")).toBeUndefined();
    for (const wrong of ["x", 1, [{ b: 1 }]]) {
      expect(() => part({ a: wrong }, "a")).toThrow("`a` is an object");
    }
  });

  it("name minds by their addresses, and this mind as `me` where that is known", () => {
    expect(addressOf(ADDRESS, "to")).toBe(ADDRESS);
    expect(() => addressOf("bob", "to")).toThrow("`to` names a mind by its address");
    expect(() => addressOf(`${ADDRESS} and a long story ${"x".repeat(200)}`, "to")).toThrow(
      /^`to` names a mind by its address.{0,200}is none$/u,
    );
    expect(addresses({ to: [ADDRESS, "me"] }, "to", "did:oip:self")).toStrictEqual([
      ADDRESS,
      "did:oip:self",
    ]);
    // Where nobody is `me`, `me` is nobody's address.
    expect(() => addresses({ to: ["me"] }, "to")).toThrow("names a mind by its address");
    expect(addresses({}, "to")).toStrictEqual([]);
  });

  it("name records by their content IDs, and never by a file", () => {
    expect(recordId({ a: ID }, "a")).toBe(ID);
    expect(recordId({}, "a")).toBeUndefined();
    for (const wrong of ["/etc/passwd", "../keys/keystore.json", "bciq", ID.toUpperCase()]) {
      expect(() => recordId({ a: wrong }, "a")).toThrow("`a` names a record by its content ID");
      expect(() => recordIds({ a: [ID, wrong] }, "a")).toThrow(
        "`a` names records by their content IDs",
      );
    }
    expect(recordIds({ a: [ID] }, "a")).toStrictEqual([ID]);
    expect(recordIds({}, "a")).toStrictEqual([]);
  });

  it("are times as the protocol writes them", () => {
    expect(time({ a: "2031-01-31T12:00:00Z" }, "a")).toBe("2031-01-31T12:00:00Z");
    expect(time({}, "a")).toBeUndefined();
    for (const wrong of ["next Friday", "2031-01-31", "2031-01-31T12:00:00+01:00"]) {
      expect(() => time({ a: wrong }, "a")).toThrow("`a` is a time in UTC");
    }
  });

  it("are amounts written as text: a record holds no floating-point number", () => {
    for (const right of ["0", "120", "99.50", "0.001"])
      expect(amount({ a: right }, "a")).toBe(right);
    expect(amount({}, "a")).toBeUndefined();
    for (const wrong of ["1e3", "-5", "01", ".5", "5.", "12 USD", "1,000"]) {
      expect(() => amount({ a: wrong }, "a")).toThrow("`a` is an amount written as text");
    }
    for (const wrong of [120, 99.5]) {
      expect(() => amount({ a: wrong }, "a")).toThrow("pass it in quotes");
    }
  });
});
