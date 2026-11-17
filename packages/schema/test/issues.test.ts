// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What a refusal says. A verdict alone is not enough for the person who has
 * to fix the record, nor for a server that must answer with the right
 * problem type: each refusal names the value at fault, says what is wrong
 * with it, and cites the clause it breaks. These tests read all three.
 */

import { clause, type JsonObject } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import {
  IMPLEMENTATION_LIMIT,
  type Issue,
  type JsonValue,
  MAX_CONTAINER_DEPTH,
  MAX_VALUES,
  type Validation,
  validateExtensionRecord,
  validateJson,
  validateParsedExtensionRecord,
  validateParsedRecord,
  validateProof,
  validateRecord,
  validateRecordOfType,
} from "../src/index.ts";
import { AMINA, sample, sampleProof } from "./fixtures.ts";

function issues(result: Validation<unknown>): readonly Issue[] {
  if (result.ok) throw new Error("it was accepted");
  return result.issues;
}

const first = (result: Validation<unknown>): Issue => issues(result)[0]!;

const NOT_JSON: Issue = {
  path: "",
  message:
    "something here is not a JSON value: only objects, arrays, strings, true, false, null and integers are permitted",
  clause: "core 1.2",
};
const NOT_AN_OBJECT: Issue = { path: "", message: "a record is a JSON object", clause: "core 1.1" };
const TOO_DEEP: Issue = {
  path: "",
  message: "arrays and objects nest more than 64 deep",
  clause: "core 1.9",
};
const UNREADABLE: Issue = {
  path: "",
  message: "the value could not be read as plain JSON data",
  clause: "core 1.2",
};
const tooMany = (budget: number): Issue => ({
  path: "",
  message: `there are more than ${budget} values here, the most this reader was set to read at once`,
  clause: IMPLEMENTATION_LIMIT,
});

/** A value nested to a depth: 1 is an empty array. */
function nested(depth: number): JsonValue {
  let value: JsonValue = [];
  for (let i = 1; i < depth; i++) value = [value];
  return value;
}

describe(`${clause("core 1.2")} what is not a JSON value`, () => {
  it("says so of every value that has no JSON form", () => {
    const values: [kind: string, value: unknown][] = [
      ["undefined", undefined],
      ["a bigint", 1n],
      ["a symbol", Symbol("s")],
      ["a function", () => 1],
      ["a Date", new Date(0)],
      ["a Map", new Map()],
      ["a RegExp", /x/],
    ];
    for (const [kind, value] of values) {
      expect(issues(validateJson(value)), kind).toEqual([NOT_JSON]);
      expect(issues(validateJson({ a: [value] })), kind).toEqual([NOT_JSON]);
    }
  });

  it("says which number is not an integer in range", () => {
    for (const number of [0.5, 2 ** 53, -(2 ** 53), Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(issues(validateJson({ n: number }))).toEqual([
        {
          path: "",
          message: `the number ${number} is not an integer between -(2^53-1) and 2^53-1; write decimal quantities as strings`,
          clause: "core 1.2",
        },
      ]);
    }
    for (const number of [0, -0, 2 ** 53 - 1, -(2 ** 53 - 1)]) {
      expect(validateJson({ n: number })).toEqual({ ok: true, value: { n: number } });
    }
  });

  it("accepts each kind of JSON value, and gives back an equal one", () => {
    const value = { s: "text", t: true, f: false, n: null, i: 7, a: [true, [false], {}], o: {} };
    expect(validateJson(value)).toEqual({ ok: true, value });
    for (const scalar of ["", "text", true, false, null, 0]) {
      expect(validateJson(scalar)).toEqual({ ok: true, value: scalar });
    }
  });

  it("refuses a member that is not plain data: an accessor, a hidden member, a symbol", () => {
    let read = 0;
    const accessor = Object.defineProperty({}, "a", {
      enumerable: true,
      get: () => {
        read++;
        return 1;
      },
    });
    const hidden = Object.defineProperty({}, "a", { value: 1, enumerable: false });
    const symbol = { [Symbol("s")]: 1 };
    const instance = new (class Record {
      a = 1;
    })();
    for (const object of [accessor, hidden, symbol, instance, Object.create({ inherited: 1 })]) {
      expect(issues(validateJson(object))).toEqual([NOT_JSON]);
      expect(issues(validateJson([object]))).toEqual([NOT_JSON]);
    }
    expect(read).toBe(0);
    // An object with no prototype is plain data all the same.
    const bare = Object.assign(Object.create(null) as JsonObject, { a: 1 });
    expect(validateJson(bare)).toEqual({ ok: true, value: { a: 1 } });
  });

  it("refuses an array that is not plain data: a hole, an accessor, a hidden element, a member", () => {
    let read = 0;
    const hole: number[] = [1, 2, 3];
    // eslint-disable-next-line @typescript-eslint/no-array-delete -- a hole is the point
    delete hole[1];
    const accessor = Object.defineProperty([1, 2], 1, {
      enumerable: true,
      get: () => {
        read++;
        return 2;
      },
    });
    const hidden = Object.defineProperty([1, 2], 1, { value: 2, enumerable: false });
    const extra = Object.assign([1, 2], { toJSON: () => "x" });
    const longer = Object.assign([1, 2], { note: 1 });
    class List extends Array<number> {}
    for (const array of [hole, accessor, hidden, extra, longer, List.from([1, 2])]) {
      expect(issues(validateJson(array))).toEqual([NOT_JSON]);
      expect(issues(validateJson({ a: array }))).toEqual([NOT_JSON]);
    }
    expect(read).toBe(0);
  });

  it("refuses an array whose length is not a count", () => {
    for (const length of ["2", 1.5, -1, 2 ** 53, undefined]) {
      const array = new Proxy([1, 2], {
        get: (target, name): unknown => (name === "length" ? length : Reflect.get(target, name)),
      });
      expect(issues(validateJson(array)), String(length)).toEqual([NOT_JSON]);
    }
  });

  it("answers for a value that cannot be read at all", () => {
    const throws = new Proxy(
      {},
      {
        ownKeys: () => {
          throw new Error("boom");
        },
      },
    );
    for (const validate of [validateJson, validateRecord, validateExtensionRecord, validateProof]) {
      expect(issues(validate(throws))).toEqual([UNREADABLE]);
    }
    expect(issues(validateRecordOfType("Intent", throws))).toEqual([UNREADABLE]);
  });
});

describe(`${clause("core 1.1")} text that is not valid`, () => {
  const SURROGATE: Issue = {
    path: "",
    message: "a string has an unpaired surrogate, which is not valid Unicode",
    clause: "core 1.1",
  };
  const NONCHARACTER: Issue = {
    path: "",
    message:
      "a string has a noncharacter (U+FDD0 to U+FDEF, or a code point ending FFFE or FFFF), which a record may not contain",
    clause: "core 1.1",
  };

  it("says which fault a string has, as a value and as a member's name", () => {
    for (const [text, issue] of [
      ["\ud800", SURROGATE],
      ["a\udc00b", SURROGATE],
      ["﷐", NONCHARACTER],
      ["￿", NONCHARACTER],
      ["\u{1fffe}", NONCHARACTER],
    ] as const) {
      expect(issues(validateJson(text))).toEqual([issue]);
      expect(issues(validateJson({ a: [text] }))).toEqual([issue]);
      expect(issues(validateJson({ [text]: 1 }))).toEqual([issue]);
      expect(issues(validateRecord(sample("Intent", { want: text })))).toEqual([issue]);
    }
  });
});

describe(`${clause("core 1.9")} depth`, () => {
  it("says how deep a record may nest, at the depth where it is refused", () => {
    expect(validateJson(nested(64)).ok).toBe(true);
    expect(issues(validateJson(nested(65)))).toEqual([TOO_DEEP]);
    expect(issues(validateJson({ a: nested(64) }))).toEqual([TOO_DEEP]);
    // A value that may be a container is read three levels deeper, and no further.
    expect(MAX_CONTAINER_DEPTH).toBe(67);
    expect(validateJson(nested(67), "container").ok).toBe(true);
    expect(issues(validateJson(nested(68), "container"))).toEqual([TOO_DEEP]);
    expect(issues(validateJson(nested(65), "record"))).toEqual([TOO_DEEP]);
    // A proof stands at depth 3 of its record, so it nests 62 deep at most.
    const proof = (depth: number) => sampleProof({ authority: [nested(depth - 2)] });
    expect(first(validateProof(proof(62))).clause).not.toBe("core 1.9");
    expect(issues(validateProof(proof(63)))).toEqual([TOO_DEEP]);
  });

  it("refuses a record deeper than 64 that is not a container, and one deeper than any container", () => {
    // The record, its `ext`, the block, and then a value that nests the rest of the way.
    const deep = (depth: number) =>
      sample("Intent", { ext: { "com.example": { v: nested(depth - 3) } } });
    expect(validateRecord(deep(64)).ok).toBe(true);
    expect(issues(validateRecord(deep(65)))).toEqual([TOO_DEEP]);
    expect(issues(validateRecord(deep(68)))).toEqual([TOO_DEEP]);
    expect(issues(validateParsedRecord(deep(65) as JsonValue, 65))).toEqual([TOO_DEEP]);
    // A parser says how deep the value it built nests, and is taken at its word.
    expect(validateParsedRecord(sample("Intent") as JsonValue, 64).ok).toBe(true);
    expect(issues(validateParsedRecord(sample("Intent") as JsonValue, 65))).toEqual([TOO_DEEP]);
    expect(validateParsedRecord(sample("LogPage") as JsonValue, 67).ok).toBe(true);
    expect(issues(validateParsedRecord(sample("LogPage") as JsonValue, 68))).toEqual([TOO_DEEP]);
    const extension = {
      oip: "1",
      type: "com.example.Note",
      created: "2026-11-17T09:00:00Z",
      ext: { "com.example": { v: nested(62) } },
      critical: ["com.example"],
    };
    expect(issues(validateExtensionRecord(extension))).toEqual([TOO_DEEP]);
    expect(issues(validateParsedExtensionRecord(extension, 68))).toEqual([TOO_DEEP]);
  });
});

describe("the most values a reader reads at once", () => {
  it("says what the limit was, and counts to it exactly", () => {
    const members = (count: number) =>
      Object.fromEntries(Array.from({ length: count }, (_, i) => [`m${i}`, i]));
    const elements = (count: number) => Array.from({ length: count }, (_, i) => i);
    for (const maxValues of [0, 1, 5]) {
      expect(validateJson(members(maxValues), "record", { maxValues }).ok).toBe(true);
      expect(validateJson(elements(maxValues), "record", { maxValues }).ok).toBe(true);
      expect(issues(validateJson(members(maxValues + 1), "record", { maxValues }))).toEqual([
        tooMany(maxValues),
      ]);
      expect(issues(validateJson(elements(maxValues + 1), "record", { maxValues }))).toEqual([
        tooMany(maxValues),
      ]);
    }
    // The values of an array and of the object beside it are counted together.
    expect(validateJson({ a: [1, 2] }, "record", { maxValues: 3 }).ok).toBe(true);
    expect(issues(validateJson({ a: [1, 2] }, "record", { maxValues: 2 }))).toEqual([tooMany(2)]);
    expect(issues(validateJson({ a: [1], b: [2] }, "record", { maxValues: 3 }))).toEqual([
      tooMany(3),
    ]);
    expect(issues(validateRecord(sample("Intent"), { maxValues: 3 }))).toEqual([tooMany(3)]);
    expect(issues(validateExtensionRecord(sample("Intent"), { maxValues: 3 }))).toEqual([
      tooMany(3),
    ]);
  });

  it("keeps the default when it is given anything but a count of its own", () => {
    const three = { a: 1, b: 2, c: 3 };
    for (const limits of [
      undefined,
      null,
      {},
      { maxValues: -1 },
      { maxValues: 1.5 },
      { maxValues: "1" },
      { maxValues: Number.NaN },
      Object.create({ maxValues: 1 }),
    ]) {
      expect(validateJson(three, "record", limits as never).ok, JSON.stringify(limits)).toBe(true);
    }
    expect(MAX_VALUES).toBe(4_194_304);
  });
});

describe("the copy a validator returns", () => {
  it("is plain data: each member can be read, written, listed and removed", () => {
    const source = JSON.parse('{"a":[1,{"b":2}],"__proto__":{"c":3}}') as JsonObject;
    const copy = validateJson(source);
    if (!copy.ok) throw new Error("it was refused");
    const plain = { writable: true, enumerable: true, configurable: true };
    const value = copy.value as { a: [number, { b: number }]; ["__proto__"]: { c: number } };
    expect(Object.getOwnPropertyDescriptor(value, "a")).toEqual({ ...plain, value: value.a });
    expect(Object.getOwnPropertyDescriptor(value, "__proto__")).toEqual({
      ...plain,
      value: { c: 3 },
    });
    expect(Object.getOwnPropertyDescriptor(value.a, 1)).toEqual({ ...plain, value: { b: 2 } });
    expect(Object.getOwnPropertyDescriptor(value.a[1], "b")).toEqual({ ...plain, value: 2 });
    expect(Object.getPrototypeOf(value)).toBe(Object.prototype);
    expect(Object.getPrototypeOf(value.a)).toBe(Array.prototype);
    expect(value).not.toBe(source);
    expect(value.a).not.toBe(source["a"]);
  });
});

describe(`${clause("core 7", "core 11")} what a record must be before its schema is looked at`, () => {
  it("is a JSON object", () => {
    for (const value of [null, 5, "record", true, [], [sample("Intent")]]) {
      expect(issues(validateRecord(value))).toEqual([NOT_AN_OBJECT]);
      expect(issues(validateExtensionRecord(value))).toEqual([NOT_AN_OBJECT]);
      expect(issues(validateRecordOfType("Intent", value))).toEqual([NOT_AN_OBJECT]);
      expect(issues(validateParsedRecord(value as JsonValue, 1))).toEqual([NOT_AN_OBJECT]);
      expect(issues(validateParsedExtensionRecord(value as JsonValue, 1))).toEqual([NOT_AN_OBJECT]);
    }
  });

  it('has oip "1" and a type that is a string', () => {
    const oip: Issue = { path: "/oip", message: 'oip must be the string "1"', clause: "core 7" };
    const type: Issue = {
      path: "/type",
      message: "type must name a record type",
      clause: "core 7",
    };
    for (const validate of [validateRecord, validateExtensionRecord]) {
      for (const value of [1, "2", "1.0", null]) {
        expect(issues(validate({ ...sample("Intent"), oip: value }))).toEqual([oip]);
      }
      for (const value of [1, null, ["Intent"]]) {
        expect(issues(validate({ ...sample("Intent"), type: value }))).toEqual([type]);
      }
      const { oip: _, ...noOip } = sample("Intent");
      expect(issues(validate(noOip))).toEqual([oip]);
      const { type: __, ...noType } = sample("Intent");
      expect(issues(validate(noType))).toEqual([type]);
      // oip is looked at first.
      expect(issues(validate({ oip: "2", type: 5 }))).toEqual([oip]);
    }
    const parsedType = validateParsedRecord({ oip: "1", type: 5 }, 1);
    expect(issues(parsedType)).toEqual([type]);
  });

  it(`${clause("L1 3.9")} is not of a reserved type`, () => {
    const reserved: Issue = {
      path: "/type",
      message: "Merge is reserved in this revision and must be rejected",
      clause: "L1 3.9",
    };
    for (const validate of [validateRecord, validateExtensionRecord]) {
      expect(issues(validate({ ...sample("Update"), type: "Merge" }))).toEqual([reserved]);
    }
  });

  it("is of a type this revision defines, or is read as an extension's", () => {
    expect(issues(validateRecord({ ...sample("Intent"), type: "com.example.Note" }))).toEqual([
      {
        path: "/type",
        message:
          '"com.example.Note" is not a record type this revision defines; if an extension defines it, use validateExtensionRecord',
        clause: "core 11",
      },
    ]);
    expect(issues(validateExtensionRecord(sample("Intent")))).toEqual([
      {
        path: "/type",
        message: "Intent is a record type this revision defines; use validateRecord",
        clause: "core 11",
      },
    ]);
    expect(issues(validateRecordOfType("com.example.Note" as never, sample("Intent")))).toEqual([
      {
        path: "",
        message: '"com.example.Note" is not a record type this revision defines',
        clause: "core 11",
      },
    ]);
    // A name is not looked up on any prototype.
    for (const name of ["constructor", "toString", "__proto__", "Proof", "ExtensionRecord"]) {
      expect(first(validateRecordOfType(name as never, sample("Intent"))).clause).toBe("core 11");
      expect(first(validateRecord({ ...sample("Intent"), type: name })).clause).toBe("core 11");
    }
  });
});

describe("the clause a refusal cites", () => {
  /** The clause cited for a record with one member changed, and where. */
  function cited(record: JsonObject): [path: string, clause: string] {
    const issue = first(validateRecord(record));
    return [issue.path, issue.clause];
  }

  it("is the one that defines the syntax of the value at fault", () => {
    const genesis = sample("Genesis");
    const controller = genesis["controller"] as JsonObject;
    const cases: [record: JsonObject, path: string, clause: string][] = [
      [sample("Intent", { created: "yesterday" }), "/created", "core 1.4"],
      [sample("Intent", { expires: "2026-11-17" }), "/expires", "core 1.4"],
      [sample("Intent", { author: "did:web:example.com" }), "/author", "core 6.1"],
      [
        { ...genesis, controller: { ...controller, keys: ["z6MkNotAKey"] } },
        "/controller/keys/0",
        "core 4.1",
      ],
      [{ ...genesis, keys: [{ key: "zNotAKey" }] }, "/keys/0/key", "core 4.1"],
      [{ ...genesis, agreement: [{ key: "zNotAKey" }] }, "/agreement/0/key", "core 4.1"],
      [
        { ...genesis, controller: { ...controller, next: ["bciqnotahash"] } },
        "/controller/next/0",
        "core 3.2",
      ],
      [{ ...genesis, parents: [{ mind: AMINA, at: "latest" }] }, "/parents/0/at", "core 6.1"],
      [sample("Update", { prev: "bciqshort" }), "/prev", "core 3.2"],
    ];
    for (const [record, path, expected] of cases) {
      expect(cited(record), path).toEqual([path, expected]);
    }
  });

  it("is the one for amounts, decimals and durations where a record carries them", () => {
    const offer = sample("Offer");
    const terms = offer["terms"] as JsonObject;
    const price = terms["price"] as JsonObject;
    expect(cited({ ...offer, terms: { ...terms, price: { ...price, amount: "1,000" } } })).toEqual([
      "/terms/price/amount",
      "core 1.3",
    ]);
    const packet = sample("Packet");
    const constraints = {
      ...(packet["constraints"] as JsonObject | undefined),
      retention: "a week",
    };
    const refused = issues(validateRecord({ ...packet, constraints }));
    expect(refused.map((issue) => [issue.path, issue.clause])).toContainEqual([
      "/constraints/retention",
      "core 1.5",
    ]);
  });

  it("is the one for the member every record shares, when that member is at fault", () => {
    const intent = sample("Intent");
    const cases: [record: JsonObject, path: string, clause: string][] = [
      [{ ...intent, ext: [] }, "/ext", "core 8.1"],
      [{ ...intent, ext: { "com.example": 5 } }, "/ext/com.example", "core 8.1"],
      [{ ...intent, critical: "com.example" }, "/critical", "core 8.3"],
      [{ ...intent, proof: [] }, "/proof", "core 5.1"],
      [{ ...intent, proof: [5] }, "/proof/0", "core 5.1"],
    ];
    for (const [record, path, expected] of cases) {
      expect(cited(record), path).toEqual([path, expected]);
    }
  });

  it("is otherwise the one that defines the record", () => {
    expect(cited(sample("Intent", { want: 5 }))).toEqual(["/want", "L2 4.1"]);
    expect(cited(sample("Genesis", { kind: "" }))).toEqual(["/kind", "L1 3.6"]);
    const noWant = { ...sample("Intent") };
    delete (noWant as { want?: unknown }).want;
    expect(first(validateRecord(noWant))).toMatchObject({ path: "", clause: "L2 4.1" });
  });

  it("is core 5.2 for everything in a proof, its type included", () => {
    const cases: [changes: JsonObject, path: string][] = [
      [{ type: "Ed25519Signature2020" }, "/type"],
      [{ cryptosuite: "ecdsa" }, "/cryptosuite"],
      [{ proofValue: "not base58" }, "/proofValue"],
      [{ proofPurpose: "signing" }, "/proofPurpose"],
      [{ extra: 1 }, ""],
    ];
    for (const [changes, path] of cases) {
      const issue = first(validateProof(sampleProof(changes)));
      expect([issue.path, issue.clause], path).toEqual([path, "core 5.2"]);
    }
    // The value syntaxes keep their own clauses inside a proof too.
    expect(first(validateProof(sampleProof({ created: "now" })))).toMatchObject({
      path: "/created",
      clause: "core 1.4",
    });
    expect(first(validateProof(sampleProof({ verificationMethod: "did:web:x#key" }))).clause).toBe(
      "core 6.1",
    );
  });

  it("puts the deepest value at fault first, and leaves out what says nothing more", () => {
    // A controller is one of two shapes. This one is neither: the errors of
    // each shape are given, and not the remark that it matches none of them.
    const genesis = sample("Genesis");
    const refused = issues(
      // As a key controller its first key is no key; as a member controller it has no members.
      validateRecord({ ...genesis, controller: { keys: [5], next: [] } }),
    );
    expect(refused.length).toBeGreaterThan(1);
    const depths = refused.map((issue) => issue.path.split("/").length);
    expect(depths).toEqual([...depths].sort((a, b) => b - a));
    expect(Math.max(...depths)).toBeGreaterThan(Math.min(...depths));
    expect(refused.every((issue) => issue.message.length > 0)).toBe(true);
    expect(refused.some((issue) => /must match .* schema in anyOf/.test(issue.message))).toBe(
      false,
    );
    // Alone, that remark is all there is to say.
    const alone = issues(validateRecord({ ...genesis, controller: 5 }));
    expect(alone.length).toBeGreaterThan(0);
  });
});
