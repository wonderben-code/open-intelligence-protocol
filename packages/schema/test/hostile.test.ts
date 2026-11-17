// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Input chosen to break the validator rather than to be rejected by it. Each
 * case here once made validation throw, hang, exhaust memory or answer with
 * megabytes; none may do so again.
 */

import { type JsonObject, positiveVectorRecords, withAmbientTrapped } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import {
  declareParsed,
  IMPLEMENTATION_LIMIT,
  MAX_ISSUES,
  type Limits,
  MAX_VALUES,
  parseSelector,
  type RecordType,
  textFault,
  validateExtensionRecord,
  validateJson,
  validateProof,
  validateRecord,
  validateRecordOfType,
} from "../src/index.ts";
import { sample, sampleProof, samples } from "./fixtures.ts";

const KEY = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

/**
 * Rejected, with a bounded answer, in bounded time. The bound on time is
 * loose on purpose: the work it guards against is quadratic or exponential,
 * and would take hours, while a busy machine or mutation testing can make
 * honest work take several seconds.
 */
function expectBoundedRejection(run: () => { ok: boolean; issues?: readonly unknown[] }): void {
  const started = performance.now();
  const result = run();
  expect(result.ok).toBe(false);
  expect(result.issues?.length).toBeGreaterThan(0);
  expect(result.issues?.length).toBeLessThanOrEqual(MAX_ISSUES);
  expect(JSON.stringify(result.issues).length).toBeLessThan(32_768);
  expect(performance.now() - started).toBeLessThan(30_000);
}

describe("many violations in one record", () => {
  it("are reported up to a limit, however many there are", () => {
    const critical = Array.from({ length: 200_000 }, () => "a");
    expectBoundedRejection(() => validateRecord(sample("Offer", { critical })));
    expectBoundedRejection(() =>
      validateExtensionRecord({ oip: "1", type: "com.example.X", critical }),
    );
    const bad = sample("Update", { keys: [{ key: KEY }, { key: KEY }] });
    const events = Array.from({ length: 20_000 }, () => bad);
    expectBoundedRejection(() => validateRecord(sample("LogPage", { events })));
  });

  it("do not multiply the size of the input in the answer", () => {
    const badSelectors = Array.from({ length: 64 }, () => ["==", "not a selector", 1]);
    const powers = Array.from({ length: 64 }, () => ({ command: "/x/y", policy: badSelectors }));
    const roles = { ["r".repeat(100_000)]: { powers } };
    expectBoundedRejection(() => validateRecord(sample("Collective", { roles })));
    const policy = Array.from({ length: 64 }, () => ["and", badSelectors]);
    expectBoundedRejection(() => validateRecord(sample("Delegation", { policy })));
  });

  it("are answered from a deep call stack too", () => {
    const critical = Array.from({ length: 50_000 }, () => "a");
    const record = sample("Offer", { critical });
    const fromDepth = (depth: number): boolean =>
      depth === 0 ? validateRecord(record).ok : fromDepth(depth - 1);
    expect(fromDepth(3000)).toBe(false);
  });
});

describe("a type name that is not a record type", () => {
  const anything = "a string, not a record";

  it.each([
    "constructor",
    "toString",
    "valueOf",
    "__proto__",
    "hasOwnProperty",
    "Merge",
    "Proof",
    "ExtensionRecord",
    "Policy",
    "",
  ])("%j never reaches a validator through validateRecordOfType", (name) => {
    for (const value of [anything, samples.Intent, { oip: "1", type: "Genesis" }, {}]) {
      const result = validateRecordOfType(name as RecordType, value);
      expect(result.ok).toBe(false);
    }
  });

  it("is rejected whatever it is", () => {
    for (const name of [undefined, null, 7, {}, ["Intent"], Symbol("Intent")]) {
      expect(validateRecordOfType(name as RecordType, samples.Intent).ok).toBe(false);
    }
  });
});

describe("values that answer differently each time they are read", () => {
  /** An array whose first element is an accessor: 1 the first time it is read, 1.5 after. */
  const shifting = () => {
    let reads = 0;
    const array: unknown[] = [0, 2];
    Object.defineProperty(array, 0, { get: () => (reads++ === 0 ? 1 : 1.5), enumerable: true });
    return array;
  };

  it("are rejected: an accessor is never called, on an object or on an array", () => {
    let called = 0;
    const array: unknown[] = [0];
    Object.defineProperty(array, 0, { get: () => ++called, enumerable: true });
    const object = Object.defineProperty({}, "a", { get: () => ++called, enumerable: true });
    for (const member of [array, object, shifting(), [shifting()], { deep: [object] }]) {
      expect(validateJson(member).ok).toBe(false);
      expect(validateRecord(sample("Intent", { futureMember: member })).ok).toBe(false);
      expect(validateProof(sampleProof({ authority: [{ x: member }] })).ok).toBe(false);
    }
    expect(called).toBe(0);
  });

  it("are read once, when they hide behind a proxy: what is returned is what was checked", () => {
    let reads = 0;
    const target = sample("Intent", { futureMember: 1 });
    // The proxy says 1 the first time each member is described, and 1.5 from then on.
    const proxy = new Proxy(target, {
      getOwnPropertyDescriptor(inner, name) {
        const descriptor = Reflect.getOwnPropertyDescriptor(inner, name);
        if (name === "futureMember" && descriptor !== undefined && reads++ > 0) {
          return { ...descriptor, value: 1.5 };
        }
        return descriptor;
      },
      get(inner, name) {
        return name === "futureMember" ? 1.5 : (Reflect.get(inner, name) as unknown);
      },
    });
    const result = validateRecord(proxy);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // The copy holds what the check saw. Reading the proxy again would give 1.5.
    expect(result.value).not.toBe(proxy);
    expect((result.value as JsonObject)["futureMember"]).toBe(1);
    expect(proxy["futureMember"]).toBe(1.5);
    expect(JSON.stringify(result.value)).not.toContain("1.5");
  });

  it("never make a validator throw", () => {
    const boom = () => {
      throw new Error("boom");
    };
    const revoked = Proxy.revocable({}, {});
    revoked.revoke();
    const revokedArray = Proxy.revocable([], {});
    revokedArray.revoke();
    // None of these can be read as plain data.
    const unreadable: unknown[] = [
      new Proxy({}, { ownKeys: boom }),
      new Proxy({ a: 1 }, { getOwnPropertyDescriptor: boom }),
      new Proxy({}, { getPrototypeOf: boom }),
      new Proxy([], { get: boom }),
      new Proxy([1, 2], { getOwnPropertyDescriptor: boom }),
      revoked.proxy,
      revokedArray.proxy,
      Object.defineProperty({}, "oip", { get: boom, enumerable: true }),
    ];
    for (const value of unreadable) {
      for (const candidate of [value, sample("Intent", { futureMember: value }), [value]]) {
        expect(validateJson(candidate).ok).toBe(false);
        expect(validateRecord(candidate).ok).toBe(false);
        expect(validateExtensionRecord(candidate).ok).toBe(false);
        expect(validateProof(candidate).ok).toBe(false);
        expect(validateRecordOfType("Intent", candidate).ok).toBe(false);
      }
    }
    // A proxy that only watches reads of members is read through its descriptors, and is plain data.
    const watching = new Proxy(sample("Intent"), { get: boom });
    expect(validateRecord(watching).ok).toBe(true);
  });
});

/** Whether a text holds a control character or a line separator. */
function hasControl(text: string): boolean {
  return Array.from(text).some((character) => {
    const code = character.codePointAt(0) ?? 0;
    return code < 0x20 || (code >= 0x7f && code <= 0x9f) || code === 0x2028 || code === 0x2029;
  });
}

describe("what an issue shows of the input", () => {
  it("writes control characters in a path as escapes, so that a member name cannot forge a log line", () => {
    const name = "evil\n2026-11-17 INFO login ok user=admin\u001b[2K\u2028\u0085";
    const result = validateRecord(sample("Offer", { terms: { [name]: 1.5, price: 5 } }));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    for (const issue of result.issues) {
      expect(hasControl(issue.path), issue.path).toBe(false);
      expect(hasControl(issue.message), issue.message).toBe(false);
    }
    const schema = validateRecord(
      sample("Collective", { roles: { [`role\nINFO forged\u0007`]: { powers: "not an array" } } }),
    );
    expect(!schema.ok && schema.issues.some((issue) => issue.path.includes("\\u000a"))).toBe(true);
    expect(!schema.ok && schema.issues.every((issue) => !issue.path.includes("\n"))).toBe(true);
  });

  it("cuts a long path between characters, never inside one", () => {
    const name = "😀".repeat(400);
    const result = validateRecord(sample("Collective", { roles: { [name]: { powers: 1 } } }));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    for (const issue of result.issues) {
      expect(Array.from(issue.path).length).toBeLessThanOrEqual(256);
      expect(textFault(issue.path), "a path is valid Unicode").toBeUndefined();
    }
    expect(result.issues.some((issue) => issue.path.endsWith("…"))).toBe(true);
  });
});

describe("a value a parser of the JSON profile has just built", () => {
  const plain = () => JSON.parse(JSON.stringify(samples.Intent)) as JsonObject;

  it("is validated as it is, and only the once", () => {
    const record = plain();
    declareParsed(record, 4);
    const first = validateRecord(record);
    // The same object: the parser has done what the copy is for.
    expect(first.ok && first.value).toBe(record);
    // The declaration is spent. What happened to the value since is not known.
    const second = validateRecord(record);
    expect(second.ok && second.value).not.toBe(record);
    expect(second.ok && second.value).toEqual(record);
    const json = plain();
    declareParsed(json, 4);
    const whole = validateJson(json);
    expect(whole.ok && whole.value).toBe(json);
    const again = validateJson(json);
    expect(again.ok && again.value).not.toBe(json);
  });

  it("is still held to the depth the validator allows", () => {
    for (const [deepest, clause] of [
      [64, undefined],
      [65, "core 1.9"],
      [1000, "core 1.9"],
    ] as const) {
      const value = plain();
      declareParsed(value, deepest);
      const result = validateJson(value);
      expect(result.ok ? undefined : result.issues[0].clause, String(deepest)).toBe(clause);
    }
    // A record may be a container, which nests three deeper; beyond that nothing does.
    const record = plain();
    declareParsed(record, 68);
    const tooDeep = validateRecord(record);
    expect(!tooDeep.ok && tooDeep.issues[0].clause).toBe("core 1.9");
    // Between the two, only a container may be: the declaration is believed.
    const between = plain();
    declareParsed(between, 66);
    const refused = validateRecord(between);
    expect(!refused.ok && refused.issues[0].clause).toBe("core 1.9");
  });

  it("is checked against its schema and rules like any other", () => {
    const record = plain();
    delete record["want"];
    declareParsed(record, 4);
    expect(validateRecord(record).ok).toBe(false);
  });
});

describe("values that are not JSON", () => {
  const rejected = (member: unknown) =>
    expectBoundedRejection(() => validateRecord(sample("Intent", { futureMember: member })));

  it("more values than a reader allows are refused as its own limit, never as a rule about records", () => {
    // As many as a text of 8 MiB can hold, at two characters a value.
    expect(MAX_VALUES).toBe(4 * 1024 * 1024);
    const big = new Array<number>(MAX_VALUES + 1).fill(0);
    const many = validateRecord(sample("Intent", { futureMember: big }));
    expect(!many.ok && many.issues[0]).toEqual({
      path: "",
      message: `there are more than ${MAX_VALUES} values here, the most this reader was set to read at once`,
      clause: IMPLEMENTATION_LIMIT,
    });
    expect(validateJson(big).ok).toBe(false);
    // A reader that accepts longer texts allows more values with them.
    const more = { maxValues: 2 * MAX_VALUES };
    expect(validateRecord(sample("Intent", { futureMember: big }), more).ok).toBe(true);
    expect(validateJson(big, "record", more).ok).toBe(true);
    expect(validateJson(big, "container", more).ok).toBe(true);
    // And one that accepts less, fewer. The array is one value and each element another.
    expect(validateJson([0, 0, 0], "record", { maxValues: 3 }).ok).toBe(true);
    const few = validateJson([0, 0, 0], "record", { maxValues: 2 });
    expect(!few.ok && few.issues[0].message).toBe(
      "there are more than 2 values here, the most this reader was set to read at once",
    );
    expect(validateRecord(sample("Intent"), { maxValues: 5 }).ok).toBe(false);
    const extension = {
      oip: "1",
      type: "com.example.X",
      created: "2026-11-17T09:00:00Z",
      ext: { "com.example": {} },
      critical: ["com.example"],
    };
    expect(validateExtensionRecord(extension).ok).toBe(true);
    expect(validateExtensionRecord(extension, { maxValues: 3 }).ok).toBe(false);
    // Anything but a count leaves the default in force: no limit is switched off by mistake.
    for (const maxValues of [Number.NaN, -1, 1.5, "7", null, Infinity, undefined]) {
      const limits = { maxValues } as unknown as Limits;
      expect(validateJson([0, 0, 0], "record", limits).ok).toBe(true);
      expect(validateJson(big, "record", limits).ok).toBe(false);
    }
  });

  it("an array that is not a plain array is rejected", () => {
    class Sub extends Array<unknown> {}
    const withMember = Object.assign([1, 2], { toJSON: () => "rewritten" });
    const withHidden = Object.defineProperty([1, 2], "extra", { value: 1, enumerable: false });
    const holed: unknown[] = [];
    holed[3] = 1;
    for (const array of [Sub.from([1]), withMember, withHidden, holed, new Array(3)]) {
      rejected(array);
      expect(validateJson(array).ok).toBe(false);
    }
    expect(validateJson([]).ok).toBe(true);
    expect(validateJson([[], [1, [2]]])).toEqual({ ok: true, value: [[], [1, [2]]] });
  });

  it("an array with millions of holes is rejected without reading them", () => {
    rejected(new Array(2 ** 27));
    rejected([new Array(2 ** 30)]);
    const holed: unknown[] = [1, 2, 3];
    holed.length = 5;
    rejected(holed);
  });

  it("a structure that shares its parts is rejected without being walked exponentially", () => {
    let shared: unknown = "leaf";
    for (let i = 0; i < 60; i++) shared = [shared, shared];
    rejected(shared);
    let wide: unknown = "leaf";
    for (let i = 0; i < 60; i++) wide = { a: wide, b: wide };
    rejected(wide);
  });

  it("undefined, bigint, symbols and functions are rejected wherever they are", () => {
    for (const value of [undefined, 10n, Symbol("x"), () => 1]) {
      rejected(value);
      rejected([value]);
      rejected({ deep: { deeper: [value] } });
    }
  });

  it("objects that are not plain are rejected", () => {
    class Custom {
      member = 1;
    }
    for (const value of [new Date(0), new Map(), new Set(), new Custom(), /x/, new Uint8Array(4)]) {
      rejected(value);
      rejected([value]);
    }
    rejected({ [Symbol("hidden")]: 1 });
  });

  it("a member the limits cannot see is rejected, not passed on to the schema", () => {
    let deep: unknown = ["==", ".a", 1];
    for (let i = 0; i < 100_000; i++) deep = ["not", deep];
    const hidden = sample("Delegation");
    Object.defineProperty(hidden, "policy", { value: [deep], enumerable: false });
    expectBoundedRejection(() => validateRecord(hidden));

    const inherited = Object.create(sample("Delegation", { policy: [deep] })) as JsonObject;
    expectBoundedRejection(() => validateRecord(inherited));
    expectBoundedRejection(() => validateRecordOfType("Delegation", inherited));
  });

  it("an accessor is rejected without being called", () => {
    let calls = 0;
    const record = sample("Intent");
    Object.defineProperty(record, "want", {
      enumerable: true,
      get() {
        calls++;
        return "text";
      },
    });
    expectBoundedRejection(() => validateRecord(record));
    const nested = sample("Intent", { futureMember: {} });
    Object.defineProperty(nested["futureMember"], "x", { enumerable: true, get: () => 1.5 });
    expectBoundedRejection(() => validateRecord(nested));
    expect(calls).toBe(0);
  });

  it("an object that throws when read gives a rejection, never an exception", () => {
    const trap = () => {
      throw new Error("no");
    };
    const hostile = new Proxy(sample("Intent"), { get: trap, ownKeys: trap, getPrototypeOf: trap });
    expect(validateRecord(hostile).ok).toBe(false);
    expect(validateRecordOfType("Intent", hostile).ok).toBe(false);
    expect(validateExtensionRecord(hostile).ok).toBe(false);
    expect(validateProof(hostile).ok).toBe(false);
    const inner = new Proxy({}, { ownKeys: trap, getOwnPropertyDescriptor: trap });
    expect(validateRecord(sample("Intent", { futureMember: inner })).ok).toBe(false);
    expect(validateProof(sampleProof({ authority: [inner] })).ok).toBe(false);
  });
});

describe("selectors of hostile size", () => {
  it("parse in one pass, whatever their length", () => {
    const name = "n".repeat(8 * 1024 * 1024);
    expect(parseSelector(`["${name}"]`)).toEqual([name]);
    expect(parseSelector(`["${"\\\\".repeat(1024 * 1024)}"]`)?.[0]).toHaveLength(1024 * 1024);
    expect(parseSelector(`["${name}`)).toBeUndefined();
    expect(parseSelector(`.${"a".repeat(1024 * 1024)}`)?.[0]).toHaveLength(1024 * 1024);
    expect(parseSelector(".a".repeat(200_000))).toHaveLength(200_000);
  });

  it("give an index beyond any array one fixed value, never Infinity", () => {
    expect(parseSelector(`[1${"0".repeat(1024 * 1024)}]`)).toEqual([Number.MAX_SAFE_INTEGER]);
    expect(parseSelector("[9007199254740993]")).toEqual([Number.MAX_SAFE_INTEGER]);
    expect(parseSelector("[999999999999999]")).toEqual([999999999999999]);
  });

  it("are rejected in a policy with a short message", () => {
    const selector = `["${"n".repeat(1024 * 1024)}`;
    expectBoundedRejection(() =>
      validateRecord(sample("Delegation", { policy: [["==", selector, 1]] })),
    );
  });
});

describe("purity", () => {
  it("reads no clock and no randomness, whatever it validates", () => {
    const inputs: unknown[] = [
      ...positiveVectorRecords().map((entry) => entry.record),
      ...Object.values(samples),
      sample("Delegation", { delegate: samples.Delegation["author"] }),
      sample("Offer", { critical: ["missing"] }),
      sample("Intent", { futureMember: 1.5 }),
      { oip: "1", type: "com.example.Escrow" },
      "not a record",
    ];
    const verdicts = withAmbientTrapped(() =>
      inputs.map((input) => [
        validateRecord(input).ok,
        validateExtensionRecord(input).ok,
        validateProof(input).ok,
        parseSelector(input) !== undefined,
      ]),
    );
    expect(verdicts).toHaveLength(inputs.length);
    expect(verdicts.filter(([record]) => record === true).length).toBeGreaterThan(70);
  });
});
