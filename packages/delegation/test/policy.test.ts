// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import type { JsonValue } from "@oip/schema";
import { clause } from "@oip/testkit";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { checkPolicy, evaluatePolicy, MAX_POLICY_WORK, policyHolds, select } from "../src/index.ts";

/** A commitment of the kind a policy is written for. */
const record = {
  type: "Commitment",
  author: "did:oip:agent",
  parties: [
    { mind: "did:oip:amina", role: "debtor", required: true },
    { mind: "did:oip:lexis", role: "creditor", required: true },
  ],
  terms: { price: { amount: "120.00", currency: "USD", payee: "did:oip:lexis" }, units: 3 },
  tags: [],
  "odd name": { "": 1 },
  proof: [{ secret: "not part of what a policy sees" }],
} satisfies JsonValue;

const holds = (...policy: unknown[]) => policyHolds(policy, record);
/** The clause and path of the first reason a policy does not hold. */
const refusal = (...policy: unknown[]) => {
  const result = evaluatePolicy(policy, record);
  if (result.ok) throw new Error("the policy holds");
  const [first] = result.issues;
  return { path: first.path, clause: first.clause };
};
const ERROR = { clause: "L1 11.3" };

describe(`${clause("L1 11.3")} selectors`, () => {
  it("lead from the value itself, by member names and by indexes", () => {
    expect(select(record, [])).toBe(record);
    expect(select(record, ["terms", "price", "amount"])).toBe("120.00");
    expect(select(record, ["parties", 1, "mind"])).toBe("did:oip:lexis");
    expect(select(record, ["odd name", ""])).toBe(1);
    expect(select(record, ["tags"])).toStrictEqual([]);
  });

  it("do not resolve where the path leads nowhere", () => {
    // No such member, no such element, a name asked of a list and an index of an object.
    expect(select(record, ["terms", "discount"])).toBeUndefined();
    expect(select(record, ["parties", 2])).toBeUndefined();
    expect(select(record, ["parties", "length"])).toBeUndefined();
    expect(select(record, ["terms", 0])).toBeUndefined();
    expect(select(record, ["type", 0])).toBeUndefined();
    expect(select(record, ["type", "length"])).toBeUndefined();
    expect(select(null, ["a"])).toBeUndefined();
    // Nothing is found on a prototype.
    expect(select(record, ["toString"])).toBeUndefined();
    expect(select(record, ["__proto__"])).toBeUndefined();
    expect(select(record, ["terms", "constructor"])).toBeUndefined();
  });
});

describe(`${clause("L1 11.3")} comparisons`, () => {
  it("order integers and decimal strings by their value", () => {
    expect(holds(["<=", ".terms.price.amount", "500"])).toBe(true);
    expect(holds(["<=", ".terms.price.amount", "120"])).toBe(true);
    expect(holds(["<", ".terms.price.amount", "120"])).toBe(false);
    expect(holds([">", ".terms.price.amount", "119.999"])).toBe(true);
    expect(holds([">=", ".terms.price.amount", "120.000"])).toBe(true);
    expect(holds([">=", ".terms.price.amount", "120.01"])).toBe(false);
    // An integer is a decimal, whichever side it is on.
    expect(holds(["<", ".terms.units", "3.5"])).toBe(true);
    expect(holds([">=", ".terms.units", 3])).toBe(true);
    expect(holds(["<", ".terms.price.amount", 121])).toBe(true);
    expect(holds([">", ".terms.units", -1])).toBe(true);
  });

  it("are an error when they order what is no decimal", () => {
    for (const policy of [
      ["<", ".terms.price.currency", "500"],
      ["<", ".terms.price.amount", "five hundred"],
      [">=", ".terms.price.amount", "1e2"],
      ["<=", ".terms.price.amount", " 500"],
      ["<", ".terms.price", "500"],
      ["<", ".tags", "500"],
      [">", ".terms.units", true],
      [">", ".terms.units", null],
      ["<", ".terms.units", 1.5],
      ["<", ".terms.units", 2 ** 60],
      ["<", ".terms.units", "9".repeat(65)],
    ]) {
      expect(refusal(policy)).toStrictEqual({ path: "/0", ...ERROR });
    }
  });

  it("test equality by value where both are decimals, and by canonical form otherwise", () => {
    expect(holds(["==", ".terms.price.amount", "120"])).toBe(true);
    expect(holds(["==", ".terms.price.amount", 120])).toBe(true);
    expect(holds(["==", ".terms.units", "3.0"])).toBe(true);
    expect(holds(["!=", ".terms.units", "3.0"])).toBe(false);
    expect(holds(["!=", ".terms.price.amount", "120.01"])).toBe(true);
    // Text is compared as text, and a decimal is not equal to text that is none.
    expect(holds(["==", ".terms.price.currency", "USD"])).toBe(true);
    expect(holds(["==", ".terms.price.currency", "usd"])).toBe(false);
    expect(holds(["!=", ".terms.price.currency", "EUR"])).toBe(true);
    expect(holds(["==", ".terms.price.amount", "120.00 "])).toBe(false);
    expect(holds(["==", ".terms.units", true])).toBe(false);
    expect(holds(["!=", ".terms.units", null])).toBe(true);
    // Whole values, whatever order their members were written in.
    expect(
      holds(["==", ".terms.price", { payee: "did:oip:lexis", currency: "USD", amount: "120.00" }]),
    ).toBe(true);
    expect(
      holds(["==", ".terms.price", { payee: "did:oip:lexis", currency: "USD", amount: "120" }]),
    ).toBe(false);
    expect(holds(["==", ".tags", []])).toBe(true);
    expect(holds(["==", ".", record])).toBe(false);
  });

  it("are an error when the selector does not resolve, whatever is asked", () => {
    for (const op of ["==", "!=", "<", "<=", ">", ">="]) {
      expect(refusal([op, ".terms.discount", "0"])).toStrictEqual({ path: "/0/1", ...ERROR });
    }
    expect(refusal(["==", ".parties[2].mind", "did:oip:amina"])).toStrictEqual({
      path: "/0/1",
      ...ERROR,
    });
  });

  it("see the record without its proofs", () => {
    expect(refusal(["!=", ".proof", "x"])).toStrictEqual({ path: "/0/1", ...ERROR });
    expect(holds(["==", '["odd name"][""]', 1])).toBe(true);
    // Only the record's own `proof` is left out.
    expect(policyHolds([["==", ".inner.proof", 1]], { inner: { proof: 1 }, proof: [] })).toBe(true);
  });
});

describe(`${clause("L1 11.3")} connectives`, () => {
  const within = ["<=", ".terms.price.amount", "500"];
  const beyond = ["<=", ".terms.price.amount", "100"];
  const missing = ["==", ".terms.discount", "0"];

  it("are what their names say", () => {
    expect(holds(["not", beyond])).toBe(true);
    expect(holds(["not", within])).toBe(false);
    expect(holds(["and", [within, ["not", beyond]]])).toBe(true);
    expect(holds(["and", [within, beyond]])).toBe(false);
    expect(holds(["or", [beyond, within]])).toBe(true);
    expect(holds(["or", [beyond, beyond]])).toBe(false);
    expect(holds(within, ["not", beyond])).toBe(true);
    expect(holds(within, beyond)).toBe(false);
  });

  it("never turn an error into a pass: every statement is evaluated in full", () => {
    // A negated comparison on a missing member, and a disjunction with one.
    expect(refusal(["not", missing])).toStrictEqual({ path: "/0/1/1", ...ERROR });
    expect(refusal(["or", [within, missing]])).toStrictEqual({ path: "/0/1/1/1", ...ERROR });
    expect(refusal(["or", [missing, within]])).toStrictEqual({ path: "/0/1/0/1", ...ERROR });
    expect(refusal(["and", [beyond, missing]])).toStrictEqual({ path: "/0/1/1/1", ...ERROR });
    expect(refusal(["not", ["not", ["or", [within, ["not", missing]]]]]).clause).toBe("L1 11.3");
    // An error in a later statement fails a policy whose earlier statement already failed,
    // and is the reason given.
    expect(refusal(beyond, missing)).toStrictEqual({ path: "/1/1", ...ERROR });
    expect(refusal(within, ["<", ".type", "5"])).toStrictEqual({ path: "/1", ...ERROR });
  });
});

describe(`${clause("L1 11.3")} quantifiers`, () => {
  const known = [
    "or",
    [
      ["==", ".mind", "did:oip:amina"],
      ["==", ".mind", "did:oip:lexis"],
    ],
  ];

  it("test a statement against each element, with selectors relative to the element", () => {
    expect(holds(["all", ".parties", known])).toBe(true);
    expect(holds(["all", ".parties", ["==", ".mind", "did:oip:amina"]])).toBe(false);
    expect(holds(["any", ".parties", ["==", ".mind", "did:oip:amina"]])).toBe(true);
    expect(holds(["any", ".parties", ["==", ".mind", "did:oip:agent"]])).toBe(false);
    // The delegate is no party.
    expect(holds(["all", ".parties", ["!=", ".mind", "did:oip:agent"]])).toBe(true);
    expect(policyHolds([["all", ".", ["<", ".", 4]]], [1, 2, 3])).toBe(true);
    expect(
      policyHolds(
        [["any", ".", ["all", ".", [">", ".", 2]]]],
        [
          [1, 5],
          [3, 4],
        ],
      ),
    ).toBe(true);
  });

  it("hold for every element of an empty array, and for none of them", () => {
    expect(holds(["all", ".tags", ["==", ".", "never asked"]])).toBe(true);
    expect(holds(["any", ".tags", ["==", ".", "never asked"]])).toBe(false);
    // The statement is not evaluated, so an error in it is not found.
    expect(holds(["all", ".tags", ["<", ".nothing", "x"]])).toBe(true);
  });

  it("are an error when the selector does not resolve to an array", () => {
    expect(refusal(["all", ".terms", known])).toStrictEqual({ path: "/0/1", ...ERROR });
    expect(refusal(["any", ".type", known])).toStrictEqual({ path: "/0/1", ...ERROR });
    expect(refusal(["all", ".guests", known])).toStrictEqual({ path: "/0/1", ...ERROR });
    expect(refusal(["not", ["any", ".guests", known]])).toStrictEqual({ path: "/0/1/1", ...ERROR });
  });

  it("find an error in any element, whatever the others came to", () => {
    const parties = { parties: [{ mind: "a" }, { name: "b" }, { mind: "c" }] };
    expect(policyHolds([["any", ".parties", ["==", ".mind", "a"]]], parties)).toBe(false);
    expect(policyHolds([["not", ["all", ".parties", ["==", ".mind", "a"]]]], parties)).toBe(false);
  });
});

describe(`${clause("L1 11.3", "L1 11.1")} a policy`, () => {
  it("holds when it has no statement, and when there is none at all", () => {
    expect(evaluatePolicy([], record)).toStrictEqual({ ok: true, value: true });
    expect(evaluatePolicy(undefined, record)).toStrictEqual({ ok: true, value: true });
    expect(policyHolds([], null)).toBe(true);
    // `null` is not the absence of a policy: it is a value that is no policy.
    expect(evaluatePolicy(null, record)).toMatchObject({
      ok: false,
      issues: [{ clause: "L1 11.3" }],
    });

    expect(policyHolds(null, record)).toBe(false);
  });

  it("is read whole before any of it is asked of the record", () => {
    // A quantifier over an empty array tries its statement on nothing. The statement
    // is part of the policy all the same, and one that is none makes it no policy.
    const empty = { list: [] };
    expect(policyHolds([["all", ".list", ["==", ".", 1]]], empty)).toBe(true);
    for (const inner of [
      ["==", "list", 1],
      ["==", '.["x y"]', 1],
      ["like", ".", "a*"],
      ["==", "."],
      ["and", []],
      ["all", ".[0]", ["==", ".", 1]],
      "==",
      null,
    ]) {
      expect(policyHolds([["all", ".list", inner]], empty), JSON.stringify(inner)).toBe(false);
      expect(policyHolds([["not", ["any", ".list", inner]]], empty), JSON.stringify(inner)).toBe(
        false,
      );
    }
    expect(evaluatePolicy([["all", ".list", ["==", "list", 1]]], empty)).toMatchObject({
      ok: false,
      issues: [{ path: "/0/2/1", clause: "L1 11.3" }],
    });
    // Too deep, where no record reaches.
    let deep: unknown = ["==", ".", 1];
    for (let i = 0; i < 8; i++) deep = ["not", deep];
    expect(policyHolds([["all", ".list", deep]], empty)).toBe(false);
    // Every fault is named, and nothing is asked of the record once one is found.
    expect(
      evaluatePolicy(
        [
          ["==", ".missing", 1],
          ["like", ".", 1],
          ["all", ".list", ["nor", ".", 1]],
        ],
        empty,
      ),
    ).toMatchObject({ ok: false, issues: [{ path: "/1" }, { path: "/2/2" }] });
  });

  it("names every statement that does not hold, when none is an error", () => {
    const result = evaluatePolicy(
      [
        ["==", ".type", "Commitment"],
        ["==", ".type", "Offer"],
        ["<", ".terms.units", 2],
      ],
      record,
    );
    expect(result).toMatchObject({ ok: false, issues: [{ path: "/1" }, { path: "/2" }] });
  });

  it("is an error when it is not one: nothing is read as a statement that is none", () => {
    const within = ["<=", ".terms.price.amount", "500"];
    for (const statement of [
      "==",
      5,
      null,
      {},
      [],
      ["=="],
      ["==", ".type"],
      ["==", ".type", "Commitment", "more"],
      ["like", ".type", "Commit*"],
      ["=", ".type", "Commitment"],
      ["==", "type", "Commitment"],
      ["==", ".type..x", "Commitment"],
      ["==", 5, "Commitment"],
      ["not"],
      ["not", within, within],
      ["not", "within"],
      ["and", []],
      ["and", within],
      ["or", [within], [within]],
      ["and", Array.from({ length: 65 }, () => within)],
      ["all", ".parties"],
      ["all", "parties", within],
      ["any", ".parties", "within"],
    ]) {
      const result = evaluatePolicy([statement], record);
      expect(!result.ok && result.issues[0].clause).toBe("L1 11.3");
    }
    for (const policy of ["==", {}, 5, Array.from({ length: 65 }, () => within)]) {
      const result = evaluatePolicy(policy, record);
      expect(!result.ok && result.issues).toStrictEqual([
        { path: "", message: "a policy is an array of at most 64 statements", clause: "L1 11.3" },
      ]);
    }
    expect(holds(["and", Array.from({ length: 64 }, () => within)])).toBe(true);
    expect(
      policyHolds(
        Array.from({ length: 64 }, () => within),
        record,
      ),
    ).toBe(true);
  });

  it(`${clause("L1 19")} nests its statements at most 8 deep`, () => {
    const nested = (depth: number): unknown =>
      depth === 0 ? ["==", ".type", "Commitment"] : ["not", ["not", nested(depth - 2)]];
    expect(holds(nested(8))).toBe(true);
    expect(refusal(["not", nested(8)])).toMatchObject(ERROR);
    expect(refusal(nested(10))).toMatchObject(ERROR);
  });

  it(`${clause("L1 19")} counts one for each value a statement is tried on, up to the work allowed`, () => {
    expect(MAX_POLICY_WORK).toBe(262_144);
    // One `all`, and for each of 4,032 elements an `and` and its 64 comparisons: 262,081.
    const within = { xs: Array.from({ length: 4032 }, () => 0) };
    const sixtyFour = Array.from({ length: 64 }, () => ["==", ".", 0]);
    const every = ["all", ".xs", ["and", sixtyFour]];
    /** An `and` of `n` comparisons, tried on the record once: `n + 1`. */
    const more = (n: number) => ["and", Array.from({ length: n }, () => ["==", ".xs[0]", 0])];
    expect(1 + 4032 * 65).toBe(262_081);
    expect(evaluatePolicy([every], within)).toStrictEqual({ ok: true, value: true });
    // Sixty-three more make the work allowed, to the unit, and it holds.
    expect(evaluatePolicy([every, more(62)], within)).toStrictEqual({ ok: true, value: true });
    // One more does not, whichever statement is the one too many.
    for (const over of [
      [every, more(63)],
      [more(63), every],
      [every, more(62), ["==", ".xs[0]", 0]],
    ]) {
      const refused = evaluatePolicy(over, within);
      expect(refused).toMatchObject({ ok: false, issues: [{ clause: "L1 11.3" }] });
      expect(!refused.ok && refused.issues).toHaveLength(1);
    }
    // Negated, it is refused all the same: work that cannot be done is an error.
    expect(policyHolds([["not", ["and", [every, more(63)]]]], within)).toBe(false);
    // A statement tried on every element of every element: two hundred by six hundred.
    const grid = { rows: Array.from({ length: 600 }, () => Array.from({ length: 600 }, () => 1)) };
    const each = [["all", ".rows", ["all", ".", ["==", ".", 1]]]];
    expect(policyHolds(each, grid)).toBe(false);
    expect(policyHolds(each, { rows: grid.rows.slice(0, 400) })).toBe(true);
  });

  it(`${clause("L1 19")} counts the bytes of both canonical forms for a comparison by canonical form`, () => {
    // One for the statement, and five bytes for each of `"abc"`: eleven.
    const text = (length: number) => "a".repeat(length);
    const blob = text(131_069);
    // 1 + 2 × (131,069 + 2) for the first, and one for the second, a comparison of numbers.
    const two = [
      ["==", ".blob", blob],
      ["==", ".n", 1],
    ];
    expect(1 + 2 * (blob.length + 2) + 1).toBe(MAX_POLICY_WORK);
    expect(evaluatePolicy(two, { blob, n: 1 })).toStrictEqual({ ok: true, value: true });
    expect(evaluatePolicy([...two, ["==", ".n", 1]], { blob, n: 1 })).toMatchObject({
      ok: false,
      issues: [{ clause: "L1 11.3" }],
    });
    // Whether or not the two are equal, and whichever is the larger.
    expect(policyHolds([["!=", ".blob", text(131_070)]], { blob, n: 1 })).toBe(true);
    expect(policyHolds([["!=", ".blob", text(131_071)]], { blob, n: 1 })).toBe(false);
    expect(policyHolds([["!=", ".blob", "a"]], { blob: text(262_138) })).toBe(true);
    expect(policyHolds([["!=", ".blob", "a"]], { blob: text(262_139) })).toBe(false);
    // The bytes of the form, not the characters of the value: a quote is written as two.
    expect(policyHolds([["==", ".blob", '"'.repeat(65_534)]], { blob: '"'.repeat(65_534) })).toBe(
      true,
    );
    expect(policyHolds([["==", ".blob", '"'.repeat(65_535)]], { blob: '"'.repeat(65_535) })).toBe(
      false,
    );
    // A comparison of numbers counts no bytes, however they are written.
    const numbers = Array.from({ length: 64 }, () => ["==", ".amount", "1".repeat(64)]);
    expect(policyHolds(numbers, { amount: "1".repeat(64) })).toBe(true);
  });

  it("compares by canonical form whatever the order of an object's members", () => {
    const priced = { terms: { price: { amount: "5", currency: "USD" }, tags: ["a", "b"] } };
    const eq = (selector: string, value: unknown) => policyHolds([["==", selector, value]], priced);
    expect(eq(".terms.price", { currency: "USD", amount: "5" })).toBe(true);
    expect(eq(".terms", { tags: ["a", "b"], price: { currency: "USD", amount: "5" } })).toBe(true);
    // An array's order is part of its form, and a member more or less is another value.
    expect(eq(".terms.tags", ["b", "a"])).toBe(false);
    expect(eq(".terms.price", { amount: "5" })).toBe(false);
    expect(eq(".terms.price", { amount: "5", currency: "USD", unit: null })).toBe(false);
    // Inside a value nothing is compared as a number: `5` and `"5"` are different forms.
    expect(eq(".terms.price", { amount: 5, currency: "USD" })).toBe(false);
    expect(eq(".terms.price.amount", 5)).toBe(true);
    // Values of one size and different content.
    expect(eq(".terms.price", { amount: "6", currency: "USD" })).toBe(false);
    expect(policyHolds([["!=", ".terms.price", { amount: "6", currency: "USD" }]], priced)).toBe(
      true,
    );
    expect(eq(".terms.tags", ["a", "c"])).toBe(false);
    expect(eq(".terms.price", { amount: "5", currencY: "USD" })).toBe(false);
    expect(eq(".terms.tags", "[a,b]")).toBe(false);
    expect(eq(".terms.price.currency", null)).toBe(false);
    expect(eq(".terms.price.currency", "USD")).toBe(true);
  });

  it("bounds the reasons it gives", () => {
    const many = Array.from({ length: 64 }, () => [
      "and",
      Array.from({ length: 64 }, () => ["==", ".no", 1]),
    ]);
    const result = evaluatePolicy(many, record);
    expect(!result.ok && result.issues.length).toBe(32);
  });
});

describe(`${clause("L1 11.3")} whether a value is a policy at all`, () => {
  it("is asked of the policy alone, and answered as the evaluation answers it first", () => {
    const policy = [
      ["==", ".terms.price.currency", "USD"],
      ["<=", ".terms.price.amount", "500"],
      ["all", ".parties", ["not", ["==", ".mind", "did:oip:x"]]],
    ];
    expect(checkPolicy(policy)).toStrictEqual({ ok: true, value: true });
    expect(checkPolicy([])).toStrictEqual({ ok: true, value: true });
    expect(checkPolicy(undefined)).toStrictEqual({ ok: true, value: true });
    // It is a policy whether or not it holds for a record, and whether or not it resolves there.
    expect(policyHolds(policy, {})).toBe(false);
    for (const none of [
      null,
      "a policy",
      { 0: ["==", ".a", 1] },
      [["==", "a", 1]],
      [["maybe", ".a", 1]],
      [["==", ".a"]],
      ["==", ".a", 1],
      [["all", ".list", ["==", "x", 1]]],
      Array.from({ length: 65 }, () => ["==", ".a", 1]),
    ]) {
      const checked = checkPolicy(none);
      expect(checked.ok, JSON.stringify(none)).toBe(false);
      // The same reasons, whatever record it would have been asked of.
      expect(checked).toStrictEqual(evaluatePolicy(none, {}));
      expect(checked).toStrictEqual(evaluatePolicy(none, record));
      if (!checked.ok) expect(checked.issues[0].clause).toBe("L1 11.3");
    }
  });

  it("says of any value what the evaluation would say first, whatever the record", () => {
    fc.assert(
      fc.property(fc.jsonValue(), fc.jsonValue(), (value, asked) => {
        const checked = checkPolicy(value);
        const evaluated = evaluatePolicy(value, asked as JsonValue);
        // What is no policy holds for no record, for the same reasons.
        if (!checked.ok) expect(evaluated).toStrictEqual(checked);
        // And what holds for a record is a policy.
        if (evaluated.ok) expect(checked).toStrictEqual({ ok: true, value: true });
      }),
      { numRuns: 300 },
    );
  });
});

describe(`${clause("L1 11.3")} whatever a policy and a record are`, () => {
  const junk = fc.anything({
    maxDepth: 4,
    withBigInt: true,
    withDate: true,
    withSparseArray: true,
  });
  const selector = fc.constantFrom(".", ".a", ".b", ".a.b", "[0]", ".a[1]", ".missing", '["a"]');
  const value: fc.Arbitrary<JsonValue> = fc.oneof(
    fc.integer({ min: -5, max: 5 }),
    fc.constantFrom("1", "1.0", "-0", "x", "", "2.50"),
    fc.constant(null),
    fc.boolean(),
    fc.constant([1, "1"] as JsonValue),
  );
  const { statement } = fc.letrec<{ statement: unknown }>((tie) => ({
    statement: fc.oneof(
      { depthSize: "small", maxDepth: 5 },
      fc.tuple(fc.constantFrom("==", "!=", "<", "<=", ">", ">="), selector, value),
      fc.tuple(fc.constant("not"), tie("statement")),
      fc.tuple(
        fc.constantFrom("and", "or"),
        fc.array(tie("statement"), { minLength: 1, maxLength: 3 }),
      ),
      fc.tuple(fc.constantFrom("all", "any"), selector, tie("statement")),
    ),
  }));
  const subject: fc.Arbitrary<JsonValue> = fc.oneof(
    fc.record({
      a: fc.oneof(value, fc.array(value, { maxLength: 3 }), fc.record({ b: value })),
      b: value,
    }) as fc.Arbitrary<JsonValue>,
    fc.array(value, { maxLength: 3 }) as fc.Arbitrary<JsonValue>,
    value,
  );
  const errors = (policy: unknown, on: JsonValue) => {
    const result = evaluatePolicy(policy, on);
    return !result.ok && result.issues[0].message !== "the statement does not hold for the record";
  };

  it("answers and does not throw", () => {
    fc.assert(
      fc.property(junk, junk, (policy, on) => {
        const result = evaluatePolicy(policy, on as JsonValue);
        expect(typeof result.ok).toBe("boolean");
      }),
      { numRuns: 500 },
    );
  });

  it("fails a policy with an error in it, and its negation as well", () => {
    fc.assert(
      fc.property(statement, subject, (made, on) => {
        fc.pre(errors([made], on));
        expect(policyHolds([["not", made]], on)).toBe(false);
        expect(policyHolds([["or", [made, ["==", ".", on]]]], on)).toBe(false);
        expect(policyHolds([["and", [["==", ".", on], made]]], on)).toBe(false);
      }),
      { numRuns: 500 },
    );
  });

  it("holds for a statement or for its negation and never both, where there is no error", () => {
    fc.assert(
      fc.property(statement, subject, (made, on) => {
        fc.pre(!errors([made], on));
        expect(policyHolds([made], on)).toBe(!policyHolds([["not", made]], on));
      }),
      { numRuns: 500 },
    );
  });

  it("never holds for more records when a statement is added to it", () => {
    fc.assert(
      fc.property(fc.array(statement, { maxLength: 3 }), statement, subject, (policy, more, on) => {
        if (!policyHolds(policy, on)) {
          expect(policyHolds([...policy, more], on)).toBe(false);
          expect(policyHolds([more, ...policy], on)).toBe(false);
        }
      }),
      { numRuns: 500 },
    );
  });
});
