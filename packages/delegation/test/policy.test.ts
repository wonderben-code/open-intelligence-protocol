// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import type { JsonValue } from "@oip/schema";
import { clause } from "@oip/testkit";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { evaluatePolicy, MAX_POLICY_STEPS, policyHolds, select } from "../src/index.ts";

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

  it("is evaluated for no more statements than a verifier allows", () => {
    // A statement tried on every element of every element: two hundred by six hundred.
    const grid = { rows: Array.from({ length: 200 }, () => Array.from({ length: 600 }, () => 1)) };
    const every = [["all", ".rows", ["all", ".", ["==", ".", 1]]]];
    expect(200 * 600).toBeGreaterThan(MAX_POLICY_STEPS);
    expect(evaluatePolicy(every, grid)).toMatchObject({
      ok: false,
      issues: [{ clause: "implementation limit" }],
    });
    // Negated, it is refused all the same, and for one reason.
    const negated = evaluatePolicy([["not", every[0]]], grid);
    expect(negated).toMatchObject({ ok: false, issues: [{ clause: "implementation limit" }] });
    expect(!negated.ok && negated.issues).toHaveLength(1);
    const small = { rows: grid.rows.slice(0, 100) };
    expect(evaluatePolicy(every, small)).toStrictEqual({ ok: true, value: true });
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
