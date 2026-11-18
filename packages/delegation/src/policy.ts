// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The policy language (Layer 1, 11.3): what a delegation or a role lets its
 * holder sign, said as statements about the record.
 *
 * Three rules shape everything here. Ordering is defined between decimals
 * and nothing else. Every statement is evaluated in full. And an error
 * anywhere fails the policy, so that `not` and `or` can never turn a missing
 * or malformed value into a pass.
 */

import { canonicalSizeUpTo, compareDecimals, isDecimal, type JsonObject } from "@oip/core";
import {
  IMPLEMENTATION_LIMIT,
  type Issue,
  type JsonValue,
  judging,
  MAX_ISSUES,
  MAX_POLICY_DEPTH,
  parseSelector,
  type SelectorStep,
  validateJson,
  type Validation,
} from "@oip/schema";

import { ok, type Rejection } from "./result.ts";

/**
 * Layer 1, 11.3 and Section 19: the most work one policy may ask for one
 * record. Each time a statement is tried on a value counts one, and a
 * comparison by canonical form counts, besides, the bytes of the two
 * canonical forms it compares. A policy that would count more does not hold.
 *
 * A quantifier tries its statement on every element of an array, so a policy
 * of a few statements can ask for work in proportion to the record, and one
 * of many for the product of the two. The count is of what is asked, in
 * terms every verifier counts alike, so that all of them give one answer.
 */
export const MAX_POLICY_WORK = 262_144;

const CLAUSE = "L1 11.3";
const ORDERING = ["<", "<=", ">", ">="];
const EQUALITY = ["==", "!="];

/** What does not resolve: no JSON value is `undefined`. */
const MISSING = undefined;

/**
 * Layer 1, 11.3: the value a selector's path leads to, or `undefined` if it
 * does not resolve. A name selects a member of an object, and an index an
 * element of an array; neither selects from anything else.
 */
export function select(value: JsonValue, path: readonly SelectorStep[]): JsonValue | undefined {
  let at: JsonValue = value;
  for (const step of path) {
    if (typeof step === "number") {
      if (!Array.isArray(at) || step >= at.length) return MISSING;
      at = (at as readonly JsonValue[])[step] as JsonValue;
    } else {
      if (typeof at !== "object" || at === null || Array.isArray(at)) return MISSING;
      if (!Object.hasOwn(at, step)) return MISSING;
      at = (at as JsonObject)[step] as JsonValue;
    }
  }
  return at;
}

/** core 1.3: an integer or a decimal string as a decimal string, and nothing else as one. */
function decimalOf(value: unknown): string | undefined {
  if (typeof value === "number") return Number.isSafeInteger(value) ? String(value) : undefined;
  return isDecimal(value) ? value : undefined;
}

/** One evaluation of a policy: the errors found, and the work done. */
interface Run {
  readonly errors: Issue[];
  /** The work counted so far (Layer 1, 11.3). */
  work: number;
  /** Set once the work allowed is spent. Nothing more is evaluated. */
  spent: boolean;
  /**
   * The path of each statement's selector, read once when the policy is
   * checked. A quantifier tries its statement on every element, and the
   * selector says the same thing each time.
   */
  readonly paths: Map<unknown, readonly SelectorStep[]>;
}

function error(run: Run, path: string, message: string, clause = CLAUSE): false {
  if (run.errors.length < MAX_ISSUES) run.errors.push({ path, message, clause });
  // What an error "holds" as is never used: any error fails the policy.
  return false;
}

/** Notes that the work allowed for one policy is spent. Nothing more is read or evaluated. */
function spent(run: Run, path: string, clause = CLAUSE): false {
  run.spent = true;
  return error(run, path, `the policy asks for more work than ${MAX_POLICY_WORK}`, clause);
}

/** A selector as an error message shows it: one of any length would make a message of that length. */
function shown(selector: unknown): string {
  const text = String(selector);
  return text.length > 64 ? `${text.slice(0, 64)}…` : text;
}

/**
 * Whether two values have the same canonical form (core Section 2), without
 * writing either: the same value, the same elements in the same order, or
 * the same members whatever their order.
 *
 * @param budget - How many values to look at before giving up. Two values
 *   of one canonical size have no more values than that size.
 */
function sameCanonicalForm(left: unknown, right: unknown, budget: { left: number }): boolean {
  if (--budget.left < 0) return false;
  if (typeof left !== "object" || left === null || typeof right !== "object" || right === null) {
    return left === right;
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;
    return left.every((element, index) => sameCanonicalForm(element, right[index], budget));
  }
  const names = Object.keys(left);
  if (names.length !== Object.keys(right).length) return false;
  return names.every(
    (name) =>
      Object.hasOwn(right, name) &&
      sameCanonicalForm(
        (left as Readonly<Record<string, unknown>>)[name],
        (right as Readonly<Record<string, unknown>>)[name],
        budget,
      ),
  );
}

/**
 * Whether a statement is one of the policy language, whatever record it is
 * asked of: its shape, its selectors and how deep it nests. Every part of it
 * is read and every fault noted, the parts that no record would reach among
 * them: the statement of a quantifier is never tried on an empty array, and
 * is a statement or not all the same.
 */
function wellFormed(statement: unknown, path: string, depth: number, run: Run): boolean {
  if (run.spent) return false;
  // A policy read from text has far fewer statements than this. One built in memory,
  // with one statement standing in many places, is read no further.
  if (++run.work > MAX_POLICY_WORK) return spent(run, path, IMPLEMENTATION_LIMIT);
  if (depth > MAX_POLICY_DEPTH) {
    return error(run, path, `a policy statement nests more than ${MAX_POLICY_DEPTH} deep`);
  }
  if (!Array.isArray(statement)) return error(run, path, "a policy statement is an array");
  const [op, second, third] = statement as readonly unknown[];
  const size = statement.length;

  if (op === "not") {
    if (size !== 2) return error(run, path, "`not` takes one statement");
    return wellFormed(second, `${path}/1`, depth + 1, run);
  }
  if (op === "and" || op === "or") {
    if (size !== 2 || !Array.isArray(second) || second.length < 1 || second.length > 64) {
      return error(run, path, `\`${op}\` takes a list of 1 to 64 statements`);
    }
    // Every statement of the list, with no short cut.
    return (second as readonly unknown[])
      .map((inner, i) => wellFormed(inner, `${path}/1/${i}`, depth + 1, run))
      .every(Boolean);
  }

  const quantifier = op === "all" || op === "any";
  const comparison = ORDERING.includes(op as string) || EQUALITY.includes(op as string);
  if ((!quantifier && !comparison) || size !== 3) {
    return error(run, path, "the statement is none that the policy language defines");
  }
  const steps = parseSelector(second);
  if (steps === undefined) return error(run, `${path}/1`, "the selector is not well formed");
  run.paths.set(statement, steps);
  if (quantifier) return wellFormed(third, `${path}/2`, depth + 1, run);
  // What is compared by canonical form has one: a JSON value of the profile. An
  // ordering takes a decimal, and says so when it is asked of the record.
  if (EQUALITY.includes(op as string) && !validateJson(third, "container").ok) {
    return error(run, `${path}/2`, "the value compared with is not a JSON value of the profile");
  }
  return true;
}

/**
 * Whether one statement, which is well formed, holds for a value. Every
 * part of it is evaluated, whatever the parts before it came to, so that an
 * error is found wherever it is.
 */
function holds(statement: unknown, value: JsonValue, path: string, run: Run): boolean {
  if (run.spent) return false;
  if (++run.work > MAX_POLICY_WORK) return spent(run, path);
  const [op, second, third] = statement as readonly unknown[];

  if (op === "not") return !holds(second, value, `${path}/1`, run);
  if (op === "and" || op === "or") {
    // Every statement of the list, with no short cut.
    const results = (second as readonly unknown[]).map((inner, i) =>
      holds(inner, value, `${path}/1/${i}`, run),
    );
    return op === "and" ? results.every(Boolean) : results.some(Boolean);
  }

  const selected = select(value, run.paths.get(statement) ?? []);
  if (selected === MISSING) {
    return error(run, `${path}/1`, `the selector ${shown(second)} does not resolve to a value`);
  }

  if (op === "all" || op === "any") {
    if (!Array.isArray(selected)) {
      return error(run, `${path}/1`, `the selector ${shown(second)} does not resolve to an array`);
    }
    const results = (selected as readonly JsonValue[]).map((element) =>
      holds(third, element, `${path}/2`, run),
    );
    return op === "all" ? results.every(Boolean) : results.some(Boolean);
  }

  const [left, right] = [decimalOf(selected), decimalOf(third)];
  const order =
    left === undefined || right === undefined ? undefined : compareDecimals(left, right);
  if (ORDERING.includes(op as string)) {
    if (order === undefined) {
      return error(run, path, `\`${String(op)}\` compares integers and decimal strings only`);
    }
    return op === "<" ? order < 0 : op === "<=" ? order <= 0 : op === ">" ? order > 0 : order >= 0;
  }
  // Numerically where both are decimals, and otherwise by canonical form.
  let equal: boolean;
  if (order !== undefined) equal = order === 0;
  else {
    // The comparison counts the bytes of both forms. Each is measured only as far as
    // the work left allows, so a value too large to compare is not read to its end.
    const left = MAX_POLICY_WORK - run.work;
    const mine = canonicalSizeUpTo(selected, left);
    const theirs = mine > left ? 0 : canonicalSizeUpTo(third as JsonValue, left - mine);
    run.work += mine + theirs;
    if (run.work > MAX_POLICY_WORK) return spent(run, path);
    // Two forms of different sizes differ. Two of one size are compared value by value.
    equal = mine === theirs && sameCanonicalForm(selected, third, { left: mine });
  }
  return op === "==" ? equal : !equal;
}

/**
 * Layer 1, 11.3: whether every statement of a policy holds for a record,
 * taken without its `proof`.
 *
 * The answer is a rejection if a statement does not hold, and if any
 * statement anywhere in the policy is an error: a selector that does not
 * resolve to a value, an ordering whose operands are not both integers or
 * decimal strings, a quantifier whose selector does not resolve to an
 * array. The rejection names the statements, by their place in the policy.
 * Every statement is evaluated, whatever the others came to.
 *
 * The policy should come from a record that has been validated, and so
 * should the record. Neither is trusted to be: the whole policy is read
 * first, and one that is not a policy in any part does not hold, whether or
 * not this record would have reached that part. Nothing here throws.
 *
 * @param policy - The statements. No policy at all is the empty policy,
 *   which holds for every record (Layer 1, 11.1).
 * @param record - The record being authorised.
 */
export function evaluatePolicy(policy: unknown, record: JsonValue): Validation<true> {
  return judging(() => evaluated(policy, record));
}

/** The verdict, as `evaluatePolicy` answers when no check is cut short. */
function evaluated(policy: unknown, record: JsonValue): Validation<true> {
  // A record with no `policy` member has the empty policy. `null` is not a policy.
  const statements: unknown = policy === undefined ? [] : policy;
  if (!Array.isArray(statements) || statements.length > 64) {
    return failed([
      { path: "", message: "a policy is an array of at most 64 statements", clause: CLAUSE },
    ]);
  }
  // The record without its proofs: a policy constrains what was signed.
  let subject: JsonValue = record;
  if (typeof record === "object" && record !== null && !Array.isArray(record)) {
    const { proof: _proof, ...content } = record as JsonObject;
    subject = content;
  }
  const run: Run = { errors: [], work: 0, spent: false, paths: new Map() };
  // Validate, then use. The whole policy is read before any of it is asked of the
  // record: a part that this record does not reach is part of the policy too.
  (statements as readonly unknown[]).forEach((statement, i) =>
    wellFormed(statement, `/${i}`, 0, run),
  );
  const [malformed, ...others] = run.errors;
  if (malformed !== undefined) return failed([malformed, ...others]);
  run.work = 0;
  const unmet: Issue[] = [];
  (statements as readonly unknown[]).forEach((statement, i) => {
    if (!holds(statement, subject, `/${i}`, run) && unmet.length < MAX_ISSUES) {
      unmet.push({
        path: `/${i}`,
        message: "the statement does not hold for the record",
        clause: CLAUSE,
      });
    }
  });
  // An error says more than "does not hold", and is the reason whatever held.
  const [first, ...rest] = run.errors.length > 0 ? run.errors : unmet;
  return first === undefined ? ok(true) : failed([first, ...rest]);
}

function failed(issues: readonly [Issue, ...Issue[]]): Rejection {
  return { ok: false, issues };
}

/** Layer 1, 11.3: whether a policy holds for a record. See `evaluatePolicy` for why not. */
export function policyHolds(policy: unknown, record: JsonValue): boolean {
  return evaluatePolicy(policy, record).ok;
}
