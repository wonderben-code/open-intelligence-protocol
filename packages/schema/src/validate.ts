// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Validation: the first step of "validate, verify, then use". A value that
 * passes is a well-formed record of its type. Nothing here checks a signature,
 * an identity log or the time; a validated record is not yet a verified one.
 */

import { type ValidatorError, validators } from "./generated/validators.ts";
import { type Issue, quote, type Validation } from "./issue.ts";
import { patterns } from "./primitives.ts";
import type { Proof } from "./proof.ts";
import type { ExtensionRecord } from "./records/extension.ts";
import {
  DEFINING_CLAUSE,
  isRecordType,
  type OipRecord,
  type RecordOf,
  type RecordType,
  RESERVED_RECORD_TYPES,
} from "./registry.ts";
import { checkExtensionRules, checkProofRules, checkRecordRules } from "./rules.ts";

/**
 * The deepest nesting of arrays and objects this implementation accepts in a
 * record. The specification sets no limit yet; this one is an implementation
 * limit, far above anything the defined record types need, that keeps
 * recursive code safe from hostile input.
 */
export const MAX_DEPTH = 64;

/** The `clause` of an issue raised by an implementation limit rather than by the specification. */
export const IMPLEMENTATION_LIMIT = "implementation limit";

/** The most issues one validation reports. Hostile input must not buy unbounded output. */
export const MAX_ISSUES = 32;

/** The longest path an issue carries. Member names come from the input. */
const MAX_PATH = 256;

/**
 * The most values this implementation reads in one record. core 1.6 bounds a
 * record's canonical form at 1 MiB and every value takes at least two bytes
 * of it, so no record within that limit comes near this number. It bounds
 * the work done on values that did not come from a JSON text, such as an
 * array with millions of holes or a structure that shares its parts.
 */
const MAX_VALUES = 1_048_576;

function reject<T>(issues: readonly Issue[], fallback: Issue): Validation<T> {
  const [first = fallback, ...rest] = issues
    .slice(0, MAX_ISSUES)
    .map((issue) =>
      issue.path.length <= MAX_PATH
        ? issue
        : { ...issue, path: `${issue.path.slice(0, MAX_PATH - 1)}…` },
    );
  return { ok: false, issues: [first, ...rest] };
}

function fail<T>(issue: Issue): Validation<T> {
  return reject([], issue);
}

/** Whether a string is valid Unicode: every surrogate is half of a pair (core 1.1). */
function isWellFormed(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit < 0xd800 || unit > 0xdfff) continue;
    const next = value.charCodeAt(i + 1);
    // A high surrogate must be followed by a low one; a low one on its own is unpaired.
    if (unit > 0xdbff || !(next >= 0xdc00 && next <= 0xdfff)) return false;
    i++;
  }
  return true;
}

const UNPAIRED: Issue = {
  path: "",
  message: "a string has an unpaired surrogate, which is not valid Unicode",
  clause: "core 1.1",
};

const NOT_JSON: Issue = {
  path: "",
  message:
    "something here is not a JSON value: only objects, arrays, strings, true, false, null and integers are permitted",
  clause: "core 1.2",
};

const TOO_DEEP: Issue = {
  path: "",
  message: `arrays and objects nest more than ${MAX_DEPTH} deep`,
  clause: IMPLEMENTATION_LIMIT,
};

const TOO_MANY: Issue = {
  path: "",
  message: "there are more values here than a record of 1 MiB can hold",
  clause: "core 1.6",
};

/**
 * Checks what holds for every value in a record, whatever its type:
 *
 *   - it is plain JSON data: objects, arrays, strings, booleans, null and
 *     numbers, with no holes, accessors, hidden members or other prototypes
 *     (core 1.2). A value parsed from JSON text always is; one built by other
 *     code may not be, and the schema validators would read members this
 *     check had not seen;
 *   - strings and member names are valid Unicode (core 1.1);
 *   - numbers are safe integers (core 1.2);
 *   - nesting is no deeper than `MAX_DEPTH`, and there are no more than
 *     `MAX_VALUES` values.
 *
 * It does not recurse, so no input can exhaust the stack, and it reads
 * accessors' descriptors rather than calling them.
 */
function checkValues(root: unknown): Issue | undefined {
  let budget = MAX_VALUES;
  const pending: { value: object; depth: number }[] = [];

  const visit = (value: unknown, depth: number): Issue | undefined => {
    switch (typeof value) {
      case "boolean":
        return undefined;
      case "string":
        return isWellFormed(value) ? undefined : UNPAIRED;
      case "number":
        if (Number.isSafeInteger(value)) return undefined;
        return {
          path: "",
          message: `the number ${value} is not an integer between -(2^53-1) and 2^53-1; write decimal quantities as strings`,
          clause: "core 1.2",
        };
      case "object":
        if (value === null) return undefined;
        if (depth > MAX_DEPTH) return TOO_DEEP;
        pending.push({ value, depth });
        return undefined;
      default:
        // undefined (which is also what a hole in an array reads as), bigint, symbol, function.
        return NOT_JSON;
    }
  };

  let issue = visit(root, 1);
  for (let next = pending.pop(); issue === undefined && next !== undefined; next = pending.pop()) {
    const { value, depth } = next;
    if (Array.isArray(value)) {
      if (value.length > budget) return TOO_MANY;
      budget -= value.length;
      // A plain array has its elements and its length and nothing else: no
      // other prototype and no member such as `toJSON`, which a serialiser
      // would call and so write something other than what was checked here.
      if (Object.getPrototypeOf(value) !== Array.prototype) return NOT_JSON;
      if (Object.getOwnPropertyNames(value).length !== value.length + 1) return NOT_JSON;
      for (let i = 0; i < value.length && issue === undefined; i++) {
        issue = visit(value[i], depth + 1);
      }
      continue;
    }
    const prototype: unknown = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return NOT_JSON;
    if (Object.getOwnPropertySymbols(value).length > 0) return NOT_JSON;
    const names = Object.getOwnPropertyNames(value);
    if (names.length > budget) return TOO_MANY;
    budget -= names.length;
    for (const name of names) {
      if (!isWellFormed(name)) return UNPAIRED;
      const member = Object.getOwnPropertyDescriptor(value, name);
      if (member === undefined || !member.enumerable || !("value" in member)) return NOT_JSON;
      issue = visit(member.value, depth + 1);
      if (issue !== undefined) break;
    }
  }
  return issue;
}

/** The clause that defines each value syntax, by its pattern. */
const PATTERN_CLAUSE: ReadonlyMap<string, string> = new Map([
  [patterns.timestamp, "core 1.4"],
  [patterns.duration, "core 1.5"],
  [patterns.decimal, "core 1.3"],
  [patterns.amount, "core 1.3"],
  [patterns.contentId, "core 3.2"],
  [patterns.mindAddress, "core 6.1"],
  [patterns.versionId, "core 6.1"],
  [patterns.versionedMind, "core 6.1"],
  [patterns.keyRef, "core 6.1"],
  [patterns.controlKeyRef, "core 6.1"],
  [patterns.recordRef, "core 6.1"],
  [patterns.ed25519Multikey, "core 4.1"],
  [patterns.x25519Multikey, "core 4.1"],
  [patterns.proofValue, "core 5.2"],
]);

/** The clause that defines each member every record shares. */
const COMMON_MEMBER_CLAUSE: Readonly<Record<string, string>> = {
  "/oip": "core 7",
  "/type": "core 7",
  "/ext": "core 8.1",
  "/critical": "core 8.3",
  "/proof": "core 5.1",
};

/**
 * The clause an error is about: the one that defines the value's syntax or
 * the common member at fault, and otherwise the one that defines the record.
 */
function clauseOf(error: ValidatorError, name: string, defining: string): string {
  const pattern = error.keyword === "pattern" ? error.params?.["pattern"] : undefined;
  if (typeof pattern === "string") {
    const clause = PATTERN_CLAUSE.get(pattern);
    if (clause !== undefined) return clause;
  }
  // A proof has a `type` too, and core 5.2 defines it, not core 7.
  if (name === "Proof") return defining;
  return COMMON_MEMBER_CLAUSE[error.instancePath] ?? defining;
}

const depthOf = (path: string) => path.split("/").length;

function schemaIssues(name: string, defining: string): Issue[] {
  const errors = validators[name]?.errors ?? [];
  const issues = errors
    // "Must match one of several schemas" says nothing the errors beside it do not.
    .filter((error) => errors.length === 1 || error.keyword !== "anyOf")
    .map((error) => ({
      path: error.instancePath,
      message: error.message ?? `does not match the ${name} schema`,
      clause: clauseOf(error, name, defining),
    }));
  // The deepest value at fault first: it is the most specific thing to fix.
  return issues.sort((a, b) => depthOf(b.path) - depthOf(a.path));
}

const UNREADABLE: Issue = {
  path: "",
  message: "the value could not be read as plain JSON data",
  clause: "core 1.2",
};

/**
 * Runs a validation so that it always answers. Judging hostile input is the
 * work of this package: whatever the value (a proxy, an object that throws
 * when read), the caller gets a rejection, never an exception.
 */
function answering<T>(run: () => Validation<T>): Validation<T> {
  try {
    return run();
  } catch {
    return fail(UNREADABLE);
  }
}

function validateWith<T>(
  name: string,
  defining: string,
  value: unknown,
  rules: (valid: T) => Issue[],
): Validation<T> {
  const unsafe = checkValues(value);
  if (unsafe !== undefined) return fail(unsafe);
  const validator = validators[name];
  if (validator === undefined) throw new Error(`no compiled validator for ${name}`);
  if (!validator(value)) {
    return reject(schemaIssues(name, defining), {
      path: "",
      message: `not a well-formed ${name}`,
      clause: defining,
    });
  }
  const valid = value as T;
  const issues = rules(valid);
  return issues.length === 0
    ? { ok: true, value: valid }
    : reject(issues, { path: "", message: `not a well-formed ${name}`, clause: defining });
}

/**
 * A value permitted in a record (core 1.2): an object, an array, a string,
 * `true`, `false`, `null`, or an integer between -(2^53-1) and 2^53-1.
 */
export type JsonValue =
  null | boolean | number | string | readonly JsonValue[] | { readonly [name: string]: JsonValue };

/**
 * Checks that a value is plain JSON data within the profile of core
 * Section 1, whatever it is for: objects, arrays, strings, booleans, null and
 * safe integers; valid Unicode; no deeper than `MAX_DEPTH`. Every validator
 * here applies this check first. `@oip/core` applies it before it computes a
 * canonical form, so that nothing outside the profile is ever hashed or
 * signed.
 */
export function validateJson(value: unknown): Validation<JsonValue> {
  return answering(() => {
    const unsafe = checkValues(value);
    return unsafe === undefined ? { ok: true, value: value as JsonValue } : fail(unsafe);
  });
}

/**
 * Validates a record of a known type against its schema and the structural
 * rules. Use `validateRecord` when the type is not known in advance.
 *
 * `type` is checked at run time as well: a name that is not a record type,
 * such as one taken from a URL, gives a rejection and never reaches a
 * validator.
 */
export function validateRecordOfType<K extends RecordType>(
  type: K,
  value: unknown,
): Validation<RecordOf<K>> {
  return answering(() => {
    if (!isRecordType(type)) {
      return fail({
        path: "",
        message: `${quote(String(type))} is not a record type this revision defines`,
        clause: "core 11",
      });
    }
    return validateWith<RecordOf<K>>(type, DEFINING_CLAUSE[type], value, (record) =>
      checkRecordRules(record),
    );
  });
}

function typeOf(value: unknown): Validation<string> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return fail({ path: "", message: "a record is a JSON object", clause: "core 1.1" });
  }
  const { oip, type } = value as { readonly oip?: unknown; readonly type?: unknown };
  if (oip !== "1") {
    return fail({ path: "/oip", message: 'oip must be the string "1"', clause: "core 7" });
  }
  if (typeof type !== "string") {
    return fail({ path: "/type", message: "type must name a record type", clause: "core 7" });
  }
  if ((RESERVED_RECORD_TYPES as readonly string[]).includes(type)) {
    return fail({
      path: "/type",
      message: `${type} is reserved in this revision and must be rejected`,
      clause: "L1 3.9",
    });
  }
  return { ok: true, value: type };
}

/**
 * Validates a record of a type this revision defines: `oip` is `"1"`
 * (core Section 7), `type` names one of the record types of core Section 11,
 * and the record matches that type's schema and structural rules.
 *
 * A record of any other type is rejected here. If an extension defines the
 * type (core 7), `validateExtensionRecord` checks the members it shares with
 * every record; use `isRecordType` to tell the two apart beforehand.
 */
export function validateRecord(value: unknown): Validation<OipRecord> {
  return answering(() => {
    const type = typeOf(value);
    if (!type.ok) return type;
    if (!isRecordType(type.value)) {
      return fail({
        path: "/type",
        message: `${quote(type.value)} is not a record type this revision defines; if an extension defines it, use validateExtensionRecord`,
        clause: "core 11",
      });
    }
    return validateRecordOfType(type.value, value);
  });
}

/**
 * Validates a record whose type this revision does not define, as an
 * extension may define one (core 7): only the members every record shares
 * are checked. Such a record can be stored and forwarded. Whether it may be
 * acted on depends on its `critical` list (core 8.3), which is the caller's
 * decision; a reader that does not understand a critical extension answers
 * `unsupported-critical` (core 10.2), not `invalid-record`.
 */
export function validateExtensionRecord(value: unknown): Validation<ExtensionRecord> {
  return answering(() => {
    const type = typeOf(value);
    if (!type.ok) return type;
    if (isRecordType(type.value)) {
      return fail({
        path: "/type",
        message: `${type.value} is a record type this revision defines; use validateRecord`,
        clause: "core 11",
      });
    }
    return validateWith<ExtensionRecord>("ExtensionRecord", "core 7", value, checkExtensionRules);
  });
}

/**
 * Validates one proof against core 5.2: exactly the members it allows. A
 * proof that fails never counts, but the record that carries it may still be
 * valid (core 5.5). The entries of `authority` are checked for shape only;
 * see `AuthorityItem`.
 */
export function validateProof(value: unknown): Validation<Proof> {
  return answering(() => validateWith<Proof>("Proof", "core 5.2", value, checkProofRules));
}
