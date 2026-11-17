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

function fail<T>(first: Issue, ...rest: Issue[]): Validation<T> {
  return { ok: false, issues: [first, ...rest] };
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
  message: "the record contains a string with an unpaired surrogate, which is not valid Unicode",
  clause: "core 1.1",
};

/**
 * Checks what holds for every value in a record, whatever its type: strings
 * and member names are valid Unicode (core 1.1), numbers are safe integers
 * (core 1.2), and nesting is no deeper than `MAX_DEPTH`. It does not
 * recurse, so no input can exhaust the stack.
 */
function checkValues(root: unknown): Issue | undefined {
  const pending: { value: unknown; depth: number }[] = [{ value: root, depth: 0 }];
  for (let next = pending.pop(); next !== undefined; next = pending.pop()) {
    const { value, depth } = next;
    if (typeof value === "string") {
      if (!isWellFormed(value)) return UNPAIRED;
    } else if (typeof value === "number") {
      if (!Number.isSafeInteger(value)) {
        return {
          path: "",
          message: `the record contains the number ${value}, which is not an integer between -(2^53-1) and 2^53-1; write decimal quantities as strings`,
          clause: "core 1.2",
        };
      }
    } else if (typeof value === "object" && value !== null) {
      if (depth >= MAX_DEPTH) {
        return {
          path: "",
          message: `the record nests arrays and objects more than ${MAX_DEPTH} deep`,
          clause: IMPLEMENTATION_LIMIT,
        };
      }
      if (!Array.isArray(value)) {
        for (const name of Object.keys(value)) {
          if (!isWellFormed(name)) return UNPAIRED;
        }
      }
      const children: unknown[] = Array.isArray(value) ? value : Object.values(value);
      for (const child of children) {
        if (child !== null && typeof child !== "boolean") {
          pending.push({ value: child, depth: depth + 1 });
        }
      }
    }
  }
  return undefined;
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
function clauseOf(error: ValidatorError, defining: string): string {
  const pattern = error.keyword === "pattern" ? error.params?.["pattern"] : undefined;
  if (typeof pattern === "string") {
    const clause = PATTERN_CLAUSE.get(pattern);
    if (clause !== undefined) return clause;
  }
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
      clause: clauseOf(error, defining),
    }));
  // The deepest value at fault first: it is the most specific thing to fix.
  return issues.sort((a, b) => depthOf(b.path) - depthOf(a.path));
}

function runValidator(name: string, value: unknown): boolean {
  const validator = validators[name];
  if (validator === undefined) throw new Error(`no compiled validator for ${name}`);
  return validator(value);
}

function validateWith<T>(
  name: string,
  defining: string,
  value: unknown,
  rules: (valid: T) => Issue[],
): Validation<T> {
  const unsafe = checkValues(value);
  if (unsafe !== undefined) return fail(unsafe);
  if (!runValidator(name, value)) {
    const [first, ...rest] = schemaIssues(name, defining);
    return fail(
      first ?? { path: "", message: `not a well-formed ${name}`, clause: defining },
      ...rest,
    );
  }
  const valid = value as T;
  const [first, ...rest] = rules(valid);
  return first === undefined ? { ok: true, value: valid } : fail(first, ...rest);
}

/**
 * Validates a record of a known type against its schema and the structural
 * rules. Use `validateRecord` when the type is not known in advance.
 */
export function validateRecordOfType<K extends RecordType>(
  type: K,
  value: unknown,
): Validation<RecordOf<K>> {
  return validateWith<RecordOf<K>>(type, DEFINING_CLAUSE[type], value, (record) =>
    checkRecordRules(record),
  );
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
}

/**
 * Validates one proof against core 5.2: exactly the members it allows. A
 * proof that fails never counts, but the record that carries it may still be
 * valid (core 5.5). The entries of `authority` are checked for shape only;
 * see `AuthorityItem`.
 */
export function validateProof(value: unknown): Validation<Proof> {
  return validateWith<Proof>("Proof", "core 5.2", value, checkProofRules);
}
