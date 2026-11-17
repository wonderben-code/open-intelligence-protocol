// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Validation: the first step of "validate, verify, then use". A value that
 * passes is a well-formed record of its type. Nothing here checks a signature,
 * an identity log or the time; a validated record is not yet a verified one.
 */

import { validators } from "./generated/validators.ts";
import type { Issue, Validation } from "./issue.ts";
import type { Proof } from "./proof.ts";
import {
  DEFINING_CLAUSE,
  isRecordType,
  type OipRecord,
  type RecordOf,
  type RecordType,
  RESERVED_RECORD_TYPES,
} from "./registry.ts";
import { checkProofRules, checkRecordRules } from "./rules.ts";

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

/**
 * Checks what holds for every value in a record, whatever its type: nesting
 * no deeper than `MAX_DEPTH`, and no number other than a safe integer
 * (core 1.2). It does not recurse, so no input can exhaust the stack.
 */
function checkValues(root: unknown): Issue | undefined {
  const pending: { value: unknown; depth: number }[] = [{ value: root, depth: 0 }];
  for (let next = pending.pop(); next !== undefined; next = pending.pop()) {
    const { value, depth } = next;
    if (typeof value === "number") {
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
      const children: unknown[] = Array.isArray(value) ? value : Object.values(value);
      for (const child of children) {
        if (typeof child === "number" || (typeof child === "object" && child !== null)) {
          pending.push({ value: child, depth: depth + 1 });
        }
      }
    }
  }
  return undefined;
}

function schemaIssues(name: RecordType | "Proof", clause: string): Issue[] {
  const errors = validators[name]?.errors ?? [];
  return errors.map((error) => ({
    path: error.instancePath,
    message: error.message ?? `does not match the ${name} schema`,
    clause,
  }));
}

function runValidator(name: RecordType | "Proof", value: unknown): boolean {
  const validator = validators[name];
  if (validator === undefined) throw new Error(`no compiled validator for ${name}`);
  return validator(value);
}

/**
 * Validates a record of a known type against its schema and the structural
 * rules. Use `validateRecord` when the type is not known in advance.
 */
export function validateRecordOfType<K extends RecordType>(
  type: K,
  value: unknown,
): Validation<RecordOf<K>> {
  const unsafe = checkValues(value);
  if (unsafe !== undefined) return fail(unsafe);
  if (!runValidator(type, value)) {
    const [first, ...rest] = schemaIssues(type, DEFINING_CLAUSE[type]);
    return fail(
      first ?? { path: "", message: `not a well-formed ${type}`, clause: DEFINING_CLAUSE[type] },
      ...rest,
    );
  }
  const record = value as RecordOf<K>;
  const [first, ...rest] = checkRecordRules(record as OipRecord);
  return first === undefined ? { ok: true, value: record } : fail(first, ...rest);
}

/**
 * Validates any record: `oip` is `"1"` (core Section 7), `type` names a
 * record type this revision defines, and the record matches that type's
 * schema and structural rules.
 */
export function validateRecord(value: unknown): Validation<OipRecord> {
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
  if (!isRecordType(type)) {
    return fail({
      path: "/type",
      message: `"${type}" is not a record type this revision defines`,
      clause: "core 11",
    });
  }
  return validateRecordOfType(type, value);
}

/**
 * Validates one proof against core 5.2: exactly the members it allows, and a
 * well-formed chain or charter in `authority`. A proof that fails never
 * counts, but the record that carries it may still be valid (core 5.5).
 */
export function validateProof(value: unknown): Validation<Proof> {
  const unsafe = checkValues(value);
  if (unsafe !== undefined) return fail(unsafe);
  if (!runValidator("Proof", value)) {
    const [first, ...rest] = schemaIssues("Proof", "core 5.2");
    return fail(first ?? { path: "", message: "not a well-formed proof", clause: "core 5.2" }, ...rest);
  }
  const proof = value as Proof;
  const [first, ...rest] = checkProofRules(proof);
  return first === undefined ? { ok: true, value: proof } : fail(first, ...rest);
}
