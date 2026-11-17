// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Validation: the first step of "validate, verify, then use". A value that
 * passes is a well-formed record of its type. Nothing here checks a signature,
 * an identity log or the time; a validated record is not yet a verified one.
 */

import { type ValidatorError, validators } from "./generated/validators.ts";
import { containerParts, depthOf } from "./containers.ts";
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
import { type TextFault, textFault } from "./text.ts";

/**
 * core 1.9: the deepest nesting of arrays and objects in a record. The record
 * itself is at depth 1. It is far above anything the defined record types
 * need, and it keeps recursive code safe from hostile input.
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
 * of it, so no record within that limit has more than half this number. It
 * bounds the work and the memory spent on a value before its size is known:
 * a text of nothing but brackets, an array with millions of holes, a
 * structure that shares its parts.
 */
export const MAX_VALUES = 1_048_576;

/**
 * A path as an issue carries it. Its member names come from the input, and
 * issues are logged and shown: control characters and line separators are
 * written as escapes, so that a name cannot forge a line of a log, and a long
 * path is cut between characters, never inside one.
 */
function safePath(path: string): string {
  let safe = "";
  let count = 0;
  for (const character of path) {
    if (++count === MAX_PATH) return `${safe}…`;
    const code = character.codePointAt(0) ?? 0;
    const unsafe =
      code < 0x20 || (code >= 0x7f && code <= 0x9f) || code === 0x2028 || code === 0x2029;
    safe += unsafe ? `\\u${code.toString(16).padStart(4, "0")}` : character;
    // An input cannot make this loop long: stop well before the end of a huge path.
    if (safe.length > 6 * MAX_PATH) return `${safe.slice(0, MAX_PATH)}…`;
  }
  return safe;
}

function reject<T>(issues: readonly Issue[], fallback: Issue): Validation<T> {
  const [first = fallback, ...rest] = issues
    .slice(0, MAX_ISSUES)
    .map((issue) => ({ ...issue, path: safePath(issue.path) }));
  return { ok: false, issues: [first, ...rest] };
}

function fail<T>(issue: Issue): Validation<T> {
  return reject([], issue);
}

const TEXT_FAULTS: Readonly<Record<TextFault, Issue>> = {
  "unpaired surrogate": {
    path: "",
    message: "a string has an unpaired surrogate, which is not valid Unicode",
    clause: "core 1.1",
  },
  noncharacter: {
    path: "",
    message:
      "a string has a noncharacter (U+FDD0 to U+FDEF, or a code point ending FFFE or FFFF), which a record may not contain",
    clause: "core 1.1",
  },
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
  clause: "core 1.9",
};

const TOO_MANY: Issue = {
  path: "",
  message: `there are more than ${MAX_VALUES} values here, the most this implementation reads in one record or container`,
  clause: IMPLEMENTATION_LIMIT,
};

/**
 * core 1.9: the deepest a container nests as a whole. A container carries a
 * record three levels down at most (an event in a pair in `pairs`), and that
 * record may itself nest as deep as `MAX_DEPTH`.
 */
export const MAX_CONTAINER_DEPTH = MAX_DEPTH + 3;

type Container = unknown[] | Record<string, unknown>;

/** Adds a member to a copy. Assigning to "__proto__" would set the prototype instead. */
function put(target: Record<string, unknown>, name: string, value: unknown): void {
  Object.defineProperty(target, name, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

/**
 * Checks what holds for every value in a record, whatever its type, and
 * returns a plain copy of the value:
 *
 *   - it is plain JSON data: objects, arrays, strings, booleans, null and
 *     numbers, with no holes, accessors, hidden members or other prototypes
 *     (core 1.2);
 *   - strings and member names are valid Unicode (core 1.1);
 *   - numbers are safe integers (core 1.2);
 *   - nesting is no deeper than `MAX_DEPTH` (core 1.9), and there are no
 *     more than `MAX_VALUES` values.
 *
 * Everything after this check works on the copy, never on the value it was
 * given. A value parsed from JSON text is plain already; one built by other
 * code may be anything: an accessor that answers differently each time, a
 * proxy, an array with a `toJSON`. Whatever was read here, once, is what is
 * then validated, hashed, signed and returned.
 *
 * It reads every member through its descriptor, so no accessor is called,
 * and it does not recurse, so no input can exhaust the stack.
 */
function plainCopy(
  root: unknown,
  maxDepth: number,
): { readonly issue: Issue } | { readonly value: JsonValue; readonly deepest: number } {
  let budget = MAX_VALUES;
  let deepest = 0;
  const pending: { source: object; target: Container; depth: number }[] = [];

  /** The copy of a value that is not a container; for a container, an empty copy to be filled. */
  const start = (value: unknown, depth: number): { issue: Issue } | { value: unknown } => {
    switch (typeof value) {
      case "boolean":
        return { value };
      case "string": {
        const fault = textFault(value);
        return fault === undefined ? { value } : { issue: TEXT_FAULTS[fault] };
      }
      case "number":
        if (Number.isSafeInteger(value)) return { value };
        return {
          issue: {
            path: "",
            message: `the number ${value} is not an integer between -(2^53-1) and 2^53-1; write decimal quantities as strings`,
            clause: "core 1.2",
          },
        };
      case "object": {
        if (value === null) return { value };
        if (depth > maxDepth) return { issue: TOO_DEEP };
        if (depth > deepest) deepest = depth;
        const target: Container = Array.isArray(value) ? [] : {};
        pending.push({ source: value, target, depth });
        return { value: target };
      }
      default:
        // undefined, bigint, symbol, function.
        return { issue: NOT_JSON };
    }
  };

  const top = start(root, 1);
  if ("issue" in top) return top;
  for (let next = pending.pop(); next !== undefined; next = pending.pop()) {
    const { source, target, depth } = next;
    if (Array.isArray(target)) {
      // A plain array has its elements and its length and nothing else: no
      // other prototype and no member such as `toJSON`.
      if (Object.getPrototypeOf(source) !== Array.prototype) return { issue: NOT_JSON };
      const length = (source as unknown[]).length;
      if (length > budget) return { issue: TOO_MANY };
      budget -= length;
      // Its own members are its elements and its length: a hole leaves one out, and
      // anything else, such as a `toJSON`, adds one.
      if (Object.getOwnPropertyNames(source).length !== length + 1) return { issue: NOT_JSON };
      for (let i = 0; i < length; i++) {
        // A hole has no descriptor, and an accessor has no value.
        const element = Object.getOwnPropertyDescriptor(source, i);
        if (element === undefined || !element.enumerable || !("value" in element)) {
          return { issue: NOT_JSON };
        }
        const copied = start(element.value, depth + 1);
        if ("issue" in copied) return copied;
        target.push(copied.value);
      }
      continue;
    }
    const prototype: unknown = Object.getPrototypeOf(source);
    if (prototype !== Object.prototype && prototype !== null) return { issue: NOT_JSON };
    if (Object.getOwnPropertySymbols(source).length > 0) return { issue: NOT_JSON };
    const names = Object.getOwnPropertyNames(source);
    if (names.length > budget) return { issue: TOO_MANY };
    budget -= names.length;
    for (const name of names) {
      const fault = textFault(name);
      if (fault !== undefined) return { issue: TEXT_FAULTS[fault] };
      const member = Object.getOwnPropertyDescriptor(source, name);
      if (member === undefined || !member.enumerable || !("value" in member)) {
        return { issue: NOT_JSON };
      }
      const copied = start(member.value, depth + 1);
      if ("issue" in copied) return copied;
      put(target, name, copied.value);
    }
  }
  return { value: top.value as JsonValue, deepest };
}

/**
 * core 1.9, for a record that has passed its schema and nests deeper than
 * the limit somewhere. A container may: the limit applies to each record it
 * carries, counted from that record, and to the container without them.
 */
function depthIssues(record: OipRecord | ExtensionRecord): Issue[] {
  const parts = isRecordType(record.type) ? containerParts(record as OipRecord) : undefined;
  if (parts === undefined) return [TOO_DEEP];
  const tooDeep = parts.carried
    .filter(([, carried]) => depthOf(carried) > MAX_DEPTH)
    .map(([path]) => ({ ...TOO_DEEP, path }));
  return depthOf(parts.rest) > MAX_DEPTH ? [TOO_DEEP, ...tooDeep] : tooDeep;
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
  // The common member the error is in or under: "/ext/com.example/v" is about "/ext".
  const member = `/${error.instancePath.split("/")[1] ?? ""}`;
  return Object.hasOwn(COMMON_MEMBER_CLAUSE, member)
    ? (COMMON_MEMBER_CLAUSE[member] ?? defining)
    : defining;
}

const pathDepth = (path: string) => path.split("/").length;

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
  return issues.sort((a, b) => pathDepth(b.path) - pathDepth(a.path));
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

/** Validates a plain copy against a schema and its rules. */
function validatePlain<T>(
  name: string,
  defining: string,
  plain: JsonValue,
  rules: (valid: T) => Issue[],
): Validation<T> {
  const validator = validators[name];
  if (validator === undefined) throw new Error(`no compiled validator for ${name}`);
  if (!validator(plain)) {
    return reject(schemaIssues(name, defining), {
      path: "",
      message: `not a well-formed ${name}`,
      clause: defining,
    });
  }
  const valid = plain as T;
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
 *
 * With `"container"` the value may nest as deep as a container does
 * (`MAX_CONTAINER_DEPTH`). That is for a value which may be a container and
 * is only to be serialised or hashed: whether each record in it keeps the
 * limit is `validateRecord`'s question.
 *
 * The value it returns is a plain copy of the one it was given, as every
 * validator's is. Use the copy: the original may be an object that answers
 * differently the next time it is read.
 */
export function validateJson(
  value: unknown,
  depth: "record" | "container" = "record",
): Validation<JsonValue> {
  return answering(() => {
    const copied = plainCopy(value, depth === "container" ? MAX_CONTAINER_DEPTH : MAX_DEPTH);
    return "issue" in copied ? fail(copied.issue) : { ok: true, value: copied.value };
  });
}

/**
 * Copies a value that should be a record. It may nest a little deeper than
 * the limit, as a container does; `validateRecordCopy` then applies core 1.9
 * exactly.
 */
function recordCopy(value: unknown) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return { issue: { path: "", message: "a record is a JSON object", clause: "core 1.1" } };
  }
  return plainCopy(value, MAX_CONTAINER_DEPTH);
}

/** Applies a schema and its rules to a copy, and then the depth limit of core 1.9. */
function validateRecordCopy<T extends OipRecord | ExtensionRecord>(
  name: string,
  defining: string,
  copied: { readonly value: JsonValue; readonly deepest: number },
  rules: (valid: T) => Issue[],
): Validation<T> {
  const validated = validatePlain<T>(name, defining, copied.value, rules);
  if (!validated.ok || copied.deepest <= MAX_DEPTH) return validated;
  const tooDeep = depthIssues(validated.value);
  return tooDeep.length === 0 ? validated : reject(tooDeep, TOO_DEEP);
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
    const copied = recordCopy(value);
    if ("issue" in copied) return fail(copied.issue);
    return validateKnown(type, copied);
  });
}

function validateKnown<K extends RecordType>(
  type: K,
  copied: { readonly value: JsonValue; readonly deepest: number },
): Validation<RecordOf<K>> {
  return validateRecordCopy<RecordOf<K>>(type, DEFINING_CLAUSE[type], copied, (record) =>
    checkRecordRules(record),
  );
}

/** The type a plain copy names, if it is a record at all. */
function typeOf(value: JsonValue): Validation<string> {
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
    const copied = recordCopy(value);
    if ("issue" in copied) return fail(copied.issue);
    const type = typeOf(copied.value);
    if (!type.ok) return type;
    if (!isRecordType(type.value)) {
      return fail({
        path: "/type",
        message: `${quote(type.value)} is not a record type this revision defines; if an extension defines it, use validateExtensionRecord`,
        clause: "core 11",
      });
    }
    return validateKnown(type.value, copied);
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
    const copied = recordCopy(value);
    if ("issue" in copied) return fail(copied.issue);
    const type = typeOf(copied.value);
    if (!type.ok) return type;
    if (isRecordType(type.value)) {
      return fail({
        path: "/type",
        message: `${type.value} is a record type this revision defines; use validateRecord`,
        clause: "core 11",
      });
    }
    return validateRecordCopy<ExtensionRecord>(
      "ExtensionRecord",
      "core 7",
      copied,
      checkExtensionRules,
    );
  });
}

/**
 * Validates one proof against core 5.2: exactly the members it allows. A
 * proof that fails never counts, but the record that carries it may still be
 * valid (core 5.5). The entries of `authority` are checked for shape only;
 * see `AuthorityItem`.
 */
export function validateProof(value: unknown): Validation<Proof> {
  return answering(() => {
    // A proof stands at depth 3 of its record: the record, its proof array, the proof.
    const copied = plainCopy(value, MAX_DEPTH - 2);
    if ("issue" in copied) return fail(copied.issue);
    return validatePlain<Proof>("Proof", "core 5.2", copied.value, checkProofRules);
  });
}
