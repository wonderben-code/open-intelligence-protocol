// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Problem types (core 10.2) and the one exception this implementation throws
 * (ADR-0004). Judging input returns a result; `OipError` is for the caller
 * or the environment being at fault.
 */

import type { Issue } from "@oip/schema";

/** core 10.1: the media type of OIP records. */
export const MEDIA_TYPE = "application/oip+json";

/** RFC 9457: the media type of problem details. */
export const PROBLEM_MEDIA_TYPE = "application/problem+json";

/** core 10.2: every problem code, with its HTTP status and its meaning. */
export const PROBLEMS = {
  "invalid-record": { status: 400, title: "Not a well-formed record of the expected type" },
  "invalid-proof": { status: 400, title: "A required proof is missing or does not verify" },
  "unsupported-critical": {
    status: 400,
    title: "The record lists a critical extension the server does not understand",
  },
  expired: { status: 400, title: "The record has expired or is too old" },
  "stale-version": {
    status: 409,
    title:
      "The record pins an identity version the server cannot reach or that has been superseded where the latest is required",
  },
  duplicity: { status: 409, title: "The mind's identity log is duplicitous" },
  unauthorised: { status: 401, title: "Authentication is missing or invalid" },
  forbidden: { status: 403, title: "Authenticated, but not permitted" },
  "not-found": { status: 404, title: "Unknown mind or record" },
  "too-large": { status: 413, title: "The record exceeds a size limit" },
  "rate-limited": { status: 429, title: "Too many requests" },
} as const;

/** One of the codes of core 10.2. */
export type ProblemCode = keyof typeof PROBLEMS;

/** The codes of core 10.2, in the specification's order. */
export const PROBLEM_CODES = Object.keys(PROBLEMS) as readonly ProblemCode[];

const TYPE_PREFIX = "urn:oip:error:";

/** The `type` of a problem: `urn:oip:error:<code>`. */
export function problemType(code: ProblemCode): string {
  return TYPE_PREFIX + code;
}

/** The code a problem `type` names, or `undefined` if it is not one of core 10.2. */
export function problemCode(type: unknown): ProblemCode | undefined {
  if (typeof type !== "string" || !type.startsWith(TYPE_PREFIX)) return undefined;
  const code = type.slice(TYPE_PREFIX.length);
  return Object.hasOwn(PROBLEMS, code) ? (code as ProblemCode) : undefined;
}

/** RFC 9457 problem details, as an OIP service returns them. */
export interface ProblemDetails {
  readonly type: string;
  readonly title: string;
  readonly status: number;
  readonly detail?: string;
  /** The reasons, when the problem is a rejected record or proof. An extension member (RFC 9457, 3.2). */
  readonly issues?: readonly Issue[];
}

/** Builds the problem details for a code. */
export function problemDetails(
  code: ProblemCode,
  detail?: string,
  issues?: readonly Issue[],
): ProblemDetails {
  const { status, title } = PROBLEMS[code];
  return {
    type: problemType(code),
    title,
    status,
    ...(detail === undefined ? {} : { detail }),
    ...(issues === undefined || issues.length === 0 ? {} : { issues }),
  };
}

/** What an `OipError` carries besides its code and detail. */
export interface OipErrorOptions {
  /** The clause enforced, when there is one. */
  readonly clause?: string;
  /** The reasons, when a rejected record or proof is behind the error. */
  readonly issues?: readonly Issue[];
  /** The error that caused this one. It is never copied into `detail`. */
  readonly cause?: unknown;
}

/**
 * The error this implementation throws when the caller or the environment is
 * at fault. It never contains key material: functions that hold secrets build
 * their messages from constants.
 */
export class OipError extends Error {
  override readonly name = "OipError";
  /** One of the codes of core 10.2. */
  readonly code: ProblemCode;
  /** For a person: what went wrong and what to do. */
  readonly detail: string;
  /** The clause enforced, when there is one. */
  readonly clause: string | undefined;
  /** The reasons, when a rejected record or proof is behind the error. */
  readonly issues: readonly Issue[];

  constructor(code: ProblemCode, detail: string, options: OipErrorOptions = {}) {
    super(detail, options.cause === undefined ? undefined : { cause: options.cause });
    this.code = code;
    this.detail = detail;
    this.clause = options.clause;
    this.issues = options.issues ?? [];
  }

  /** The problem details an HTTP service returns for this error. */
  toProblem(): ProblemDetails {
    return problemDetails(this.code, this.detail, this.issues);
  }
}

/**
 * Turns a rejection into an `OipError`, for callers who prefer to throw. The
 * first issue gives the detail and the clause; all of them are kept.
 */
export function errorFrom(
  rejection: { readonly issues: readonly [Issue, ...Issue[]] },
  code: ProblemCode = "invalid-record",
): OipError {
  const [first] = rejection.issues;
  const where = first.path === "" ? "" : `${first.path}: `;
  return new OipError(code, `${where}${first.message}`, {
    clause: first.clause,
    issues: rejection.issues,
  });
}
