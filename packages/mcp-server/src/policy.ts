// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What the assistant may sign without asking.
 *
 * A Commitment binds the mind, so the person the mind belongs to is asked
 * before one is signed (Layer 0, 2.2). They may say beforehand what need
 * not be asked about: a policy, in the language a delegation limits a
 * delegate with (Layer 1, 11.3). A Commitment for which every statement
 * holds is signed without a question. Any other is asked about.
 *
 * The policy is a file in the mind's directory, `policy.json`, written by
 * the person and never by this server:
 *
 * ```json
 * { "commit": [["==", ".terms.price.currency", "USD"], ["<=", ".terms.price.amount", "50"]] }
 * ```
 *
 * A statement that selects what a Commitment does not have does not hold:
 * with the policy above, a Commitment that names no price is asked about.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { type JsonObject, type JsonValue, parseJsonBytes } from "@oip/core";
import { checkPolicy, evaluatePolicy } from "@oip/delegation";
import { UsageError } from "@oip/local";

/** The name of the file, in the mind's directory. */
export const POLICY_FILE = "policy.json";

/** What a mind's directory says may be signed without asking. */
export interface Policy {
  /** The statements a Commitment must meet to be signed unasked. Absent: every one is asked about. */
  readonly commit?: readonly JsonValue[];
}

/**
 * Reads the policy of a mind's directory.
 *
 * @returns The policy, which permits nothing where there is no file.
 * @throws UsageError if the file is there and is no policy. A server that
 *   cannot read what it was told does not guess: it does not start.
 */
export function readPolicy(dir: string): Policy {
  const file = join(dir, POLICY_FILE);
  let bytes: Uint8Array;
  try {
    bytes = readFileSync(file);
  } catch {
    return {};
  }
  const parsed = parseJsonBytes(bytes);
  const value = parsed.ok ? parsed.value : undefined;
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new UsageError(`${file} is no policy: it holds a JSON object, as { "commit": [ … ] }`);
  }
  const { commit, ...others } = value as JsonObject;
  const unknown = Object.keys(others);
  if (unknown.length > 0) {
    throw new UsageError(
      `${file} says something of ${unknown.join(", ")}: a policy has \`commit\` alone`,
    );
  }
  if (commit === undefined) return {};
  if (!Array.isArray(commit) || commit.length === 0) {
    // No statement holds for every record: that would let any Commitment be signed unasked.
    throw new UsageError(
      `${file} has no statement under \`commit\`: say what may be signed unasked, or remove the file`,
    );
  }
  // A policy that is none would hold for nothing, silently. It is said now, and not found out later.
  const checked = checkPolicy(commit);
  if (!checked.ok) {
    const [{ message, clause, path }] = checked.issues;
    throw new UsageError(
      `${file} is no policy: ${message}, at ${path === "" ? "its top" : path} (${clause})`,
    );
  }
  return { commit };
}

/**
 * Whether a record may be signed without asking: there is a policy for it,
 * and every statement of the policy holds for the record.
 */
export function permits(policy: Policy, record: JsonValue): boolean {
  return policy.commit !== undefined && evaluatePolicy(policy.commit, record).ok;
}
