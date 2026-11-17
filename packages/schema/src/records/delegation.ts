// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Delegation, policies and revocation (Layer 1, Section 11). */

import { type Static, Type } from "typebox";

import { signedRecord } from "../common.ts";
import { meta, ref } from "../naming.ts";
import { MindAddress, Nonce, OIP_COMMANDS, patterns, RecordRef, Timestamp } from "../primitives.ts";

/** A comparison operator of the policy language (Layer 1, 11.3). */
export type ComparisonOperator = "==" | "!=" | "<" | "<=" | ">" | ">=";

/** A policy statement (Layer 1, 11.3). */
export type PolicyStatement =
  | readonly [op: ComparisonOperator, selector: string, value: unknown]
  | readonly [op: "not", statement: PolicyStatement]
  | readonly [op: "and" | "or", statements: readonly PolicyStatement[]]
  | readonly [op: "all" | "any", selector: string, statement: PolicyStatement];

const statement = { $ref: "#/$defs/statement" };
const selector = { $ref: "#/$defs/selector" };
const tuple = (...prefixItems: unknown[]) => ({
  type: "array",
  prefixItems,
  items: false,
  minItems: prefixItems.length,
  maxItems: prefixItems.length,
});

/**
 * Layer 1, 11.3. The schema fixes the shape of each statement. The selector
 * grammar and the nesting limit are rules (`rules.ts`), because JSON Schema
 * cannot bound recursion.
 */
export const Policy = Type.Unsafe<readonly PolicyStatement[]>({
  ...meta(
    "Policy",
    "A policy: at most 64 statements, all of which must hold for the record being authorised (Layer 1, 11.3).",
  ),
  type: "array",
  maxItems: 64,
  items: statement,
  $defs: {
    selector: { type: "string", minLength: 1 },
    statement: {
      anyOf: [
        tuple({ enum: ["==", "!=", "<", "<=", ">", ">="] }, selector, true),
        tuple({ const: "not" }, statement),
        tuple(
          { enum: ["and", "or"] },
          { type: "array", minItems: 1, maxItems: 64, items: statement },
        ),
        tuple({ enum: ["all", "any"] }, selector, statement),
      ],
    },
  },
});

/** Layer 1, 11.2: the syntax of a command. Reserved commands are still commands. */
export const Command = Type.String({ pattern: patterns.command });

/**
 * Layer 1, 11.2: a command a delegation may carry. Under `/oip` only the five
 * listed commands exist; every other `/oip` command is reserved, and a
 * delegation that uses one is invalid.
 */
export const DelegableCommand = Type.Unsafe<string>({
  type: "string",
  pattern: patterns.command,
  anyOf: [{ enum: [...OIP_COMMANDS] }, { not: { pattern: patterns.oipCommandSpace } }],
});

export const Delegation = Type.Object(
  {
    ...signedRecord,
    type: Type.Literal("Delegation"),
    author: MindAddress,
    delegate: MindAddress,
    subject: MindAddress,
    command: DelegableCommand,
    policy: Type.Optional(ref(Policy)),
    notBefore: Type.Optional(Timestamp),
    expires: Timestamp,
    nonce: Nonce,
  },
  meta(
    "Delegation",
    "Grants a delegate the authority to act for a subject, within a command and a policy (Layer 1, 11.1).",
  ),
);
export type Delegation = Static<typeof Delegation>;

export const Revocation = Type.Object(
  {
    ...signedRecord,
    type: Type.Literal("Revocation"),
    author: MindAddress,
    revokes: RecordRef,
  },
  meta(
    "Revocation",
    "Revokes a delegation from the revocation's own evaluation time (Layer 1, 11.5).",
  ),
);
export type Revocation = Static<typeof Revocation>;
