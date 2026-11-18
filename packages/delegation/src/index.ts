// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Delegation for the Open Intelligence Protocol (Layer 1, Section 11): what
 * one mind lets another sign for it, and whether a proof that says it acts
 * for another does.
 *
 * @packageDocumentation
 */

export {
  type DelegatedOptions,
  delegatedProofTime,
  delegatedTime,
  type DelegationContext,
  MAX_CHAIN,
} from "./chain.ts";
export {
  covers,
  DELEGABLE_TYPES,
  type DelegableType,
  isCommand,
  isDelegableCommand,
  isDelegableType,
  SEND_COMMAND,
  signCommand,
} from "./command.ts";
export { evaluatePolicy, MAX_POLICY_STEPS, policyHolds, select } from "./policy.ts";
export { RecordSet, type RecordView } from "./records.ts";
export { revokedTime } from "./revocation.ts";
