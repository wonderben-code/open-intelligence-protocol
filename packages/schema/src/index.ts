// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `@oip/schema`: JSON Schemas, TypeScript types and compiled validators for
 * every Open Intelligence Protocol record (core Section 11).
 *
 * @packageDocumentation
 */

export { type ContainerParts, containerParts } from "./containers.ts";
export { type Issue, quote, type Validation } from "./issue.ts";
export { MAX_SAFE_INTEGER, OIP_COMMANDS, patterns, SHORT_NAMESPACES } from "./primitives.ts";
export { type AuthorityItem, type Proof, PROOF_PURPOSES, type ProofPurpose } from "./proof.ts";
export type { Bundle, DuplicityEvidence, FeedPage, LogPage } from "./records/containers.ts";
export type { ExtensionRecord } from "./records/extension.ts";
export type {
  ComparisonOperator,
  Delegation,
  PolicyStatement,
  Revocation,
} from "./records/delegation.ts";
export type {
  AgreementKeyEntry,
  Controller,
  Fork,
  Genesis,
  IdentityEvent,
  KeyController,
  MemberController,
  Retire,
  RevokedKey,
  SigningKeyEntry,
  Update,
} from "./records/identity.ts";
export type {
  Ack,
  Branch,
  Capability,
  Checkpoint,
  Content,
  Endpoint,
  Entry,
  Forwarded,
  Hello,
  InlineContent,
  Lineage,
  Location,
  MultipartContent,
  Packet,
  PacketTo,
  Participant,
  QueryResult,
  ReferencedContent,
  Resume,
  Sealed,
  Session,
  Verb,
} from "./records/net.ts";
export type {
  Audience,
  CapabilityQuery,
  Collective,
  Commitment,
  Evidence,
  Intent,
  Offer,
  OfferTerms,
  Party,
  Power,
  Receipt,
} from "./records/web.ts";
export {
  CONTAINER_RECORD_TYPES,
  IDENTITY_EVENT_TYPES,
  isRecordType,
  type OipRecord,
  RECORD_TYPES,
  type RecordOf,
  type RecordType,
  type RecordTypes,
  RESERVED_RECORD_TYPES,
  SIGNED_RECORD_TYPES,
  UNSIGNED_RECORD_TYPES,
} from "./registry.ts";
export { MAX_POLICY_DEPTH } from "./rules.ts";
export { type JsonSchema, jsonSchemas, SCHEMA_DIALECT } from "./json-schemas.ts";
export { parseSelector, type SelectorStep } from "./selector.ts";
export { type TextFault, textFault } from "./text.ts";
export {
  IMPLEMENTATION_LIMIT,
  type JsonValue,
  MAX_CONTAINER_DEPTH,
  MAX_DEPTH,
  MAX_ISSUES,
  MAX_VALUES,
  validateExtensionRecord,
  validateJson,
  validateProof,
  validateRecord,
  validateRecordOfType,
} from "./validate.ts";
