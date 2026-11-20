// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `@oip/conformance`: the golden test vectors, run against any implementation
 * through an adapter, and differential testing against the independent
 * Python checker.
 *
 * @packageDocumentation
 */

export {
  type Answer,
  type ChainReading,
  type ConformanceAdapter,
  type FeedReading,
  type LineageStatus,
  type LogIntake,
  METHOD_FOR_KIND,
  type NetworkAnswer,
  NOT_JUDGED,
  type ProofRequest,
  type Received,
  type VerifierView,
} from "./adapter.ts";
export { type Agreement, compareVerdicts, type Disagreement, type Judge } from "./differential.ts";
export {
  loadVectors,
  PythonJudge,
  type PythonJudgeOptions,
  pythonJudgeUnavailable,
  VECTORS_DIRECTORY,
  type Verdict,
} from "./node.ts";
export { referenceAdapter } from "./reference.ts";
export {
  type CaseResult,
  claimHolds,
  claimMustHold,
  type Outcome,
  POSITIVE_CHECKS,
  type PositiveCheck,
  runCase,
  runPositiveCheck,
  runVectors,
  tally,
  viewFor,
} from "./runner.ts";
export {
  type AckCase,
  type AssuranceCase,
  CASE_KINDS,
  type CaseBase,
  type CaseKind,
  type ChainCase,
  type CheckpointCase,
  type CountsForCase,
  type ExpectedStatus,
  type FeedCase,
  type HelloCase,
  type JsonCase,
  type JsonObject,
  type LocationCase,
  type Log,
  type LogCase,
  type LogCopy,
  namedLog,
  namedRecord,
  type NetworkCase,
  type ParticipantCase,
  parseVectors,
  positiveRecords,
  type ReceiveCase,
  type RecordCase,
  type Section,
  SECTIONS,
  type Seen,
  type SentForCase,
  type StatusCase,
  type TestKey,
  type VectorCase,
  type Vectors,
} from "./vectors.ts";
export {
  WireClient,
  type WireAnswer,
  type WireAsking,
  type WireFrame,
  type WireOptions,
  type WireRequest,
  type WireSocket,
  type WireStream,
  type WireStreamEvent,
} from "./wire/client.ts";
export { type Randomness, type SignedEvent, WireMind } from "./wire/minds.ts";
export {
  WIRE_PROFILES,
  type WireCheck,
  type WireOutcome,
  type WireProfile,
  type WireReport,
} from "./wire/report.ts";
export { resolverProfile } from "./wire/resolver.ts";
export { type HostOptions, hostProfile, type HostSetup, referenceHostSetup } from "./wire/host.ts";
