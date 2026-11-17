// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `@oip/identity`: identity logs and their verification (Layer 1, Sections 3
 * and 4), identity state and DID documents (Section 5), key validity
 * (Section 6), duplicity (Section 7), lineage (Section 8), collectives
 * (Section 9), and the evidence of time all of them are judged on (core
 * Section 9).
 *
 * The package does no I/O and never reads the clock: the logs, the evidence
 * and every time are parameters.
 *
 * @packageDocumentation
 */

export {
  type Divergence,
  divergence,
  type IdentityView,
  LogBook,
  type LogBookOptions,
} from "./book.ts";
export {
  draftFork,
  draftGenesis,
  draftRetire,
  draftUpdate,
  type EventSigner,
  type ForkFields,
  type GenesisFields,
  type LogHead,
  type RetireFields,
  signEvent,
  signEventSync,
  type Unsigned,
  type UpdateFields,
} from "./create.ts";
export {
  type DidDocument,
  didDocument,
  type DidDocumentMetadata,
  type DidDocumentOptions,
  type DidResolution,
  type DidService,
  type DidVerificationMethod,
} from "./did.ts";
export {
  earliestEvidence,
  type Evaluation,
  eventTime,
  type EvidenceView,
  FirstSeen,
  proofTime,
} from "./evidence.ts";
export { type Lineage, lineage } from "./lineage.ts";
export {
  type LogContext,
  MAX_HEIGHT,
  MAX_LOG_EVENTS,
  MIN_ACCEPTED_LOG_EVENTS,
  verifyLog,
} from "./log.ts";
export {
  collectiveSignedTime,
  type CountedProof,
  CURRENT_STATE_TYPES,
  type JudgedRecord,
  judgeRecord,
  operationalProofs,
  operationalProofTime,
  ownSignedTime,
} from "./signing.ts";
export {
  type AcknowledgedChild,
  childrenAt,
  compromisedSince,
  type ControllerState,
  entryAt,
  type IdentityState,
  latestState,
  type LogEntry,
  type Parent,
  removalTime,
  type Revocation,
  revokedAt,
  stateAt,
  type VerifiedLog,
} from "./state.ts";
