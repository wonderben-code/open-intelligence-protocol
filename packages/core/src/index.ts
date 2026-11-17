// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `@oip/core`: the foundation every Open Intelligence Protocol record
 * stands on. The JSON profile and its parser (core Section 1), canonical form
 * (2), content IDs and key hashes (3), Multikey and strict Ed25519 (4),
 * `eddsa-jcs-2022` proofs (5), references (6), extensions (8), time values
 * (1.4, 1.5, 9.1) and problem types (10).
 *
 * The package is pure: it does no I/O and never reads the clock.
 *
 * @packageDocumentation
 */

export type { Issue, JsonValue, Validation } from "@oip/schema";
export {
  bytesEqual,
  bytesToHex,
  codePointLength,
  decodeUtf8,
  hexToBytes,
  isWellFormed,
  utf8,
} from "./bytes.ts";
export {
  contentId,
  contentIdOfDigest,
  digestOfContentId,
  documentHash,
  isContentId,
  type JsonObject,
  keyHash,
} from "./content-id.ts";
export { compareDecimals, isAmount, isDecimal, MAX_DECIMAL_LENGTH } from "./decimal.ts";
export {
  ed25519PublicKey,
  isEd25519PublicKey,
  ORDER_CHECK_CACHE_SIZE,
  PRIVATE_KEY_LENGTH,
  PUBLIC_KEY_LENGTH,
  SIGNATURE_LENGTH,
  signEd25519,
  verifyEd25519,
} from "./ed25519.ts";
export {
  errorFrom,
  MEDIA_TYPE,
  OipError,
  type OipErrorOptions,
  PROBLEM_CODES,
  PROBLEM_MEDIA_TYPE,
  type ProblemCode,
  problemCode,
  type ProblemDetails,
  problemDetails,
  PROBLEMS,
  problemType,
} from "./errors.ts";
export { isNamespace, understandsCritical, unsupportedCritical } from "./extensions.ts";
export { sha256, sha256Digest } from "./hash.ts";
export { canonicalBytes, canonicalize } from "./jcs.ts";
export { MAX_TEXT_LENGTH, parseJson, parseJsonBytes, type ParseOptions } from "./json.ts";
export {
  decodeEd25519Multikey,
  decodeX25519Multikey,
  encodeEd25519Multikey,
  encodeX25519Multikey,
  isEd25519Multikey,
  isX25519Multikey,
  type KeyType,
} from "./multikey.ts";
export {
  createProof,
  createProofSync,
  MAX_PROOFS,
  proofDigest,
  proofHashData,
  type ProofOptions,
  purposeFor,
  type Signer,
  type SyncSigner,
  type VerifiedProof,
  verifyProof,
  verifyProofs,
  withProofs,
} from "./proof.ts";
export {
  checkSize,
  MAX_RECORD_BYTES,
  MAX_SEALED_BYTES,
  MIN_ACCEPTED_RECORD_BYTES,
  parseRecord,
} from "./record.ts";
export {
  type ControlKeyRef,
  formatControlKeyRef,
  formatKeyRef,
  formatRecordRef,
  formatVersionId,
  isMindAddress,
  type KeyRef,
  mindAddress,
  mindId,
  parseControlKeyRef,
  parseKeyRef,
  parseRecordRef,
  parseVerificationMethod,
  parseVersionedMind,
  parseVersionId,
  type RecordRef,
  recordRefMatches,
  type VerificationMethod,
  type VersionedMind,
  type VersionId,
} from "./refs.ts";
export { signerFromPrivateKey } from "./signer.ts";
export {
  CLOCK_SKEW,
  formatTimestamp,
  type Instant,
  isDuration,
  isTimestamp,
  parseDuration,
  parseTimestamp,
} from "./time.ts";
