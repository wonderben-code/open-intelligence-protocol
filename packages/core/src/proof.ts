// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Data Integrity proofs with the `eddsa-jcs-2022` cryptosuite (core
 * Section 5), and proof digests (core 9.4).
 *
 * Verifying a proof here answers one question: is this a well-formed proof
 * on this record, with a valid signature by the key its verification method
 * names? Whether that key may sign for anyone, and from when, is decided by
 * the packages above this one, from identity logs and evidence.
 */

import {
  type AuthorityItem,
  type Issue,
  type JsonValue,
  type Proof,
  type ProofPurpose,
  UNSIGNED_RECORD_TYPES,
  type Validation,
  validateJson,
  validateProof,
} from "@oip/schema";
import { base58 } from "@scure/base";

import { concatBytes } from "./bytes.ts";
import { documentHashOf, isJsonObject, type JsonObject } from "./content-id.ts";
import { SIGNATURE_LENGTH, verifyEd25519 } from "./ed25519.ts";
import { errorFrom, OipError } from "./errors.ts";
import { sha256, sha256Digest } from "./hash.ts";
import { canonicalBytesOf, canonicalText } from "./jcs.ts";
import { decodeEd25519Multikey } from "./multikey.ts";
import { parseVerificationMethod, type VerificationMethod } from "./refs.ts";
import { no, ok, under } from "./result.ts";
import { type Instant, instantOf } from "./time.ts";

/** core 5.1: the most proofs a record carries. */
export const MAX_PROOFS = 256;

const IDENTITY_LOG_EVENTS: readonly string[] = ["Genesis", "Update", "Fork", "Merge", "Retire"];

/**
 * The proof purpose a record's type requires (core 5.6). A proof with any
 * other purpose never counts towards the validity of the record.
 */
export function purposeFor(type: string): ProofPurpose {
  if (IDENTITY_LOG_EVENTS.includes(type)) return "capabilityInvocation";
  if (type === "Delegation") return "capabilityDelegation";
  if (type === "Hello") return "authentication";
  return "assertionMethod";
}

function jsonObject(value: unknown, what: string): JsonObject {
  const checked = validateJson(value);
  if (!checked.ok) throw errorFrom(checked);
  if (!isJsonObject(checked.value)) {
    throw new OipError("invalid-record", `${what} is a JSON object`, { clause: "core 5.2" });
  }
  return checked.value;
}

/**
 * The digest of one proof: `"sha256:"` and the hex of
 * `SHA-256(JCS(proof))`. Evidence that a proof existed is keyed by it
 * (core 9.4), and a feed entry commits to proofs by it (Layer 1, 10.1).
 *
 * @throws OipError `invalid-record` if the value is not a JSON object within
 * the profile of core Section 1.
 */
export function proofDigest(proof: unknown): string {
  return sha256Digest(canonicalBytesOf(jsonObject(proof, "a proof")));
}

/** core 5.3: `SHA-256(JCS(options)) ‖ SHA-256(JCS(record without "proof"))`. */
function hashDataOf(options: JsonObject, documentHash: Uint8Array): Uint8Array {
  return concatBytes(sha256(canonicalBytesOf(options)), documentHash);
}

/**
 * The bytes a proof signs (core 5.3), for a signer that works outside this
 * package. `options` is the proof object without `proofValue`.
 *
 * @throws OipError `invalid-record` if either value is not a JSON object
 * within the profile of core Section 1.
 */
export function proofHashData(record: unknown, options: unknown): Uint8Array {
  const config = jsonObject(options, "a proof's options");
  if (Object.hasOwn(config, "proofValue")) {
    throw new OipError("invalid-proof", "the options of a proof do not include proofValue", {
      clause: "core 5.3",
    });
  }
  return hashDataOf(config, documentHashOf(jsonObject(record, "a record")));
}

/** A proof whose form and signature have been verified against its record. */
export interface VerifiedProof {
  /** The proof. */
  readonly proof: Proof;
  /** What its `verificationMethod` names. */
  readonly method: VerificationMethod;
  /** The key that made the signature, as an Ed25519 Multikey. */
  readonly key: string;
  /** The proof's digest, by which evidence that it existed is keyed (core 9.4). */
  readonly digest: string;
  /** The proof's `created`. It is the signer's claim, never evidence of when the proof was made (core 9.2). */
  readonly created: Instant;
}

/** What every proof on one record is checked against. */
interface Subject {
  readonly type: string;
  readonly documentHash: Uint8Array;
  /** The canonical form of the record's `@context`, if it has one. */
  readonly context: string | undefined;
}

function subjectOf(record: unknown): Validation<Subject> {
  const checked = validateJson(record);
  if (!checked.ok) return checked;
  const value = checked.value;
  if (!isJsonObject(value)) return no("a record is a JSON object", "core 1.1");
  const type = value["type"];
  if (typeof type !== "string") return no("type must name a record type", "core 7", "/type");
  if ((UNSIGNED_RECORD_TYPES as readonly string[]).includes(type)) {
    return no(`a ${type} record is unsigned: no proof on it counts`, "core 5.1", "/proof");
  }
  const context = Object.hasOwn(value, "@context")
    ? canonicalText(value["@context"] as JsonValue)
    : undefined;
  return ok({ type, documentHash: documentHashOf(value), context });
}

function verifyAgainst(subject: Subject, candidate: unknown): Validation<VerifiedProof> {
  // 5.4: exactly the members 5.2 allows, with the required type and cryptosuite.
  const validated = validateProof(candidate);
  if (!validated.ok) return validated;
  const proof = validated.value;
  const required = purposeFor(subject.type);
  if (proof.proofPurpose !== required) {
    return no(
      `a ${subject.type.slice(0, 64)} record needs a proof with the purpose ${required}; this proof's purpose is ${proof.proofPurpose}`,
      "core 5.6",
      "/proofPurpose",
    );
  }
  // 5.2: the proof has @context if and only if the record has, with the same value.
  const context = Object.hasOwn(proof, "@context")
    ? canonicalText(proof["@context"] as JsonValue)
    : undefined;
  if (context !== subject.context) {
    return no(
      subject.context === undefined
        ? "the proof has @context but the record has none"
        : "the proof's @context must be present and equal to the record's",
      "core 5.2",
      "/@context",
    );
  }
  const method = parseVerificationMethod(proof.verificationMethod);
  if (method === undefined) {
    return no(
      "the verification method pins a position beyond 2^53-1, which no identity log has",
      "core 6.1",
      "/verificationMethod",
    );
  }
  // 4.2, 4.3 and 4.4: an Ed25519 key, of the right length, of order exactly L.
  const key = decodeEd25519Multikey(method.key);
  if (!key.ok) return under("/verificationMethod", key);
  const signature = base58.decode(proof.proofValue.slice(1));
  if (signature.length !== SIGNATURE_LENGTH) {
    return no("proofValue is not a signature of 64 bytes", "core 5.2", "/proofValue");
  }
  const { proofValue: _proofValue, ...options } = proof as Proof & JsonObject;
  if (!verifyEd25519(signature, hashDataOf(options, subject.documentHash), key.value)) {
    return no(
      "the signature does not verify: the record or the proof was changed after signing, the key is not the signer's, or the signature breaks the rule every verifier applies",
      "core 4.4",
      "/proofValue",
    );
  }
  return ok({
    proof,
    method,
    key: method.key,
    digest: sha256Digest(canonicalBytesOf(proof as Proof & JsonObject)),
    // The schema has checked that created is a timestamp.
    created: instantOf(proof.created),
  });
}

/**
 * Verifies one proof against a record (core 5.4): its members, its purpose,
 * its `@context`, its key and its signature under core 4.4.
 *
 * The proof need not be one of the record's own `proof` entries: every proof
 * covers the record without its `proof` member (core 5.3).
 *
 * This judges the proof, not the record, and not the signer's authority.
 * Validate the record first; a verified proof on a malformed record is worth
 * nothing. It never throws.
 */
export function verifyProof(record: unknown, proof: unknown): Validation<VerifiedProof> {
  const subject = subjectOf(record);
  return subject.ok ? verifyAgainst(subject.value, proof) : subject;
}

/**
 * Verifies every proof of a record, each on its own (core 5.5): an invalid
 * proof does not invalidate the record or any other proof, and it never
 * counts. The answers are in the order of the record's `proof` array.
 *
 * The outer rejection means there is no proof set to judge: the record is not
 * JSON within the profile, is of an unsigned type, or its `proof` is not an
 * array of 1 to 256 entries (core 5.1). It never throws.
 */
export function verifyProofs(record: unknown): Validation<readonly Validation<VerifiedProof>[]> {
  const subject = subjectOf(record);
  if (!subject.ok) return subject;
  const proofs = (record as { readonly proof?: unknown }).proof;
  if (!Array.isArray(proofs) || proofs.length === 0 || proofs.length > MAX_PROOFS) {
    return no(
      `a signed record carries a proof member that is an array of 1 to ${MAX_PROOFS} proofs`,
      "core 5.1",
      "/proof",
    );
  }
  return ok(
    (proofs as readonly unknown[]).map((proof, index) => {
      const verdict = verifyAgainst(subject.value, proof);
      return verdict.ok ? verdict : under<VerifiedProof>(`/proof/${index}`, verdict);
    }),
  );
}

/**
 * Something that signs with one Ed25519 key. Signing goes through this
 * interface so that a keystore, a hardware key or a remote signer can stand
 * behind it: the private key never needs to reach the code that builds
 * records.
 */
export interface Signer {
  /** The public key, as an Ed25519 Multikey. */
  readonly publicKey: string;
  /** Signs a message with Ed25519 (RFC 8032): 64 bytes. */
  sign(message: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

/** What the creator of a proof decides. Everything else is fixed by core 5.2 and the record. */
export interface ProofOptions {
  /**
   * The signing key: a `key-ref` for an operational key, pinned to a version
   * of the mind's identity, or a `control-key-ref` for a control key
   * (core 6.2).
   */
  readonly verificationMethod: string;
  /** When the proof is made, as a timestamp. The caller reads the clock. */
  readonly created: string;
  /** Only in `authentication` proofs (Layer 1, 13.3). */
  readonly challenge?: string;
  /** Only in `authentication` proofs (Layer 1, 13.3). */
  readonly domain?: string;
  /** One delegation chain, root first, or one charter (core 5.2). */
  readonly authority?: readonly AuthorityItem[];
}

function invalidProof(issues: readonly [Issue, ...Issue[]]): OipError {
  return errorFrom({ issues }, "invalid-proof");
}

/**
 * Creates a proof on a record (core 5.3). The purpose is the one the
 * record's type requires (core 5.6), and `@context` is copied from the
 * record if it has one. The record is not changed; add the proof with
 * `withProofs`.
 *
 * The finished proof is verified before it is returned, so a wrong option, a
 * verification method that names another key, or a faulty signer is caught
 * here and not by the first receiver.
 *
 * @throws OipError `invalid-record` if the record is not a JSON object within
 * the profile, and `invalid-proof` if the proof would not verify.
 */
export async function createProof(
  record: unknown,
  options: ProofOptions,
  signer: Signer,
): Promise<Proof> {
  const subject = jsonObject(record, "a record");
  const type = subject["type"];
  if (typeof type !== "string") {
    throw new OipError("invalid-record", "type must name a record type", { clause: "core 7" });
  }
  const method = parseVerificationMethod(options.verificationMethod);
  if (method?.key !== signer.publicKey) {
    throw new OipError(
      "invalid-proof",
      "the verification method must be a key reference that names the signer's own key",
      { clause: "core 6.2" },
    );
  }
  const config = {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    verificationMethod: options.verificationMethod,
    proofPurpose: purposeFor(type),
    created: options.created,
    ...(options.challenge === undefined ? {} : { challenge: options.challenge }),
    ...(options.domain === undefined ? {} : { domain: options.domain }),
    ...(options.authority === undefined ? {} : { authority: options.authority }),
    ...(Object.hasOwn(subject, "@context") ? { "@context": subject["@context"] } : {}),
  };
  // Nothing is signed that is not a proof: the options are checked first,
  // with a placeholder where the signature will go.
  const draft = validateProof({ ...config, proofValue: `z${"1".repeat(64)}` });
  if (!draft.ok) throw invalidProof(draft.issues);
  const signature = await signer.sign(proofHashData(subject, config));
  if (!(signature instanceof Uint8Array) || signature.length !== SIGNATURE_LENGTH) {
    throw new OipError("invalid-proof", "the signer did not return a signature of 64 bytes", {
      clause: "core 5.2",
    });
  }
  const verified = verifyProof(subject, { ...config, proofValue: `z${base58.encode(signature)}` });
  if (!verified.ok) throw invalidProof(verified.issues);
  return verified.value.proof;
}

/**
 * A record with proofs added to its proof set. Proofs are merged by union
 * (core 5.3): one that is already there, member for member, is not added
 * again. The record is not changed and its content ID stays the same.
 *
 * @throws OipError `invalid-record` if a value is not a JSON object within
 * the profile, the record's `proof` is not an array, or the set would hold
 * more than 256 proofs (core 5.1).
 */
export function withProofs<T extends object>(
  record: T,
  proofs: readonly Proof[],
): Omit<T, "proof"> & { proof: Proof[] } {
  const subject = jsonObject(record, "a record");
  const existing = subject["proof"] ?? [];
  if (!Array.isArray(existing)) {
    throw new OipError("invalid-record", "proof must be an array", { clause: "core 5.1" });
  }
  const seen = new Set<string>();
  const merged: Proof[] = [];
  for (const proof of [...(existing as readonly unknown[]), ...proofs]) {
    const digest = proofDigest(proof);
    if (seen.has(digest)) continue;
    seen.add(digest);
    merged.push(proof as Proof);
  }
  if (merged.length > MAX_PROOFS) {
    throw new OipError("invalid-record", `a record carries at most ${MAX_PROOFS} proofs`, {
      clause: "core 5.1",
    });
  }
  return { ...(subject as T), proof: merged };
}
