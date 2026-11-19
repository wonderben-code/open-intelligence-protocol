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
  isRecordType,
  type Issue,
  type JsonValue,
  type Proof,
  type ProofPurpose,
  quote,
  UNSIGNED_RECORD_TYPES,
  type Validation,
  validateExtensionRecord,
  validateJson,
  validateProof,
  validateRecord,
} from "@oip/schema";
import { base58 } from "@scure/base";

import { concatBytes } from "./bytes.ts";
import { documentHashOf, isJsonObject, type JsonObject } from "./content-id.ts";
import { SIGNATURE_LENGTH, verifyEd25519 } from "./ed25519.ts";
import { errorFrom, OipError } from "./errors.ts";
import { sha256, sha256Digest } from "./hash.ts";
import { canonicalBytesOf, canonicalSizeUpTo, canonicalText } from "./jcs.ts";
import { decodeEd25519Multikey } from "./multikey.ts";
import { checkSize, MAX_RECORD_BYTES } from "./record.ts";
import { parseVerificationMethod, type VerificationMethod } from "./refs.ts";
import { issuesUnder, no, ok, under } from "./result.ts";
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
 * within the profile of core Section 1, and `invalid-proof` if the options
 * already hold a `proofValue`.
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
  /** The record's own `proof` member, as it was read. */
  readonly proofs: JsonValue | undefined;
}

function isUnsignedType(type: unknown): boolean {
  return (UNSIGNED_RECORD_TYPES as readonly unknown[]).includes(type);
}

function isUnsigned(value: JsonValue): boolean {
  return isJsonObject(value) && isUnsignedType(value["type"]);
}

/** Reads a record once, into a plain copy, and takes from the copy all that a proof is checked against. */
function subjectOf(record: unknown): Validation<Subject> {
  let checked = validateJson(record);
  if (!checked.ok) {
    // A container may nest deeper than any signed record. It carries no proof
    // of its own, and that is the reason to give, not its depth. Only a value
    // refused for its depth is looked at a second time.
    if (checked.issues[0].clause !== "core 1.9") return checked;
    const container = validateJson(record, "container");
    if (!container.ok || !isUnsigned(container.value)) return checked;
    checked = container;
  }
  const value = checked.value;
  if (!isJsonObject(value)) return no("a record is a JSON object", "core 1.1");
  const type = value["type"];
  if (typeof type !== "string") return no("type must name a record type", "core 7", "/type");
  if (isUnsignedType(type)) {
    return no(`a ${type} record is unsigned: no proof on it counts`, "core 5.1", "/proof");
  }
  const context = Object.hasOwn(value, "@context")
    ? canonicalText(value["@context"] as JsonValue)
    : undefined;
  return ok({ type, documentHash: documentHashOf(value), context, proofs: value["proof"] });
}

function verifyAgainst(subject: Subject, candidate: unknown): Validation<VerifiedProof> {
  // 5.4: exactly the members 5.2 allows, with the required type and cryptosuite.
  const validated = validateProof(candidate);
  if (!validated.ok) return validated;
  const proof = validated.value;
  const required = purposeFor(subject.type);
  if (proof.proofPurpose !== required) {
    return no(
      `a record of type ${quote(subject.type)} needs a proof with the purpose ${required}; this proof's purpose is ${proof.proofPurpose}`,
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
  try {
    const subject = subjectOf(record);
    return subject.ok ? verifyAgainst(subject.value, proof) : subject;
  } catch {
    return no("the record or the proof could not be read as plain JSON data", "core 1.2");
  }
}

/** A verified proof, and where it stands in its record's `proof` array. */
export interface PlacedProof extends VerifiedProof {
  /** The proof's position in the record's `proof` array, from 0. */
  readonly index: number;
}

/** An entry of a record's `proof` array that did not verify, and why. */
export interface RejectedProof {
  /** The entry's position in the record's `proof` array, from 0. */
  readonly index: number;
  /** Why it did not verify, each with the clause it comes from. */
  readonly issues: readonly [Issue, ...Issue[]];
}

/** What verifying a record's proof set found. */
export interface ProofVerdicts {
  /**
   * The proofs that verified, in the record's order. One proof may stand in
   * a record more than once, and one key may make several: count distinct
   * keys, never entries.
   */
  readonly verified: readonly PlacedProof[];
  /** The entries that did not verify, in the record's order, each with its reasons. */
  readonly rejected: readonly RejectedProof[];
  /**
   * Why no proof was judged at all: the record is not JSON within the
   * profile, is of an unsigned type, or its `proof` is not an array of 1 to
   * 256 objects (core 5.1). Empty when the proof set was judged.
   */
  readonly issues: readonly Issue[];
}

function notJudged(issues: readonly Issue[]): ProofVerdicts {
  return { verified: [], rejected: [], issues };
}

/**
 * Verifies every proof of a record, each on its own (core 5.5): an invalid
 * proof does not invalidate the record or any other proof, and it never
 * counts.
 *
 * There is no single answer to read as "the record is verified": look at
 * `verified`, and at whose keys made those proofs. A record with no valid
 * proof gives an empty `verified`. It never throws.
 */
export function verifyProofs(record: unknown): ProofVerdicts {
  try {
    const subject = subjectOf(record);
    if (!subject.ok) return notJudged(subject.issues);
    const proofs = subject.value.proofs;
    if (
      !Array.isArray(proofs) ||
      proofs.length === 0 ||
      proofs.length > MAX_PROOFS ||
      !(proofs as readonly JsonValue[]).every(isJsonObject)
    ) {
      return notJudged([
        {
          path: "/proof",
          message: `a signed record carries a proof member that is an array of 1 to ${MAX_PROOFS} proof objects`,
          clause: "core 5.1",
        },
      ]);
    }
    const verified: PlacedProof[] = [];
    const rejected: RejectedProof[] = [];
    // A proof repeated in the set is verified once: a signature check is the costly part.
    const verdicts = new Map<string, Validation<VerifiedProof>>();
    (proofs as readonly JsonObject[]).forEach((proof, index) => {
      const text = canonicalText(proof);
      const verdict = verdicts.get(text) ?? verifyAgainst(subject.value, proof);
      verdicts.set(text, verdict);
      if (verdict.ok) verified.push({ ...verdict.value, index });
      else rejected.push({ index, issues: issuesUnder(`/proof/${index}`, verdict) });
    });
    return { verified, rejected, issues: [] };
  } catch {
    return notJudged([
      {
        path: "",
        message: "the record could not be read as plain JSON data",
        clause: "core 1.2",
      },
    ]);
  }
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

/** A signer that answers at once, such as one that holds its key in memory. */
export interface SyncSigner extends Signer {
  sign(message: Uint8Array): Uint8Array;
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
  /**
   * core 5.7 says a proof's `created` should not be earlier than its
   * record's, and a proof dated earlier is refused unless this is `true`.
   * The case for it: a co-signer whose clock runs behind the author's has no
   * later time that is honestly its own.
   */
  readonly earlierThanRecord?: boolean;
}

function invalidProof(issues: readonly [Issue, ...Issue[]]): OipError {
  return errorFrom({ issues }, "invalid-proof");
}

/** The record's own proofs, which must be an array of objects if it has any (core 5.1). */
function existingProofs(subject: JsonObject): readonly JsonObject[] {
  const existing = subject["proof"] ?? [];
  if (!Array.isArray(existing) || !(existing as readonly JsonValue[]).every(isJsonObject)) {
    throw new OipError("invalid-record", "proof must be an array of proof objects", {
      clause: "core 5.1",
    });
  }
  return existing as readonly JsonObject[];
}

/** The record as a JSON object of a type that carries proofs. */
function signedSubject(record: unknown): { subject: JsonObject; type: string } {
  const subject = jsonObject(record, "a record");
  const type = subject["type"];
  if (typeof type !== "string") {
    throw new OipError("invalid-record", "type must name a record type", { clause: "core 7" });
  }
  if ((UNSIGNED_RECORD_TYPES as readonly string[]).includes(type)) {
    throw new OipError("invalid-proof", `a ${type} record is unsigned: it carries no proof`, {
      clause: "core 5.1",
    });
  }
  return { subject, type };
}

/**
 * A record as it will stand with its proofs: well formed for its type, and
 * within the limits on size and depth (core 1.6, 1.9).
 */
function wellFormed(candidate: JsonObject, type: string): void {
  const validated = isRecordType(type)
    ? validateRecord(candidate)
    : validateExtensionRecord(candidate);
  if (!validated.ok) throw errorFrom(validated, "invalid-record");
  const [first, ...rest] = checkSize(validated.value);
  if (first !== undefined) throw errorFrom({ issues: [first, ...rest] }, "too-large");
}

/** A proof that lacks only its signature. */
interface Draft {
  readonly record: JsonObject;
  readonly config: JsonObject;
  readonly hashData: Uint8Array;
}

/** Everything that is checked before a signer is asked to sign. */
function prepare(record: unknown, options: ProofOptions, publicKey: string): Draft {
  const { subject, type } = signedSubject(record);
  // Each option is read once, and what was read is what is checked and signed:
  // an options object may answer differently the second time it is asked.
  const { verificationMethod, created, challenge, domain, authority, earlierThanRecord } = options;
  const method = parseVerificationMethod(verificationMethod);
  // A signer with no key and a reference that names none must not pass as a match.
  if (typeof publicKey !== "string" || method?.key !== publicKey) {
    throw new OipError(
      "invalid-proof",
      "the verification method must be a key reference that names the signer's own key",
      { clause: "core 6.2" },
    );
  }
  const config = {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    verificationMethod,
    proofPurpose: purposeFor(type),
    created,
    ...(challenge === undefined ? {} : { challenge }),
    ...(domain === undefined ? {} : { domain }),
    ...(authority === undefined ? {} : { authority }),
    ...(Object.hasOwn(subject, "@context") ? { "@context": subject["@context"] } : {}),
  };
  // Nothing is signed that is not a proof on a well-formed record: the options
  // are checked first, with a placeholder where the signature will go, and
  // then the record as it will stand with the proof on it.
  const placeholder = validateProof({ ...config, proofValue: `z${"1".repeat(88)}` });
  if (!placeholder.ok) throw invalidProof(placeholder.issues);
  const draft = placeholder.value as Proof & JsonObject;
  wellFormed({ ...subject, proof: [...existingProofs(subject), draft] }, type);
  const { proofValue: _placeholder, ...checked } = draft;
  // Every record that can be signed carries created (core 7), and both times
  // have just been validated as timestamps.
  if (
    earlierThanRecord !== true &&
    instantOf(draft.created) < instantOf(subject["created"] as string)
  ) {
    throw new OipError(
      "invalid-proof",
      "a proof's created should not be earlier than its record's created: sign with the later of the two times, or set earlierThanRecord",
      { clause: "core 5.7" },
    );
  }
  return {
    record: subject,
    config: checked,
    hashData: hashDataOf(checked, documentHashOf(subject)),
  };
}

/** Attaches the signature and checks that the finished proof verifies. */
function finish(draft: Draft, signature: unknown): Proof {
  if (!(signature instanceof Uint8Array) || signature.length !== SIGNATURE_LENGTH) {
    throw new OipError("invalid-proof", "the signer did not return a signature of 64 bytes", {
      clause: "core 5.2",
    });
  }
  const proof = { ...draft.config, proofValue: `z${base58.encode(signature)}` };
  const verified = verifyProof(draft.record, proof);
  if (!verified.ok) throw invalidProof(verified.issues);
  return verified.value.proof;
}

/**
 * Creates a proof on a record (core 5.3). The purpose is the one the
 * record's type requires (core 5.6), and `@context` is copied from the
 * record if it has one. The record is not changed; add the proof with
 * `withProofs`.
 *
 * Before the signer is asked for anything, the options are checked, and so
 * is the record as it will stand with the proof on it: its schema, its rules
 * and its size. The finished proof is verified before it is returned. A
 * wrong option, a malformed record, a verification method that names another
 * key, or a faulty signer is caught here and not by the first receiver.
 *
 * @throws OipError `invalid-record` if the record, with the proof, is not a
 * well-formed record of its type; `too-large` if it would exceed the size
 * limit; and `invalid-proof` if the type is unsigned, an option is not one
 * core 5.2 allows, the proof would be dated before the record (core 5.7), or
 * the proof does not verify.
 */
export async function createProof(
  record: unknown,
  options: ProofOptions,
  signer: Signer,
): Promise<Proof> {
  const draft = prepare(record, options, signer.publicKey);
  return finish(draft, await signer.sign(draft.hashData));
}

/**
 * As `createProof`, for a signer that answers at once. Tools and tests that
 * hold a key in memory need no promise.
 */
export function createProofSync(record: unknown, options: ProofOptions, signer: SyncSigner): Proof {
  const draft = prepare(record, options, signer.publicKey);
  return finish(draft, signer.sign(draft.hashData));
}

/**
 * A record with proofs added to its proof set. Proofs are merged by union
 * (core 5.3): one that is already there, member for member, is not added
 * again. The record is not changed and its content ID stays the same.
 *
 * Each proof added must have the form of a proof (core 5.2). That is not
 * verification: merge only proofs that `verifyProof` has accepted, because
 * anything merged takes one of the 256 places.
 *
 * @throws OipError `invalid-record` if the record is not a JSON object
 * within the profile, its `proof` is not an array of objects, or the result
 * would nest too deeply (core 1.9); `invalid-proof` if the record's type is
 * unsigned or an added entry has not the form of a proof; and `too-large` if
 * the set would hold more than 256 proofs (core 5.1) or the record would
 * exceed 1 MiB (core 1.6).
 */
export function withProofs<T extends object>(
  record: T,
  proofs: readonly Proof[],
): Omit<T, "proof"> & { proof: Proof[] } {
  const { subject } = signedSubject(record);
  const seen = new Set<string>();
  const merged: JsonObject[] = [];
  const add = (proof: JsonObject) => {
    const digest = sha256Digest(canonicalBytesOf(proof));
    if (seen.has(digest)) return;
    seen.add(digest);
    merged.push(proof);
  };
  existingProofs(subject).forEach(add);
  for (const proof of proofs) {
    const validated = validateProof(proof);
    if (!validated.ok) throw invalidProof(validated.issues);
    add(validated.value as Proof & JsonObject);
  }
  if (merged.length > MAX_PROOFS) {
    throw new OipError("too-large", `a record carries at most ${MAX_PROOFS} proofs`, {
      clause: "core 5.1",
    });
  }
  // The record and each proof have been validated, so the result is plain data
  // within the depth limit: a proof nests at most 62 deep and stands at depth 3.
  // What remains to check is the size of the whole.
  const result = { ...subject, proof: merged };
  if (canonicalSizeUpTo(result, MAX_RECORD_BYTES) > MAX_RECORD_BYTES) {
    throw new OipError(
      "too-large",
      `with these proofs the record is more than ${MAX_RECORD_BYTES} bytes in canonical form`,
      { clause: "core 1.6" },
    );
  }
  return result as unknown as Omit<T, "proof"> & { proof: Proof[] };
}
