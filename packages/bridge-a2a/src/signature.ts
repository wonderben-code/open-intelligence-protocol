// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The signatures on an Agent Card (A2A, Section 8.4): a gateway verifies
 * any that a card has before it bridges the card's agent (Layer 0, 3.1).
 *
 * A signature is a JWS (RFC 7515) over the card without its `signatures`,
 * in canonical form (RFC 8785). The arithmetic is the platform's
 * (`crypto.subtle`): nothing of it is written here. These are A2A's
 * signatures, by keys of A2A's world. They are not OIP proofs, and core
 * 4.4 does not speak of them.
 *
 * What a verified signature shows depends on where its key came from, and
 * that is the caller's to decide: `KeySource` is given the key ID and the
 * URL the signature names, and answers with the keys the gateway's
 * operator lets stand for them.
 */

import type { webcrypto } from "node:crypto";

import { canonicalBytes, type JsonValue, OipError } from "@oip/core";
import type { Validation } from "@oip/schema";

import type { ReadCard } from "./card.ts";

/** A public key as a JSON Web Key (RFC 7517), as far as it is read here. */
export interface PublicJwk {
  readonly kty?: unknown;
  readonly kid?: unknown;
  readonly crv?: unknown;
  readonly x?: unknown;
  readonly y?: unknown;
  readonly n?: unknown;
  readonly e?: unknown;
}

/**
 * Gives the keys that may verify a signature.
 *
 * @param wanted.kid - The key ID the signature's protected header names.
 * @param wanted.jku - The URL of a key set the header names, if it names one.
 *   It is the signer's word: whether to fetch it is the source's to decide.
 * @returns The keys. None, if the source has none it lets stand for these.
 */
export type KeySource = (wanted: {
  readonly kid: string;
  readonly jku?: string;
}) => Promise<readonly PublicJwk[]>;

/** What verifying a card's signatures came to. */
export interface CardSignatures {
  /** Whether the card has a signature at all. A2A lets a card have none. */
  readonly signed: boolean;
  /** The key IDs of the signatures that verified. */
  readonly verifiedBy: readonly string[];
}

const CLAUSE = "L0 3.1";
const refused = (message: string, path = "/signatures"): Validation<CardSignatures> => ({
  ok: false,
  issues: [{ path, message, clause: CLAUSE }],
});

/** How a JWS algorithm is verified by the platform, and what key it takes. */
interface Scheme {
  readonly kty: "EC" | "RSA" | "OKP";
  readonly crv?: string;
  readonly imported:
    webcrypto.EcKeyImportParams | webcrypto.RsaHashedImportParams | webcrypto.AlgorithmIdentifier;
  readonly verified: webcrypto.EcdsaParams | webcrypto.RsaPssParams | webcrypto.AlgorithmIdentifier;
  /** The length of a signature in bytes, where the algorithm fixes it. */
  readonly length?: number;
}

const ecdsa = (crv: string, hash: string, length: number): Scheme => ({
  kty: "EC",
  crv,
  imported: { name: "ECDSA", namedCurve: crv },
  verified: { name: "ECDSA", hash },
  length,
});
const pkcs1 = (hash: string): Scheme => ({
  kty: "RSA",
  imported: { name: "RSASSA-PKCS1-v1_5", hash },
  verified: { name: "RSASSA-PKCS1-v1_5" },
});
const pss = (hash: string, saltLength: number): Scheme => ({
  kty: "RSA",
  imported: { name: "RSA-PSS", hash },
  verified: { name: "RSA-PSS", saltLength },
});

/**
 * The algorithms a signature may name (RFC 7518, RFC 8037). `none` and the
 * algorithms of a shared secret are not among them: a card is signed by a
 * key its reader does not hold.
 */
const SCHEMES: Readonly<Record<string, Scheme>> = {
  ES256: ecdsa("P-256", "SHA-256", 64),
  ES384: ecdsa("P-384", "SHA-384", 96),
  ES512: ecdsa("P-521", "SHA-512", 132),
  RS256: pkcs1("SHA-256"),
  RS384: pkcs1("SHA-384"),
  RS512: pkcs1("SHA-512"),
  PS256: pss("SHA-256", 32),
  PS384: pss("SHA-384", 48),
  PS512: pss("SHA-512", 64),
  EdDSA: {
    kty: "OKP",
    crv: "Ed25519",
    imported: { name: "Ed25519" },
    verified: { name: "Ed25519" },
    length: 64,
  },
};

/** The shortest RSA modulus a signature is taken from, in bytes: 2048 bits. */
const MIN_RSA_BYTES = 256;

const BASE64URL = /^[A-Za-z0-9_-]+$/u;

/** The bytes a base64url text stands for, or `undefined` if it is none. */
function decoded(text: unknown): Uint8Array | undefined {
  if (typeof text !== "string" || !BASE64URL.test(text) || text.length % 4 === 1) return undefined;
  return new Uint8Array(Buffer.from(text, "base64url"));
}

const isObject = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** A copy of an object without the members named whose value is the default of its kind. */
function without(
  from: Readonly<Record<string, unknown>>,
  defaults: readonly string[],
): Record<string, unknown> {
  const kept: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(from)) {
    const empty =
      value === "" ||
      value === false ||
      (Array.isArray(value) && value.length === 0) ||
      (isObject(value) && Object.keys(value).length === 0);
    if (!(empty && defaults.includes(name))) kept[name] = value;
  }
  return kept;
}

const each = (
  value: unknown,
  change: (item: Readonly<Record<string, unknown>>) => unknown,
): unknown =>
  Array.isArray(value)
    ? value.map((item: unknown) => (isObject(item) ? change(item) : item))
    : value;

/**
 * The card as its signer is to have canonicalised it (A2A, Section 8.4.1):
 * without `signatures`, and without the members that are at their default
 * and are neither required nor marked optional in A2A's definition. Those
 * are the lists and maps that may be empty, a `tenant` that is empty, and
 * what an extension says of itself.
 */
function withoutDefaults(card: Readonly<Record<string, unknown>>): Record<string, unknown> {
  const { signatures: _, ...rest } = card;
  const top = without(rest, ["securitySchemes", "securityRequirements"]);
  if (isObject(top["capabilities"])) {
    const capabilities = without(top["capabilities"], ["extensions"]);
    if (capabilities["extensions"] !== undefined) {
      capabilities["extensions"] = each(capabilities["extensions"], (extension) =>
        without(extension, ["uri", "description", "required", "params"]),
      );
    }
    top["capabilities"] = capabilities;
  }
  top["supportedInterfaces"] = each(top["supportedInterfaces"], (one) => without(one, ["tenant"]));
  top["skills"] = each(top["skills"], (skill) =>
    without(skill, ["examples", "inputModes", "outputModes", "securityRequirements"]),
  );
  return top;
}

/**
 * The payloads a signature may be over, as base64url: the card as it was
 * served without `signatures`, and the same with its defaults left out. A
 * signer leaves them out before it signs, and a server may still write
 * them: the two say the same of the agent.
 *
 * @throws OipError if the card has no canonical form here: it holds a
 *   number that is not a whole number, say, or a text that is no Unicode.
 */
function payloads(card: Readonly<Record<string, unknown>>): string[] {
  const { signatures: _, ...served } = card;
  const texts = [served, withoutDefaults(card)].map((value) =>
    Buffer.from(canonicalBytes(value as JsonValue)).toString("base64url"),
  );
  return [...new Set(texts)];
}

/** The public members of a key, for the algorithm it is to verify by, or `undefined` if it is no such key. */
function publicMembers(jwk: PublicJwk, scheme: Scheme): webcrypto.JsonWebKey | undefined {
  if (jwk.kty !== scheme.kty) return undefined;
  if (scheme.kty === "RSA") {
    const modulus = decoded(jwk.n);
    if (modulus === undefined || typeof jwk.n !== "string" || typeof jwk.e !== "string") {
      return undefined;
    }
    // A leading zero byte is not part of the modulus.
    const size = modulus[0] === 0 ? modulus.length - 1 : modulus.length;
    return size < MIN_RSA_BYTES ? undefined : { kty: "RSA", n: jwk.n, e: jwk.e };
  }
  const { crv } = scheme;
  if (crv === undefined || jwk.crv !== crv || typeof jwk.x !== "string") return undefined;
  if (scheme.kty === "OKP") return { kty: "OKP", crv, x: jwk.x };
  return typeof jwk.y === "string" ? { kty: "EC", crv, x: jwk.x, y: jwk.y } : undefined;
}

/**
 * A key the platform will verify by, from what a source gave: its public
 * members alone, as a key of the signature's algorithm. What the platform
 * does not take as such a key is no key for this signature.
 */
async function usableKey(jwk: PublicJwk, scheme: Scheme): Promise<webcrypto.CryptoKey | undefined> {
  const members = publicMembers(jwk, scheme);
  if (members === undefined) return undefined;
  try {
    return await crypto.subtle.importKey("jwk", members, scheme.imported, false, ["verify"]);
  } catch {
    return undefined;
  }
}

/**
 * The most signatures of a card that are verified, and the most keys of one
 * name that a signature is tried under. A card is a stranger's, and so is a
 * key set an agent serves: without these a card could cost its reader
 * hundreds of fetches and many thousands of verifications.
 */
export const MAX_SIGNATURES = 8;
export const MAX_KEYS_OF_A_NAME = 4;

/** Whether a signature verifies over one of the payloads by one of the keys. */
async function verifies(
  scheme: Scheme,
  keys: readonly webcrypto.CryptoKey[],
  header: string,
  payloadTexts: readonly string[],
  signature: Uint8Array,
): Promise<boolean> {
  for (const key of keys) {
    for (const payload of payloadTexts) {
      const signed = new TextEncoder().encode(`${header}.${payload}`);
      if (await crypto.subtle.verify(scheme.verified, key, signature, signed)) return true;
    }
  }
  return false;
}

/**
 * Verifies the signatures on a card (Layer 0, 3.1; A2A, Section 8.4.3).
 *
 * A card with no signature is not refused: A2A lets a card have none. A
 * card with signatures is taken only if at least one verifies and none is
 * wrong. A signature is wrong if it names no algorithm that is taken, says
 * something of itself that this reader must understand and does not, or
 * fails under a key the source gave for it. One whose key the source does
 * not have is passed over: an agent that changes its key signs with both
 * for a while. If every signature is passed over, the card is refused.
 *
 * @param keys - Where the keys come from: see `KeySource`.
 */
export async function verifySignatures(
  read: ReadCard,
  keys: KeySource,
): Promise<Validation<CardSignatures>> {
  const { signatures } = read.card;
  if (signatures.length === 0) return { ok: true, value: { signed: false, verifiedBy: [] } };
  if (signatures.length > MAX_SIGNATURES) {
    return refused(
      `the card has more signatures than are verified: ${String(MAX_SIGNATURES)} at most`,
      "/signatures",
    );
  }
  let payloadTexts: string[];
  try {
    payloadTexts = payloads(read.json);
  } catch (error) {
    if (!(error instanceof OipError)) throw error;
    // Why it has none is in this reader's own words: a fraction, a text that is no Unicode, a nesting too deep.
    return refused(
      `the card cannot be put in the form its signatures are over: ${error.message}`,
      "",
    );
  }
  const verifiedBy: string[] = [];
  for (const [index, { protected: header, signature }] of signatures.entries()) {
    const at = `/signatures/${String(index)}`;
    const headerBytes = decoded(header);
    let said: unknown;
    try {
      said = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(headerBytes));
    } catch {
      return refused("the protected header is not base64url of JSON", `${at}/protected`);
    }
    if (headerBytes === undefined || !isObject(said)) {
      return refused("the protected header is not base64url of a JSON object", `${at}/protected`);
    }
    const { alg, kid, jku, crit } = said;
    const scheme =
      typeof alg === "string" && Object.hasOwn(SCHEMES, alg) ? SCHEMES[alg] : undefined;
    if (scheme === undefined) {
      return refused("the signature names no algorithm that is taken", `${at}/protected`);
    }
    // RFC 7515, 4.1.11: what a signature marks as critical must be understood, and nothing is.
    if (crit !== undefined) {
      return refused(
        "the signature marks a header as critical that is not understood",
        `${at}/protected`,
      );
    }
    if (typeof kid !== "string" || kid === "") {
      return refused("the signature names no key", `${at}/protected`);
    }
    const bytes = decoded(signature);
    if (bytes === undefined || (scheme.length !== undefined && bytes.length !== scheme.length)) {
      return refused(
        "the signature is not base64url of a signature of its algorithm",
        `${at}/signature`,
      );
    }
    const given = await keys({ kid, ...(typeof jku === "string" ? { jku } : {}) });
    const usable: webcrypto.CryptoKey[] = [];
    for (const jwk of given) {
      // A key that says which it is must be the one that was named.
      if (jwk.kid !== undefined && jwk.kid !== kid) continue;
      const key = await usableKey(jwk, scheme);
      if (key !== undefined) usable.push(key);
      // A name is one key's, or a few while a key is changed: no more of them are tried.
      if (usable.length >= MAX_KEYS_OF_A_NAME) break;
    }
    if (usable.length === 0) continue;
    if (!(await verifies(scheme, usable, header, payloadTexts, bytes))) {
      return refused("the signature does not verify under the key that was named for it", at);
    }
    verifiedBy.push(kid);
  }
  if (verifiedBy.length === 0) {
    return refused("the card is signed, and there is no key to verify any of its signatures by");
  }
  return { ok: true, value: { signed: true, verifiedBy } };
}
