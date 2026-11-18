// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Authenticated HTTP requests (Layer 1, 13.3): HTTP Message Signatures
 * (RFC 9421) in the profile the protocol uses.
 *
 * A request that needs authentication carries a signature with the
 * algorithm `ed25519`, a `keyid` that is a key reference of the requesting
 * mind, over the method, the target URI and, when there is a body, its
 * `Content-Digest` (RFC 9530, `sha-256`), with the parameters `created`,
 * `expires` (at most 300 seconds later) and `nonce`.
 *
 * The signature base of RFC 9421 is built here for the components the
 * profile uses and a few more. The signature itself is Ed25519 under the
 * rule of core 4.4, and the key is judged as a proof's key is (Layer 1,
 * 6.1), with the current-state rule.
 */

import {
  bytesEqual,
  bytesToBase64,
  decodeEd25519Multikey,
  type Instant,
  parseKeyRef,
  sha256,
  type Signer,
  utf8,
  verifyEd25519,
} from "@oip/core";
import { type IdentityView, requestKeyTime } from "@oip/identity";
import type { Validation } from "@oip/schema";

import { requestDates, withinWindow } from "./dates.ts";
import { judging, no, ok } from "./result.ts";
import {
  type InnerList,
  type Item,
  parseDictionary,
  type Parameters,
  writeInnerList,
} from "./structured.ts";

const SECOND = 1_000_000_000n;

/** Layer 1, 13.3: a signature is valid for at most 300 seconds, and clocks differ by as much. */
const WINDOW = 300n * SECOND;

/** An HTTP request, as the party that signs or verifies it sees it. */
export interface HttpRequest {
  /** The method, as sent: `POST`. */
  readonly method: string;
  /**
   * The target URI, whole: `https://host.example/oip/inbox?after=7`. A
   * server gives the URI its clients address it by, and not one that a
   * proxy in front of it has rewritten.
   */
  readonly url: string;
  /** The header fields, each name with its value, in the order received. Names are matched in any case. */
  readonly headers: readonly (readonly [name: string, value: string])[];
  /** The body, if the request has one. */
  readonly body?: Uint8Array | undefined;
}

const URI = /^(https?):\/\/([^/?#\s]+)([^?#\s]*)(\?[^#\s]*)?$/u;

/** RFC 9421, 2.2: the value of a derived component of a request, or `undefined` if it has none here. */
function derived(name: string, request: HttpRequest): string | undefined {
  if (name === "@method") return request.method;
  const uri = URI.exec(request.url);
  if (uri === null) return undefined;
  const [, scheme, authority, path, query] = uri as unknown as [
    string,
    string,
    string,
    string,
    string?,
  ];
  switch (name) {
    case "@target-uri":
      return request.url;
    case "@scheme":
      return scheme;
    case "@authority":
      return authority.toLowerCase();
    case "@path":
      return path === "" ? "/" : path;
    case "@query":
      return query ?? "?";
    case "@request-target":
      return (path === "" ? "/" : path) + (query ?? "");
    default:
      return undefined;
  }
}

/** RFC 9421, 2.1: the value of a field, its instances joined, or `undefined` if the request has none. */
function field(name: string, request: HttpRequest): string | undefined {
  const values = request.headers
    .filter(([given]) => given.toLowerCase() === name)
    .map(([, value]) => value.trim());
  return values.length === 0 ? undefined : values.join(", ");
}

/** A character a line of the signature base may hold: printable ASCII and the space. */
const PRINTABLE = /^[\x20-\x7e]*$/u;

/**
 * RFC 9421, 2.5: the signature base of a request for the components and
 * parameters of one signature.
 *
 * Components are a field's name in lower case, or one of the derived
 * components `@method`, `@target-uri`, `@authority`, `@scheme`, `@path`,
 * `@query` and `@request-target`. A component with parameters of its own,
 * one named twice, one the request does not have, and a value that is not
 * printable ASCII each make an error, as the RFC requires.
 *
 * @param input - The inner list of the signature's `Signature-Input`
 *   member: its covered components, and its parameters.
 */
export function signatureBase(request: HttpRequest, input: InnerList): Validation<string> {
  const lines: string[] = [];
  const named = new Set<string>();
  for (const [index, component] of input.items.entries()) {
    const path = `/components/${index}`;
    if (component.value.kind !== "string" || component.parameters.length > 0) {
      return no("a covered component is a name, with no parameters", "L1 13.3", path);
    }
    const name = component.value.value;
    if (named.has(name)) return no("a component is covered twice", "L1 13.3", path);
    named.add(name);
    const value = name.startsWith("@") ? derived(name, request) : field(name, request);
    if (value === undefined || !PRINTABLE.test(value) || name !== name.toLowerCase()) {
      return no(
        `the request has no value for the component ${JSON.stringify(name)}`,
        "L1 13.3",
        path,
      );
    }
    lines.push(`"${name}": ${value}`);
  }
  lines.push(`"@signature-params": ${writeInnerList(input)}`);
  return ok(lines.join("\n"));
}

/**
 * RFC 9530: the `Content-Digest` of a body, with SHA-256, as the profile
 * uses it: `sha-256=:<base64>:`.
 */
export function contentDigest(body: Uint8Array): string {
  return `sha-256=:${bytesToBase64(sha256(body))}:`;
}

/** What a signer of a request decides. */
export interface RequestSignature {
  /** The key that signs: a `key-ref` of the requesting mind. */
  readonly keyRef: string;
  /** When the signature is made. */
  readonly created: Instant;
  /** When it expires: at most 300 seconds after `created`. Default: 300 seconds after. */
  readonly expires?: Instant;
  /** A nonce, used once for this key: a string of printable ASCII, made by the caller. */
  readonly nonce: string;
  /** The label of the signature among those the request carries. Default `oip`. */
  readonly label?: string;
}

const seconds = (instant: Instant): number => Number(instant / SECOND);

const text = (value: string) => ({ kind: "string", value }) as const;
const name = (value: string): Item => ({ kind: "item", value: text(value), parameters: [] });

/**
 * Layer 1, 13.3: signs a request.
 *
 * It covers the method and the target URI, and for a request with a body
 * its `Content-Digest`.
 *
 * @returns The header fields to add to the request: `Signature-Input`,
 *   `Signature`, and `Content-Digest` for a request with a body. Any
 *   `Content-Digest` the request already has is replaced by this one.
 * @throws TypeError if the signature is not one the profile allows: no
 *   key reference, a time that is none, more than 300 seconds of validity,
 *   or a nonce or a label that cannot be written.
 */
export async function signRequest(
  request: HttpRequest,
  signature: RequestSignature,
  signer: Signer,
): Promise<[name: string, value: string][]> {
  const { created, nonce, keyRef } = signature;
  const expires = signature.expires ?? created + WINDOW;
  const label = signature.label ?? "oip";
  if (typeof (created as unknown) !== "bigint" || typeof (expires as unknown) !== "bigint") {
    throw new TypeError("the times of a signature are instants");
  }
  if (!withinWindow({ created, expires })) {
    throw new TypeError("a signature expires after it is made, and at most 300 seconds after");
  }
  if (parseKeyRef(keyRef) === undefined)
    throw new TypeError("`keyid` is a key reference of a mind");
  if (typeof (nonce as unknown) !== "string" || nonce.length === 0 || !PRINTABLE.test(nonce)) {
    throw new TypeError("a nonce is printable ASCII, and not empty");
  }
  if (!/^[a-z*][a-z0-9_\-.*]*$/u.test(label)) {
    throw new TypeError("a label is a key of a structured field");
  }
  const hasBody = request.body !== undefined && request.body.length > 0;
  const added: [string, string][] = [];
  let signed = request;
  if (hasBody) {
    const digest = contentDigest(request.body);
    added.push(["Content-Digest", digest]);
    signed = {
      ...request,
      headers: [
        ...request.headers.filter(([given]) => given.toLowerCase() !== "content-digest"),
        ["content-digest", digest],
      ],
    };
  }
  const parameters: Parameters = [
    ["created", { kind: "integer", value: seconds(created) }],
    ["expires", { kind: "integer", value: seconds(expires) }],
    ["nonce", text(nonce)],
    ["keyid", text(keyRef)],
    ["alg", text("ed25519")],
  ];
  const input: InnerList = {
    kind: "list",
    items: ["@method", "@target-uri", ...(hasBody ? ["content-digest"] : [])].map(name),
    parameters,
  };
  const base = signatureBase(signed, input);
  if (!base.ok) throw new TypeError(base.issues[0].message);
  const made = await signer.sign(utf8(base.value));
  added.push(["Signature-Input", `${label}=${writeInnerList(input)}`]);
  added.push(["Signature", `${label}=:${bytesToBase64(made)}:`]);
  return added;
}

/** A server's memory of the nonces it has seen, each with the key that used it. */
export interface SeenNonces {
  /** Whether this key has used this nonce in a signature that is still valid. */
  seen(keyid: string, nonce: string): boolean;
  /** Remembers that it has, until the signature expires. */
  remember(keyid: string, nonce: string, until: Instant): void;
}

/** A server that authenticates requests. */
export interface RequestVerifier {
  /** The present: the server's own clock, read by the caller. */
  readonly now: Instant;
  /** The identity logs the server holds, and its evidence of time. */
  readonly view: IdentityView;
  /** The nonces the server has seen. `RequestNonces` is one such memory. */
  readonly nonces: SeenNonces;
}

/** A request that a mind has signed. */
export interface AuthenticatedRequest {
  /** The mind that signed it. */
  readonly mind: string;
  /** The key reference it signed with. */
  readonly keyid: string;
  /** The label of the signature that counted. */
  readonly label: string;
  /** The nonce, which this key cannot use again while the signature is valid. */
  readonly nonce: string;
  /** When the signature expires. */
  readonly expires: Instant;
}

/** One signature of a request, read from its header fields. */
interface Candidate {
  readonly label: string;
  readonly input: InnerList;
  readonly signature: Uint8Array;
}

/** A parameter of a kind, by name. */
function parameter<K extends "integer" | "string">(
  parameters: Parameters,
  wanted: string,
  kind: K,
): (K extends "integer" ? number : string) | undefined {
  const value = parameters.find(([given]) => given === wanted)?.[1];
  return value?.kind === kind ? (value.value as K extends "integer" ? number : string) : undefined;
}

/**
 * Layer 1, 13.3: judges the signature of a request.
 *
 * A request may carry several signatures. It is authenticated by the first
 * that passes, and if none passes the answer says why the first did not.
 * A signature passes if:
 *
 * - it covers `@method` and `@target-uri`, and `content-digest` when the
 *   request has a body, and the request's `Content-Digest` gives the
 *   SHA-256 of that body;
 * - it has `created`, `expires` at most 300 seconds later, and `nonce`;
 *   `created` is within 300 seconds of the server's clock, and it has not
 *   expired;
 * - its `alg`, if it gives one, is `ed25519`;
 * - its `keyid` is a key reference, the signature verifies under that key
 *   (core 4.4), and the key is a valid operational key of its mind under
 *   the current-state rule (6.1);
 * - that key has not used the nonce in a signature still valid.
 *
 * The nonce of a signature that passes is remembered, last, until the
 * signature expires. It never throws on the request.
 */
export function verifyRequest(
  request: HttpRequest,
  server: RequestVerifier,
): Validation<AuthenticatedRequest> {
  if (typeof (server.now as unknown) !== "bigint") throw new TypeError("now is not a time");
  const answer = judging(() => authenticated(request, server));
  // Remembered last, for an answer that stands (ADR-0004).
  if (answer.ok)
    server.nonces.remember(answer.value.keyid, answer.value.nonce, answer.value.expires);
  return answer;
}

function authenticated(
  request: HttpRequest,
  server: RequestVerifier,
): Validation<AuthenticatedRequest> {
  const candidates = signaturesOf(request);
  if (!candidates.ok) return candidates;
  let first: Validation<AuthenticatedRequest> | undefined;
  for (const candidate of candidates.value) {
    const judged = judgedSignature(request, candidate, server);
    if (judged.ok) return judged;
    first ??= judged;
  }
  return first ?? no("the request carries no signature", "L1 13.3", "/signature-input");
}

/** The signatures a request carries: each member of `Signature-Input` with its `Signature`. */
function signaturesOf(request: HttpRequest): Validation<Candidate[]> {
  if (
    typeof (request as { method?: unknown } | null)?.method !== "string" ||
    typeof request.url !== "string" ||
    !Array.isArray(request.headers) ||
    !request.headers.every(
      (header) =>
        Array.isArray(header) && typeof header[0] === "string" && typeof header[1] === "string",
    )
  ) {
    return no("a request has a method, a target URI and header fields", "L1 13.3");
  }
  const inputs = parseDictionary(field("signature-input", request));
  const signatures = parseDictionary(field("signature", request));
  if (inputs === undefined || signatures === undefined) {
    return no(
      "the request has no `Signature-Input` and `Signature` fields that can be read",
      "L1 13.3",
      "/signature-input",
    );
  }
  const found: Candidate[] = [];
  for (const [label, input] of inputs) {
    const signature = signatures.get(label);
    if (input.kind !== "list" || signature?.kind !== "item" || signature.value.kind !== "bytes") {
      continue;
    }
    found.push({ label, input, signature: signature.value.value });
  }
  return ok(found);
}

function judgedSignature(
  request: HttpRequest,
  { label, input, signature }: Candidate,
  server: RequestVerifier,
): Validation<AuthenticatedRequest> {
  const at = `/signature-input/${label}`;
  const covered = input.items.map((item) => (item.value.kind === "string" ? item.value.value : ""));
  const hasBody = request.body !== undefined && request.body.length > 0;
  for (const needed of ["@method", "@target-uri", ...(hasBody ? ["content-digest"] : [])]) {
    if (!covered.includes(needed)) {
      return no(`the signature does not cover ${JSON.stringify(needed)}`, "L1 13.3", at);
    }
  }
  const created = parameter(input.parameters, "created", "integer");
  const expires = parameter(input.parameters, "expires", "integer");
  const nonce = parameter(input.parameters, "nonce", "string");
  const keyid = parameter(input.parameters, "keyid", "string");
  if (
    created === undefined ||
    expires === undefined ||
    nonce === undefined ||
    keyid === undefined
  ) {
    return no("the signature lacks `created`, `expires`, `nonce` or `keyid`", "L1 13.3", at);
  }
  const alg = input.parameters.find(([given]) => given === "alg")?.[1];
  if (alg !== undefined && (alg.kind !== "string" || alg.value !== "ed25519")) {
    return no("the algorithm of a signature is `ed25519`", "L1 13.3", `${at}/alg`);
  }
  const dated = requestDates(created, expires, server.now, at);
  if (!dated.ok) return dated;
  if (covered.includes("content-digest") && !digestHolds(request)) {
    return no(
      "`Content-Digest` does not give the SHA-256 of the body",
      "L1 13.3",
      "/content-digest",
    );
  }
  const key = parseKeyRef(keyid);
  const publicKey = key === undefined ? undefined : decodeEd25519Multikey(key.key);
  if (key === undefined || publicKey?.ok !== true) {
    return no("`keyid` is not a key reference of a mind", "L1 13.3", `${at}/keyid`);
  }
  const base = signatureBase(request, input);
  if (!base.ok) return base;
  if (!verifyEd25519(signature, utf8(base.value), publicKey.value)) {
    return no("the signature does not verify", "L1 13.3", `/signature/${label}`);
  }
  const counted = requestKeyTime(key, dated.value.created, server.now, server.view);
  if (!counted.ok) return counted;
  if (server.nonces.seen(keyid, nonce)) {
    return no("this key has used this nonce already", "L1 13.3", `${at}/nonce`);
  }
  return ok({ mind: key.mind, keyid, label, nonce, expires: dated.value.expires });
}

/** RFC 9530: whether the request's `Content-Digest` has the SHA-256 of its body. */
function digestHolds(request: HttpRequest): boolean {
  const digest = parseDictionary(field("content-digest", request))?.get("sha-256");
  if (digest?.kind !== "item" || digest.value.kind !== "bytes") return false;
  return bytesEqual(digest.value.value, sha256(request.body ?? new Uint8Array(0)));
}

/**
 * Layer 1, 13.3: the nonces a server has seen, each remembered for as long
 * as the signature that used it is valid. It holds one entry for each
 * request authenticated in the last 300 seconds, so call `forget` as the
 * clock moves.
 */
export class RequestNonces implements SeenNonces {
  readonly #until = new Map<string, Instant>();

  /** How many nonces are remembered. */
  get size(): number {
    return this.#until.size;
  }

  seen(keyid: string, nonce: string): boolean {
    // A key reference has no space, so the two cannot run together.
    return this.#until.has(`${keyid} ${nonce}`);
  }

  remember(keyid: string, nonce: string, until: Instant): void {
    this.#until.set(`${keyid} ${nonce}`, until);
  }

  /**
   * Forgets every nonce whose signature has expired at `now`.
   *
   * @returns How many were forgotten.
   */
  forget(now: Instant): number {
    if (typeof (now as unknown) !== "bigint") throw new TypeError("now is not a time");
    let forgotten = 0;
    for (const [used, until] of this.#until) {
      if (until < now) {
        this.#until.delete(used);
        forgotten++;
      }
    }
    return forgotten;
  }
}
