// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Resolving `did:oip` (Layer 1, Section 5), in the shape the DID Resolution
 * specification gives a result, and as a driver for the DIF `did-resolver`
 * library.
 *
 * A `did:oip` address is resolved by asking resolvers for the mind's
 * identity log, verifying the log, and replaying it. Nothing is taken on a
 * resolver's word: a log that does not verify gives no document. This
 * module runs anywhere the client does, a browser too.
 */

import { Lookup, type LookupOptions, TransportError } from "@oip/client";
import { isMindAddress, OipError } from "@oip/core";
import { didDocument, type DidDocument, type DidDocumentMetadata } from "@oip/identity";

/** The one representation of a DID document this method has: JSON (DID Core, 6.2). */
export const DID_JSON = "application/did+json";

/** The errors of a resolution (DID Resolution, Section 10), as far as this method gives them. */
export type DidResolutionError =
  "invalidDid" | "notFound" | "representationNotSupported" | "methodNotSupported" | "internalError";

/**
 * A thing whose lists can be written to: the tools of the DID ecosystem
 * declare their documents so, and a result is theirs to keep.
 */
export type Writable<T> = T extends readonly (infer Item)[]
  ? Writable<Item>[]
  : T extends object
    ? { -readonly [Key in keyof T]: Writable<T[Key]> }
    : T;

/** What a resolution says of itself. */
export interface DidResolutionMetadata {
  /** The media type of the document, where there is one. */
  readonly contentType?: typeof DID_JSON;
  /** Why there is no document. */
  readonly error?: DidResolutionError;
  /** The same in words, for a person. */
  readonly message?: string;
}

/**
 * The result of resolving a DID (DID Resolution, Section 4). It is the
 * `DIDResolutionResult` of the DIF `did-resolver` library.
 */
export interface DidResolutionResult {
  readonly didResolutionMetadata: DidResolutionMetadata;
  /** The document (Layer 1, 5.2), or `null` where there is none. */
  readonly didDocument: Writable<DidDocument> | null;
  /** What the log holds and the document does not (Layer 1, 5.2). Empty where there is no document. */
  readonly didDocumentMetadata: Writable<DidDocumentMetadata> | Record<string, never>;
}

/** A DID URL as the DIF `did-resolver` library has parsed it: what a driver is given. */
export interface ParsedDid {
  readonly did: string;
  readonly didUrl: string;
  readonly method: string;
  readonly id: string;
  readonly path?: string;
  readonly fragment?: string;
  readonly query?: string;
}

/** A driver of the DIF `did-resolver` library: its `DIDResolver`. */
export type DidResolver = (
  did: string,
  parsed: ParsedDid,
  resolver: unknown,
  options: { readonly accept?: string },
) => Promise<DidResolutionResult>;

const none = (error: DidResolutionError, message: string): DidResolutionResult => ({
  didResolutionMetadata: { error, message },
  didDocument: null,
  didDocumentMetadata: {},
});

/** Whether a caller that names what it accepts would take the JSON representation. */
function takesJson(accept: string | undefined): boolean {
  if (accept === undefined || accept.trim() === "") return true;
  return accept
    .split(",")
    .map((range) => (range.split(";")[0] ?? "").trim().toLowerCase())
    .some(
      (type) =>
        type === DID_JSON ||
        type === "application/json" ||
        type === "*/*" ||
        type === "application/*",
    );
}

/**
 * Resolves a `did:oip` DID, or a DID URL of one.
 *
 * Of a DID URL the DID is resolved, with the parameter `versionId` if it
 * has one (Layer 1, 2.4): the document is then of the log up to that event,
 * and its keys are named as a proof pinned to that version names them. A
 * path or a fragment is the caller's to follow: the document it is followed
 * in is the same.
 *
 * The aliases a mind lists are not shown: a document shows the aliases that
 * were verified in both directions (Layer 1, 5.3), and this driver fetches
 * from nowhere but the resolvers it is given. `Lookup.aliases` of
 * `@oip/client` verifies them.
 *
 * Nothing a DID or a resolver can do makes it throw: what goes wrong is in
 * the result. A mistake in the options is the caller's own, and is thrown.
 *
 * @param didUrl - The DID or DID URL.
 * @param options - The resolvers to ask, and how: what a `Lookup` takes.
 * @param accept - The media types the caller takes. Default: any.
 */
export async function resolveDid(
  didUrl: string,
  options: LookupOptions,
  accept?: string,
): Promise<DidResolutionResult> {
  const [beforeFragment = ""] = didUrl.split("#");
  const [beforeQuery = "", query = ""] = beforeFragment.split("?");
  const [did = ""] = beforeQuery.split("/");
  if (!did.startsWith("did:oip:")) {
    return none("methodNotSupported", "This driver resolves did:oip, and no other method.");
  }
  if (!isMindAddress(did)) {
    return none("invalidDid", "That is no did:oip address: did:oip: and 56 characters of base32.");
  }
  if (!takesJson(accept)) {
    return none(
      "representationNotSupported",
      `A did:oip document is represented as ${DID_JSON}, and in no other way.`,
    );
  }
  const versionId = new URLSearchParams(query).get("versionId");
  try {
    // A lookup of its own for each resolution: nothing one caller asked about is kept for another.
    const resolved = await new Lookup(options).resolve(did);
    let resolution = resolved.did;
    if (versionId !== null) {
      // The document of the log up to that event, with its keys named as a proof pinned to the
      // version names them. Where the mind takes packets is said of now alone, by its location
      // record: it is part of the document of the latest version, and of no earlier one.
      const latest = versionId === resolved.state.versionId;
      const endpoints = resolved.location?.record.endpoints.map(({ url }) => url);
      const pinned = didDocument(resolved.log, {
        versionId,
        ...(latest && endpoints !== undefined ? { endpoints } : {}),
      });
      if (!pinned.ok) return none("notFound", "versionId names no event of the mind's log.");
      resolution = pinned.value;
    }
    // A copy of its own: what a caller does with a result changes nothing of the next.
    const copied = structuredClone(resolution) as Writable<typeof resolution>;
    return {
      didResolutionMetadata: { contentType: DID_JSON },
      didDocument: copied.didDocument,
      didDocumentMetadata: copied.didDocumentMetadata,
    };
  } catch (error) {
    if (error instanceof OipError && error.code === "not-found") {
      return none("notFound", "No resolver that was asked holds that mind.");
    }
    if (error instanceof OipError) {
      // What a resolver served does not verify: there is no document to give.
      return none("internalError", `The mind's log could not be verified: ${error.code}.`);
    }
    if (error instanceof TransportError) {
      return none("internalError", `No resolver could be asked: ${error.failure}.`);
    }
    throw error;
  }
}

/**
 * The driver for the DIF `did-resolver` library:
 *
 * ```ts
 * import { Resolver } from "did-resolver";
 * import { getResolver } from "@oip/did-resolver";
 *
 * const resolver = new Resolver(getResolver({ resolvers: ["https://resolver.example"] }));
 * const { didDocument } = await resolver.resolve("did:oip:…");
 * ```
 *
 * @param options - The resolvers to ask, and how: what a `Lookup` of
 *   `@oip/client` takes. Name two, run by different people.
 */
export function getResolver(options: LookupOptions): { readonly oip: DidResolver } {
  return {
    oip: (_did, parsed, _resolver, asked) => resolveDid(parsed.didUrl, options, asked.accept),
  };
}
