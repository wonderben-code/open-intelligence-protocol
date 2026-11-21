// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The HTTP interface of a DID resolver (DID Resolution, Section 11), as a
 * driver of the DIF Universal Resolver has it:
 *
 *     GET /1.0/identifiers/<DID or DID URL>
 *
 * This is the protocol alone: a request is a method, a path and what the
 * caller accepts, and the answer is a status, headers and a body. It runs
 * anywhere. `serve` puts it on a port.
 */

import type { LookupOptions } from "@oip/client";

import { DID_JSON, type DidResolutionError, resolveDid } from "./driver.ts";

/** A request, as it arrived. */
export interface Asking {
  /** The HTTP method. */
  readonly method: string;
  /** The path of the URL, with its query if it has one. */
  readonly path: string;
  /** The `Accept` header, if there was one. */
  readonly accept?: string;
}

/** What is answered. */
export interface Answer {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}

/** The media type of a whole resolution result (DID Resolution, 11.1). */
export const RESOLUTION_RESULT = 'application/ld+json;profile="https://w3id.org/did-resolution"';

const PREFIX = "/1.0/identifiers/";
/** The status of each error (DID Resolution, 11.1). */
const STATUS: Readonly<Record<DidResolutionError, number>> = {
  invalidDid: 400,
  notFound: 404,
  representationNotSupported: 406,
  methodNotSupported: 501,
  internalError: 500,
};

const text = (status: number, body: string): Answer => ({
  status,
  headers: { "content-type": "text/plain; charset=utf-8" },
  body,
});

/** What a caller asks for, by what it says it accepts: the whole result of resolving, the document, or neither. */
function asksFor(accept: string | undefined): "result" | "document" | "neither" {
  const types = (accept ?? "")
    .split(",")
    .map((range) => (range.split(";")[0] ?? "").trim().toLowerCase())
    .filter((type) => type !== "");
  if (
    types.length === 0 ||
    types.some((type) =>
      ["application/ld+json", "application/did-resolution", "*/*"].includes(type),
    )
  ) {
    return "result";
  }
  return types.some((type) => type === DID_JSON || type === "application/json")
    ? "document"
    : "neither";
}

/**
 * Answers one request of the resolver's HTTP interface.
 *
 * A caller that asks for `application/did+json` is given the document. One
 * that asks for the result of resolving, or says nothing of what it
 * accepts, is given the whole result: the document, with what the
 * resolution and the log say besides. One that takes neither is answered
 * with 406. A mind that is retired is answered with 410, and its document
 * all the same.
 *
 * @param options - The resolvers to ask, and how: what a `Lookup` of `@oip/client` takes.
 */
export async function handle(asked: Asking, options: LookupOptions): Promise<Answer> {
  const url = new URL(asked.path, "http://resolver.invalid");
  if (url.pathname === "/healthz") return text(200, "ok\n");
  if (url.pathname === "/1.0/methods") {
    return { status: 200, headers: { "content-type": "application/json" }, body: '["oip"]' };
  }
  if (!url.pathname.startsWith(PREFIX)) return text(404, "Not found.\n");
  if (asked.method !== "GET") return text(405, "Method not allowed.\n");
  const wanted = asksFor(asked.accept);
  let didUrl: string;
  try {
    const named = decodeURIComponent(url.pathname.slice(PREFIX.length));
    // The parameters of a DID URL come inside the name, or after it as the query of the request.
    didUrl = named.includes("?") || url.search === "" ? named : `${named}${url.search}`;
  } catch {
    // What cannot be read as a name at all: the resolution says that it is no DID of this method.
    didUrl = "did:oip:";
  }
  // A caller that takes neither the result nor the document in JSON is told so, as a result.
  const result = await resolveDid(didUrl, options, wanted === "neither" ? asked.accept : undefined);
  const { error } = result.didResolutionMetadata;
  const retired = result.didDocumentMetadata.deactivated;
  const status = error === undefined ? (retired ? 410 : 200) : STATUS[error];
  if (wanted === "document" && error === undefined) {
    return {
      status,
      headers: { "content-type": DID_JSON },
      body: JSON.stringify(result.didDocument),
    };
  }
  return {
    status,
    headers: { "content-type": RESOLUTION_RESULT },
    body: JSON.stringify({ "@context": "https://w3id.org/did-resolution/v1", ...result }),
  };
}
