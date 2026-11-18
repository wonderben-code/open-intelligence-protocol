// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What every OIP endpoint does with a request before it is anybody's
 * business, and with a failure after: the size of a body is bounded before
 * it is read (BUILD.md 3.7), a record is read by the reader of `@oip/core`
 * and by nothing else, and an error leaves as RFC 9457 problem details
 * (core 10.2) that say nothing a caller should not see.
 *
 * It works on the `Request` and `Response` of the web platform, so a
 * handler is a function a test can call.
 */

import {
  MEDIA_TYPE,
  OipError,
  type OipRecord,
  parseRecord,
  PROBLEM_MEDIA_TYPE,
  type ProblemDetails,
} from "@oip/core";
import { cutShort, IMPLEMENTATION_LIMIT } from "@oip/schema";

import { isBusy } from "./storage.ts";

/**
 * A failure that is not the request's fault and will pass: a check that was
 * cut short (ADR-0010), or a database another writer holds. The answer is
 * 503, and the client asks again.
 */
export class Unavailable extends Error {
  /** After how many seconds to ask again. */
  readonly retryAfter: number;

  constructor(message: string, retryAfter = 1) {
    super(message);
    this.name = "Unavailable";
    this.retryAfter = retryAfter;
  }
}

/** An HTTP failure that core 10.2 has no code for: the method, the media type. */
export class HttpFailure extends Error {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;

  constructor(status: number, title: string, headers: Readonly<Record<string, string>> = {}) {
    super(title);
    this.name = "HttpFailure";
    this.status = status;
    this.headers = headers;
  }
}

/** The response for problem details. */
export function problemResponse(
  problem: ProblemDetails,
  headers: Readonly<Record<string, string>> = {},
): Response {
  return new Response(JSON.stringify(problem), {
    status: problem.status,
    headers: { ...headers, "content-type": PROBLEM_MEDIA_TYPE },
  });
}

/** A problem that is none of core 10.2: RFC 9457's `about:blank`, whose title is the status's own. */
function plainProblem(status: number, title: string): ProblemDetails {
  return { type: "about:blank", title, status };
}

/**
 * The response for whatever a handler threw.
 *
 * An `OipError` is the caller's fault, and says so in the terms of core
 * 10.2. Anything else is ours: the answer is a 500 that says nothing of
 * what failed, since what an unexpected error carries is not known to be
 * fit to send. The caller logs it.
 *
 * @returns The response, and whether the failure was one nobody expected.
 */
export function responseFor(error: unknown): { response: Response; unexpected: boolean } {
  if (error instanceof OipError) {
    return { response: problemResponse(error.toProblem()), unexpected: false };
  }
  if (error instanceof HttpFailure) {
    return {
      response: problemResponse(plainProblem(error.status, error.message), error.headers),
      unexpected: false,
    };
  }
  if (error instanceof Unavailable || isBusy(error)) {
    const retryAfter = error instanceof Unavailable ? error.retryAfter : 1;
    return {
      response: problemResponse(plainProblem(503, "Service Unavailable"), {
        "retry-after": String(retryAfter),
      }),
      unexpected: false,
    };
  }
  return {
    response: problemResponse(plainProblem(500, "Internal Server Error")),
    unexpected: true,
  };
}

/** A record, or any other JSON an endpoint answers with, as `application/oip+json`. */
export function recordResponse(
  body: unknown,
  status = 200,
  headers: Readonly<Record<string, string>> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...headers, "content-type": MEDIA_TYPE },
  });
}

/** The media type of a request's body, without its parameters, in lower case. */
function mediaType(request: Request): string {
  return (request.headers.get("content-type") ?? "").split(";", 1)[0]?.trim().toLowerCase() ?? "";
}

/**
 * Reads a request's body, which is at most `limit` bytes.
 *
 * A body that declares more is refused before a byte of it is read. One
 * that declares nothing, or less than it sends, is read up to the limit and
 * no further.
 *
 * @throws OipError `too-large` if the body is longer than `limit` bytes.
 */
export async function readBody(request: Request, limit: number): Promise<Uint8Array> {
  if (!Number.isSafeInteger(limit) || limit < 0)
    throw new TypeError("a limit is a number of bytes");
  const tooLarge = (): OipError =>
    new OipError(
      "too-large",
      `the body is longer than ${limit} bytes, the most this endpoint reads`,
    );
  const declared = request.headers.get("content-length");
  if (declared !== null && /^\d+$/u.test(declared) && Number(declared) > limit) throw tooLarge();
  if (request.body === null) return new Uint8Array(0);
  const reader = (request.body as ReadableStream<Uint8Array>).getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.length;
    if (length > limit) {
      // The rest is not read. The sender is told to stop.
      await reader.cancel();
      throw tooLarge();
    }
    chunks.push(value);
  }
  const body = new Uint8Array(length);
  let at = 0;
  for (const chunk of chunks) {
    body.set(chunk, at);
    at += chunk.length;
  }
  return body;
}

/**
 * Reads the record a request carries (core 10.1): well formed, of the JSON
 * profile, within the limits of core 1.6. Its proofs are not verified here.
 *
 * @param limit - The most bytes read. A record's canonical form is at most
 *   1 MiB, and the text sent may be longer: `MAX_TEXT_LENGTH` of
 *   `@oip/core` is what its reader accepts.
 * @throws HttpFailure 415 if the body is not `application/oip+json`.
 * @throws OipError `too-large` or `invalid-record`.
 * @throws Unavailable if the check was cut short (ADR-0010): that says
 *   nothing of the record.
 */
export async function readRecord(request: Request, limit: number): Promise<OipRecord> {
  if (mediaType(request) !== MEDIA_TYPE) {
    throw new HttpFailure(415, "Unsupported Media Type", { accept: MEDIA_TYPE });
  }
  const parsed = parseRecord(await readBody(request, limit), { maxLength: limit });
  if (parsed.ok) return parsed.value;
  if (parsed === cutShort()) throw new Unavailable("the record could not be judged just now");
  const [first] = parsed.issues;
  // The reader's own limits on a text are the size limit of core 1.6, met early.
  const code = first.clause === IMPLEMENTATION_LIMIT ? "too-large" : "invalid-record";
  throw new OipError(code, first.message, { clause: first.clause, issues: parsed.issues });
}
