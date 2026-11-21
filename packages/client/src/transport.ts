// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * How a client talks to a service over HTTPS. A service is a stranger:
 * whatever it answers is bounded in size and in time before it is read, and
 * read as a record before anything is made of it.
 *
 * Two kinds of failure are told apart. A service that speaks the protocol
 * and refuses says why, as a problem of core 10.2: that is an `OipError`
 * with the service's code. A service that cannot be reached, or that does
 * not speak the protocol, is a `TransportError`.
 */

import {
  MAX_RECORD_BYTES,
  MEDIA_TYPE,
  OipError,
  type OipRecord,
  parseJsonBytes,
  parseRecord,
  PROBLEM_MEDIA_TYPE,
  problemCode,
  utf8,
} from "@oip/core";
import type { JsonValue } from "@oip/schema";

/** What makes a request: `fetch`, or something that stands in for it. */
export type Fetch = (request: Request) => Promise<Response>;

/** What a client needs to talk to services. */
export interface TransportOptions {
  /** Default: the platform's `fetch`. */
  readonly fetch?: Fetch;
  /** How long a service has to answer, in milliseconds. Default: 10 seconds. */
  readonly timeoutMs?: number;
  /**
   * The most bytes of one answer that are read. Default: 8 MiB, which holds a
   * bundle with a long log. One record is never more than 1 MiB (core 1.6).
   */
  readonly maxBytes?: number;
}

/** The longest an answer may take, unless a client says otherwise. */
export const DEFAULT_TIMEOUT_MS = 10_000;
/** The most bytes of an answer that are read, unless a client says otherwise. */
export const DEFAULT_MAX_BYTES = 8 * MAX_RECORD_BYTES;
/** The most characters of a service's own words that are kept in an error. */
export const MAX_DETAIL_LENGTH = 256;

/** Why a service could not be talked to. */
export type TransportFailure =
  /** The URL is not an HTTPS URL a client asks. */
  | "url"
  /** No answer came: the name does not resolve, the connection failed, or it was redirected. */
  | "unreachable"
  /** No answer came in time. */
  | "timeout"
  /** The answer is longer than a client reads. */
  | "too-large"
  /** The answer is not what the protocol says a service answers. */
  | "not-oip";

/** Thrown when a service cannot be reached or does not speak the protocol. */
export class TransportError extends Error {
  /** The name of the error: `TransportError`. */
  override readonly name = "TransportError";
  /** What failed. */
  readonly failure: TransportFailure;
  /** The origin that was asked: never the path, which may name a mind. */
  readonly origin: string;
  /** The status the service answered with, if it answered. */
  readonly status: number | undefined;

  /**
   * @param failure - What failed.
   * @param origin - The origin that was asked.
   * @param detail - What happened, in words of the client's own.
   * @param status - The status the service answered with, if it answered.
   */
  constructor(failure: TransportFailure, origin: string, detail: string, status?: number) {
    super(`${origin}: ${detail}`);
    this.failure = failure;
    this.origin = origin;
    this.status = status;
  }
}

/** A request a client makes. */
export interface Asking {
  /** The method of the request. */
  readonly method: "GET" | "PUT" | "POST" | "DELETE";
  /** An HTTPS URL. */
  readonly url: string;
  /** What is sent, with its media type. */
  readonly body?: { readonly bytes: Uint8Array; readonly mediaType: string };
  /** Other headers: those of a signed request (Layer 1, 13.3). */
  readonly headers?: readonly (readonly [name: string, value: string])[];
}

/** What a service answered, read in full and bounded. */
export interface Answer {
  /** The origin that was asked. */
  readonly origin: string;
  /** The status of the answer. */
  readonly status: number;
  /** The media type of the body, in lower case and without parameters, or `""`. */
  readonly mediaType: string;
  /** The body, whole. */
  readonly body: Uint8Array;
  /** When the service says to ask again, as it wrote it, if it said. */
  readonly retryAfter: string | undefined;
}

/**
 * The origin of an HTTPS URL, or `undefined` if it is not one a client asks:
 * HTTPS, with no user information.
 */
export function httpsOrigin(url: string): string | undefined {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return undefined;
  }
  if (parsed.protocol !== "https:" || parsed.username !== "" || parsed.password !== "") {
    return undefined;
  }
  return parsed.origin;
}

/** What is said of a URL that is none, without repeating what a stranger wrote. */
const NO_ORIGIN = "a URL that is not HTTPS";

/**
 * Makes one request and reads the answer, bounded.
 *
 * - Only HTTPS is asked.
 * - A redirect is not followed: a service that moves says so in a record,
 *   which is signed, and not in a header, which is not.
 * - The body is read up to `maxBytes`, and the request is given up after
 *   `timeoutMs`, whichever a service tries first.
 *
 * @throws TransportError if no answer of that kind came.
 */
export async function exchange(asking: Asking, options: TransportOptions = {}): Promise<Answer> {
  const origin = httpsOrigin(asking.url);
  if (origin === undefined) {
    throw new TransportError("url", NO_ORIGIN, "only HTTPS URLs are asked");
  }
  const send = options.fetch ?? ((request: Request) => fetch(request));
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const signal = AbortSignal.timeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const headers = new Headers(asking.headers?.map(([name, value]) => [name, value]));
  headers.set("accept", `${MEDIA_TYPE}, ${PROBLEM_MEDIA_TYPE}, application/json`);
  if (asking.body !== undefined) headers.set("content-type", asking.body.mediaType);
  const timedOut = (): TransportError =>
    new TransportError("timeout", origin, "the service did not answer in time");
  let response: Response;
  try {
    response = await send(
      new Request(asking.url, {
        method: asking.method,
        headers,
        redirect: "error",
        signal,
        // The bytes are in memory of this program's own. A browser's types ask to be told so: a
        // body there may not be memory that is shared.
        ...(asking.body === undefined
          ? {}
          : { body: asking.body.bytes as Uint8Array<ArrayBuffer> }),
      }),
    );
  } catch {
    if (signal.aborted) throw timedOut();
    throw new TransportError("unreachable", origin, "the service could not be reached");
  }
  // What stands in for `fetch` may not know of `redirect`: a redirect that came through is refused here.
  if (response.status >= 300 && response.status < 400) {
    await response.body?.cancel();
    throw new TransportError(
      "unreachable",
      origin,
      "the service redirects, and a client follows no redirect",
      response.status,
    );
  }
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (declared > maxBytes) {
    await response.body?.cancel();
    throw new TransportError(
      "too-large",
      origin,
      "the answer is longer than is read",
      response.status,
    );
  }
  let body: Uint8Array;
  try {
    body = await readUpTo(response, maxBytes, origin);
  } catch (error) {
    if (error instanceof TransportError) throw error;
    if (signal.aborted) throw timedOut();
    throw new TransportError("unreachable", origin, "the answer broke off", response.status);
  }
  const type = response.headers.get("content-type") ?? "";
  const parameters = type.indexOf(";");
  return {
    origin,
    status: response.status,
    mediaType: (parameters < 0 ? type : type.slice(0, parameters)).trim().toLowerCase(),
    body,
    retryAfter: response.headers.get("retry-after") ?? undefined,
  };
}

/** The body of a response, or a `TransportError` once it is longer than `limit`. */
async function readUpTo(from: Response, limit: number, origin: string): Promise<Uint8Array> {
  if (from.body === null) return new Uint8Array();
  const reader = from.body.getReader() as ReadableStreamDefaultReader<Uint8Array>;
  const chunks: Uint8Array[] = [];
  let length = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.length;
    if (length > limit) {
      await reader.cancel();
      throw new TransportError(
        "too-large",
        origin,
        "the answer is longer than is read",
        from.status,
      );
    }
    chunks.push(value);
  }
  const whole = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    whole.set(chunk, offset);
    offset += chunk.length;
  }
  return whole;
}

/** A service's own words, cut short and with nothing in them that is not printable. */
function quoted(text: unknown): string | undefined {
  if (typeof text !== "string") return undefined;
  const plain = text.replace(/[^\x20-\x7e]/gu, " ").trim();
  if (plain === "") return undefined;
  return plain.length > MAX_DETAIL_LENGTH ? `${plain.slice(0, MAX_DETAIL_LENGTH - 1)}…` : plain;
}

/**
 * The error for an answer that is not a success.
 *
 * A problem of core 10.2 is an `OipError` with the service's code. Its
 * detail is the service's own words, which are a stranger's: they are cut
 * short and are never to be shown as anything but that.
 */
export function refusalOf(answer: Answer): Error {
  const { origin } = answer;
  if (answer.mediaType === PROBLEM_MEDIA_TYPE) {
    const parsed = parseJsonBytes(answer.body);
    const problem =
      parsed.ok && typeof parsed.value === "object" && parsed.value !== null
        ? (parsed.value as Readonly<Record<string, JsonValue>>)
        : undefined;
    const code = problemCode(problem?.["type"]);
    if (code !== undefined) {
      const said = quoted(problem?.["detail"]) ?? quoted(problem?.["title"]) ?? code;
      return new OipError(code, `${origin} answered: ${said}`);
    }
  }
  return new TransportError(
    "not-oip",
    origin,
    `the service answered ${String(answer.status)} with no problem of the protocol`,
    answer.status,
  );
}

/**
 * Asks a service for a record.
 *
 * @returns The record, read by the reader of `@oip/core`: well-formed JSON of
 *   the protocol's profile, with `oip` and `type`. It is not yet verified.
 * @throws OipError with the service's code if it refused, or `invalid-record`
 *   if what it served is not a record; TransportError if it could not be
 *   asked, or answered something else.
 */
export async function askRecord(
  asking: Asking,
  options: TransportOptions = {},
): Promise<OipRecord> {
  const answer = await exchange(asking, options);
  const { origin } = answer;
  if (answer.status < 200 || answer.status >= 300) throw refusalOf(answer);
  if (answer.mediaType !== MEDIA_TYPE) {
    throw new TransportError(
      "not-oip",
      origin,
      "the service answered with something that is not a record",
      answer.status,
    );
  }
  const record = parseRecord(answer.body, { maxLength: options.maxBytes ?? DEFAULT_MAX_BYTES });
  if (!record.ok) {
    const [first] = record.issues;
    throw new OipError(
      "invalid-record",
      `${origin} served what is not a record: ${first.message}`,
      {
        clause: first.clause,
        issues: record.issues,
      },
    );
  }
  return record.value;
}

/**
 * Asks a service for JSON that is not a record: what it says it stored, or
 * took in.
 *
 * @throws As `askRecord` does.
 */
export async function askJson(asking: Asking, options: TransportOptions = {}): Promise<JsonValue> {
  const answer = await exchange(asking, options);
  const { origin } = answer;
  if (answer.status < 200 || answer.status >= 300) throw refusalOf(answer);
  if (answer.mediaType !== "application/json" && answer.mediaType !== MEDIA_TYPE) {
    throw new TransportError(
      "not-oip",
      origin,
      "the service answered with something that is not JSON",
      answer.status,
    );
  }
  const parsed = parseJsonBytes(answer.body);
  if (!parsed.ok) {
    throw new TransportError(
      "not-oip",
      origin,
      "the service answered with broken JSON",
      answer.status,
    );
  }
  return parsed.value;
}

/** A record as the body of a request. */
export function recordBody(record: unknown): { bytes: Uint8Array; mediaType: string } {
  return { bytes: utf8(JSON.stringify(record)), mediaType: MEDIA_TYPE };
}
