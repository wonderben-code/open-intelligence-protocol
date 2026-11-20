// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * How the suite asks an implementation: HTTP requests, signed where a check
 * asks for it (Layer 1, 13.3), server-sent event streams and WebSockets.
 * Everything that comes back is read with a bound on its size and on the
 * time it may take, since what is tested may be broken.
 */

import { type Instant, MEDIA_TYPE, PROBLEMS, type ProblemCode, problemCode, utf8 } from "@oip/core";
import { signRequest } from "@oip/net";

import type { Randomness, WireMind } from "./minds.ts";
import { word } from "./minds.ts";
import { expect, Failed } from "./report.ts";

/** The most bytes of an answer the suite reads. */
const MAX_ANSWER_BYTES = 16 * 1024 * 1024;
/** How often a request the implementation rate-limits is asked again, and the longest wait before each. */
const RATE_LIMIT_RETRIES = 5;
const MAX_RETRY_AFTER_MS = 15_000;

/** What every profile's run is given. */
export interface WireOptions {
  /** Where to connect: the base URL of the implementation, such as `https://resolver.example`. */
  readonly target: string;
  /**
   * The origin the implementation knows itself by, which a signed request and
   * a `Hello` name (Layer 1, 13.3). The origin of `target` unless given: it
   * differs where the suite reaches a test deployment by another address.
   */
  readonly origin?: string;
  /** The clock, in nanoseconds since the Unix epoch. The machine's unless given. */
  readonly clock?: () => Instant;
  /** Where the suite's keys and nonces come from. The platform's generator unless given. */
  readonly randomness?: Randomness;
  /** `fetch`. The platform's unless given. */
  readonly fetch?: typeof fetch;
  /** The `WebSocket` class. The platform's unless given. */
  readonly webSocket?: typeof WebSocket;
  /** How long the implementation may take over one answer, in milliseconds. 10 seconds unless given. */
  readonly timeoutMs?: number;
}

/** A request as it is sent. */
export interface WireRequest {
  readonly method: string;
  /** The path and query, from the implementation's origin. */
  readonly path: string;
  readonly headers: readonly (readonly [string, string])[];
  readonly body?: Uint8Array;
}

/** What a request is made of besides its method and path. */
export interface WireAsking {
  /** The body: bytes or text as they are, anything else as JSON. */
  readonly body?: unknown;
  /** The body's media type. `application/oip+json` unless given. */
  readonly type?: string;
  readonly headers?: Readonly<Record<string, string>>;
  /** The mind that signs the request (Layer 1, 13.3). */
  readonly signedBy?: WireMind;
  /** Parameters of the signature other than the ones the client would choose. */
  readonly signature?: { readonly created?: Instant; readonly expires?: Instant };
}

/** An answer, read in full. */
export interface WireAnswer {
  readonly status: number;
  readonly headers: Headers;
  readonly bytes: Uint8Array;
  readonly text: string;
  /** The body as JSON, or `undefined` if it is not JSON. */
  readonly json: unknown;
}

/** An event of a server-sent event stream. */
export interface WireStreamEvent {
  /** The event's `id` field, if it has one. */
  readonly id: string | undefined;
  /** The event's `data` lines, joined by line feeds. */
  readonly data: string;
}

/** An open server-sent event stream. */
export interface WireStream {
  readonly status: number;
  readonly headers: Headers;
  /** The next event, or `undefined` if none comes within `timeoutMs` or the stream has ended. */
  next(timeoutMs?: number): Promise<WireStreamEvent | undefined>;
  close(): void;
}

/** What comes from a WebSocket: a text message, or its close. */
export type WireFrame =
  { readonly message: string } | { readonly closed: number; readonly reason: string };

/** An open WebSocket. */
export interface WireSocket {
  /** The subprotocol the server chose. */
  readonly protocol: string;
  /** The next message or the close, or `undefined` if neither comes within `timeoutMs`. */
  next(timeoutMs?: number): Promise<WireFrame | undefined>;
  send(text: string): void;
  close(): void;
}

const systemClock = (): Instant => BigInt(Date.now()) * 1_000_000n;
const systemRandomness: Randomness = (bytes) => crypto.getRandomValues(new Uint8Array(bytes));

const wait = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** Asks one implementation. */
export class WireClient {
  /** Where the suite connects, without a trailing slash. */
  readonly target: string;
  /** The origin the implementation knows itself by. */
  readonly origin: string;
  /** The clock: nanoseconds since the Unix epoch. */
  readonly now: () => Instant;
  /** Where keys, nonces and the words of a run come from. */
  readonly random: Randomness;
  /** How long the implementation may take over one answer, in milliseconds. */
  readonly timeoutMs: number;
  readonly #fetch: typeof fetch;
  readonly #webSocket: typeof WebSocket;

  constructor(options: WireOptions) {
    this.target = options.target.replace(/\/+$/u, "");
    this.origin = options.origin ?? new URL(this.target).origin;
    this.now = options.clock ?? systemClock;
    this.random = options.randomness ?? systemRandomness;
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.#fetch = options.fetch ?? fetch;
    this.#webSocket = options.webSocket ?? WebSocket;
  }

  /** The path of a URL the implementation gave under its own origin, or `undefined` if it is elsewhere. */
  pathOf(url: string): string | undefined {
    return url.startsWith(`${this.origin}/`) ? url.slice(this.origin.length) : undefined;
  }

  /** A request, signed if `asking` says by whom. Sending it twice sends the same signature twice. */
  async prepare(method: string, path: string, asking: WireAsking = {}): Promise<WireRequest> {
    const body = bodyOf(asking.body);
    const headers: [string, string][] = Object.entries(asking.headers ?? {});
    if (body !== undefined) headers.push(["content-type", asking.type ?? MEDIA_TYPE]);
    if (asking.signedBy !== undefined) {
      const created = asking.signature?.created ?? this.now();
      const added = await signRequest(
        // What is signed is the URL as the implementation knows it.
        { method, url: `${this.origin}${path}`, headers, ...(body === undefined ? {} : { body }) },
        {
          keyRef: asking.signedBy.keyRef,
          created,
          nonce: word(this.random, 16),
          ...(asking.signature?.expires === undefined ? {} : { expires: asking.signature.expires }),
        },
        asking.signedBy.signer,
      );
      headers.push(...added);
    }
    return { method, path, headers, ...(body === undefined ? {} : { body }) };
  }

  /** Sends a request and reads the answer. One that is rate-limited is sent again after the wait asked for. */
  async send(prepared: WireRequest): Promise<WireAnswer> {
    for (let attempt = 0; ; attempt++) {
      const answer = await this.#once(prepared);
      if (answer.status !== 429 || attempt === RATE_LIMIT_RETRIES) return answer;
      const seconds = Number(answer.headers.get("retry-after") ?? "1");
      await wait(Math.min(MAX_RETRY_AFTER_MS, Number.isFinite(seconds) ? seconds * 1000 : 1000));
    }
  }

  async #once(prepared: WireRequest): Promise<WireAnswer> {
    const response = await this.#fetch(`${this.target}${prepared.path}`, {
      method: prepared.method,
      headers: prepared.headers.map(([name, value]) => [name, value] as [string, string]),
      ...(prepared.body === undefined ? {} : { body: prepared.body }),
      redirect: "manual",
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    const bytes = await bounded(response);
    const text = new TextDecoder().decode(bytes);
    let json: unknown;
    try {
      json = JSON.parse(text) as unknown;
    } catch {
      json = undefined;
    }
    return { status: response.status, headers: response.headers, bytes, text, json };
  }

  /** Prepares a request and sends it. */
  async ask(method: string, path: string, asking: WireAsking = {}): Promise<WireAnswer> {
    return this.send(await this.prepare(method, path, asking));
  }

  /** Opens a server-sent event stream. */
  async stream(path: string, headers: Readonly<Record<string, string>> = {}): Promise<WireStream> {
    const abort = new AbortController();
    const opening = setTimeout(() => {
      abort.abort();
    }, this.timeoutMs);
    let response: Response;
    try {
      response = await this.#fetch(`${this.target}${path}`, {
        headers: { accept: "text/event-stream", ...headers },
        redirect: "manual",
        signal: abort.signal,
      });
    } finally {
      clearTimeout(opening);
    }
    const reader = response.body?.getReader();
    const decoder = new TextDecoder();
    const events: WireStreamEvent[] = [];
    let text = "";
    let ended = reader === undefined;
    let reading: Promise<void> | undefined;
    /** Reads one chunk and keeps the events it completes. */
    const read = async (): Promise<void> => {
      const chunk = (await reader?.read().catch(() => undefined)) as
        { done: boolean; value?: Uint8Array } | undefined;
      if (chunk === undefined || chunk.done) {
        ended = true;
        return;
      }
      text += decoder.decode(chunk.value ?? new Uint8Array(0), { stream: true });
      if (text.length > MAX_ANSWER_BYTES) throw new Failed("the stream sent an event without end");
      for (;;) {
        const end = /\r?\n\r?\n/u.exec(text);
        if (end === null) break;
        const event = eventOf(text.slice(0, end.index));
        text = text.slice(end.index + end[0].length);
        if (event !== undefined) events.push(event);
      }
    };
    return {
      status: response.status,
      headers: response.headers,
      next: async (timeoutMs = this.timeoutMs) => {
        const deadline = Date.now() + timeoutMs;
        while (events.length === 0 && !ended) {
          const left = deadline - Date.now();
          if (left <= 0) return undefined;
          reading ??= read().finally(() => (reading = undefined));
          await Promise.race([reading, wait(left)]);
        }
        return events.shift();
      },
      close: () => {
        ended = true;
        abort.abort();
      },
    };
  }

  /**
   * Opens a WebSocket.
   *
   * @param path - The path from the implementation's origin.
   * @throws Failed if the connection is not made in time.
   */
  async socket(path: string, protocol: string): Promise<WireSocket> {
    const url = `${this.target.replace(/^http/u, "ws")}${path}`;
    const ws = new this.#webSocket(url, protocol);
    const frames: WireFrame[] = [];
    let waiting: (() => void) | undefined;
    const arrived = (frame: WireFrame): void => {
      frames.push(frame);
      waiting?.();
    };
    ws.addEventListener("message", (event: MessageEvent) => {
      arrived({ message: typeof event.data === "string" ? event.data : "" });
    });
    ws.addEventListener("close", (event: CloseEvent) => {
      arrived({ closed: event.code, reason: event.reason });
    });
    const opened = await Promise.race([
      new Promise<boolean>((resolve) => {
        ws.addEventListener("open", () => {
          resolve(true);
        });
        ws.addEventListener("error", () => {
          resolve(false);
        });
      }),
      wait(this.timeoutMs).then(() => false),
    ]);
    if (!opened) {
      ws.close();
      throw new Failed(`no WebSocket with subprotocol ${protocol} could be opened at ${path}`);
    }
    return {
      protocol: ws.protocol,
      next: async (timeoutMs = this.timeoutMs) => {
        if (frames.length === 0) {
          await Promise.race([
            new Promise<void>((resolve) => (waiting = resolve)),
            wait(timeoutMs),
          ]);
          waiting = undefined;
        }
        return frames.shift();
      },
      send: (text) => {
        ws.send(text);
      },
      close: () => {
        ws.close();
      },
    };
  }
}

function bodyOf(body: unknown): Uint8Array | undefined {
  if (body === undefined) return undefined;
  if (body instanceof Uint8Array) return body;
  return utf8(typeof body === "string" ? body : JSON.stringify(body));
}

/** The body of a response, up to the most the suite reads. */
async function bounded(response: Response): Promise<Uint8Array> {
  const reader = response.body?.getReader();
  if (reader === undefined) return new Uint8Array(0);
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = (await reader.read()) as { done: boolean; value?: Uint8Array };
    if (done || value === undefined) break;
    size += value.length;
    if (size > MAX_ANSWER_BYTES) {
      await reader.cancel();
      throw new Failed(`the answer is longer than ${MAX_ANSWER_BYTES} bytes`);
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let at = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, at);
    at += chunk.length;
  }
  return bytes;
}

/** One event of a stream, from the lines between two blank lines. A block of comments alone is no event. */
function eventOf(block: string): WireStreamEvent | undefined {
  let id: string | undefined;
  const data: string[] = [];
  for (const line of block.split(/\r?\n/u)) {
    if (line.startsWith(":")) continue;
    const colon = line.indexOf(":");
    const field = colon === -1 ? line : line.slice(0, colon);
    const value = colon === -1 ? "" : line.slice(colon + 1).replace(/^ /u, "");
    if (field === "id") id = value;
    if (field === "data") data.push(value);
  }
  return data.length === 0 ? undefined : { id, data: data.join("\n") };
}

/**
 * Requires that an answer is the problem of core 10.2 with this code: its
 * HTTP status, and RFC 9457 problem details whose `type` is `urn:oip:error:<code>`.
 *
 * @throws Failed if it is not.
 */
export function expectProblem(answer: WireAnswer, code: ProblemCode, when: string): void {
  const { status } = PROBLEMS[code];
  const given = problemCode((answer.json as { type?: unknown } | undefined)?.type);
  expect(
    answer.status === status && given === code,
    `${when}: required ${status} with type urn:oip:error:${code}; got ${describe(answer)}`,
  );
  const type = answer.headers.get("content-type") ?? "";
  expect(
    type.split(";")[0]?.trim().toLowerCase() === "application/problem+json",
    `${when}: a problem is served as application/problem+json (RFC 9457); got "${type}"`,
  );
}

/**
 * Requires that an answer refuses the request with one of the problems of
 * core 10.2, whichever: for refusals whose code the specification leaves open.
 *
 * @throws Failed if it does not.
 */
export function expectRefused(answer: WireAnswer, when: string): void {
  const given = problemCode((answer.json as { type?: unknown } | undefined)?.type);
  expect(
    answer.status >= 400 && answer.status < 500 && given !== undefined,
    `${when}: required a refusal with a problem of core 10.2; got ${describe(answer)}`,
  );
  expect(
    PROBLEMS[given].status === answer.status,
    `${when}: the status of a problem is the one core 10.2 gives its code; got ${describe(answer)}`,
  );
}

/**
 * Requires a status.
 *
 * @throws Failed if the answer has another.
 */
export function expectStatus(answer: WireAnswer, status: number, when: string): void {
  expect(answer.status === status, `${when}: required ${status}; got ${describe(answer)}`);
}

/** An answer in a line, for the detail of a failure. */
export function describe(answer: WireAnswer): string {
  const body = answer.text.length > 300 ? `${answer.text.slice(0, 300)}…` : answer.text;
  return `${answer.status}${body === "" ? "" : ` ${body}`}`;
}
