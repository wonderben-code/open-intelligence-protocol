// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Fuzzing a service's HTTP interface: requests made to confuse it, and what
 * every answer must be all the same. A service is asked in its own process,
 * as `app.fetch`, so a campaign of any length needs no socket.
 *
 * A campaign that sends only rubbish tests only the first check a request
 * meets. So most requests here start from one the service would take, with
 * something done to it: a member dropped or changed, a value nested deep,
 * a body cut short, a header that says something else.
 */

import { PROBLEM_MEDIA_TYPE, problemCode, PROBLEMS } from "@oip/core";
import fc from "fast-check";

/** A request as a campaign makes one. */
export interface FuzzedRequest {
  readonly method: string;
  /** The path and query. */
  readonly path: string;
  readonly headers: readonly (readonly [string, string])[];
  readonly body?: Uint8Array;
}

/** A request the service would take, for a campaign to start from. */
export interface Seed {
  readonly method: string;
  readonly path: string;
  readonly headers?: readonly (readonly [string, string])[];
  /** The body as a JSON value, if the request has one. */
  readonly json?: unknown;
}

/** How many requests a campaign makes: `OIP_FUZZ_RUNS`, or `fallback`. */
export function fuzzRuns(fallback: number): number {
  const asked = Number(process.env["OIP_FUZZ_RUNS"] ?? "");
  return Number.isInteger(asked) && asked > 0 ? asked : fallback;
}

/**
 * How a campaign is run: its length, and where its requests come from.
 *
 * The short campaign that every run of the tests makes starts from one seed,
 * so that it asks the same things each time and says the same of them. A
 * campaign whose length is set with `OIP_FUZZ_RUNS` starts from a seed of
 * its own each time, and so asks what no campaign has asked before.
 */
export function campaign(fallback: number): { numRuns: number; seed?: number } {
  return process.env["OIP_FUZZ_RUNS"] === undefined
    ? { numRuns: fallback, seed: 20_261_120 }
    : { numRuns: fuzzRuns(fallback) };
}

/** How long a campaign of this length may take, in milliseconds: room for a slow machine. */
export function campaignTimeout(fallback: number): number {
  return Math.max(60_000, fuzzRuns(fallback) * 50);
}

/** Counts the statuses a campaign was answered with, so that a test can see it went deep. */
export class Statuses {
  readonly #seen = new Map<number, number>();

  /** Notes one answer. */
  note(status: number): void {
    this.#seen.set(status, (this.#seen.get(status) ?? 0) + 1);
  }

  /** The statuses seen, in order. */
  get seen(): number[] {
    return [...this.#seen.keys()].toSorted((a, b) => a - b);
  }
}

type Step = string | number;

/** Every place in a JSON value: the steps from the value to each thing in it. */
function places(value: unknown, at: Step[] = [], found: Step[][] = []): Step[][] {
  found.push(at);
  if (Array.isArray(value)) {
    value.forEach((item, index) => places(item, [...at, index], found));
  } else if (typeof value === "object" && value !== null) {
    for (const [name, member] of Object.entries(value)) places(member, [...at, name], found);
  }
  return found;
}

/** A copy of a JSON value with what is at one place given by `change`. `undefined` removes it. */
function changed(value: unknown, at: readonly Step[], change: (old: unknown) => unknown): unknown {
  const [step, ...rest] = at;
  if (step === undefined) return change(value);
  if (Array.isArray(value)) {
    const copy: unknown[] = [...(value as unknown[])];
    const made = changed(copy[step as number], rest, change);
    if (made === undefined && rest.length === 0) copy.splice(step as number, 1);
    else copy[step as number] = made;
    return copy;
  }
  const copy: Record<string, unknown> = { ...(value as Record<string, unknown>) };
  const made = changed(copy[step as string], rest, change);
  if (made === undefined && rest.length === 0) Reflect.deleteProperty(copy, step);
  else
    Object.defineProperty(copy, step, {
      value: made,
      enumerable: true,
      writable: true,
      configurable: true,
    });
  return copy;
}

/** A value nested in arrays, `depth` deep. */
function nested(value: unknown, depth: number): unknown {
  let made = value;
  for (let level = 0; level < depth; level++) made = [made];
  return made;
}

/** What is done to a value at one place. */
const CHANGES: readonly ((old: unknown, other: unknown) => unknown)[] = [
  // Dropped.
  () => undefined,
  // Another value altogether.
  (_old, other) => other,
  // Its type changed.
  (old) => (typeof old === "string" ? [old] : JSON.stringify(old)),
  // A string with one character more, or another number.
  (old) => (typeof old === "string" ? `${old}x` : typeof old === "number" ? old + 1 : old),
  // Numbers the profile does not have (core 1.2).
  () => 1.5,
  () => 2 ** 60,
  // Deeper than a record may nest (core 1.9).
  (old) => nested(old, 70),
  // Longer than anything needs to be, and now and then longer than a record may be (core 1.6).
  (_old, other) => "x".repeat(typeof other === "number" ? 1024 * 1024 + 1 : 70_000),
  // Names that are something else to JavaScript.
  (old) => {
    const made: Record<string, unknown> = { constructor: { prototype: old } };
    // An own member of that name, which a literal would take for the prototype.
    Object.defineProperty(made, "__proto__", { value: old, enumerable: true });
    return made;
  },
  () => null,
  () => [],
  () => ({}),
  () => "",
];

/** A JSON value like `seed`, with something done to it at one to three places. */
export function mutated(seed: unknown): fc.Arbitrary<unknown> {
  const step = fc.record({
    place: fc.nat(),
    change: fc.nat({ max: CHANGES.length - 1 }),
    other: fc.jsonValue({ maxDepth: 3 }),
  });
  return fc.array(step, { minLength: 1, maxLength: 3 }).map((steps) => {
    let value = seed;
    for (const { place, change, other } of steps) {
      const all = places(value);
      const at = all[place % all.length] ?? [];
      value = changed(value, at, (old) => (CHANGES[change] ?? CHANGES[0])?.(old, other));
    }
    return value;
  });
}

const encoder = new TextEncoder();

/** A JSON value written out. What is no JSON is written as `null`. */
function textOf(value: unknown): string {
  try {
    const text: unknown = JSON.stringify(value);
    return typeof text === "string" ? text : "null";
  } catch {
    return "null";
  }
}

/** The bytes of a body: a JSON value written out, whole, cut short, or with something after it. */
function written(value: unknown): fc.Arbitrary<Uint8Array> {
  const text = textOf(value);
  return fc.oneof(
    { weight: 6, arbitrary: fc.constant(encoder.encode(text)) },
    {
      weight: 1,
      arbitrary: fc.nat({ max: text.length }).map((end) => encoder.encode(text.slice(0, end))),
    },
    {
      weight: 1,
      arbitrary: fc.string({ maxLength: 8 }).map((more) => encoder.encode(text + more)),
    },
    // The same member twice (core 1.1).
    { weight: 1, arbitrary: fc.constant(encoder.encode(text.replace(/^\{/u, '{"oip":"1",'))) },
  );
}

/** Bodies that start from nothing: bytes, text and JSON of any kind. */
const anyBody: fc.Arbitrary<Uint8Array | undefined> = fc.oneof(
  fc.constant(undefined),
  fc.uint8Array({ maxLength: 256 }),
  fc.string({ maxLength: 256 }).map((text) => encoder.encode(text)),
  fc.jsonValue({ maxDepth: 4 }).chain(written),
);

/** Headers a request should not have, or should not have like this. */
const anyHeaders: fc.Arbitrary<[string, string][]> = fc.array(
  fc.oneof(
    fc.tuple(
      fc.constant("content-type"),
      fc.constantFrom(
        "application/oip+json",
        "application/json",
        "application/oip+json; charset=utf-8",
        "APPLICATION/OIP+JSON",
        "text/plain",
        "application/x-www-form-urlencoded",
        "multipart/form-data; boundary=x",
        "",
        "application/oip+json, application/json",
      ),
    ),
    fc.tuple(
      fc.constantFrom("signature", "signature-input", "content-digest"),
      fc.oneof(
        fc.string({ maxLength: 64 }),
        fc.constantFrom(
          "sig1=:AAAA:",
          'sig1=("@method" "@target-uri");created=1;keyid="x";nonce="y"',
          'sig1=("@method" "@target-uri" "content-digest");created=1767225710;expires=1767226010;keyid="did:oip:x?versionId=0-y#z";nonce="abcdefgh";alg="ed25519"',
          "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:",
          "sig1=(), sig2=()",
          'sig1=("@method";req)',
        ),
      ),
    ),
    fc.tuple(
      fc.constantFrom("last-event-id", "x-forwarded-for", "accept", "origin", "content-length"),
      fc.oneof(
        fc.string({ maxLength: 32 }),
        fc.constantFrom("0", "-1", "99999999999999999999", "*/*"),
      ),
    ),
  ),
  { maxLength: 4 },
);

const METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] as const;

/** Something done to a path: a segment changed, the query changed, or rubbish. */
function pathLike(path: string, segments: fc.Arbitrary<string>): fc.Arbitrary<string> {
  const [before = "", query] = path.split("?");
  const parts = before.split("/");
  return fc.oneof(
    { weight: 6, arbitrary: fc.constant(path) },
    {
      weight: 3,
      arbitrary: fc
        .tuple(fc.nat({ max: Math.max(parts.length - 1, 0) }), segments)
        .map(
          ([at, segment]) =>
            `${parts.map((part, index) => (index === at && index > 0 ? segment : part)).join("/")}${
              query === undefined ? "" : `?${query}`
            }`,
        ),
    },
    {
      weight: 2,
      arbitrary: fc
        .array(
          fc.tuple(
            fc.constantFrom("after", "limit", "since", "x"),
            fc.oneof(
              fc.constantFrom("0", "1", "-1", "1e3", "9007199254740993", "", "%00", "a"),
              fc.nat().map(String),
            ),
          ),
          { maxLength: 3 },
        )
        .map((pairs) => `${before}?${pairs.map(([name, value]) => `${name}=${value}`).join("&")}`),
    },
    { weight: 1, arbitrary: segments.map((segment) => `${before}/${segment}`) },
  );
}

/** What a campaign is told of a service. */
export interface FuzzOptions {
  /** Requests the service would take, one at least for each of its routes. */
  readonly seeds: readonly Seed[];
  /** Path segments a campaign puts where others were: content IDs that are known, unknown and malformed. */
  readonly segments: readonly string[];
}

/** Requests for a campaign: most of them a seed with something done to it, some made of nothing. */
export function anyRequest(options: FuzzOptions): fc.Arbitrary<FuzzedRequest> {
  const segments = fc.oneof(
    fc.constantFrom(...options.segments),
    fc.constantFrom("..", ".", "%2e%2e", "%2F", "", " ", "a".repeat(300), "\u0000", "ws", "inbox"),
    fc.string({ maxLength: 12 }).map((text) => encodeURIComponent(text)),
  );
  const fromSeed = fc.constantFrom(...options.seeds).chain((seed) =>
    fc
      .record({
        method: fc.oneof(
          { weight: 8, arbitrary: fc.constant(seed.method) },
          { weight: 1, arbitrary: fc.constantFrom(...METHODS) },
        ),
        path: pathLike(seed.path, segments),
        more: fc.oneof(
          { weight: 3, arbitrary: fc.constant([]) },
          { weight: 1, arbitrary: anyHeaders },
        ),
        dropped: fc.nat({ max: 8 }),
        body:
          seed.json === undefined
            ? fc.oneof(
                { weight: 5, arbitrary: fc.constant(undefined) },
                { weight: 1, arbitrary: anyBody },
              )
            : fc.oneof(
                { weight: 2, arbitrary: written(seed.json) },
                { weight: 6, arbitrary: mutated(seed.json).chain(written) },
                { weight: 1, arbitrary: anyBody },
              ),
      })
      .map(({ method, path, more, dropped, body }) => {
        const kept = (seed.headers ?? []).filter((_, index) => index !== dropped);
        return {
          method,
          path,
          // A header given twice is the later one: what was added stands in for what the seed had.
          headers: [...kept, ...more],
          ...(body === undefined || method === "GET" || method === "HEAD" ? {} : { body }),
        };
      }),
  );
  const fromNothing = fc
    .record({
      method: fc.constantFrom(...METHODS),
      path: fc
        .array(segments, { minLength: 1, maxLength: 6 })
        .map((parts) => `/${parts.join("/")}`),
      headers: anyHeaders,
      body: anyBody,
    })
    .map(({ method, path, headers, body }) => ({
      method,
      path,
      headers,
      ...(body === undefined || method === "GET" || method === "HEAD" ? {} : { body }),
    }));
  return fc.oneof({ weight: 9, arbitrary: fromSeed }, { weight: 1, arbitrary: fromNothing });
}

/** A fuzzed request as a `Request` to an origin, or `undefined` if nothing can send it. */
export function requestOf(origin: string, fuzzed: FuzzedRequest): Request | undefined {
  try {
    const headers = new Headers();
    for (const [name, value] of fuzzed.headers) headers.set(name, value);
    return new Request(`${origin}${fuzzed.path}`, {
      method: fuzzed.method,
      headers,
      ...(fuzzed.body === undefined ? {} : { body: fuzzed.body }),
    });
  } catch {
    // A header or a URL that no client can write is not a request.
    return undefined;
  }
}

/** The statuses a service answers with on purpose. Anything else is a fault. */
export const STATUSES: readonly number[] = [
  200, 201, 202, 204, 400, 401, 403, 404, 405, 409, 413, 415, 429, 503, 507,
];

/**
 * What is wrong with an answer, as sentences. None for an answer a service
 * may give to anything at all: a status it means, and for an error the
 * problem details of core 10.2, with the status of the problem's code.
 *
 * @param method - The method of the request that was answered.
 */
export async function wrongWith(
  response: Response,
  method = "GET",
  most = 16 * 1024 * 1024,
): Promise<string[]> {
  const wrong: string[] = [];
  const { status } = response;
  if (!STATUSES.includes(status)) wrong.push(`the status ${status} is none a service answers with`);
  if (method === "HEAD") {
    // The answer to a HEAD is its status and headers: there is no body to hold to anything.
    const length = (await response.arrayBuffer()).byteLength;
    if (length > 0) wrong.push(`the answer to a HEAD has a body of ${length} bytes`);
    return wrong;
  }
  const stream = (response.headers.get("content-type") ?? "").startsWith("text/event-stream");
  if (stream) {
    // A stream has no end to read to. It is let go, and its status was checked.
    await response.body?.cancel();
    if (status !== 200) wrong.push(`a stream is answered 200, not ${status}`);
    return wrong;
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.length > most) wrong.push(`the answer is ${bytes.length} bytes long`);
  const type = (response.headers.get("content-type") ?? "").split(";")[0]?.trim() ?? "";
  const text = new TextDecoder().decode(bytes);
  let body: unknown;
  if (type.endsWith("json")) {
    try {
      body = JSON.parse(text) as unknown;
    } catch {
      wrong.push(`the answer says it is ${type} and is no JSON`);
    }
  }
  if (status >= 400) {
    if (type !== PROBLEM_MEDIA_TYPE) {
      wrong.push(`an error is ${PROBLEM_MEDIA_TYPE} (core 10.2), and this ${status} is "${type}"`);
    }
    const problem = (typeof body === "object" && body !== null ? body : {}) as Record<
      string,
      unknown
    >;
    if (problem["status"] !== status) {
      wrong.push(
        `a problem's status is the HTTP status ${status}; it is ${JSON.stringify(problem["status"])}`,
      );
    }
    if (typeof problem["type"] !== "string" || typeof problem["title"] !== "string") {
      wrong.push("a problem has a type and a title");
    }
    const code = problemCode(problem["type"]);
    if (code !== undefined && PROBLEMS[code].status !== status) {
      wrong.push(`the problem ${code} is answered ${PROBLEMS[code].status}, not ${status}`);
    }
    if (
      typeof problem["type"] === "string" &&
      problem["type"].startsWith("urn:oip:error:") &&
      code === undefined
    ) {
      wrong.push(`${problem["type"]} is no problem of core 10.2`);
    }
  }
  return wrong;
}
