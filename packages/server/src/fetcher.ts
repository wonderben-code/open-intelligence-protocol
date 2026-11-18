// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The one way a service makes a request because a record told it to
 * (BUILD.md 3.7): a resolver fetching a home, a gateway fetching an Agent
 * Card. Whoever wrote the record chose the URL, so the request must not be
 * able to reach what the writer could not reach directly: the machine
 * itself, the network behind it, the cloud's metadata service.
 *
 * - HTTPS only, with no credentials in the URL.
 * - The name is resolved once. Every address it resolves to must be public
 *   (`isPublicAddress`), or in a range the operator allows.
 * - The connection is made to an address that was checked, and to no
 *   other: the name is not resolved a second time, so a name that answers
 *   differently the second time gains nothing.
 * - A response is read up to a limit of bytes, the whole exchange has a
 *   limit of time, and a redirect is followed only to the same origin, and
 *   only so many times.
 * - Nothing of the service goes with the request: no cookie, no
 *   credential.
 */

import { lookup } from "node:dns/promises";
import { request } from "node:https";
import { isIP } from "node:net";

import { inRange, isPublicAddress, parseAddress } from "./ip.ts";

/** The limits of one fetch. */
export interface FetchLimits {
  /** The most bytes of a response's body that are read. */
  readonly maxBytes: number;
  /** The most time the whole exchange may take, redirects included, in milliseconds. */
  readonly timeoutMs: number;
  /** How many redirects, each to the same origin, are followed. */
  readonly maxRedirects: number;
}

/** A megabyte for a record and what is around it, ten seconds, and three redirects. */
export const DEFAULT_FETCH_LIMITS: FetchLimits = {
  maxBytes: 2 * 1024 * 1024,
  timeoutMs: 10_000,
  maxRedirects: 3,
};

/** Gives the addresses a host name resolves to, as text. */
export type Resolve = (hostname: string) => Promise<readonly string[]>;

/** How a fetcher is set up. */
export interface GuardedFetcherOptions {
  readonly limits?: Partial<FetchLimits>;
  /** The resolver. By default the system's, asked for every address of the name. */
  readonly resolve?: Resolve;
  /**
   * Ranges that are allowed besides the public addresses, as `address/bits`.
   * None by default. An operator lists its own test network here, and
   * nothing in production.
   */
  readonly allow?: readonly string[];
  /** Certificate authorities to trust besides the system's, as PEM. */
  readonly ca?: string;
  /** What the request says it comes from. */
  readonly userAgent?: string;
}

/** Why a fetch was not made, or was given up. */
export type FetchRefusal =
  "not-https" | "credentials" | "address" | "redirect" | "too-large" | "timeout" | "network";

/** A fetch that was refused, or that failed. It says why, and never what the response held. */
export class FetchRefused extends Error {
  readonly reason: FetchRefusal;

  constructor(reason: FetchRefusal, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "FetchRefused";
    this.reason = reason;
  }
}

/** What a fetch gave. */
export interface Fetched {
  /** The URL the response came from: the one asked for, or the last one it was redirected to. */
  readonly url: string;
  readonly status: number;
  /**
   * The response's headers, their names in lower case. Several of one name
   * are one value, joined with a comma, as HTTP reads them.
   */
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Uint8Array;
}

const systemResolve: Resolve = async (hostname) =>
  (await lookup(hostname, { all: true, order: "verbatim" })).map((found) => found.address);

/** The host of a URL as an address, if it is one. An IPv6 address in a URL is in brackets. */
function literal(hostname: string): string | undefined {
  const bare = hostname.startsWith("[") ? hostname.slice(1, -1) : hostname;
  return isIP(bare) === 0 ? undefined : bare;
}

/** The fetcher. One is made for a service, with its limits and what it allows. */
export class GuardedFetcher {
  readonly #limits: FetchLimits;
  readonly #resolve: Resolve;
  readonly #allow: readonly string[];
  readonly #ca: string | undefined;
  readonly #userAgent: string;

  constructor(options: GuardedFetcherOptions = {}) {
    this.#limits = { ...DEFAULT_FETCH_LIMITS, ...options.limits };
    for (const [name, value] of Object.entries(this.#limits)) {
      if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(`${name} is a whole number, not negative`);
      }
    }
    this.#resolve = options.resolve ?? systemResolve;
    this.#allow = [...(options.allow ?? [])];
    // A range that is none is a mistake in the configuration, found now and not at a request.
    const probe = parseAddress("0.0.0.0");
    if (probe !== undefined) for (const range of this.#allow) inRange(probe, range);
    this.#ca = options.ca;
    this.#userAgent = options.userAgent ?? "oip-server";
  }

  /**
   * Gets a URL.
   *
   * @param accept - The media types asked for.
   * @returns The response, whatever its status: a 404 is an answer.
   * @throws FetchRefused if the URL may not be fetched, or the fetch failed.
   */
  async get(url: string, accept = "*/*"): Promise<Fetched> {
    const deadline = AbortSignal.timeout(this.#limits.timeoutMs);
    let next = url;
    for (let redirects = 0; ; redirects++) {
      const target = this.#vetted(next);
      const addresses = await this.#addresses(target.hostname, deadline);
      const answer = await this.#exchange(target, addresses, accept, deadline);
      if (answer.status < 300 || answer.status >= 400 || answer.headers["location"] === undefined) {
        return answer;
      }
      if (redirects >= this.#limits.maxRedirects) {
        throw new FetchRefused("redirect", "the response redirects more often than is followed");
      }
      let to: URL;
      try {
        to = new URL(answer.headers["location"], target);
      } catch (error) {
        throw new FetchRefused("redirect", "the response redirects to what is no URL", {
          cause: error,
        });
      }
      // The same scheme, host and port: a redirect leads nowhere the first URL did not.
      if (to.origin !== target.origin) {
        throw new FetchRefused("redirect", "the response redirects to another origin");
      }
      next = to.href;
    }
  }

  /** The URL, if it is one this fetcher may ask at all. */
  #vetted(url: string): URL {
    let target: URL;
    try {
      target = new URL(url);
    } catch (error) {
      throw new FetchRefused("not-https", "what was to be fetched is no URL", { cause: error });
    }
    if (target.protocol !== "https:") throw new FetchRefused("not-https", "only HTTPS is fetched");
    if (target.username !== "" || target.password !== "") {
      throw new FetchRefused("credentials", "a URL with credentials in it is not fetched");
    }
    return target;
  }

  /** The addresses to connect to: every one the name has, each checked. */
  async #addresses(hostname: string, deadline: AbortSignal): Promise<Addresses> {
    const written = literal(hostname);
    let found: readonly string[];
    if (written === undefined) {
      try {
        found = await raced(this.#resolve(hostname), deadline);
      } catch (error) {
        if (error instanceof FetchRefused) throw error;
        throw new FetchRefused("network", "the host's name did not resolve", { cause: error });
      }
    } else {
      found = [written];
    }
    const [first, ...rest] = found;
    if (first === undefined) throw new FetchRefused("network", "the host's name has no address");
    for (const text of found) {
      const address = parseAddress(text);
      const allowed =
        address !== undefined &&
        (isPublicAddress(address) || this.#allow.some((range) => inRange(address, range)));
      // One address that is not allowed refuses the name: which of them a connection
      // would take is not ours to say.
      if (!allowed) {
        throw new FetchRefused("address", "the host is at an address that is not fetched from");
      }
    }
    return [first, ...rest];
  }

  /** One request and its response, made to one of the addresses given and to no other. */
  #exchange(
    target: URL,
    addresses: Addresses,
    accept: string,
    deadline: AbortSignal,
  ): Promise<Fetched> {
    const { maxBytes } = this.#limits;
    return new Promise<Fetched>((resolve, reject) => {
      const outgoing = request(
        target,
        {
          method: "GET",
          // No connection is kept for another request to find.
          agent: false,
          signal: deadline,
          headers: {
            accept,
            "accept-encoding": "identity",
            "user-agent": this.#userAgent,
          },
          ...(this.#ca === undefined ? {} : { ca: this.#ca }),
          // The name is not resolved again: the connection goes to an address that was checked.
          lookup: pinnedTo(addresses),
        },
        (response) => {
          const give = (failure: FetchRefused): void => {
            response.destroy();
            reject(failure);
          };
          // Where the connection went, as the socket has it: one of the addresses checked.
          if (!addresses.some((address) => sameAddress(address, response.socket.remoteAddress))) {
            give(
              new FetchRefused("address", "the connection is not to an address that was checked"),
            );
            return;
          }
          const declared = Number(response.headers["content-length"]);
          if (Number.isFinite(declared) && declared > maxBytes) {
            give(new FetchRefused("too-large", "the response says it is longer than is read"));
            return;
          }
          const chunks: Uint8Array[] = [];
          let length = 0;
          response.on("data", (chunk: Uint8Array) => {
            length += chunk.length;
            if (length > maxBytes)
              give(new FetchRefused("too-large", "the response is longer than is read"));
            else chunks.push(chunk);
          });
          response.on("error", (error) => {
            reject(failureOf(error, deadline));
          });
          response.on("end", () => {
            const headers: Record<string, string> = {};
            for (const [name, value] of Object.entries(response.headers)) {
              // Node.js gives a list for the one header it does not join, which is no use here.
              if (typeof value === "string") headers[name] = value;
            }
            const body = new Uint8Array(length);
            let at = 0;
            for (const chunk of chunks) {
              body.set(chunk, at);
              at += chunk.length;
            }
            resolve({ url: target.href, status: response.statusCode ?? 0, headers, body });
          });
        },
      );
      outgoing.on("error", (error) => {
        reject(failureOf(error, deadline));
      });
      outgoing.end();
    });
  }
}

/** The addresses of a name: at least one, each checked. */
type Addresses = readonly [string, ...string[]];

/** What Node.js asks for an address with, and how it takes the answer. */
type Lookup = (
  hostname: string,
  options: { readonly all?: boolean | undefined },
  callback: (
    error: Error | null,
    address: string | { address: string; family: number }[],
    family?: number,
  ) => void,
) => void;

/**
 * A lookup that answers with the addresses given, whatever name it is
 * asked for: one of them, or all, as it is asked.
 *
 * @internal
 */
export function pinnedTo(addresses: Addresses): Lookup {
  const pinned = addresses.map((address) => ({ address, family: isIP(address) }));
  return (_hostname, options, callback) => {
    if (options.all === true) callback(null, pinned);
    else callback(null, addresses[0], isIP(addresses[0]));
  };
}

/**
 * Whether two texts are the same address: an IPv4 address may be given as
 * one mapped into IPv6, as a socket that speaks both gives it.
 *
 * @internal
 */
export function sameAddress(one: string, other: string | undefined): boolean {
  if (other === undefined) return false;
  const mapped = (text: string): string => (text.startsWith("::ffff:") ? text.slice(7) : text);
  const [a, b] = [parseAddress(mapped(one)), parseAddress(mapped(other))];
  if (a === undefined || a.family !== b?.family) return false;
  return a.bytes.every((byte, position) => byte === b.bytes[position]);
}

/** The failure of a request, told from the time running out. */
function failureOf(error: unknown, deadline: AbortSignal): FetchRefused {
  return deadline.aborted
    ? new FetchRefused("timeout", "the fetch took longer than it may", { cause: error })
    : new FetchRefused("network", "the request failed", { cause: error });
}

/**
 * A promise, given up when the time runs out.
 *
 * @internal
 */
export function raced<T>(work: Promise<T>, deadline: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const expired = (): void => {
      reject(new FetchRefused("timeout", "the fetch took longer than it may"));
    };
    if (deadline.aborted) {
      expired();
      return;
    }
    deadline.addEventListener("abort", expired, { once: true });
    work.then(resolve, reject).finally(() => {
      deadline.removeEventListener("abort", expired);
    });
  });
}
