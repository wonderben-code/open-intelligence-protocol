// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The gate every request to a service passes (ADR-0013): a rate limit for
 * the client's address, a count and a duration for the metrics, and one
 * place where whatever was thrown becomes an answer (core 10.2). A failure
 * nobody expected is logged, and tells the client nothing.
 *
 * It is written against the shape of a request as a router hands it over,
 * and names no router.
 */

import { problemDetails } from "@oip/core";

import type { Clock } from "./edges.ts";
import { problemResponse, responseFor } from "./http.ts";
import type { Log } from "./log.ts";
import type { Metrics } from "./metrics.ts";
import { addressKey, type RateLimiter } from "./rate.ts";

/** What a request arrives with besides itself: the address it came from. */
export interface Arrival {
  /** The client's IP address, as the socket has it. A socket that has closed has none. */
  readonly address?: string | undefined;
}

/** A request as the server has it, as far as telling where it came from needs. */
export interface Arrived {
  readonly socket: { readonly remoteAddress?: string | undefined };
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
}

/**
 * The address a request came from. With no proxy in front it is the
 * socket's. Each trusted proxy adds the address it was asked from to
 * `X-Forwarded-For`, so with `trusted` of them the client is that many from
 * the end. What stands before that is the sender's to write, and is not
 * read.
 */
export function clientAddress(incoming: Arrived, trusted: number): string | undefined {
  const socket = incoming.socket.remoteAddress;
  if (trusted === 0) return socket;
  const forwarded = incoming.headers["x-forwarded-for"];
  const hops = (Array.isArray(forwarded) ? forwarded.join(",") : (forwarded ?? ""))
    .split(",")
    .map((hop) => hop.trim())
    .filter((hop) => hop !== "");
  return hops.at(-trusted) ?? socket;
}

/** A request as a router hands it to a handler. */
export interface Asked {
  readonly req: { readonly raw: Request; param(name: string): string };
  readonly env: Arrival | undefined;
}

/** What answers a request that has passed the gate. `param` gives a parameter of the route's path. */
export type Handler = (
  request: Request,
  param: (name: string) => string,
) => Response | Promise<Response>;

/** What a gate is made with. */
export interface GateOptions {
  readonly clock: Clock;
  readonly log: Log;
  readonly metrics: Metrics;
  /** The service's name in its metrics, as in `oip_resolver_requests_total`. */
  readonly service: string;
}

/**
 * Makes the gate of a service.
 *
 * @returns A function that puts a handler behind the gate: it is given the
 *   name of the route for the metrics, which names no mind, and the limit
 *   on what one address may ask of it.
 */
export function gate(
  options: GateOptions,
): (route: string, limiter: RateLimiter, handle: Handler) => (asked: Asked) => Promise<Response> {
  const { clock, log, metrics, service } = options;
  const requests = metrics.counter(`oip_${service}_requests_total`, "Requests answered.", [
    "route",
    "status",
  ]);
  const seconds = metrics.histogram(
    `oip_${service}_request_seconds`,
    "How long a request took to answer.",
    ["route"],
  );
  return (route, limiter, handle) => async (asked) => {
    const started = clock.now();
    let response: Response;
    try {
      // An address that is none is one client: what cannot be told apart is limited together.
      const client = addressKey(asked.env?.address ?? "") ?? "unknown";
      const allowed = limiter.take(client);
      if (!allowed.ok) {
        response = problemResponse(problemDetails("rate-limited", "too many requests"), {
          "retry-after": String(allowed.retryAfter),
        });
      } else {
        response = await handle(asked.req.raw, (name) => asked.req.param(name));
      }
    } catch (error) {
      const answer = responseFor(error);
      if (answer.unexpected) log.failure("request failed", error, { route });
      response = answer.response;
    }
    requests.add({ route, status: String(response.status) });
    seconds.observe(Number(clock.now() - started) / 1e9, { route });
    // No answer depends on who the browser is logged in as: what is not public is signed for.
    response.headers.set("access-control-allow-origin", "*");
    response.headers.set("x-content-type-options", "nosniff");
    return response;
  };
}
