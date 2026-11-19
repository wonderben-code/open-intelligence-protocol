// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The resolver's HTTP interface (Layer 1, 17.1), as a function from a
 * request to a response. What listens on a socket is `main.ts`; a test
 * calls this.
 *
 * Every request passes the same gate: a rate limit for the client's
 * address, a count and a duration for the metrics, and one place where
 * whatever was thrown becomes an answer (core 10.2). A failure nobody
 * expected is logged, and tells the client nothing.
 */

import { isContentId, MAX_TEXT_LENGTH, OipError, problemDetails } from "@oip/core";
import {
  addressKey,
  authenticate,
  type Clock,
  healthResponse,
  HttpFailure,
  type Log,
  type LogArchive,
  type Metrics,
  type NotTaken,
  METRICS_MEDIA_TYPE,
  problemResponse,
  type RateLimiter,
  readBody,
  readyResponse,
  recordFrom,
  recordResponse,
  requireRecordType,
  responseFor,
  type Shutdown,
  type StoredNonces,
  Unavailable,
} from "@oip/server";
import { Hono } from "hono";

/** What the HTTP interface is made with. */
export interface ResolverAppOptions {
  /** The logs the resolver keeps. */
  readonly resolver: LogArchive;
  readonly clock: Clock;
  readonly log: Log;
  readonly metrics: Metrics;
  /** The origin clients reach the resolver at, as it is configured. */
  readonly origin: string;
  /** The nonces of signed requests, kept in the resolver's database. */
  readonly nonces: StoredNonces;
  /** Whether a bundle may be published only by a request a mind has signed (Layer 1, 17.3). */
  readonly authenticatedPublication: boolean;
  /** The most bytes of a published bundle that are read. `MAX_TEXT_LENGTH` of `@oip/core` by default. */
  readonly maxBundleBytes?: number;
  /** The limit on what one address may read, and on what it may publish. */
  readonly limits: { readonly read: RateLimiter; readonly publish: RateLimiter };
  /** How the service stops, for `/readyz`. */
  readonly shutdown: Shutdown;
  /** What must hold for the service to be ready, each by a name. */
  readonly ready: Readonly<Record<string, () => boolean>>;
  /** The most streams open at once. 256 by default. */
  readonly maxStreams?: number;
  /** How often a stream with nothing to tell says that it is there, in milliseconds. 15,000 by default. */
  readonly heartbeatMs?: number;
}

/** What a request arrives with besides itself: the address it came from. */
export interface Arrival {
  /** The client's IP address, as the socket has it. */
  readonly address?: string;
}

/** The problem that says why an event of a published log was not taken (core 10.2). */
function refusal(refused: NotTaken): OipError {
  const [first] = refused.issues;
  const detail = `event ${refused.position} of the log: ${first.message}`;
  const options = { clause: first.clause, issues: refused.issues };
  // An extension the resolver does not implement: the event may be the mind's own.
  if (refused.issues.some((issue) => issue.clause === "core 8.3")) {
    return new OipError("unsupported-critical", detail, options);
  }
  // What the resolver cannot judge with the logs and the evidence it holds.
  if (refused.undecided) return new OipError("stale-version", detail, options);
  return new OipError("invalid-proof", detail, options);
}

const NOT_FOUND = "the resolver holds no log of that mind";

/** Layer 1, 17.1: the resolver's HTTP interface. */
export function resolverApp(options: ResolverAppOptions): Hono<{ Bindings: Arrival }> {
  const { resolver, clock, log, metrics, limits } = options;
  const maxBundleBytes = options.maxBundleBytes ?? MAX_TEXT_LENGTH;
  const requests = metrics.counter("oip_resolver_requests_total", "Requests answered.", [
    "route",
    "status",
  ]);
  const seconds = metrics.histogram(
    "oip_resolver_request_seconds",
    "How long a request took to answer.",
    ["route"],
  );
  const merged = metrics.counter(
    "oip_resolver_events_merged_total",
    "Identity events taken in that were not held before.",
  );

  /** The gate every request passes: a rate limit, the metrics, and the answer to a failure. */
  const gated =
    (
      route: string,
      limiter: RateLimiter,
      handle: (request: Request, id: string) => Response | Promise<Response>,
    ) =>
    async (context: {
      req: { raw: Request; param(name: string): string };
      env: Arrival | undefined;
    }) => {
      const started = clock.now();
      let response: Response;
      try {
        // An address that is none is one client: what cannot be told apart is limited together.
        const client = addressKey(context.env?.address ?? "") ?? "unknown";
        const allowed = limiter.take(client);
        if (!allowed.ok) {
          response = problemResponse(problemDetails("rate-limited", "too many requests"), {
            "retry-after": String(allowed.retryAfter),
          });
        } else {
          response = await handle(context.req.raw, context.req.param("id"));
        }
      } catch (error) {
        const answer = responseFor(error);
        if (answer.unexpected) log.failure("request failed", error, { route });
        response = answer.response;
      }
      requests.add({ route, status: String(response.status) });
      seconds.observe(Number(clock.now() - started) / 1e9, { route });
      // Public data, read by clients in browsers too.
      response.headers.set("access-control-allow-origin", "*");
      response.headers.set("x-content-type-options", "nosniff");
      return response;
    };

  /** The content ID a path names, or a 404: what is no content ID names no mind. */
  const named = (id: string): string => {
    if (!isContentId(id)) throw new OipError("not-found", NOT_FOUND);
    return id;
  };

  const app = new Hono<{ Bindings: Arrival }>();

  const maxStreams = options.maxStreams ?? 256;
  const heartbeatMs = options.heartbeatMs ?? 15_000;
  const streams = new Set<() => void>();
  const open = metrics.gauge("oip_resolver_streams_open", "Streams open.");
  // A service that stops ends its streams: a client follows on from its cursor elsewhere.
  options.shutdown.add("streams", () => {
    for (const end of [...streams]) end();
  });

  /**
   * Layer 1, 17.1: a stream of what the resolver takes in, as server-sent
   * events, from a cursor on. Each event's `id` is its cursor, so a client
   * that reconnects says where it was.
   */
  const streamFrom = (since: number): Response => {
    let cursor = since;
    const encoder = new TextEncoder();
    let wake: (() => void) | undefined;
    let ended = false;
    const end = (): void => {
      ended = true;
      wake?.();
    };
    const unsubscribe = resolver.subscribe(() => wake?.());
    const close = (): void => {
      unsubscribe();
      streams.delete(end);
      open.set(streams.size);
    };
    streams.add(end);
    open.set(streams.size);
    const body = new ReadableStream<Uint8Array>({
      // Asked for when the client has room: nothing is read from the store before that.
      async pull(controller) {
        for (;;) {
          if (ended) {
            close();
            controller.close();
            return;
          }
          const entries = resolver.stream(cursor, 100);
          if (entries.length > 0) {
            for (const entry of entries) {
              cursor = entry.cursor;
              const data = JSON.stringify({ ...entry, cursor: String(entry.cursor) });
              controller.enqueue(encoder.encode(`id: ${entry.cursor}\ndata: ${data}\n\n`));
            }
            return;
          }
          // Nothing new: wait to be told, or say that the stream is there.
          const told = await new Promise<boolean>((resolve) => {
            const timer = setTimeout(() => {
              resolve(false);
            }, heartbeatMs);
            wake = () => {
              clearTimeout(timer);
              resolve(true);
            };
          });
          wake = undefined;
          if (!told) {
            controller.enqueue(encoder.encode(": here\n\n"));
            return;
          }
        }
      },
      cancel() {
        end();
        close();
      },
    });
    return new Response(body, {
      headers: {
        "content-type": "text/event-stream",
        "cache-control": "no-store",
        // A proxy that gathers a response before it passes it on would hold the stream back.
        "x-accel-buffering": "no",
      },
    });
  };

  app.get(
    "/oip/v1/stream",
    gated("stream", limits.read, (request) => {
      const asked =
        new URL(request.url).searchParams.get("since") ?? request.headers.get("last-event-id");
      if (asked !== null && !/^(?:0|[1-9]\d{0,14})$/u.test(asked)) {
        throw new HttpFailure(400, "Bad Request");
      }
      if (streams.size >= maxStreams) {
        throw new Unavailable("as many streams are open as this resolver serves", 30);
      }
      return streamFrom(asked === null ? 0 : Number(asked));
    }),
  );

  app.get(
    "/oip/v1/resolve/:id",
    gated("resolve", limits.read, (_request, id) => {
      const bundle = resolver.resolve(named(id));
      if (bundle === undefined) throw new OipError("not-found", NOT_FOUND);
      return recordResponse(bundle, 200, { "cache-control": "no-cache" });
    }),
  );

  app.put(
    "/oip/v1/resolve/:id",
    gated("publish", limits.publish, async (request, id) => {
      const mind = named(id);
      requireRecordType(request);
      const body = await readBody(request, maxBundleBytes);
      const record = recordFrom(body, maxBundleBytes);
      if (record.type !== "Bundle") {
        throw new OipError("invalid-record", "what is published to a resolver is a Bundle", {
          clause: "L1 17.1",
        });
      }
      const published = resolver.publish(
        mind,
        record,
        options.authenticatedPublication
          ? (view) => {
              authenticate(request, body, {
                origin: options.origin,
                now: clock.now(),
                view,
                nonces: options.nonces,
              });
            }
          : undefined,
      );
      if (published.added > 0) merged.add({}, published.added);
      if (published.outcome === "duplicity") {
        throw new OipError(
          "duplicity",
          `the log holds another valid event at position ${published.position} than the one this resolver saw first`,
          { clause: "L1 7.1" },
        );
      }
      if (published.outcome === "refused") throw refusal(published.refused);
      if (published.outcome === "not-counted") {
        throw new OipError(
          "invalid-proof",
          `the ${published.record} record in the bundle is not signed by the mind's own authority under the current-state rule`,
          { clause: published.record === "location" ? "L1 15.1" : "L1 16.1" },
        );
      }
      return new Response(JSON.stringify({ added: published.added }), {
        status: 202,
        headers: { "content-type": "application/json" },
      });
    }),
  );

  app.get(
    "/oip/v1/duplicity/:id",
    gated("duplicity", limits.read, (_request, id) => {
      const evidence = resolver.duplicity(named(id));
      if (evidence === undefined) throw new OipError("not-found", NOT_FOUND);
      return recordResponse(evidence, 200, { "cache-control": "no-cache" });
    }),
  );

  // A browser asks before it sends a signed request from another origin.
  app.options("/oip/v1/*", () => {
    return new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET, PUT",
        "access-control-allow-headers": "content-type, content-digest, signature, signature-input",
        "access-control-max-age": "86400",
      },
    });
  });

  app.get("/healthz", () => healthResponse());
  app.get("/readyz", () => readyResponse(options.ready, options.shutdown.stopping));
  app.get(
    "/metrics",
    () => new Response(metrics.render(), { headers: { "content-type": METRICS_MEDIA_TYPE } }),
  );

  app.notFound(() => responseFor(new HttpFailure(404, "Not Found")).response);
  app.onError((error) => {
    log.failure("request failed", error, { route: "(none)" });
    return responseFor(error).response;
  });
  return app;
}
