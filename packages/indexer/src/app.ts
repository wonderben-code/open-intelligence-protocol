// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The indexer's HTTP interface (Layer 1, Section 18), as a function from a
 * request to a response. What listens on a socket is `main.ts`; a test
 * calls this.
 *
 * | Request | What it is |
 * |---|---|
 * | `POST /oip/v1/submit` | Records to list: `{ "records": [ … ] }` (18.1) |
 * | `POST /oip/v1/query` | A capability query, answered with a signed `QueryResult` (18.2, 18.3) |
 * | `POST /oip/v1/inbox` | A packet addressed to a query, to be forwarded (18.5) |
 * | `GET /.well-known/oip/mind/<id>` | The indexer's own `Bundle`, by which its signatures are judged |
 */

import { isContentId, MAX_TEXT_LENGTH, mindId, OipError } from "@oip/core";
import {
  type Arrival,
  type Clock,
  gate,
  healthResponse,
  HttpFailure,
  type Log,
  type LogArchive,
  type Metrics,
  METRICS_MEDIA_TYPE,
  type RateLimiter,
  readJson,
  readRecord,
  readyResponse,
  recordResponse,
  responseFor,
  type Shutdown,
} from "@oip/server";
import { Hono } from "hono";

import type { Broker } from "./broker.ts";
import type { Indexer } from "./indexer.ts";

/** What the HTTP interface is made with. */
export interface IndexerAppOptions {
  readonly indexer: Indexer;
  readonly broker: Broker;
  /** The identity logs the indexer holds: the same archive the indexer was made with. */
  readonly archive: LogArchive;
  readonly clock: Clock;
  readonly log: Log;
  readonly metrics: Metrics;
  /** The limits on what one address may ask: queries, submissions, and packets to forward. */
  readonly limits: {
    readonly query: RateLimiter;
    readonly submit: RateLimiter;
    readonly deliver: RateLimiter;
  };
  /** The most bytes of a body that are read. `MAX_TEXT_LENGTH` of `@oip/core` by default. */
  readonly maxBodyBytes?: number;
  /** The most records in one submission. 100 by default. */
  readonly maxRecords?: number;
  /** How the service stops, for `/readyz`. */
  readonly shutdown: Shutdown;
  /** What must hold for the service to be ready, each by a name. */
  readonly ready: Readonly<Record<string, () => boolean>>;
}

const json = (body: unknown, status: number): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

/** Layer 1, Section 18: the indexer's HTTP interface. */
export function indexerApp(options: IndexerAppOptions): Hono<{ Bindings: Arrival }> {
  const { indexer, broker, archive, clock, log, metrics, limits } = options;
  const maxBodyBytes = options.maxBodyBytes ?? MAX_TEXT_LENGTH;
  const maxRecords = options.maxRecords ?? 100;
  const gated = gate({ clock, log, metrics, service: "indexer" });
  const submitted = metrics.counter(
    "oip_indexer_records_submitted_total",
    "Records submitted, by what became of each.",
    ["outcome"],
  );

  const app = new Hono<{ Bindings: Arrival }>();

  app.post(
    "/oip/v1/submit",
    gated("submit", limits.submit, async (request) => {
      const body = await readJson(request, maxBodyBytes);
      const records =
        typeof body === "object" && body !== null && !Array.isArray(body)
          ? (body as { records?: unknown }).records
          : undefined;
      if (!Array.isArray(records) || records.length === 0) {
        throw new OipError(
          "invalid-record",
          'a submission is { "records": [ … ] }, with one record at least',
          {
            clause: "L1 18.1",
          },
        );
      }
      if (records.length > maxRecords) {
        throw new OipError("too-large", `a submission holds at most ${maxRecords} records here`);
      }
      const submission = indexer.submit(records);
      submitted.add({ outcome: "taken" }, submission.taken);
      submitted.add({ outcome: "refused" }, submission.refused.length);
      return json(submission, 202);
    }),
  );

  app.post(
    "/oip/v1/query",
    gated("query", limits.query, async (request) =>
      // An answer is to one question at one time: it is not kept by anything between.
      recordResponse(indexer.query(await readJson(request, maxBodyBytes)), 200, {
        "cache-control": "no-store",
      }),
    ),
  );

  app.post(
    "/oip/v1/inbox",
    gated("inbox", limits.deliver, async (request) => {
      const { forwarding } = await broker.accept(await readRecord(request, maxBodyBytes));
      // Taken, as an inbox that signs for nobody says it (13.2), and to how many minds it goes.
      return json({ stored: true, forwarding }, 202);
    }),
  );

  // The indexer is a mind: whoever judges a QueryResult or a Forwarded record needs its log.
  app.get(
    "/.well-known/oip/mind/:id",
    gated("bundle", limits.query, (_request, param) => {
      const id = param("id");
      const bundle =
        isContentId(id) && id === mindId(indexer.address) ? archive.resolve(id) : undefined;
      if (bundle === undefined) {
        throw new OipError("not-found", "the indexer serves the bundle of its own mind only");
      }
      return recordResponse(bundle, 200, { "cache-control": "no-cache" });
    }),
  );

  // A browser asks before it sends JSON from another origin.
  const preflight = (): Response =>
    new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET, POST",
        "access-control-allow-headers": "content-type",
        "access-control-max-age": "86400",
      },
    });
  app.options("/oip/v1/*", preflight);
  app.options("/.well-known/oip/*", preflight);

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
