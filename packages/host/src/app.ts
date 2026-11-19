// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The host's HTTP interface (Layer 1, Section 13), as a function from a
 * request to a response. What listens on a socket is `main.ts`; a test
 * calls this.
 *
 * A mind `M` whose genesis has the content ID `m` is served at:
 *
 * | Request | What it is |
 * |---|---|
 * | `GET /.well-known/oip/mind/m` | Its `Bundle` (13.1) |
 * | `GET /.well-known/oip/mind/m/log` | A `LogPage` of its identity log (13.1) |
 * | `GET /.well-known/oip/mind/m/feed` | A `FeedPage` of its public feed (13.1) |
 * | `GET /.well-known/oip/mind/m/obj/<contentId>` | A record its feed lists (10.2, 13.1) |
 * | `POST /oip/v1/minds/m/inbox` | Its inbox (13.2) |
 * | `POST /oip/v1/minds/m/mailbox` | Its mailbox (13.5) |
 * | `GET /oip/v1/minds/m/mailbox` | The owner drains it, with a signed request (13.3) |
 * | `DELETE /oip/v1/minds/m/mailbox/<cursor>` | The owner removes an item |
 * | `PUT /oip/v1/minds/m` | The mind brings its own `Bundle`, with a signed request |
 * | `PUT /oip/v1/minds/m/obj/<contentId>` | The mind brings a record for the host to serve |
 * | `POST /oip/v1/minds/m/feed` | The mind adds entries to its feed, as a `FeedPage` |
 *
 * The last three are this host's own: Layer 1 says what a host serves for
 * a mind, and leaves to the host how the mind hands it over. The endpoint a
 * location record gives for the `https` binding is
 * `{origin}/oip/v1/minds/m`, and for the `mailbox` binding
 * `{origin}/oip/v1/minds/m/mailbox` (15.1).
 */

import {
  contentId,
  isContentId,
  MAX_TEXT_LENGTH,
  mindAddress,
  OipError,
  type OipRecord,
} from "@oip/core";
import {
  type Arrival,
  authenticate,
  type Clock,
  gate,
  healthResponse,
  HttpFailure,
  type Log,
  type LogArchive,
  type Metrics,
  METRICS_MEDIA_TYPE,
  publicationProblem,
  type RateLimiter,
  readBody,
  readRecord,
  readyResponse,
  recordFrom,
  recordResponse,
  requireRecordType,
  responseFor,
  type Shutdown,
  type StoredNonces,
} from "@oip/server";
import { Hono } from "hono";

import type { Host } from "./host.ts";
import { deliverLearning, type Lookup } from "./lookup.ts";

/** What the HTTP interface is made with. */
export interface HostAppOptions {
  readonly host: Host;
  /** The identity logs the host holds: the same archive the host was made with. */
  readonly archive: LogArchive;
  readonly clock: Clock;
  readonly log: Log;
  readonly metrics: Metrics;
  /** The origin clients reach the host at, as it is configured. */
  readonly origin: string;
  /** The nonces of signed requests, kept in the host's database. */
  readonly nonces: StoredNonces;
  /**
   * Whether the host takes on a mind it does not serve yet, when the mind
   * publishes its bundle here. A host is somebody's to run: by default it
   * takes on nobody.
   */
  readonly admits?: (mind: string) => boolean;
  /**
   * How the host learns the log of a sender it cannot judge. Without it, an
   * inbox takes packets only from minds whose logs the host holds already.
   */
  readonly lookup?: Lookup;
  /** The most bytes of a record that are read. `MAX_TEXT_LENGTH` of `@oip/core` by default. */
  readonly maxRecordBytes?: number;
  /** The most events in a page of a log, and items in a page of a mailbox. 100 by default. */
  readonly maxPage?: number;
  /**
   * The limits on what one address may ask: reading what is public,
   * delivering to an inbox or a mailbox, and the requests a mind signs.
   */
  readonly limits: {
    readonly read: RateLimiter;
    readonly deliver: RateLimiter;
    readonly owner: RateLimiter;
  };
  /** How the service stops, for `/readyz`. */
  readonly shutdown: Shutdown;
  /** What must hold for the service to be ready, each by a name. */
  readonly ready: Readonly<Record<string, () => boolean>>;
}

const NOT_SERVED = "the host does not serve that mind";
const WHOLE = /^(?:0|[1-9]\d{0,14})$/u;

/** A whole number a query gives, or what it is when the query does not give it. */
function whole(request: Request, name: string, absent: number): number {
  const given = new URL(request.url).searchParams.get(name);
  if (given === null) return absent;
  if (!WHOLE.test(given)) throw new HttpFailure(400, "Bad Request");
  return Number(given);
}

/** The size of a page asked for: the most the host serves, unless fewer are asked for (13.1). */
function pageOf(request: Request, most: number): number {
  const limit = whole(request, "limit", most);
  if (limit === 0) throw new HttpFailure(400, "Bad Request");
  return Math.min(limit, most);
}

const json = (body: unknown, status: number, headers: Record<string, string> = {}): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...headers, "content-type": "application/json" },
  });

/** Layer 1, Section 13: the host's HTTP interface. */
export function hostApp(options: HostAppOptions): Hono<{ Bindings: Arrival }> {
  const { host, archive, clock, log, metrics, limits } = options;
  const maxRecordBytes = options.maxRecordBytes ?? MAX_TEXT_LENGTH;
  const maxPage = options.maxPage ?? 100;
  const admits = options.admits ?? (() => false);
  const gated = gate({ clock, log, metrics, service: "host" });
  const kept = metrics.counter("oip_host_records_kept_total", "Records taken for a mind.", [
    "at",
    "answer",
  ]);

  /** The mind a path names, if the host serves it: what is no content ID names no mind. */
  const served = (id: string): string => {
    if (!isContentId(id)) throw new OipError("not-found", NOT_SERVED);
    const mind = mindAddress(id);
    if (!host.hosts(mind)) throw new OipError("not-found", NOT_SERVED);
    return mind;
  };

  /**
   * Layer 1, 13.3: asks that a request is signed by the mind it concerns.
   *
   * @throws OipError `unauthorised` if it is not signed as 13.3 asks;
   *   `forbidden` if it is signed by another mind.
   */
  const signedBy = (
    mind: string,
    request: Request,
    body: Uint8Array,
    // The clock is read once: a signature is judged at the reading the logs are held as of.
    now = clock.now(),
    view = archive.view(now),
  ): void => {
    const who = authenticate(request, body, {
      origin: options.origin,
      now,
      view,
      nonces: options.nonces,
    });
    if (who.mind !== mind) {
      throw new OipError("forbidden", "only the mind itself may ask that", { clause: "L1 13.3" });
    }
  };

  const app = new Hono<{ Bindings: Arrival }>();

  app.get(
    "/.well-known/oip/mind/:id",
    gated("bundle", limits.read, (_request, param) => {
      const id = param("id");
      served(id);
      const bundle = archive.resolve(id);
      if (bundle === undefined) throw new OipError("not-found", NOT_SERVED);
      return recordResponse(bundle, 200, { "cache-control": "no-cache" });
    }),
  );

  app.get(
    "/.well-known/oip/mind/:id/log",
    gated("log", limits.read, (request, param) => {
      const id = param("id");
      const mind = served(id);
      // An event's place in the log is its `seq`, and the genesis is at 0. `after` is exclusive.
      const from = new URL(request.url).searchParams.has("after")
        ? whole(request, "after", 0) + 1
        : 0;
      const limit = pageOf(request, maxPage);
      const bundle = archive.resolve(id);
      if (bundle === undefined) throw new OipError("not-found", NOT_SERVED);
      const events = bundle.log.slice(from, from + limit);
      const seen = (bundle as { firstSeen?: Record<string, string> }).firstSeen ?? {};
      const firstSeen: Record<string, string> = {};
      for (const event of events) {
        const at = seen[contentId(event)];
        if (at !== undefined) firstSeen[contentId(event)] = at;
      }
      return recordResponse(
        {
          oip: "1",
          type: "LogPage",
          mind,
          events,
          ...(from + events.length < bundle.log.length && events.length > 0
            ? { next: from + events.length - 1 }
            : {}),
          firstSeen,
        },
        200,
        { "cache-control": "no-cache" },
      );
    }),
  );

  app.get(
    "/.well-known/oip/mind/:id/feed",
    gated("feed", limits.read, (request, param) => {
      const mind = served(param("id"));
      const after = new URL(request.url).searchParams.has("after")
        ? whole(request, "after", 0)
        : undefined;
      const { entries, next } = host.feed(mind, after, pageOf(request, maxPage));
      return recordResponse(
        { oip: "1", type: "FeedPage", mind, entries, ...(next === undefined ? {} : { next }) },
        200,
        { "cache-control": "no-cache" },
      );
    }),
  );

  app.get(
    "/.well-known/oip/mind/:id/obj/:object",
    gated("object", limits.read, (_request, param) => {
      const record = host.object(served(param("id")), param("object"));
      if (record === undefined) {
        throw new OipError("not-found", "the host serves no record with that content ID");
      }
      // A record gains proofs, and its content ID stays: a copy held is asked after again.
      return recordResponse(record, 200, { "cache-control": "no-cache" });
    }),
  );

  /** A record for a mind, which is a `Packet` or a `Sealed` record. */
  const sent = async (request: Request, clause: string): Promise<OipRecord> => {
    const record = await readRecord(request, maxRecordBytes);
    if (record.type !== "Packet" && record.type !== "Sealed") {
      throw new OipError(
        "invalid-record",
        "what is sent to a mind is a Packet or a Sealed record",
        {
          clause,
        },
      );
    }
    return record;
  };

  app.post(
    "/oip/v1/minds/:id/inbox",
    gated("inbox", limits.deliver, async (request, param) => {
      const mind = served(param("id"));
      const record = await sent(request, "L1 13.2");
      const answer = await deliverLearning(host, options.lookup, mind, record);
      const acknowledged = answer["type"] === "Ack";
      kept.add({ at: "inbox", answer: acknowledged ? "ack" : "stored" });
      return acknowledged ? recordResponse(answer, 202) : json(answer, 202);
    }),
  );

  app.post(
    "/oip/v1/minds/:id/mailbox",
    gated("mailbox", limits.deliver, async (request, param) => {
      const mind = served(param("id"));
      const answer = host.post(mind, await sent(request, "L1 13.5"));
      kept.add({ at: "mailbox", answer: "stored" });
      return json(answer, 202);
    }),
  );

  app.get(
    "/oip/v1/minds/:id/mailbox",
    gated("drain", limits.owner, (request, param) => {
      const mind = served(param("id"));
      const after = whole(request, "after", 0);
      const limit = pageOf(request, maxPage);
      signedBy(mind, request, new Uint8Array(0));
      const { items, next } = host.drain(mind, after, limit);
      return json(
        {
          items: items.map((item) => ({ cursor: String(item.cursor), record: item.record })),
          ...(next === undefined ? {} : { next: String(next) }),
        },
        200,
        // A mind's mail is for the mind.
        { "cache-control": "no-store" },
      );
    }),
  );

  app.delete(
    "/oip/v1/minds/:id/mailbox/:cursor",
    gated("remove", limits.owner, (request, param) => {
      const mind = served(param("id"));
      const cursor = param("cursor");
      signedBy(mind, request, new Uint8Array(0));
      if (!WHOLE.test(cursor) || !host.remove(mind, Number(cursor))) {
        throw new OipError("not-found", "the mailbox holds no item at that cursor");
      }
      return new Response(null, { status: 204 });
    }),
  );

  app.put(
    "/oip/v1/minds/:id",
    gated("publish", limits.owner, async (request, param) => {
      const id = param("id");
      if (!isContentId(id)) throw new OipError("not-found", NOT_SERVED);
      const mind = mindAddress(id);
      const hosted = host.hosts(mind);
      // Said before anything is read: whether a mind is served here is no secret (13.1).
      if (!hosted && !admits(mind)) {
        throw new OipError("forbidden", "this host does not take that mind on");
      }
      requireRecordType(request);
      const body = await readBody(request, maxRecordBytes);
      const record = recordFrom(body, maxRecordBytes);
      if (record.type !== "Bundle") {
        throw new OipError("invalid-record", "what a mind publishes to its host is a Bundle", {
          clause: "L1 13.1",
        });
      }
      // Judged against the log in the bundle as far as it verified: a mind can so bring
      // its own log for the first time, and nobody else can bring it for the mind.
      const published = archive.publish(id, record, (view, now) => {
        signedBy(mind, request, body, now, view);
      });
      const problem = publicationProblem(published);
      if (problem !== undefined) throw problem;
      if (!hosted) host.adopt(mind);
      return json({ added: published.added }, hosted ? 200 : 201);
    }),
  );

  /** The record a mind brings with a request it signed. */
  const brought = async (mind: string, request: Request): Promise<OipRecord> => {
    requireRecordType(request);
    const body = await readBody(request, maxRecordBytes);
    signedBy(mind, request, body);
    return recordFrom(body, maxRecordBytes);
  };

  app.put(
    "/oip/v1/minds/:id/obj/:object",
    gated("keep", limits.owner, async (request, param) => {
      const mind = served(param("id"));
      const record = await brought(mind, request);
      if (contentId(record) !== param("object")) {
        throw new OipError(
          "invalid-record",
          "the record has another content ID than the one named",
          {
            clause: "core 3.1",
          },
        );
      }
      const { fresh } = host.keep(mind, record);
      return json({ stored: true }, fresh ? 201 : 200);
    }),
  );

  app.post(
    "/oip/v1/minds/:id/feed",
    gated("append", limits.owner, async (request, param) => {
      const mind = served(param("id"));
      const page = (await brought(mind, request)) as {
        type: string;
        mind?: unknown;
        entries?: unknown;
      };
      if (page.type !== "FeedPage" || page.mind !== mind || !Array.isArray(page.entries)) {
        throw new OipError("invalid-record", "entries are brought as a FeedPage of the mind", {
          clause: "L1 13.1",
        });
      }
      return json({ added: host.append(mind, page.entries) }, 200);
    }),
  );

  // A browser asks before it sends a signed request, or a record, from another origin.
  const preflight = (): Response =>
    new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET, POST, PUT, DELETE",
        "access-control-allow-headers": "content-type, content-digest, signature, signature-input",
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
