// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Services that run in the test's own process: the real resolver, host and
 * indexer, each with a database of its own, reached through a `fetch` that
 * finds a service by its origin. No socket is opened.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { MEDIA_TYPE, mindId } from "@oip/core";
import { Host, HOST_MIGRATIONS, hostApp } from "@oip/host";
import { RESOLVER_MIGRATIONS, resolverApp } from "@oip/resolver";
import {
  Database,
  Log,
  LogArchive,
  Metrics,
  RateLimiter,
  Shutdown,
  StoredNonces,
} from "@oip/server";
import { at, type Mind } from "@oip/testkit/minds";

import type { Clock, Fetch } from "../src/index.ts";

/** A clock a test sets. */
export interface TestClock extends Clock {
  at: bigint;
}

/** What answers at an origin: a service's `fetch`, or something a test put there. */
type Answering = (request: Request) => Response | Promise<Response>;

/** The services of a test, and the `fetch` that reaches them. */
export class World {
  readonly clock: TestClock;
  readonly #directory = mkdtempSync(join(tmpdir(), "oip-client-"));
  readonly #origins = new Map<string, Answering>();
  readonly #databases: Database[] = [];
  /** The requests made, as `METHOD url`. */
  readonly asked: string[] = [];

  constructor(seconds = 1000) {
    const clock: TestClock = { at: at(seconds), now: () => clock.at };
    this.clock = clock;
  }

  /** Called with each request before it is answered: a test acts at a moment of its choosing. */
  before: ((request: Request) => void | Promise<void>) | undefined;

  /** Reaches the services of this world, and nothing else. */
  readonly fetch: Fetch = async (request) => {
    this.asked.push(`${request.method} ${request.url}`);
    await this.before?.(request);
    return this.direct(request);
  };

  /** As `fetch`, for a client a test does not watch: `before` is not called. */
  readonly direct: Fetch = async (request) => {
    const answering = this.#origins.get(new URL(request.url).origin);
    if (answering === undefined) throw new TypeError("fetch failed");
    return answering(request);
  };

  /** Puts something at an origin, in the place of what was there. */
  put(origin: string, answering: Answering): void {
    this.#origins.set(origin, answering);
  }

  /** What answers at an origin now, for a test that puts something in front of it. */
  at(origin: string): Answering {
    const answering = this.#origins.get(origin);
    if (answering === undefined) throw new Error(`nothing answers at ${origin}`);
    return answering;
  }

  /** Takes an origin away: it can no longer be reached. */
  remove(origin: string): void {
    this.#origins.delete(origin);
  }

  readonly #down = new Map<string, Answering>();

  /** Takes an origin away for a while: `up` brings back what was there. */
  down(origin: string): void {
    const answering = this.#origins.get(origin);
    if (answering === undefined) return;
    this.#down.set(origin, answering);
    this.#origins.delete(origin);
  }

  /** Brings back what `down` took away. */
  up(origin: string): void {
    const answering = this.#down.get(origin);
    if (answering === undefined) return;
    this.#origins.set(origin, answering);
    this.#down.delete(origin);
  }

  /**
   * A resolver at an origin, with a database of its own.
   *
   * @param authenticated - Whether it takes a bundle only with a request a mind signed (Layer 1, 17.3).
   */
  resolver(origin: string, authenticated = false): { archive: LogArchive } {
    const db = Database.open(
      {
        path: join(this.#directory, `resolver-${String(this.#databases.length)}.db`),
        durable: false,
      },
      RESOLVER_MIGRATIONS,
      this.clock,
    );
    this.#databases.push(db);
    const log = new Log({ service: "resolver", clock: this.clock, sink: () => undefined });
    const generous = (): RateLimiter =>
      new RateLimiter({ burst: 10_000, perMinute: 600_000 }, this.clock);
    const archive = new LogArchive({ db, clock: this.clock });
    const app = resolverApp({
      resolver: archive,
      clock: this.clock,
      log,
      metrics: new Metrics(),
      origin,
      nonces: new StoredNonces(db),
      authenticatedPublication: authenticated,
      limits: { read: generous(), publish: generous() },
      shutdown: new Shutdown({ log }),
      ready: { database: () => true },
    });
    this.put(origin, (request) => app.fetch(request, { address: "203.0.113.7" }));
    return { archive };
  }

  /**
   * A host at an origin, with a database of its own. It holds no key of the
   * minds it serves.
   *
   * @param options.admits - The minds it takes on when they bring their bundle. Default: any.
   * @param options.maxPage - The most entries it serves in one page of a feed. Default: 100.
   */
  host(
    origin: string,
    options: { admits?: (mind: string) => boolean; maxPage?: number } = {},
  ): { host: Host } {
    const db = Database.open(
      {
        path: join(this.#directory, `host-${String(this.#databases.length)}.db`),
        durable: false,
      },
      HOST_MIGRATIONS,
      this.clock,
    );
    this.#databases.push(db);
    const log = new Log({ service: "host", clock: this.clock, sink: () => undefined });
    const generous = (): RateLimiter =>
      new RateLimiter({ burst: 10_000, perMinute: 600_000 }, this.clock);
    const archive = new LogArchive({ db, clock: this.clock });
    const host = new Host({ db, archive });
    const app = hostApp({
      host,
      archive,
      clock: this.clock,
      log,
      metrics: new Metrics(),
      origin,
      nonces: new StoredNonces(db),
      admits: options.admits ?? (() => true),
      ...(options.maxPage === undefined ? {} : { maxPage: options.maxPage }),
      limits: { read: generous(), deliver: generous(), owner: generous() },
      shutdown: new Shutdown({ log }),
      ready: { database: () => true },
    });
    this.put(origin, (request) => app.fetch(request, { address: "203.0.113.7" }));
    return { host };
  }

  /** Publishes a mind's log to a resolver, as the mind would, at the present of this world. */
  async publish(
    origin: string,
    mind: Mind,
    events: readonly unknown[] = mind.events,
  ): Promise<number> {
    const response = await this.fetch(
      new Request(`${origin}/oip/v1/resolve/${mindId(mind.address) ?? ""}`, {
        method: "PUT",
        headers: { "content-type": MEDIA_TYPE },
        body: JSON.stringify({ oip: "1", type: "Bundle", mind: mind.address, log: events }),
      }),
    );
    return response.status;
  }

  /** Closes the databases and removes their files. */
  close(): void {
    for (const db of this.#databases) db.close();
    rmSync(this.#directory, { recursive: true, force: true });
  }
}
