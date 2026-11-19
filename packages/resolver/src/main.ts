// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The resolver as a running service: its configuration, its database, its
 * listener and how it stops.
 *
 * This is where the edges are joined to the rest: the clock, the
 * environment, the socket. `start` takes them as arguments, so a test
 * starts a resolver on a port of its own with a clock it moves.
 */

import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { serve } from "@hono/node-server";
import { MAX_TEXT_LENGTH } from "@oip/core";
import {
  type Arrived,
  clientAddress,
  type Clock,
  Database,
  describeConfig,
  flag,
  integer,
  list,
  Log,
  LogArchive,
  Metrics,
  origin,
  RateLimiter,
  readConfig,
  Shutdown,
  StoredNonces,
  systemClock,
  text,
} from "@oip/server";

import { resolverApp } from "./app.ts";
import { RESOLVER_MIGRATIONS } from "./store.ts";

/** What every variable of the resolver starts with. */
export const PREFIX = "OIP_RESOLVER_";

/** The resolver's settings, each read from the variable `OIP_RESOLVER_` and its name. */
export const SETTINGS = {
  ORIGIN: origin("the origin clients reach the resolver at, which a signed request names"),
  HOST: text("the address to listen on", { fallback: "0.0.0.0" }),
  PORT: integer("the port to listen on; 0 for any that is free", {
    min: 0,
    max: 65_535,
    fallback: 8080,
  }),
  DATABASE: text("the database file", { fallback: "./resolver.db" }),
  AUTHENTICATED_PUBLICATION: flag(
    "whether a bundle may be published only by a request a mind has signed",
    false,
  ),
  MAX_BUNDLE_BYTES: integer("the most bytes of a published bundle that are read", {
    min: 1024,
    max: 64 * 1024 * 1024,
    fallback: MAX_TEXT_LENGTH,
  }),
  READ_BURST: integer("how many requests one address may read at once", {
    min: 1,
    max: 100_000,
    fallback: 120,
  }),
  READ_PER_MINUTE: integer("how many requests a minute one address may read after that", {
    min: 1,
    max: 1_000_000,
    fallback: 600,
  }),
  PUBLISH_BURST: integer("how many bundles one address may publish at once", {
    min: 1,
    max: 100_000,
    fallback: 20,
  }),
  PUBLISH_PER_MINUTE: integer("how many bundles a minute one address may publish after that", {
    min: 1,
    max: 1_000_000,
    fallback: 60,
  }),
  MAX_STREAMS: integer("the most streams open at once", { min: 0, max: 100_000, fallback: 256 }),
  TRUSTED_PROXIES: integer(
    "how many proxies stand in front, each of which adds the address it was asked from to X-Forwarded-For",
    { min: 0, max: 8, fallback: 0 },
  ),
  UNDERSTOOD: list(
    "the extension namespaces the resolver implements (core 8.3)",
    text("a namespace"),
    [],
  ),
  LOG_LEVEL: text("the least level that is logged: debug, info, warn or error", {
    fallback: "info",
  }),
  SHUTDOWN_GRACE_MS: integer("how long the resolver may take to stop, in milliseconds", {
    min: 0,
    max: 600_000,
    fallback: 10_000,
  }),
};

const LEVELS = ["debug", "info", "warn", "error"] as const;

/** A resolver that is running. */
export interface Running {
  /** The port it listens on. */
  readonly port: number;
  /** Stops it, in order. It resolves when it has stopped: whether every step ended in time. */
  stop(reason: string): Promise<boolean>;
  /** Stops it when the process is told to stop, and ends the process. */
  readonly shutdown: Shutdown;
}

/**
 * Starts a resolver.
 *
 * @param environment - Its settings: `process.env`, or a test's own.
 * @param edges - The clock, and where the log goes. The machine's by default.
 * @throws ConfigError if the configuration is wrong: nothing is started.
 */
export async function start(
  environment: Readonly<Record<string, string | undefined>>,
  edges: { clock?: Clock; sink?: (line: string) => void } = {},
): Promise<Running> {
  const config = readConfig(PREFIX, SETTINGS, environment);
  const clock = edges.clock ?? systemClock;
  const level = LEVELS.find((known) => known === config.LOG_LEVEL) ?? "info";
  const log = new Log({
    service: "resolver",
    clock,
    level,
    ...(edges.sink === undefined ? {} : { sink: edges.sink }),
  });
  // Each setting under its name as a log's field has it: MAX_STREAMS as maxStreams.
  log.event(
    "info",
    "starting",
    Object.fromEntries(
      Object.entries(describeConfig(PREFIX, SETTINGS, config)).map(([variable, value]) => [
        variable
          .slice(PREFIX.length)
          .toLowerCase()
          .replace(/_([a-z])/gu, (_, letter: string) => letter.toUpperCase()),
        value,
      ]),
    ),
  );

  const shutdown = new Shutdown({ log, graceMs: config.SHUTDOWN_GRACE_MS });
  const db = Database.open({ path: config.DATABASE }, RESOLVER_MIGRATIONS, clock);
  // Added first, so stopped last: what the listener was doing is on the disk before it closes.
  shutdown.add("database", () => {
    db.checkpoint();
    db.close();
  });
  const metrics = new Metrics();
  const nonces = new StoredNonces(db);
  const tidy = setInterval(() => {
    try {
      nonces.forget(clock.now());
    } catch (error) {
      log.failure("nonces not forgotten", error);
    }
  }, 60_000);
  // A timer does not keep a process alive that has nothing else to do.
  tidy.unref();
  shutdown.add("timers", () => {
    clearInterval(tidy);
  });

  let server: Server | undefined;
  shutdown.add(
    "listener",
    () =>
      new Promise<void>((resolve) => {
        if (server === undefined) resolve();
        else {
          server.close(() => {
            resolve();
          });
          // Those with nothing in flight are closed now, and the rest when they have answered.
          server.closeIdleConnections();
        }
      }),
  );

  const limiter = (burst: number, perMinute: number): RateLimiter =>
    new RateLimiter({ burst, perMinute }, clock);
  const app = resolverApp({
    resolver: new LogArchive({ db, clock, understood: config.UNDERSTOOD }),
    clock,
    log,
    metrics,
    origin: config.ORIGIN,
    nonces,
    authenticatedPublication: config.AUTHENTICATED_PUBLICATION,
    maxBundleBytes: config.MAX_BUNDLE_BYTES,
    limits: {
      read: limiter(config.READ_BURST, config.READ_PER_MINUTE),
      publish: limiter(config.PUBLISH_BURST, config.PUBLISH_PER_MINUTE),
    },
    shutdown,
    ready: {
      database: () => db.prepare("SELECT 1 AS ok").get() !== undefined,
    },
    maxStreams: config.MAX_STREAMS,
  });

  const port = await new Promise<number>((resolve, reject) => {
    const listening = serve(
      {
        fetch: (request, env: { incoming: Arrived }) => {
          const address = clientAddress(env.incoming, config.TRUSTED_PROXIES);
          return app.fetch(request, address === undefined ? {} : { address });
        },
        hostname: config.HOST,
        port: config.PORT,
      },
      (info: AddressInfo) => {
        resolve(info.port);
      },
    ) as Server;
    listening.once("error", reject);
    server = listening;
  });
  log.event("info", "listening", { host: config.HOST, port });
  return { port, shutdown, stop: (reason) => shutdown.run(reason) };
}
