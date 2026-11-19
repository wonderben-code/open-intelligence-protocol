// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The host as a running service: its configuration, its database, its
 * listener, its sockets and how it stops.
 *
 * This is where the edges are joined to the rest: the clock, randomness,
 * the environment, the network. `start` takes them as arguments, so a test
 * starts a host on a port of its own with a clock it moves.
 */

import type { IncomingMessage, Server } from "node:http";
import type { AddressInfo } from "node:net";

import { serve } from "@hono/node-server";
import { MAX_TEXT_LENGTH, mindId } from "@oip/core";
import {
  type Arrived,
  choice,
  clientAddress,
  type Clock,
  ConfigError,
  Database,
  describeConfig,
  every,
  flag,
  GuardedFetcher,
  integer,
  list,
  Log,
  LogArchive,
  Metrics,
  origin,
  type Randomness,
  RateLimiter,
  readConfig,
  Shutdown,
  StoredNonces,
  systemClock,
  systemRandomness,
  text,
} from "@oip/server";

import { hostApp } from "./app.ts";
import { DEFAULT_HOST_LIMITS, Host } from "./host.ts";
import { Lookup, type LookupOptions } from "./lookup.ts";
import { Sockets } from "./sockets.ts";
import { HOST_MIGRATIONS } from "./store.ts";
import { attachSockets } from "./upgrade.ts";

/** What every variable of the host starts with. */
export const PREFIX = "OIP_HOST_";

const MIB = 1024 * 1024;

/** The host's settings, each read from the variable `OIP_HOST_` and its name. */
export const SETTINGS = {
  ORIGIN: origin("the origin clients reach the host at, which a Hello and a signed request name"),
  HOST: text("the address to listen on", { fallback: "0.0.0.0" }),
  PORT: integer("the port to listen on; 0 for any that is free", {
    min: 0,
    max: 65_535,
    fallback: 8080,
  }),
  DATABASE: text("the database file", { fallback: "./host.db" }),
  MINDS: list(
    "the addresses of the minds the host takes on when they bring their bundle",
    text("a mind's address"),
    [],
  ),
  OPEN: flag("whether the host takes on any mind that brings its bundle", false),
  MAX_MINDS: integer("the most minds an open host serves", {
    min: 1,
    max: 10_000_000,
    fallback: 1000,
  }),
  RESOLVERS: list(
    "the origins of the resolvers asked for the log of a sender the host has not met",
    origin("a resolver's origin"),
    [],
  ),
  FETCH_ALLOW: list(
    "address ranges the host may fetch from besides the public ones, as address/bits: a test network, and nothing in production",
    text("a range"),
    [],
  ),
  MAX_RECORD_BYTES: integer("the most bytes of a record that are read", {
    min: 1024,
    max: 64 * MIB,
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
  DELIVER_BURST: integer("how many records one address may deliver at once", {
    min: 1,
    max: 100_000,
    fallback: 60,
  }),
  DELIVER_PER_MINUTE: integer("how many records a minute one address may deliver after that", {
    min: 1,
    max: 1_000_000,
    fallback: 600,
  }),
  OWNER_BURST: integer("how many signed requests one address may make at once", {
    min: 1,
    max: 100_000,
    fallback: 60,
  }),
  OWNER_PER_MINUTE: integer("how many signed requests a minute one address may make after that", {
    min: 1,
    max: 1_000_000,
    fallback: 600,
  }),
  MAILBOX_ITEMS: integer("the most items in one mailbox", {
    min: 1,
    max: 10_000_000,
    fallback: DEFAULT_HOST_LIMITS.mailboxItems,
  }),
  MAILBOX_BYTES: integer("the most bytes in one mailbox", {
    min: MIB,
    max: 1024 * 1024 * MIB,
    fallback: DEFAULT_HOST_LIMITS.mailboxBytes,
  }),
  RETENTION_DAYS: integer(
    "how many days an item stays in a mailbox; Layer 1, 13.5 asks for 30 at least",
    { min: 30, max: 3650, fallback: 30 },
  ),
  OBJECT_BYTES: integer("the most bytes of records the host serves for one mind", {
    min: MIB,
    max: 1024 * 1024 * MIB,
    fallback: DEFAULT_HOST_LIMITS.objectBytes,
  }),
  FEED_ENTRIES: integer("the most entries in the feed of one mind", {
    min: 1,
    max: 1_000_000_000,
    fallback: DEFAULT_HOST_LIMITS.feedEntries,
  }),
  MAX_SOCKETS: integer("the most WebSocket connections open at once", {
    min: 0,
    max: 1_000_000,
    fallback: 1024,
  }),
  TRUSTED_PROXIES: integer(
    "how many proxies stand in front, each of which adds the address it was asked from to X-Forwarded-For",
    { min: 0, max: 8, fallback: 0 },
  ),
  UNDERSTOOD: list(
    "the extension namespaces the host implements (core 8.3)",
    text("a namespace"),
    [],
  ),
  LOG_LEVEL: choice("the least level that is logged", ["debug", "info", "warn", "error"], "info"),
  SHUTDOWN_GRACE_MS: integer("how long the host may take to stop, in milliseconds", {
    min: 0,
    max: 600_000,
    fallback: 10_000,
  }),
};

const DAY = 86_400_000_000_000n;

/** A host that is running. */
export interface Running {
  /** The port it listens on. */
  readonly port: number;
  /** Stops it, in order. It resolves when it has stopped: whether every step ended in time. */
  stop(reason: string): Promise<boolean>;
  /** Stops it when the process is told to stop, and ends the process. */
  readonly shutdown: Shutdown;
}

/** The edges of a host: the machine's by default, a test's own otherwise. */
export interface Edges {
  readonly clock?: Clock;
  readonly randomness?: Randomness;
  /** Where the log goes. */
  readonly sink?: (line: string) => void;
  /** How a resolver is asked. By default a `GuardedFetcher` of `@oip/server`. */
  readonly get?: LookupOptions["get"];
  /** Does something again and again, and gives how to stop. By default `every` of `@oip/server`. */
  readonly every?: (work: () => void, ms: number) => () => void;
}

/**
 * Starts a host.
 *
 * @param environment - Its settings: `process.env`, or a test's own.
 * @throws ConfigError if the configuration is wrong: nothing is started.
 */
export async function start(
  environment: Readonly<Record<string, string | undefined>>,
  edges: Edges = {},
): Promise<Running> {
  const config = readConfig(PREFIX, SETTINGS, environment);
  if (config.MINDS.some((mind) => mindId(mind) === undefined)) {
    throw new ConfigError([
      `${PREFIX}MINDS: each is the address of a mind, which starts with did:oip:`,
    ]);
  }
  const clock = edges.clock ?? systemClock;
  const log = new Log({
    service: "host",
    clock,
    level: config.LOG_LEVEL,
    ...(edges.sink === undefined ? {} : { sink: edges.sink }),
  });
  // Each setting under its name as a log's field has it: MAX_SOCKETS as maxSockets.
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
  const db = Database.open({ path: config.DATABASE }, HOST_MIGRATIONS, clock);
  // Added first, so stopped last: what the listener was doing is on the disk before it closes.
  shutdown.add("database", () => {
    db.checkpoint();
    db.close();
  });
  const metrics = new Metrics();
  const nonces = new StoredNonces(db);
  const archive = new LogArchive({ db, clock, understood: config.UNDERSTOOD });
  const host = new Host({
    db,
    archive,
    limits: {
      mailboxItems: config.MAILBOX_ITEMS,
      mailboxBytes: config.MAILBOX_BYTES,
      retention: BigInt(config.RETENTION_DAYS) * DAY,
      objectBytes: config.OBJECT_BYTES,
      feedEntries: config.FEED_ENTRIES,
    },
  });
  // What is kept only for a time is let go of every minute: nonces, old mail, packets
  // that can no longer be accepted.
  const stopTidying = (edges.every ?? every)(() => {
    try {
      nonces.forget(clock.now());
      host.prune(clock.now());
    } catch (error) {
      log.failure("not tidied", error);
    }
  }, 60_000);
  shutdown.add("timers", stopTidying);

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
  const limits = {
    read: limiter(config.READ_BURST, config.READ_PER_MINUTE),
    deliver: limiter(config.DELIVER_BURST, config.DELIVER_PER_MINUTE),
    owner: limiter(config.OWNER_BURST, config.OWNER_PER_MINUTE),
  };
  const fetcher =
    edges.get ??
    (() => {
      const guarded = new GuardedFetcher({ allow: config.FETCH_ALLOW, userAgent: "oip-host" });
      return (url: string, accept: string) => guarded.get(url, accept);
    })();
  const lookup =
    config.RESOLVERS.length === 0
      ? undefined
      : new Lookup({
          archive,
          get: fetcher,
          resolvers: config.RESOLVERS,
          clock,
          log,
          metrics,
          maxBundleBytes: config.MAX_RECORD_BYTES,
        });
  const app = hostApp({
    host,
    archive,
    clock,
    log,
    metrics,
    origin: config.ORIGIN,
    nonces,
    admits: (mind) => config.MINDS.includes(mind) || (config.OPEN && host.minds < config.MAX_MINDS),
    maxRecordBytes: config.MAX_RECORD_BYTES,
    limits,
    shutdown,
    ready: {
      database: () => db.prepare("SELECT 1 AS ok").get() !== undefined,
    },
    ...(lookup === undefined ? {} : { lookup }),
  });
  const sockets = new Sockets({
    host,
    archive,
    clock,
    randomness: edges.randomness ?? systemRandomness,
    log,
    metrics,
    origin: config.ORIGIN,
    deliver: limits.deliver,
    maxSockets: config.MAX_SOCKETS,
    maxRecordBytes: config.MAX_RECORD_BYTES,
    ...(lookup === undefined ? {} : { lookup }),
  });

  const port = await new Promise<number>((resolve, reject) => {
    const listening = serve(
      {
        fetch: (request, env: { incoming: Arrived }) => {
          return app.fetch(request, {
            address: clientAddress(env.incoming, config.TRUSTED_PROXIES),
          });
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
  const closeSockets = attachSockets(server as unknown as Server, {
    host,
    sockets,
    log,
    limiter: limits.owner,
    address: (request: IncomingMessage) => clientAddress(request, config.TRUSTED_PROXIES),
    stopping: () => shutdown.stopping,
    maxRecordBytes: config.MAX_RECORD_BYTES,
  });
  // Added last, so stopped first: a listener does not close while connections are open on it.
  shutdown.add("sockets", () => closeSockets(Math.min(config.SHUTDOWN_GRACE_MS, 2000)));
  log.event("info", "listening", { host: config.HOST, port });
  return { port, shutdown, stop: (reason) => shutdown.run(reason) };
}
