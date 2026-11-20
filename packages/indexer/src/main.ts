// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The indexer as a running service: its configuration, its own mind and
 * key, its database, its listener and how it stops.
 *
 * An indexer signs what it answers, so it is a mind: it is started with
 * its own `Bundle` and with an operational key of that mind. The key is
 * read from a file that only its owner can read, and goes nowhere else:
 * not into the log, not into an error, not into the environment.
 */

import { readFileSync, statSync } from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { serve } from "@hono/node-server";
import {
  base64urlToBytes,
  MAX_TEXT_LENGTH,
  mindId,
  OipError,
  signerFromPrivateKey,
  type SyncSigner,
} from "@oip/core";
import {
  type Arrived,
  choice,
  clientAddress,
  type Clock,
  ConfigError,
  Database,
  describeConfig,
  every,
  GuardedFetcher,
  integer,
  list,
  Log,
  LogArchive,
  Lookup,
  type LookupOptions,
  Metrics,
  origin,
  publicationProblem,
  RateLimiter,
  readConfig,
  recordFrom,
  Shutdown,
  systemClock,
  text,
  useNativeEd25519,
} from "@oip/server";

import { indexerApp } from "./app.ts";
import { Broker, type BrokerOptions } from "./broker.ts";
import { DEFAULT_INDEXER_LIMITS, Indexer } from "./indexer.ts";
import { INDEXER_MIGRATIONS } from "./store.ts";

/** What every variable of the indexer starts with. */
export const PREFIX = "OIP_INDEXER_";

const MIB = 1024 * 1024;

/** The indexer's settings, each read from the variable `OIP_INDEXER_` and its name. */
export const SETTINGS = {
  ORIGIN: origin("the origin clients reach the indexer at"),
  HOST: text("the address to listen on", { fallback: "0.0.0.0" }),
  PORT: integer("the port to listen on; 0 for any that is free", {
    min: 0,
    max: 65_535,
    fallback: 8080,
  }),
  DATABASE: text("the database file", { fallback: "./indexer.db" }),
  BUNDLE_FILE: text("a file with the Bundle of the indexer's own mind, as JSON"),
  KEY_FILE: text(
    "a file that only its owner can read, with an operational key of the indexer's mind: the 32 bytes of an Ed25519 private key, as base64url",
  ),
  RESOLVERS: list(
    "the origins of the resolvers asked for the log of a sender the indexer has not met",
    origin("a resolver's origin"),
    [],
  ),
  FETCH_ALLOW: list(
    "address ranges the indexer may reach besides the public ones, as address/bits: a test network, and nothing in production",
    text("a range"),
    [],
  ),
  MAX_BODY_BYTES: integer("the most bytes of a body that are read", {
    min: 1024,
    max: 64 * MIB,
    fallback: MAX_TEXT_LENGTH,
  }),
  MAX_RECORDS: integer("the most records in one submission", {
    min: 1,
    max: 10_000,
    fallback: 100,
  }),
  QUERY_BURST: integer("how many queries one address may ask at once", {
    min: 1,
    max: 100_000,
    fallback: 120,
  }),
  QUERY_PER_MINUTE: integer("how many queries a minute one address may ask after that", {
    min: 1,
    max: 1_000_000,
    fallback: 600,
  }),
  SUBMIT_BURST: integer("how many submissions one address may make at once", {
    min: 1,
    max: 100_000,
    fallback: 20,
  }),
  SUBMIT_PER_MINUTE: integer("how many submissions a minute one address may make after that", {
    min: 1,
    max: 1_000_000,
    fallback: 60,
  }),
  DELIVER_BURST: integer("how many packets one address may send to be forwarded at once", {
    min: 1,
    max: 100_000,
    fallback: 30,
  }),
  DELIVER_PER_MINUTE: integer("how many packets a minute one address may send after that", {
    min: 1,
    max: 1_000_000,
    fallback: 120,
  }),
  SENDER_BURST: integer("how many packets of one sender are forwarded at once", {
    min: 1,
    max: 100_000,
    fallback: 10,
  }),
  SENDER_PER_MINUTE: integer("how many packets a minute of one sender are forwarded after that", {
    min: 1,
    max: 1_000_000,
    fallback: 30,
  }),
  FANOUT: integer("how many minds a packet is forwarded to where it does not say", {
    min: 1,
    max: 50,
    fallback: 10,
  }),
  OFFERS: integer("the most Offers listed for one mind", {
    min: 0,
    max: 10_000_000,
    fallback: DEFAULT_INDEXER_LIMITS.offers,
  }),
  INTENTS: integer("the most Intents listed for one mind", {
    min: 0,
    max: 10_000_000,
    fallback: DEFAULT_INDEXER_LIMITS.intents,
  }),
  TRUSTED_PROXIES: integer(
    "how many proxies stand in front, each of which adds the address it was asked from to X-Forwarded-For",
    { min: 0, max: 8, fallback: 0 },
  ),
  UNDERSTOOD: list(
    "the extension namespaces the indexer implements (core 8.3)",
    text("a namespace"),
    [],
  ),
  ED25519: choice(
    "what does the arithmetic of a signature: OpenSSL, or the portable library",
    ["native", "portable"],
    "native",
  ),
  LOG_LEVEL: choice("the least level that is logged", ["debug", "info", "warn", "error"], "info"),
  SHUTDOWN_GRACE_MS: integer("how long the indexer may take to stop, in milliseconds", {
    min: 0,
    max: 600_000,
    fallback: 10_000,
  }),
};

/** An indexer that is running. */
export interface Running {
  /** The port it listens on. */
  readonly port: number;
  /** The address of the indexer's own mind. */
  readonly address: string;
  /** Stops it, in order. It resolves when it has stopped: whether every step ended in time. */
  stop(reason: string): Promise<boolean>;
  /** Stops it when the process is told to stop, and ends the process. */
  readonly shutdown: Shutdown;
}

/** The edges of an indexer: the machine's by default, a test's own otherwise. */
export interface Edges {
  readonly clock?: Clock;
  /** Where the log goes. */
  readonly sink?: (line: string) => void;
  /** How a resolver is asked. By default a `GuardedFetcher` of `@oip/server`. */
  readonly get?: LookupOptions["get"];
  /** How a forwarded packet is posted. By default a `GuardedFetcher` of `@oip/server`. */
  readonly post?: BrokerOptions["post"];
  /** Does something again and again, and gives how to stop. By default `every` of `@oip/server`. */
  readonly every?: (work: () => void, ms: number) => () => void;
}

/**
 * Reads the indexer's key. What is wrong with the file is said by its
 * setting's name, and never with anything the file holds.
 *
 * @throws ConfigError if the file cannot be read, can be read by others
 *   than its owner, or does not hold 32 bytes as base64url.
 */
export function readKey(path: string): SyncSigner {
  const wrong = (why: string): ConfigError => new ConfigError([`${PREFIX}KEY_FILE ${why}`]);
  let held: string;
  try {
    // Where the platform has such a thing: nobody but the owner may read a key.
    if (process.platform !== "win32" && (statSync(path).mode & 0o077) !== 0) {
      throw wrong("can be read by others than its owner: give it mode 600");
    }
    held = readFileSync(path, "utf8");
  } catch (error) {
    if (error instanceof ConfigError) throw error;
    throw wrong("cannot be read");
  }
  const key = base64urlToBytes(held.trim());
  if (key?.length !== 32) {
    throw wrong("does not hold the 32 bytes of an Ed25519 private key as base64url");
  }
  return signerFromPrivateKey(key);
}

/**
 * Starts an indexer.
 *
 * @param environment - Its settings: `process.env`, or a test's own.
 * @throws ConfigError if the configuration is wrong: nothing is started.
 */
export async function start(
  environment: Readonly<Record<string, string | undefined>>,
  edges: Edges = {},
): Promise<Running> {
  const config = readConfig(PREFIX, SETTINGS, environment);
  const signer = readKey(config.KEY_FILE);
  let bundleBytes: Uint8Array;
  try {
    bundleBytes = readFileSync(config.BUNDLE_FILE);
  } catch {
    throw new ConfigError([`${PREFIX}BUNDLE_FILE cannot be read`]);
  }
  const clock = edges.clock ?? systemClock;
  const log = new Log({
    service: "indexer",
    clock,
    level: config.LOG_LEVEL,
    ...(edges.sink === undefined ? {} : { sink: edges.sink }),
  });
  // Each setting under its name as a log's field has it: MAX_RECORDS as maxRecords.
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

  // The rule for a signature is core 4.4 either way. OpenSSL does its arithmetic in a tenth
  // of the time, where it answers as the rule needs (ADR-0016).
  if (config.ED25519 === "native" && !useNativeEd25519()) {
    log.event("warn", "OpenSSL is not in use", {
      why: "it does not answer here as core 4.4 needs, or another engine has its place",
    });
  }

  const shutdown = new Shutdown({ log, graceMs: config.SHUTDOWN_GRACE_MS });
  const db = Database.open({ path: config.DATABASE }, INDEXER_MIGRATIONS, clock);
  const archive = new LogArchive({ db, clock, understood: config.UNDERSTOOD });
  let indexer: Indexer;
  try {
    // The indexer's own log, as any log is taken: what verifies of it.
    const bundle = recordFrom(bundleBytes, config.MAX_BODY_BYTES);
    const id = bundle.type === "Bundle" ? mindId((bundle as { mind?: unknown }).mind) : undefined;
    if (id === undefined) throw new OipError("invalid-record", "it holds no Bundle");
    const problem = publicationProblem(archive.publish(id, bundle as never));
    if (problem !== undefined) throw problem;
    indexer = new Indexer({
      db,
      archive,
      clock,
      address: (bundle as unknown as { mind: string }).mind,
      signer,
      limits: { offers: config.OFFERS, intents: config.INTENTS },
    });
  } catch (error) {
    db.close();
    if (error instanceof OipError) {
      throw new ConfigError([`${PREFIX}BUNDLE_FILE: ${error.message}`]);
    }
    // The key is no operational key of the mind the bundle is of.
    if (error instanceof TypeError) throw new ConfigError([`${PREFIX}KEY_FILE: ${error.message}`]);
    throw error;
  }
  // Added first, so stopped last: what the listener was doing is on the disk before it closes.
  shutdown.add("database", () => {
    db.checkpoint();
    db.close();
  });
  const metrics = new Metrics();
  // What has expired is taken out of the index every minute.
  const stopTidying = (edges.every ?? every)(() => {
    try {
      indexer.prune(clock.now());
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
  const guarded = new GuardedFetcher({ allow: config.FETCH_ALLOW, userAgent: "oip-indexer" });
  const lookup =
    config.RESOLVERS.length === 0
      ? undefined
      : new Lookup({
          archive,
          get: edges.get ?? ((url, accept) => guarded.get(url, accept)),
          resolvers: config.RESOLVERS,
          clock,
          log,
          metrics,
          service: "indexer",
          maxBundleBytes: config.MAX_BODY_BYTES,
        });
  const broker = new Broker({
    indexer,
    archive,
    log,
    metrics,
    post: edges.post ?? ((url, body, contentType) => guarded.post(url, body, contentType)),
    perSender: limiter(config.SENDER_BURST, config.SENDER_PER_MINUTE),
    fanout: config.FANOUT,
    ...(lookup === undefined ? {} : { lookup }),
  });
  // Added after the listener, so stopped before it: what was taken to be forwarded is sent.
  shutdown.add("deliveries", () => broker.idle());
  const app = indexerApp({
    indexer,
    broker,
    archive,
    clock,
    log,
    metrics,
    limits: {
      query: limiter(config.QUERY_BURST, config.QUERY_PER_MINUTE),
      submit: limiter(config.SUBMIT_BURST, config.SUBMIT_PER_MINUTE),
      deliver: limiter(config.DELIVER_BURST, config.DELIVER_PER_MINUTE),
    },
    maxBodyBytes: config.MAX_BODY_BYTES,
    maxRecords: config.MAX_RECORDS,
    shutdown,
    ready: {
      database: () => db.prepare("SELECT 1 AS ok").get() !== undefined,
    },
  });

  const port = await new Promise<number>((resolve, reject) => {
    const listening = serve(
      {
        fetch: (request, env: { incoming: Arrived }) =>
          app.fetch(request, { address: clientAddress(env.incoming, config.TRUSTED_PROXIES) }),
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
  return { port, address: indexer.address, shutdown, stop: (reason) => shutdown.run(reason) };
}
