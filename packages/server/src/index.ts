// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What the OIP services share (ADR-0013): the edges through which a service
 * reads the clock and randomness, and its storage.
 *
 * @packageDocumentation
 */

export {
  type ArchiveOptions,
  LogArchive,
  type OtherRecord,
  publicationProblem,
  type Published,
  type Resolved,
} from "./archive.ts";
export {
  ARCHIVE_SQL,
  ArchiveStore,
  type Pair,
  type Sighting,
  type Streamed,
} from "./archive-store.ts";
export { authenticate, type Authentication, NONCES_SQL, StoredNonces } from "./auth.ts";
export {
  choice,
  ConfigError,
  type ConfigOf,
  describeConfig,
  flag,
  integer,
  list,
  origin,
  readConfig,
  type Setting,
  type Settings,
  text,
} from "./config.ts";
export { nativeEd25519, useNativeEd25519 } from "./ed25519.ts";
export { type Clock, type Randomness, systemClock, systemRandomness } from "./edges.ts";
export {
  DEFAULT_FETCH_LIMITS,
  type Fetched,
  type FetchLimits,
  type FetchRefusal,
  FetchRefused,
  GuardedFetcher,
  type GuardedFetcherOptions,
  type Resolve,
} from "./fetcher.ts";
export {
  type Arrival,
  type Arrived,
  type Asked,
  clientAddress,
  gate,
  type GateOptions,
  type Handler,
} from "./gate.ts";
export {
  HttpFailure,
  problemResponse,
  readBody,
  readJson,
  readRecord,
  recordFrom,
  recordResponse,
  requireRecordType,
  responseFor,
  Unavailable,
} from "./http.ts";
export { type Address, inRange, isPublicAddress, parseAddress } from "./ip.ts";
export {
  every,
  healthResponse,
  readyResponse,
  Shutdown,
  type ShutdownOptions,
  type Stop,
  type StopSignal,
} from "./lifecycle.ts";
export { type Held, judgeCopy, type NotTaken, type Taken } from "./intake.ts";
export { overlaid, seenAt, standing } from "./judging.ts";
export { type Fields, type FieldValue, type Level, Log, type LogOptions } from "./log.ts";
export { Lookup, type LookupOptions } from "./lookup.ts";
export {
  type Counter,
  DURATION_BUCKETS,
  type Gauge,
  type Histogram,
  type Labels,
  MAX_SERIES,
  Metrics,
  METRICS_MEDIA_TYPE,
} from "./metrics.ts";
export { addressKey, type Allowance, type RateLimit, RateLimiter } from "./rate.ts";
export {
  appendOnly,
  Database,
  type DatabaseOptions,
  isBusy,
  isConstraint,
  kept,
  type Migration,
  type SQLInputValue,
  type StatementSync,
  StorageError,
} from "./storage.ts";
