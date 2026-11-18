// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What the OIP services share (ADR-0013): the edges through which a service
 * reads the clock and randomness, and its storage.
 *
 * @packageDocumentation
 */

export {
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
  HttpFailure,
  problemResponse,
  readBody,
  readRecord,
  recordResponse,
  responseFor,
  Unavailable,
} from "./http.ts";
export { type Address, inRange, isPublicAddress, parseAddress } from "./ip.ts";
export { type Fields, type FieldValue, type Level, Log, type LogOptions } from "./log.ts";
export { addressKey, type Allowance, type RateLimit, RateLimiter } from "./rate.ts";
export {
  appendOnly,
  Database,
  type DatabaseOptions,
  isBusy,
  isConstraint,
  type Migration,
  type SQLInputValue,
  type StatementSync,
  StorageError,
} from "./storage.ts";
