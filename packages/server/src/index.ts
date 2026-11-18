// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What the OIP services share (ADR-0013): the edges through which a service
 * reads the clock and randomness, and its storage.
 *
 * @packageDocumentation
 */

export { type Clock, type Randomness, systemClock, systemRandomness } from "./edges.ts";
export {
  HttpFailure,
  problemResponse,
  readBody,
  readRecord,
  recordResponse,
  responseFor,
  Unavailable,
} from "./http.ts";
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
