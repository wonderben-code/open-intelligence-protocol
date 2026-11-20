// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `@oip/client`: the library applications use. It makes and manages a mind,
 * publishes, resolves, finds, sends and receives, and verifies everything it
 * receives before it returns it.
 *
 * @packageDocumentation
 */

export {
  type Answer,
  type Asking,
  askJson,
  askRecord,
  DEFAULT_MAX_BYTES,
  DEFAULT_TIMEOUT_MS,
  exchange,
  type Fetch,
  httpsOrigin,
  MAX_DETAIL_LENGTH,
  recordBody,
  refusalOf,
  TransportError,
  type TransportFailure,
  type TransportOptions,
} from "./transport.ts";
export {
  type Clock,
  DEFAULT_MAX_LOGS,
  Lookup,
  type LookupOptions,
  type Resolved,
  type ResolverAnswer,
  systemClock,
} from "./lookup.ts";
export {
  type ControlOptions,
  type IdentityChanges,
  type KeyEntry,
  Mind,
  type MindOptions,
  type NewMind,
  type Publication,
} from "./mind.ts";
