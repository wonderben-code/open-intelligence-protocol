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
export { type AliasCheck, type AliasOptions, type DidLike } from "./aliases.ts";
export {
  type Clock,
  DEFAULT_MAX_FEED_ENTRIES,
  DEFAULT_MAX_LOGS,
  type HomeAnswer,
  Lookup,
  type LookupOptions,
  type ReadFeed,
  type Resolved,
  type ResolverAnswer,
  systemClock,
} from "./lookup.ts";
export {
  type Finding,
  type Found,
  type IndexerAnswer,
  type Listed,
  MAX_RESULTS,
  type NotFound,
  type Ranking,
} from "./find.ts";
export {
  DEFAULT_EXPIRES_IN,
  type Delivery,
  type Inbox,
  type MailboxAnswer,
  MAX_EXPIRES_IN,
  MAX_MAILBOX_ITEMS,
  MAX_QUERY_EXPIRES_IN,
  type Message,
  type Received,
  type Sent,
} from "./messages.ts";
export {
  type ControlOptions,
  type IdentityChanges,
  type KeyEntry,
  Mind,
  type MindOptions,
  type NewMind,
} from "./mind.ts";
export {
  DEFAULT_TTL,
  type Endpoint,
  homeEndpoints,
  type LocationFields,
  type ProfileFields,
  type Publication,
} from "./publish.ts";
