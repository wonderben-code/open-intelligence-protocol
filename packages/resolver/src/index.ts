// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The resolver (Layer 1, Section 17): identity logs verified, witnessed and
 * served, with first-seen times and duplicity evidence.
 *
 * @packageDocumentation
 */

export { type Arrival, resolverApp, type ResolverAppOptions } from "./app.ts";
export { type Held, judgeCopy, type NotTaken, type Taken } from "./intake.ts";
export { type OtherRecord, type Published, Resolver, type ResolverOptions } from "./resolver.ts";
export {
  type Pair,
  RESOLVER_MIGRATIONS,
  ResolverStore,
  type Sighting,
  type Streamed,
} from "./store.ts";
