// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The indexer (Layer 1, Section 18): capability queries over the records
 * minds publish, and brokered delivery.
 *
 * @packageDocumentation
 */

export {
  DEFAULT_INDEXER_LIMITS,
  Indexer,
  type IndexerLimits,
  type IndexerOptions,
  type Submission,
} from "./indexer.ts";
export {
  type Found,
  INDEXER_MIGRATIONS,
  IndexStore,
  type Item,
  type Kind,
  type Search,
} from "./store.ts";
