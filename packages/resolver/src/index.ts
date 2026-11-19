// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The resolver (Layer 1, Section 17): identity logs verified, witnessed and
 * served, with first-seen times and duplicity evidence.
 *
 * @packageDocumentation
 */

export { resolverApp, type ResolverAppOptions } from "./app.ts";
export { type Arrival, type Arrived, clientAddress } from "@oip/server";
export { RESOLVER_MIGRATIONS } from "./store.ts";
export { type Edges, PREFIX, type Running, SETTINGS, start } from "./main.ts";
