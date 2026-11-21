// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A client as the page makes one, for a test with no browser: its requests
 * are kept to the services chosen, as the page keeps them, and carried to
 * the network of a telling on this machine.
 */

import { join } from "node:path";

import { LOCAL } from "@oip/cli";
import { Lookup, Reader } from "@oip/client";
import { readNetwork, routed } from "@oip/local";
import type { Stage } from "@oip/translation-demo";

import { Asked } from "../src/oip/asked.ts";

/** What a page holds for the services its reader chose, with every request that left it. */
export interface PageClient {
  readonly asked: Asked;
  readonly lookup: Lookup;
  readonly reader: Reader;
  /** The origin of each request that was made, in order. */
  readonly made: string[];
}

/**
 * @param chosen - The services chosen. Default: the telling's resolver and indexer.
 * @param down - Origins that cannot be reached.
 */
export function pageClient(
  stage: Stage,
  chosen: { readonly resolvers?: readonly string[]; readonly indexers?: readonly string[] } = {},
  down: readonly string[] = [],
): PageClient {
  const { resolvers = [LOCAL.resolver], indexers = [LOCAL.indexer] } = chosen;
  const { routes } = readNetwork(join(stage.root, "network"));
  const carry = routed(routes, (request) => fetch(request));
  const made: string[] = [];
  const asked = new Asked([...resolvers, ...indexers], (request) => {
    const { origin } = new URL(request.url);
    made.push(origin);
    return down.includes(origin) ? Promise.reject(new TypeError("fetch failed")) : carry(request);
  });
  const lookup = new Lookup({ resolvers, indexers, fetch: asked.fetch });
  return { asked, lookup, reader: new Reader({ lookup }), made };
}
