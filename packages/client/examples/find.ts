// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { type Clock, type Fetch, Lookup, Mind } from "@oip/client";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * One mind says what it can do, and another finds it by that.
 *
 * @param services - The HTTPS origins of the resolvers and the indexers the
 *   clients name, and of a host that takes the mind on.
 * @param lock - What the mind's keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  services: {
    readonly resolvers: readonly string[];
    readonly indexers: readonly string[];
    readonly home: string;
  },
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<string[]> {
  const output: string[] = [];
  const { resolvers, indexers, home } = services;

  // A mind publishes its profile. The indexers the client names are brought it too.
  const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
  const mind = await Mind.create(
    { keystore, lock, resolvers, indexers, ...edges },
    { kind: "agent", homes: [home] },
  );
  await mind.publishProfile({
    name: "Ada",
    capabilities: [
      { id: "translate", summary: "Translation of legal texts", tags: ["lang:en", "lang:pt"] },
      { id: "review", summary: "Review of contracts", tags: ["domain:legal"] },
    ],
  });
  const listed = mind.publications.filter(
    (publication) => publication.service === "indexer" && publication.taken,
  );
  output.push(`listed by ${String(listed.length)} indexer`);
  mind.close();

  // Anyone asks the indexer, and gets back only what was fetched and verified.
  const seeker = new Lookup({ resolvers, indexers, ...edges });
  const { found, refused, sources } = await seeker.find({
    want: "translation",
    tags: ["lang:pt"],
  });
  output.push(`the indexer named ${String(sources[0]?.results)} record`);
  for (const { record, capability, by } of found) {
    const name = record.type === "Participant" ? record.name : record.type;
    output.push(
      `found: ${name}, for "${String(capability?.summary)}", score ${String(by[0]?.score)}`,
    );
  }
  output.push(`named and not returned: ${String(refused.length)}`);
  return output;
}
