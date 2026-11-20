// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { type Clock, type Fetch, Lookup, Mind } from "@oip/client";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * A mind that says what it is, where it can be reached, and what it stands
 * by in public.
 *
 * @param resolvers - The HTTPS origins of the resolvers the mind trusts.
 * @param home - The HTTPS origin of a host that takes the mind on.
 * @param lock - What the mind's keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  resolvers: readonly string[],
  home: string,
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<string[]> {
  const output: string[] = [];
  const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
  // What the client remembers of its own work. An application keeps it where it lasts.
  const memory = memoryStorage();
  const mind = await Mind.create(
    { keystore, lock, resolvers, memory, ...edges },
    { kind: "agent", homes: [home] },
  );

  // A profile, and with it a location record that names it and the mind's endpoints at its home.
  const profile = await mind.publishProfile({
    name: "Ada",
    summary: "Translates contracts between English and Portuguese.",
    capabilities: [
      { id: "translate", summary: "Translation of legal texts", tags: ["lang:en", "lang:pt"] },
    ],
  });
  output.push(`a profile is published: ${profile.name}, ${profile.kind}`);
  const took = mind.publications.filter((publication) => publication.taken);
  output.push(`taken by: ${took.map((publication) => publication.service).join(", ")}`);

  // A record the mind stands by in public goes on its feed, at its home.
  const entry = await mind.publishRecord(profile);
  output.push(`its feed has an entry at ${String(entry.seq)} for a ${entry.objectType}`);

  // A home that could not be reached when something was published is brought it afterwards.
  const brought = await mind.bringHomes();
  output.push(
    `its home is brought all of it again: ${String(brought.every(({ taken }) => taken))}`,
  );

  // The next location record says the mind is away, and keeps the rest of the one before.
  const location = await mind.publishLocation({ status: "paused" });
  output.push(
    `location record ${String(location.seq)}: ${location.status}, ` +
      `${String(location.endpoints.length)} endpoints, feed at ${String(location.feed?.seq)}`,
  );

  // Another client reads all of it from the resolvers and the home, verified.
  const other = new Lookup({ resolvers, ...edges });
  const resolved = await other.resolve(mind.address);
  output.push(
    `another client reads: ${String(resolved.participant?.record.name)}, ` +
      String(resolved.location?.record.status),
  );
  const { feed } = await other.feed(mind.address);
  output.push(`and its feed: ${String(feed.entries.length)} entry that verifies`);
  mind.close();
  return output;
}
