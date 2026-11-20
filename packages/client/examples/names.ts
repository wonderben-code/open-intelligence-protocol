// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { type Clock, type Fetch, Lookup, Mind } from "@oip/client";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * A mind says which other names are its own, and another client checks each.
 *
 * @param resolvers - The HTTPS origins of the resolvers the mind trusts.
 * @param sites - Two websites the mind says are its own. The first is expected to say so too.
 * @param lock - What the mind's keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  resolvers: readonly string[],
  sites: readonly [string, string],
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<{ address: string; output: string[] }> {
  const output: string[] = [];
  const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
  // Listing a name proves nothing: anyone can list any name.
  const mind = await Mind.create(
    { keystore, lock, resolvers, ...edges },
    { kind: "agent", alsoKnownAs: [...sites] },
  );
  const { address } = mind;
  output.push(`the mind lists ${String(mind.state.alsoKnownAs.length)} names`);

  // A website is the mind's if it says so itself: its `/.well-known/oip/did` holds the
  // mind's address (Layer 1, 5.3). Put it there, and then ask.
  const lookup = new Lookup({ resolvers, ...edges });
  const { checks } = await lookup.aliases(address);
  for (const check of checks) {
    const said = check.verified ? "its own" : `not shown to be (${String(check.reason)})`;
    output.push(`${check.alias}: ${said}`);
  }
  mind.close();
  return { address, output };
}
