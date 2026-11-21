// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { type Clock, type Fetch, Lookup, Mind } from "@oip/client";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * A mind moves from one host to another, and takes everything with it.
 *
 * @param resolvers - The HTTPS origins of the resolvers the mind trusts.
 * @param hosts - The host it starts at, and the one it moves to.
 * @param lock - What the mind's keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  resolvers: readonly string[],
  hosts: { readonly from: string; readonly to: string },
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<string[]> {
  const output: string[] = [];
  const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
  const mind = await Mind.create(
    { keystore, lock, resolvers, memory: memoryStorage(), ...edges },
    { kind: "agent", homes: [hosts.from] },
  );
  const profile = await mind.publishProfile({ name: "Ada" });
  await mind.publishRecord(profile);
  output.push(`at ${new URL(mind.state.homes[0] ?? hosts.from).host}, with a feed of 1 entry`);

  // The new host is brought the log, the profile and the feed. Then the mind's identity names it.
  const state = await mind.moveHomes([hosts.to], { control: lock });
  output.push(
    `moved to ${new URL(state.homes[0] ?? hosts.to).host}, at event ${String(state.seq)}`,
  );

  // Anyone who resolves the mind finds it there, with its feed whole.
  const other = new Lookup({ resolvers, ...edges });
  const resolved = await other.resolve(mind.address);
  const inbox = resolved.location?.record.endpoints[0]?.url ?? hosts.to;
  const { feed, sources } = await other.feed(mind.address);
  output.push(`its endpoints are at ${new URL(inbox).host}`);
  output.push(
    `its feed is read from ${String(sources.length)} home: ${String(feed.entries.length)} entry`,
  );
  mind.close();
  return output;
}
