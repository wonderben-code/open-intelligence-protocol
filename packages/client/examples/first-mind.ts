// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { type Clock, type Fetch, Lookup, Mind, systemClock } from "@oip/client";
import { formatTimestamp } from "@oip/core";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * A mind from nothing: its keys in a keystore, its genesis with the
 * resolvers it trusts, a record it signs, and a change to its identity.
 *
 * @param resolvers - The HTTPS origins of the resolvers the mind trusts.
 * @param lock - What the mind's keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  resolvers: readonly string[],
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<string[]> {
  const output: string[] = [];
  const clock = edges.clock ?? systemClock;

  // The keys are made in the keystore, and the genesis is published to every resolver.
  const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
  const mind = await Mind.create(
    { keystore, lock, resolvers, ...edges },
    { kind: "agent", homes: ["https://home.example"] },
  );
  const took = mind.publications.filter(
    (publication) => publication.service === "resolver" && publication.taken,
  ).length;
  output.push(`a mind is made, and ${String(took)} resolvers have its genesis`);

  // The mind signs a record with its operational key.
  const intent = await mind.sign({
    oip: "1",
    type: "Intent",
    author: mind.address,
    created: formatTimestamp(clock.now()),
    want: "A lease translated into Portuguese.",
  });
  output.push(`it signs an ${intent.type} with ${String(intent.proof.length)} proof`);

  // Anyone resolves it from the same resolvers, and verifies its log.
  const other = new Lookup({ resolvers, ...edges });
  const resolved = await other.resolve(mind.address);
  output.push(`another client verifies its log: ${String(resolved.log.entries.length)} event`);

  // A change of identity takes the control keys, which are unlocked for it alone.
  const state = await mind.update({ homes: ["https://new-home.example"] }, { control: lock });
  output.push(`after an update it is at event ${String(state.seq)}, at ${String(state.homes[0])}`);
  output.push(`a backup is due for: ${(await keystore.backupDue()).join(", ")}`);
  mind.close();
  return output;
}
