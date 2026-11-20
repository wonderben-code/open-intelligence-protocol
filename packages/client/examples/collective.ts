// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { type Clock, type Fetch, Lookup, Mind } from "@oip/client";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * Three people found a collective that acts when two of them agree.
 *
 * @param resolvers - The HTTPS origins of the resolvers they trust.
 * @param lock - What their keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  resolvers: readonly string[],
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<string[]> {
  const output: string[] = [];
  const person = async (): Promise<Mind> => {
    const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
    return Mind.create({ keystore, lock, resolvers, ...edges }, { kind: "human" });
  };
  const [ada, bo, cy] = [await person(), await person(), await person()];
  const members = [ada.address, bo.address, cy.address];

  // Each founder signs the genesis, with an invocation key of its own. Then anyone publishes it.
  let genesis = await ada.foundCollective({ members, threshold: 2 }, { invocation: lock });
  genesis = await bo.signEvent(genesis, { invocation: lock });
  genesis = await cy.signEvent(genesis, { invocation: lock });
  const club = await ada.publishLog([genesis]);
  const other = await new Lookup({ resolvers, ...edges }).resolve(club.mind);
  const signers = other.state.controller.kind === "member" ? other.state.controller.threshold : 0;
  output.push(`a ${other.state.kind} of ${String(members.length)}, of whom ${String(signers)} act`);

  // What one member signs in its name is one member's. With a second, it is the collective's.
  const intent = await ada.intent({ author: club.mind, want: "A hall for the spring meeting." });
  output.push(`signed by one: the collective's? ${String(await ada.countsFor(intent, club.mind))}`);
  const both = await bo.cosign(intent);
  output.push(`signed by two: the collective's? ${String(await bo.countsFor(both, club.mind))}`);
  for (const mind of [ada, bo, cy]) mind.close();
  return output;
}
