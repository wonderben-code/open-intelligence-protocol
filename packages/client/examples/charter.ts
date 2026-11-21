// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { type Clock, type Fetch, Mind, systemClock } from "@oip/client";
import { formatTimestamp } from "@oip/core";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * A collective gives one member a role, which that member then acts in
 * alone, and takes in a fourth member.
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
  const clock = edges.clock ?? systemClock;
  const person = async (): Promise<Mind> => {
    const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
    return Mind.create({ keystore, lock, resolvers, ...edges }, { kind: "human" });
  };
  const [ada, bo, cy, dee] = [await person(), await person(), await person(), await person()];
  const members = [ada.address, bo.address, cy.address];
  let genesis = await ada.foundCollective({ members, threshold: 2 }, { invocation: lock });
  genesis = await bo.signEvent(genesis, { invocation: lock });
  genesis = await cy.signEvent(genesis, { invocation: lock });
  const club = await ada.publishLog([genesis]);

  // A charter says what its members may do alone (Layer 2, 6.2). It is the collective's
  // record, so two of the three sign it.
  const draft = await ada.charter(club.mind, {
    name: "The club",
    purpose: "To meet in spring.",
    roles: {
      buyer: {
        purpose: "Books what the club needs.",
        powers: [
          { command: "/oip/sign/Intent", policy: [["<=", ".constraints.budget.max", "100"]] },
        ],
      },
    },
    assignments: [{ mind: cy.address, role: "buyer" }],
    expires: formatTimestamp(clock.now() + 365n * 86_400_000_000_000n),
  });
  const charter = await bo.cosign(draft);
  cy.hold(charter);

  // Cy is the buyer, and signs for the club alone, as far as the role goes.
  const wanting = (max: string) =>
    cy.intent(
      {
        author: club.mind,
        want: "A hall for the spring meeting.",
        constraints: { budget: { max } },
      },
      { charter },
    );
  output.push(
    `the buyer, within the budget: ${String(await cy.countsFor(await wanting("80"), club.mind))}`,
  );
  output.push(
    `the buyer, beyond it: ${String(await cy.countsFor(await wanting("150"), club.mind))}`,
  );

  // Dee joins, and three of the four must now agree. The members that are sign the change,
  // by their threshold, and so does the member that is new (Layer 1, 9.3).
  let update = await ada.changeCollective(
    club.mind,
    { members: [...members, dee.address], threshold: 3 },
    { invocation: lock },
  );
  update = await bo.signEvent(update, { invocation: lock });
  update = await dee.signEvent(update, { invocation: lock });
  const { state } = await ada.publishLog([genesis, update]);
  if (state.controller.kind === "member") {
    const { members: now, threshold } = state.controller;
    output.push(`now a collective of ${String(now.length)}, of whom ${String(threshold)} act`);
  }
  for (const mind of [ada, bo, cy, dee]) mind.close();
  return output;
}
