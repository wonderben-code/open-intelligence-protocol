// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { carried, type Clock, type Fetch, Mind, systemClock } from "@oip/client";
import { contentId, formatRecordRef, formatTimestamp } from "@oip/core";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * A deal, as the papers tell it: Amina wants a lease translated, and the
 * agent of Lexis Ltd commits the firm to it, within what the firm lets it.
 *
 * @param resolvers - The HTTPS origins of the resolvers they trust.
 * @param home - The HTTPS origin of a host that takes them on.
 * @param lock - What their keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  resolvers: readonly string[],
  home: string,
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<string[]> {
  const output: string[] = [];
  const clock = edges.clock ?? systemClock;
  const mindOf = async (kind: string): Promise<Mind> => {
    const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
    const mind = await Mind.create(
      { keystore, lock, resolvers, memory: memoryStorage(), ...edges },
      { kind, homes: [home] },
    );
    await mind.publishLocation();
    return mind;
  };
  const amina = await mindOf("human");
  const lexis = await mindOf("institution");
  const agent = await mindOf("agent");
  /** Brings a record from one of them to another, sealed. The other reads its mailbox, and holds it. */
  const pass = async (from: Mind, to: Mind, record: object): Promise<void> => {
    await from.send({ to: [to.address], verb: "inform", content: carried(record) });
    await to.receive();
  };
  const day = 86_400_000_000_000n;

  // The firm lets its agent commit it: paid in US dollars, at most 500, the agent no party.
  const mandate = await lexis.delegate({
    delegate: agent.address,
    command: "/oip/sign/Commitment",
    policy: [
      ["==", ".terms.price.currency", "USD"],
      ["<=", ".terms.price.amount", "500"],
      ["==", ".terms.price.payee", lexis.address],
      ["all", ".parties", ["!=", ".mind", agent.address]],
    ],
    expires: formatTimestamp(clock.now() + 30n * day),
  });
  await pass(lexis, agent, mandate);

  // Amina says what she wants.
  const intent = await amina.intent({
    want: "A Swahili commercial lease translated into English.",
  });
  await pass(amina, agent, intent);
  output.push(`Amina's Intent is ${await amina.statusOf(intent)}`);

  // The agent writes the Commitment and signs it for the firm.
  const proposed = await agent.commitment(
    {
      parties: [
        { mind: lexis.address, role: "debtor", required: true },
        { mind: amina.address, role: "creditor", required: true },
      ],
      promise: "Lexis Ltd will deliver the translation; Amina will pay 120 USD on delivery.",
      terms: {
        deadline: formatTimestamp(clock.now() + 2n * day),
        price: { amount: "120", currency: "USD", payer: amina.address, payee: lexis.address },
      },
      resolves: [formatRecordRef(amina.address, contentId(intent))],
      closesIntent: true,
    },
    { chain: [mandate] },
  );
  await pass(agent, amina, proposed);
  output.push(`the Commitment is ${await amina.statusOf(proposed)}`);
  output.push(`it binds the firm: ${String(await amina.countsFor(proposed, lexis.address))}`);

  // Amina reads it, and signs. Nothing of the record changes but its proofs.
  const accepted = await amina.cosign(proposed);
  output.push(`with her proof it is ${await amina.statusOf(accepted)}`);
  output.push(`and her Intent is ${await amina.statusOf(intent)}`);

  // The firm delivers and says so. Amina, who is owed it, confirms.
  await pass(amina, lexis, accepted);
  const ref = formatRecordRef(agent.address, contentId(accepted));
  await pass(lexis, amina, await lexis.receipt({ about: ref, outcome: "fulfilled" }));
  output.push(`the firm says it delivered: ${await amina.statusOf(accepted)}`);
  await amina.receipt({ about: ref, outcome: "fulfilled" });
  output.push(`Amina confirms: ${await amina.statusOf(accepted)}`);
  for (const mind of [amina, lexis, agent]) mind.close();
  return output;
}
