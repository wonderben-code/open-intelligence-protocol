// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { carried, type Clock, type Fetch, Lookup, Mind, Reader, systemClock } from "@oip/client";
import { contentId, formatRecordRef, formatTimestamp } from "@oip/core";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * A deal, read afterwards by strangers who hold no key: what the parties
 * published is enough to work out who is bound, and how the deal stands.
 *
 * @param resolvers - The HTTPS origins of the resolvers they trust.
 * @param home - The HTTPS origin of a host that takes the parties on.
 * @param lock - What the parties' keys are sealed under.
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
  const day = 86_400_000_000_000n;
  const promised = (promise: string) => ({
    parties: [
      { mind: lexis.address, role: "debtor", required: true },
      { mind: amina.address, role: "creditor", required: true },
    ],
    promise,
    terms: { deadline: formatTimestamp(clock.now() + 2n * day) },
  });

  // The firm lets its agent commit it, and the agent does. Amina signs, confirms, and publishes.
  const mandate = await lexis.delegate({
    delegate: agent.address,
    command: "/oip/sign/Commitment",
    expires: formatTimestamp(clock.now() + 30n * day),
  });
  const accepted = await amina.cosign(
    await agent.commitment(promised("Lexis Ltd will deliver the translation."), {
      chain: [mandate],
    }),
  );
  await amina.publishRecord(accepted);
  const about = formatRecordRef(agent.address, contentId(accepted));
  await amina.publishRecord(await amina.receipt({ about, outcome: "fulfilled" }));

  // A stranger: resolvers to ask, and no key. It reads Amina's feed, and holds what it lists.
  const lookup = new Lookup({ resolvers, ...edges });
  const reader = new Reader({ lookup });
  const { feed } = await lookup.feed(amina.address);
  for (const { entry } of feed.entries) {
    reader.hold((await lookup.record(amina.address, entry.object)).record);
  }
  const held = reader.held().map((record) => record.type);
  output.push(`a stranger holds a ${held.join(" and a ")}`);
  output.push(
    `the Commitment binds the firm: ${String(await reader.countsFor(accepted, lexis.address))}`,
  );
  output.push(`and is ${await reader.status(accepted)}`);

  // The firm takes the delegation back. The agent signs for it once more all the same.
  await lexis.revoke(mandate);
  const late = await agent.commitment(promised("Lexis Ltd will deliver a second translation."), {
    chain: [mandate],
  });
  // Another stranger is handed that Commitment, as the content of a packet.
  const other = new Reader({ lookup: new Lookup({ resolvers, ...edges }) });
  other.holdCarried(carried(late));
  output.push(
    `by what another was handed, a later one binds the firm: ${String(await other.countsFor(late, lexis.address))}`,
  );
  // Before it relies on that, it reads the feed of the delegation's author.
  output.push(`Revocations on the firm's feed: ${String(await other.holdRevocations(late))}`);
  output.push(`the delegation stands: ${String(await other.delegationsStand(late))}`);
  output.push(
    `the later one binds the firm: ${String(await other.countsFor(late, lexis.address))}`,
  );
  for (const mind of [amina, lexis, agent]) mind.close();
  return output;
}
