// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { carried, type Clock, type Fetch, Mind, systemClock } from "@oip/client";
import { formatTimestamp } from "@oip/core";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * A firm lets its agent make offers for it, the agent passes part of that on
 * to a junior, and the firm takes it all back.
 *
 * @param resolvers - The HTTPS origins of the resolvers all of them trust.
 * @param home - The HTTPS origin of the host that takes them on.
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
  const firm = await mindOf("institution");
  const agent = await mindOf("agent");
  const junior = await mindOf("agent");
  const amina = await mindOf("human");
  const month = formatTimestamp(clock.now() + 30n * 86_400_000_000_000n);
  const offerOf = (amount: string) => ({
    author: firm.address,
    provides: "An English translation of a Swahili commercial lease.",
    terms: { summary: "Within two days.", price: { amount, currency: "USD" } },
  });

  // The firm lets its agent make offers in its name.
  const mandate = await firm.delegate({
    delegate: agent.address,
    command: "/oip/sign/Offer",
    expires: month,
  });
  // The agent passes that on to a junior, for less: offers of 100 at most.
  const passed = await agent.subDelegate([mandate], {
    delegate: junior.address,
    command: "/oip/sign/Offer",
    policy: [["<=", ".terms.price.amount", "100"]],
    expires: month,
  });
  const chain = [mandate, passed];

  // The junior offers for the firm, and sends Amina the offer. Its proof carries the chain.
  const offer = await junior.offer(offerOf("80"), { chain });
  await junior.send({ to: [amina.address], verb: "propose", content: carried(offer) });
  await amina.receive();
  // What a packet carried is held, to be judged when it is asked about.
  output.push(
    `Amina holds ${String(amina.records().length)} record, an ${amina.records()[0]?.type}`,
  );
  output.push(`it is the firm's offer: ${String(await amina.countsFor(offer, firm.address))}`);

  // More than the junior may offer is the junior's word, and not the firm's.
  const dear = await junior.offer(offerOf("150"), { chain });
  output.push(`one of 150 is the firm's: ${String(await amina.countsFor(dear, firm.address))}`);

  // The firm takes the mandate back. The revocation is signed, and goes on its feed.
  const revocation = await firm.revoke(mandate);
  const { feed } = await amina.lookup.feed(firm.address);
  output.push(`the firm's feed has a ${String(feed.entries[0]?.entry.objectType)}`);
  // Amina fetches it from the firm's home, and holds it: she now knows.
  const fetched = await amina.lookup.record(firm.address, feed.entries[0]?.entry.object ?? "");
  const held = amina.hold(fetched.record);
  output.push(`it is the record the firm signed: ${String(held === amina.hold(revocation))}`);

  // What the junior offers after that is not the firm's. What it offered before still is.
  const late = await junior.offer(offerOf("60"), { chain });
  output.push(`a later offer is the firm's: ${String(await amina.countsFor(late, firm.address))}`);
  output.push(`the first still is: ${String(await amina.countsFor(offer, firm.address))}`);

  // A program that stops keeps what matters: the record, and when it first obtained each of
  // its proofs. Held again with that in a later run, the offer is judged as it was then,
  // and not as if it had only now arrived, after the revocation.
  const kept = { record: offer, seen: amina.sightings(amina.hold(offer)) };
  amina.hold(kept.record, kept.seen);
  output.push(`kept with the offer: when ${String(Object.keys(kept.seen).length)} proofs came`);
  for (const mind of [firm, agent, junior, amina]) mind.close();
  return output;
}
