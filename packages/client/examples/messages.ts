// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { type Clock, type Fetch, Mind } from "@oip/client";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * One mind sends another a sealed packet, and the other reads its mailbox.
 *
 * @param resolvers - The HTTPS origins of the resolvers both trust.
 * @param homes - The HTTPS origins of the hosts that take each of them on.
 * @param lock - What their keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  resolvers: readonly string[],
  homes: { readonly ada: string; readonly bob: string },
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<string[]> {
  const output: string[] = [];
  const mindAt = async (home: string): Promise<Mind> => {
    const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
    const mind = await Mind.create(
      { keystore, lock, resolvers, memory: memoryStorage(), ...edges },
      { kind: "agent", homes: [home] },
    );
    // Where it takes packets: an inbox and a mailbox at its home.
    await mind.publishLocation();
    return mind;
  };
  const ada = await mindAt(homes.ada);
  const bob = await mindAt(homes.bob);

  // The packet is signed by Ada and sealed to Bob: his host carries it and cannot read it.
  const sent = await ada.send({
    to: [bob.address],
    verb: "request",
    goal: "A quote for a translation.",
    content: { mediaType: "text/plain", body: "Could you translate a lease by Friday?" },
  });
  for (const delivery of sent.deliveries) {
    const where = new URL(delivery.endpoint ?? homes.bob).pathname.split("/").at(-1);
    output.push(
      `sent ${delivery.sealed ? "sealed" : "in the clear"}, taken by his ${String(where)}`,
    );
  }

  // Bob reads his mailbox. What comes back was judged: addressed to him, in date, signed by Ada.
  const { received, refused } = await bob.receive();
  for (const { packet, from, sealed } of received) {
    const body = "body" in packet.content ? String(packet.content.body) : "";
    output.push(`received from ${from === ada.address ? "Ada" : "a stranger"}: ${body}`);
    output.push(`a ${packet.purpose.verb}, ${sealed ? "sealed" : "in the clear"}`);
  }
  output.push(
    `refused: ${String(refused.length)}; left in the mailbox: ${String((await bob.receive()).received.length)}`,
  );
  ada.close();
  bob.close();
  return output;
}
