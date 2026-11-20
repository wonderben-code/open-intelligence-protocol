// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { type Clock, type Fetch, Mind, type OpenSocket } from "@oip/client";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * One mind listens at its host, and hears what another sends as it is sent.
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
  edges: { readonly fetch?: Fetch; readonly clock?: Clock; readonly webSocket?: OpenSocket } = {},
): Promise<string[]> {
  const output: string[] = [];
  const mindAt = async (home: string): Promise<Mind> => {
    const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
    const mind = await Mind.create(
      { keystore, lock, resolvers, memory: memoryStorage(), ...edges },
      { kind: "agent", homes: [home] },
    );
    await mind.publishLocation();
    return mind;
  };
  const ada = await mindAt(homes.ada);
  const bob = await mindAt(homes.bob);
  const write = (body: string) =>
    ada.send({ to: [bob.address], verb: "inform", content: { mediaType: "text/plain", body } });

  // Ada writes before Bob listens. His host keeps it for him.
  await write("Sent while you were away.");

  // Bob opens a socket to his host. What waited comes first, and then what arrives.
  let heard = 0;
  let next: () => void = () => undefined;
  const another = (): Promise<void> =>
    new Promise((resolve) => {
      next = resolve;
    });
  let arrives = another();
  const listening = bob.listen({
    received: ({ received }) => {
      for (const { packet, from } of received) {
        const body = "body" in packet.content ? String(packet.content.body) : "";
        output.push(`Bob hears from ${from === ada.address ? "Ada" : "a stranger"}: ${body}`);
        heard++;
      }
      next();
    },
    changed: ({ state }) => output.push(`the socket is ${state}`),
  });
  await arrives;

  arrives = another();
  await write("Sent while you listen.");
  await arrives;

  // Each record was the host's to forget once Bob said he had it. A connection that drops
  // is opened again, and loses nothing.
  await listening.close();
  output.push(`Bob heard ${String(heard)} packets, and listens no more`);
  ada.close();
  bob.close();
  return output;
}
