// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { type Clock, type Fetch, Mind } from "@oip/client";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * A packet for a mind that cannot be reached yet is kept, and sent when it
 * can be.
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
  const mindAt = async (): Promise<Mind> => {
    const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
    // The outbox is kept in the memory: give it a storage that lasts.
    return Mind.create(
      { keystore, lock, resolvers, memory: memoryStorage(), ...edges },
      { kind: "agent", homes: [home] },
    );
  };
  const ada = await mindAt();
  const bob = await mindAt();
  const cyd = await mindAt();
  const write = (to: Mind, body: string) =>
    ada.send({ to: [to.address], verb: "inform", content: { mediaType: "text/plain", body } });

  // Bob has not yet said where he takes packets. The packet is signed, and kept.
  const sent = await write(bob, "For when you are there.");
  for (const delivery of sent.deliveries) {
    const kept = delivery.queued === true ? "kept to be tried again" : "given up";
    output.push(`not taken (${String(delivery.failure)}): ${kept}`);
  }
  const [waiting] = await ada.outbox();
  output.push(`the outbox holds a packet sent ${String(waiting?.tries)} time`);

  // He says where. `receive` and `listen` try what is due by themselves: `retry` tries now.
  await bob.publishLocation();
  for (const retried of await ada.retry()) {
    const taken = retried.deliveries.every((delivery) => delivery.stored);
    output.push(
      `tried again: ${taken ? "taken" : "not taken"}, ${String(retried.waiting)} waiting`,
    );
  }
  const { received } = await bob.receive();
  output.push(
    `Bob has ${String(received.length)} packet, the one that was signed: ${String(received[0]?.id === sent.id)}`,
  );

  // A packet nobody is expected to take any more can be given up.
  const lost = await write(cyd, "Never mind.");
  output.push(`given up: ${String(await ada.abandon(lost.id))}`);
  output.push(`the outbox holds ${String((await ada.outbox()).length)} packets`);
  ada.close();
  bob.close();
  cyd.close();
  return output;
}
