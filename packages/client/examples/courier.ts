// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { type Clock, type Fetch, Mind, systemClock } from "@oip/client";
import { bytesToBase64url, formatTimestamp } from "@oip/core";
import { Keystore, type Lock, memoryStorage, systemRandomness } from "@oip/keystore";

/**
 * A packet reaches its recipient by another's hands. Its sender signs it
 * and posts it nowhere: it hands the packet to a courier, a gateway of
 * another protocol say (Layer 0, 3.3), and the courier brings it.
 *
 * @param resolvers - The HTTPS origins of the resolvers the minds trust.
 * @param home - The HTTPS origin of a host that serves the minds.
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
  const make = async (): Promise<Mind> => {
    const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
    const mind = await Mind.create(
      { keystore, lock, resolvers, memory: memoryStorage(), ...edges },
      { kind: "agent", homes: [home] },
    );
    await mind.publishLocation();
    return mind;
  };
  const sender = await make();
  const recipient = await make();
  const courier = await make();

  // The packet is the sender's own: written and signed by it, and posted nowhere.
  const now = (edges.clock ?? systemClock).now();
  const packet = await sender.sign({
    oip: "1",
    type: "Packet",
    from: sender.address,
    to: [recipient.address],
    created: formatTimestamp(now),
    expires: formatTimestamp(now + 3_600_000_000_000n),
    nonce: bytesToBase64url(systemRandomness.bytes(16)),
    purpose: { verb: "inform" },
    content: { mediaType: "text/plain", body: "This came by another's hands." },
  });

  // The courier judges nothing and keeps nothing. It seals the packet to its recipient, and posts it.
  const delivery = await courier.pass(packet, recipient.address);
  output.push(
    `passed on ${delivery.sealed ? "sealed" : "in the clear"}: ${delivery.stored ? "it arrived" : "it did not arrive"}`,
  );

  // The recipient judges the packet by its own proof: it is the sender's, whoever brought it.
  const { received } = await recipient.receive();
  for (const { from, packet: got } of received) {
    const by =
      from === sender.address
        ? "its sender"
        : from === courier.address
          ? "the courier"
          : "a stranger";
    output.push(`received from ${by}: ${"body" in got.content ? String(got.content.body) : ""}`);
  }
  sender.close();
  recipient.close();
  courier.close();
  return output;
}
