// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { type Clock, type Fetch, type Inbox, Mind } from "@oip/client";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * Two minds talk in a session: each packet has its place, and one that goes
 * missing is asked for and sent again.
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
    // The memory is where a session is kept between runs: give it a storage that lasts.
    const mind = await Mind.create(
      { keystore, lock, resolvers, memory: memoryStorage(), ...edges },
      { kind: "agent", homes: [home] },
    );
    await mind.publishLocation();
    return mind;
  };
  const ada = await mindAt(homes.ada);
  const bob = await mindAt(homes.bob);

  /** What a reading of a mailbox found: the packets in order, and what the session asked for. */
  const tell = (who: string, inbox: Inbox): void => {
    for (const { packet } of inbox.received) {
      const parts = "parts" in packet.content ? packet.content.parts : [packet.content];
      const text = parts.find((part) => part.mediaType === "text/plain");
      const said = text !== undefined && "body" in text ? String(text.body) : packet.purpose.verb;
      output.push(`${who} has packet ${String(packet.seq)}: ${said}`);
    }
    for (const event of inbox.sessions) {
      if (event.kind === "gap") output.push(`${who} lacks the packets from ${String(event.next)}`);
      if (event.kind === "asked") output.push(`${who} asks for them, in a Resume`);
      if (event.kind === "sent-again") {
        output.push(`${who} sends ${String(event.deliveries.length)} packets again`);
      }
    }
  };

  // Ada names the session, and sends three packets in it. Nothing is sent to open it:
  // her first packet carries the Session record.
  const { id } = await ada.openSession([bob.address]);
  for (const body of ["One.", "Two.", "Three."]) {
    const sent = await ada.send({
      to: [bob.address],
      verb: "inform",
      content: { mediaType: "text/plain", body },
      session: id,
    });
    const taken = sent.deliveries.every((delivery) => delivery.stored);
    output.push(`Ada sends packet ${String(sent.packet.seq)}: ${taken ? "taken" : "not taken"}`);
  }

  // Bob reads his mailbox. A packet that is ahead of one he lacks waits there, and he asks.
  tell("Bob", await bob.receive());
  // Ada reads hers, finds what he asks for, and sends it again as it was.
  tell("Ada", await ada.receive());
  tell("Bob", await bob.receive());

  const [session] = await bob.sessions();
  output.push(`Bob holds ${String(session?.chains[0]?.received)} of Ada's packets, in order`);
  ada.close();
  bob.close();
  return output;
}
