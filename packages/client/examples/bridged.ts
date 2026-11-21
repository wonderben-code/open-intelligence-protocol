// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { type Clock, type Fetch, Lookup, Mind } from "@oip/client";
import { contentId, formatRecordRef, type JsonObject } from "@oip/core";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * A gateway makes a mind for an agent of another protocol, and another
 * client asks how far that mind is what it says (Layer 0, Section 1).
 *
 * @param resolvers - The HTTPS origins of the resolvers the minds trust.
 * @param home - The HTTPS origin of a host that serves both minds.
 * @param lock - What the minds' keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  resolvers: readonly string[],
  home: string,
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<string[]> {
  const output: string[] = [];
  const make = async (ext?: Readonly<Record<string, JsonObject>>): Promise<Mind> => {
    const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
    const mind = await Mind.create(
      { keystore, lock, resolvers, ...edges },
      { kind: "service", homes: [home], ...(ext === undefined ? {} : { ext }) },
    );
    await mind.publishLocation();
    return mind;
  };
  const gateway = await make();
  // The gateway names itself in the genesis of the mind it makes. A genesis cannot be
  // changed: it is what the address is made from.
  const block = {
    protocol: "a2a",
    endpoint: "https://agent.example/a2a",
    gateway: gateway.address,
    assurance: "bridged",
  };
  const agent = await make({ "oip.bridge": block });
  const first = await new Lookup({ resolvers, ...edges }).assurance(agent.address);
  output.push(`named in its genesis alone: ${first.level}`);

  // The gateway's own word is an entry of its feed that names that genesis.
  const genesis = agent.resolved.log.entries[0].event;
  const entry = await gateway.publishRecord(genesis);
  // The mind's profile names the entry, by reference.
  const attestation = formatRecordRef(gateway.address, contentId(entry));
  await agent.publishProfile({
    name: "An agent of another protocol",
    ext: { "oip.bridge": { ...block, attestation } },
  });

  // Anyone can ask. The gateway's feed is read, and the entry is looked for in it.
  const lookup = new Lookup({ resolvers, ...edges });
  const found = await lookup.assurance(agent.address);
  output.push(`attested in its gateway's feed: ${found.level}, over ${String(found.protocol)}`);
  output.push(`the gateway itself: ${(await lookup.assurance(gateway.address)).level}`);
  agent.close();
  gateway.close();
  return output;
}
