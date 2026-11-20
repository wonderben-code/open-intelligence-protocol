// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { type Clock, type Fetch, Mind, type MindOptions } from "@oip/client";
import { OipError } from "@oip/core";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * The life of a mind's keys: one added, one revoked, the mind opened again,
 * a child acknowledged, and the mind retired.
 *
 * @param resolvers - The HTTPS origins of the resolvers the mind trusts.
 * @param lock - What the mind's keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  resolvers: readonly string[],
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<string[]> {
  const output: string[] = [];
  const fresh = async (): Promise<MindOptions> => ({
    keystore: await Keystore.create({ storage: memoryStorage(), locks: lock }),
    lock,
    resolvers,
    ...edges,
  });
  const options = await fresh();
  const mind = await Mind.create(options, { kind: "agent" });
  const laptop = mind.signingKey();

  // A second device gets an operational key of its own. Each change takes the control keys.
  const phone = await mind.addKey({ control: lock, label: "phone" });
  output.push(`a key is added: the mind has ${String(mind.state.keys.length)}`);

  // The first is lost with its laptop. It signs nothing that counts from now on.
  const state = await mind.revokeKey(laptop, { control: lock });
  output.push(`the first is revoked: ${String(state.keys.length)} is left`);
  output.push(`the mind signs with the one it added: ${String(mind.signingKey() === phone)}`);

  // Closed, the keys are locked. The mind is opened again from what the keystore holds.
  mind.close();
  const again = await Mind.open(options);
  output.push(`opened again, the same mind: ${String(again.address === mind.address)}`);

  // Another mind is made from this one, and this one says so in its log (Layer 1, 3.8).
  const child = await Mind.create(await fresh(), { kind: "agent" });
  await again.fork(child.address, { control: lock, terms: { received: "the lease archive" } });
  output.push(`it acknowledges ${String(again.resolved.log.children.length)} child`);

  // `refresh` reads the mind's own log from the resolvers again: here, to see it is all there.
  output.push(`the resolvers have its log up to event ${String((await again.refresh()).seq)}`);

  // Retired, it names the mind that follows it. No event comes after, and its keys sign nothing.
  const retired = await again.retire({ control: lock, successor: child.address });
  output.push(`retired: ${String(retired.retired)}`);
  try {
    again.signingKey();
  } catch (error) {
    if (!(error instanceof OipError)) throw error;
    output.push(`asked for a key to sign with, it is ${error.code}`);
  }
  again.close();
  child.close();
  return output;
}
