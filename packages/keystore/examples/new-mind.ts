// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { keyHash, utf8 } from "@oip/core";
import { draftGenesis } from "@oip/identity";
import { Keystore, type KeyStorage, type Lock } from "@oip/keystore";

/**
 * The keys of a new mind: made in a keystore, its genesis signed by a control
 * key, and that key destroyed once the genesis is published.
 *
 * @param publish - Sends the genesis to the mind's resolvers.
 */
export async function example(
  storage: KeyStorage,
  lock: Lock,
  created: string,
  publish: (genesis: object) => Promise<void>,
): Promise<string[]> {
  const output: string[] = [];
  const keystore = await Keystore.create({ storage, locks: lock });

  // Each role is unlocked by itself. A new mind needs these three once.
  const control = await keystore.unlock("control", lock);
  const operational = await keystore.unlock("operational", lock);
  const agreement = await keystore.unlock("agreement", lock);

  const first = await control.generate();
  const next = await control.generate();
  const everyday = await operational.generate({ label: "everyday" });
  const sealing = await agreement.generate();

  // The genesis reveals the first control key and commits to the next (Layer 1, 3.4).
  const genesis = await control.sign(
    draftGenesis(created, {
      kind: "agent",
      controller: { keys: [first.publicKey], next: [keyHash(next.publicKey)] },
      keys: [{ key: everyday.publicKey, label: "everyday" }],
      agreement: [{ key: sealing.publicKey }],
    }),
  );
  output.push(`signed: ${String(control.pending().length)} event awaits publication`);

  await publish(genesis);
  // Layer 1, 3.11: a control key is destroyed once the event it signed is published.
  const destroyed = await control.published(genesis);
  output.push(`published: ${String(destroyed)} control key destroyed`);
  output.push(`kept for the next event: ${String(control.keys().length)} control key`);
  control.lock();

  // Everyday signing needs the operational keys, and no others.
  const signer = operational.signer(everyday.publicKey);
  output.push(`a signature of ${String(signer.sign(utf8("hello")).length)} bytes`);
  output.push(`a backup is due for: ${(await keystore.backupDue()).join(", ")}`);
  return output;
}
