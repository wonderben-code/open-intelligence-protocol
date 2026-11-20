// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What a page loads to run the client in a browser: the examples of the
 * README, as they are, and a mind whose keys are kept in the browser's own
 * storage. The test bundles this file and calls it from outside the page.
 */

import { Mind } from "@oip/client";
import { indexedDbStorage, Keystore, memoryStorage, passphrase } from "@oip/keystore";

import { example as deal } from "../../examples/deal.ts";
import { example as find } from "../../examples/find.ts";

/** A passphrase with the least work factor that is accepted: the test is of the browser, not of scrypt. */
const lock = () => passphrase("correct horse battery staple", { n: 2 ** 14 });

const page = {
  /** The scenario of the papers. */
  deal: (resolvers: readonly string[], home: string): Promise<string[]> =>
    deal(resolvers, home, lock()),

  /** A mind that is listed, and found. */
  find: (services: Parameters<typeof find>[0]): Promise<string[]> => find(services, lock()),

  /**
   * A mind whose keys are in the browser's IndexedDB: made, closed, and
   * opened again from what the browser kept.
   */
  async kept(resolvers: readonly string[]): Promise<string[]> {
    const storage = () => indexedDbStorage("oip-test-keys");
    const options = { resolvers, memory: memoryStorage() };
    const keystore = await Keystore.create({ storage: storage(), locks: lock() });
    const made = await Mind.create({ ...options, keystore, lock: lock() }, { kind: "human" });
    const { address } = made;
    made.close();
    // Another keystore object, over what the browser stored.
    const again = await Keystore.open({ storage: storage() });
    const mind = await Mind.open({ ...options, keystore: again, lock: lock() });
    const signed = await mind.sign({
      oip: "1",
      type: "Intent",
      author: mind.address,
      created: new Date().toISOString().replace(/\.\d+Z$/u, "Z"),
      want: "To be the same mind after the page is closed.",
    });
    mind.close();
    return [
      `the same mind: ${String(mind.address === address && again.mind === address)}`,
      `it signs: ${String(signed.proof.length)} proof`,
      `a wrong passphrase opens it: ${String(
        await Mind.open({
          ...options,
          keystore: again,
          lock: passphrase("wrong one", { n: 2 ** 14 }),
        }).then(
          () => true,
          () => false,
        ),
      )}`,
    ];
  },
};

export type Page = typeof page;
(globalThis as unknown as { oip: Page }).oip = page;
