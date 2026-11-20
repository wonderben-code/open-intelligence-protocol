// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The work the server does for its mind: one piece at a time.
 *
 * The mind lives in a directory that the `oip` command works in too. What
 * one writes there the other must see, so the server holds nothing of the
 * mind between two calls: it opens the mind for a call and closes it after,
 * as the command does. The keys are unlocked while a call is at work, and
 * no longer.
 *
 * A host may send several calls at once. They are done one after another:
 * two pieces of work never write to the directory at the same time.
 */

import { Lookup } from "@oip/client";
import { Keystore } from "@oip/keystore";
import { fileStorage } from "@oip/keystore/node";
import {
  type Config,
  Home,
  KeptRecords,
  lookupOptions,
  type Opened,
  UsageError,
  type Where,
  withMind,
} from "@oip/local";

import type { Policy } from "./policy.ts";

/** What a piece of work that signs nothing is given. */
export interface Reading {
  /** The address of the mind of the directory. */
  readonly address: string;
  /** Asks the mind's resolvers, hosts and indexers. It holds no key. */
  readonly lookup: Lookup;
  /** What the directory says of the mind's services. */
  readonly config: Config;
  /** The records the directory keeps. */
  readonly records: KeptRecords;
}

/** The work of a server for the mind of one directory. */
export class Work {
  /** The machine, and the directory of the mind. */
  readonly where: Where;
  /** What may be signed without asking. */
  readonly policy: Policy;
  /** The pieces of work, one after another. */
  #last: Promise<unknown> = Promise.resolve();

  /**
   * @param where - The machine, and the directory of the mind.
   * @param policy - What the person has said may be signed without asking.
   */
  constructor(where: Where, policy: Policy) {
    this.where = where;
    this.policy = policy;
  }

  #next<T>(piece: () => Promise<T>): Promise<T> {
    const done = this.#last.then(piece);
    // The next piece is done whatever became of this one.
    this.#last = done.catch(() => undefined);
    return done;
  }

  /**
   * Does a piece of work that needs no key: the mind is read, as anyone may
   * read it.
   *
   * @throws UsageError if the directory holds no mind.
   */
  reading<T>(piece: (reading: Reading) => Promise<T>): Promise<T> {
    return this.#next(async () => {
      const home = new Home(this.where.dir);
      const config = home.read();
      const keystore = await Keystore.open({ storage: fileStorage(home.keys) });
      const address = keystore.mind;
      if (address === undefined) {
        throw new UsageError(
          `the mind of ${home.dir} was never published: the user finishes making it with \`oip init\``,
        );
      }
      return piece({
        address,
        lookup: new Lookup(lookupOptions(this.where, config)),
        config,
        records: new KeptRecords(home.records),
      });
    });
  }

  /**
   * Does a piece of work with the mind open and its keys unlocked. After
   * it the records the mind holds are written down, and the keys are locked.
   *
   * @throws UsageError if the directory holds no mind, or its keys cannot be opened.
   */
  signing<T>(piece: (opened: Opened) => Promise<T>): Promise<T> {
    return this.#next(() => withMind(this.where, piece));
  }
}
