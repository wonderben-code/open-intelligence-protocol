// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Whom the page asks.
 *
 * The Explorer asks the resolvers and the indexers its reader chose. It
 * asks a mind's homes when its reader says to read the feed: the homes the
 * page named, and for as long as that reading goes on. Nobody else is asked
 * anything.
 *
 * The rule is kept here, in one place, under the client. Every request the
 * client makes passes through `fetch` of this class, whatever the client
 * then decides to fetch: a profile an indexer names is at its author's
 * home, and a log may name other homes by the time a feed is read. A
 * request to anyone else is not made, and is counted, so that a page can
 * say what it did not ask.
 */

import { type Fetch, httpsOrigin } from "@oip/client";

/** What a reading holds while it goes on. */
export interface Reading {
  /** Whether the reading has ended: its reader stopped it, or left the page. */
  readonly ended: boolean;
  /** Ends it. The homes it named are asked nothing more. */
  end(): void;
}

/** The requests of a page, kept to the services its reader chose. */
export class Asked {
  readonly #chosen: ReadonlySet<string>;
  readonly #send: Fetch;
  /** The homes that may be asked now, each with how many readings named it. */
  readonly #homes = new Map<string, number>();
  readonly #kept = new Set<string>();

  /**
   * @param chosen - The origins of the resolvers and the indexers the reader chose.
   * @param send - What makes a request. Default: the browser's `fetch`.
   */
  constructor(chosen: readonly string[], send: Fetch = (request) => fetch(request)) {
    this.#chosen = new Set(chosen);
    this.#send = send;
  }

  /** What a client is given in place of `fetch`. */
  readonly fetch: Fetch = (request) => {
    const origin = httpsOrigin(request.url);
    if (origin !== undefined && (this.#chosen.has(origin) || this.#homes.has(origin))) {
      return this.#send(request);
    }
    this.#kept.add(origin ?? "what is no HTTPS origin");
    // A client takes it as a service that could not be reached, which is so: nothing left the page.
    return Promise.reject(new TypeError("the Explorer asks only whom its reader chose"));
  };

  /**
   * Lets homes be asked, for one reading of a feed.
   *
   * @param homes - The homes the page named to its reader. What is no HTTPS origin is left out.
   */
  reading(homes: readonly string[]): Reading {
    const named = [...new Set(homes.flatMap((home) => httpsOrigin(home) ?? []))];
    for (const home of named) this.#homes.set(home, (this.#homes.get(home) ?? 0) + 1);
    let ended = false;
    return {
      get ended() {
        return ended;
      },
      end: () => {
        if (ended) return;
        ended = true;
        for (const home of named) {
          const left = (this.#homes.get(home) ?? 1) - 1;
          if (left > 0) this.#homes.set(home, left);
          else this.#homes.delete(home);
        }
      },
    };
  }

  /**
   * The origins that something wanted asked and that were not, since this
   * was last called. They are strangers' text: a mind names its own homes.
   */
  kept(): string[] {
    const kept = [...this.#kept];
    this.#kept.clear();
    return kept;
  }
}
