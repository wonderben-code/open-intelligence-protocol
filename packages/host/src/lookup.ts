// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Learning the log of a mind the host cannot judge yet.
 *
 * An inbox takes a packet only if its sender signed it, and that is judged
 * by the sender's identity log (Layer 1, 12.4). A host holds the logs of
 * the minds it serves. For a sender it has not met, or one whose log has
 * grown since, it asks the resolvers its operator configured (17.1), takes
 * of the bundle what verifies, and judges the packet again.
 *
 * What a packet names is the sender's to write, so asking is bounded: a
 * mind that was asked after is not asked after again for a while, only so
 * many are asked after at once, and only the configured resolvers are
 * asked, at the path of 17.1 and nowhere else.
 */

import { MAX_TEXT_LENGTH, MEDIA_TYPE, mindId, OipError, type OipRecord } from "@oip/core";
import { type Clock, type Log, type LogArchive, type Metrics, recordFrom } from "@oip/server";

import { type Answer, type Host, partiesOf } from "./host.ts";

/** How a lookup is made. */
export interface LookupOptions {
  /** The identity logs the host holds, which what is learned goes into. */
  readonly archive: LogArchive;
  /** Fetches a URL: `GuardedFetcher.get` of `@oip/server`. */
  readonly get: (url: string, accept: string) => Promise<{ status: number; body: Uint8Array }>;
  /** The origins of the resolvers to ask, in order. With none, nothing is asked. */
  readonly resolvers: readonly string[];
  readonly clock: Clock;
  readonly log: Log;
  readonly metrics: Metrics;
  /** How long a mind that was asked after is not asked after again, in nanoseconds. A minute by default. */
  readonly rest?: bigint;
  /** How many minds are asked after at once. 8 by default. */
  readonly maxAtOnce?: number;
  /** The most bytes of a bundle that are read. `MAX_TEXT_LENGTH` of `@oip/core` by default. */
  readonly maxBundleBytes?: number;
  /**
   * How many minds the lookup remembers having asked after. 10,000 by
   * default. Beyond that the one asked after longest ago is forgotten, and
   * may be asked after again sooner.
   */
  readonly remembered?: number;
}

/** Asks resolvers for the logs of minds the host cannot judge. */
export class Lookup {
  readonly #options: LookupOptions;
  /** When each mind may be asked after again, by the content ID of its genesis. */
  readonly #rests = new Map<string, bigint>();
  readonly #asking = new Map<string, Promise<boolean>>();
  readonly #asked;

  constructor(options: LookupOptions) {
    this.#options = options;
    this.#asked = options.metrics.counter(
      "oip_host_lookups_total",
      "Times a resolver was asked for the log of a packet's sender, by what came of it.",
      ["outcome"],
    );
  }

  /**
   * Asks the resolvers for the log of a mind, and takes what verifies of it.
   *
   * @param mind - An address, as a packet gave it. What is no address is not asked after.
   * @returns Whether the host now holds events of the mind's log that it did
   *   not hold before. It never rejects: a resolver that fails, or says
   *   what does not verify, has taught nothing.
   */
  learn(mind: string): Promise<boolean> {
    const { clock, resolvers } = this.#options;
    const id = mindId(mind);
    if (id === undefined || resolvers.length === 0) return Promise.resolve(false);
    const asking = this.#asking.get(id);
    if (asking !== undefined) return asking;
    const now = clock.now();
    const rests = this.#rests.get(id);
    if (
      (rests !== undefined && now < rests) ||
      this.#asking.size >= (this.#options.maxAtOnce ?? 8)
    ) {
      this.#asked.add({ outcome: "not-asked" });
      return Promise.resolve(false);
    }
    this.#rest(id, now);
    const asked = this.#ask(id).finally(() => this.#asking.delete(id));
    this.#asking.set(id, asked);
    return asked;
  }

  /** Notes that a mind was asked after now, and forgets the oldest notes beyond what is remembered. */
  #rest(id: string, now: bigint): void {
    this.#rests.delete(id);
    this.#rests.set(id, now + (this.#options.rest ?? 60_000_000_000n));
    const remembered = this.#options.remembered ?? 10_000;
    for (const oldest of this.#rests.keys()) {
      if (this.#rests.size <= remembered) break;
      this.#rests.delete(oldest);
    }
  }

  async #ask(id: string): Promise<boolean> {
    const { archive, get, log, resolvers } = this.#options;
    const maxBundleBytes = this.#options.maxBundleBytes ?? MAX_TEXT_LENGTH;
    for (const resolver of resolvers) {
      try {
        const fetched = await get(`${resolver}/oip/v1/resolve/${id}`, MEDIA_TYPE);
        if (fetched.status !== 200) continue;
        const bundle = recordFrom(fetched.body, maxBundleBytes);
        if (bundle.type !== "Bundle") continue;
        // Only what verifies of it is kept, as of anything published here.
        if (archive.publish(id, bundle).added > 0) {
          this.#asked.add({ outcome: "learned" });
          return true;
        }
      } catch (error) {
        // Which resolver, and no more: what a failure carries is not known to be fit to log.
        log.event("warn", "lookup failed", {
          resolver,
          reason: error instanceof Error ? error.name : "unknown",
        });
      }
    }
    this.#asked.add({ outcome: "nothing" });
    return false;
  }
}

/**
 * Whether learning more of a log might change a refusal: it was for a
 * sender or a broker the host has not met, or for a proof by a key or a
 * version of a log it does not know.
 */
function mayBeLearned(error: unknown): boolean {
  return error instanceof OipError && ["stale-version", "invalid-proof"].includes(error.code);
}

/**
 * Layer 1, 13.2: delivers a record to a mind's inbox, and if it is refused
 * for want of its sender's log, asks after the log and judges it again.
 *
 * @returns The answer at once where nothing was asked, and a promise of it
 *   where a resolver was: so one caller serves both without waiting where
 *   there is nothing to wait for.
 * @throws What `Host.deliver` throws, at once or as the promise's rejection.
 */
export function deliverLearning(
  host: Host,
  lookup: Lookup | undefined,
  mind: string,
  record: OipRecord,
): Answer | Promise<Answer> {
  try {
    return host.deliver(mind, record);
  } catch (error) {
    if (lookup === undefined || !mayBeLearned(error)) throw error;
    // The sender, and the broker if one forwarded the packet: whichever log is wanting.
    return Promise.all(partiesOf(record).map((party) => lookup.learn(party))).then((learned) => {
      if (!learned.includes(true)) throw error;
      return host.deliver(mind, record);
    });
  }
}
