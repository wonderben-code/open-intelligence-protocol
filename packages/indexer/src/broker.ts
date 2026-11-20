// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Brokered delivery (Layer 1, 18.5): a packet addressed to a capability
 * query, forwarded to the minds that match it.
 *
 * The packet is taken only if its sender signed it and its dates allow it,
 * and only if it names this indexer among its brokers, or names none. It
 * goes unchanged to at most `maxFanout` minds, each time inside a
 * `Forwarded` record the indexer signs for that mind, so a recipient can
 * tell who brought it and that it was meant for them. `brokers` and
 * `maxFanout` are inside what the sender signed: the broker cannot widen
 * them.
 *
 * A packet is forwarded once. It is delivered to the `https` endpoints of
 * each mind's current location record, through the guarded fetcher: an
 * endpoint is a URL a stranger wrote.
 */

import {
  contentId,
  formatTimestamp,
  type JsonObject,
  MEDIA_TYPE,
  mindId,
  OipError,
  type OipRecord,
  utf8,
} from "@oip/core";
import { judgeRecord, ownSignedTime, witnessRecord } from "@oip/identity";
import { endpointsToTry, packetDates, postUrl } from "@oip/net";
import { type CapabilityQuery, type Packet, validateRecordOfType } from "@oip/schema";
import {
  type Log,
  type LogArchive,
  type Lookup,
  type Metrics,
  overlaid,
  type RateLimiter,
  seenAt,
  standing,
  Unavailable,
} from "@oip/server";

import type { Indexer } from "./indexer.ts";

/** How a broker is made. */
export interface BrokerOptions {
  readonly indexer: Indexer;
  /** The identity logs the indexer holds: the same archive the indexer was made with. */
  readonly archive: LogArchive;
  readonly log: Log;
  readonly metrics: Metrics;
  /** Posts a body to a URL: `GuardedFetcher.post` of `@oip/server`. */
  readonly post: (
    url: string,
    body: Uint8Array,
    contentType: string,
  ) => Promise<{ status: number }>;
  /** The limit on what one sender may have forwarded, whatever address it sends from (18.5). */
  readonly perSender: RateLimiter;
  /** How the indexer learns the log of a sender it has not met. */
  readonly lookup?: Lookup;
  /** How many minds a packet goes to where it does not say. 10 by default, as 18.5 has it. */
  readonly fanout?: number;
  /** How many deliveries are under way at once. 16 by default. */
  readonly maxAtOnce?: number;
  /** How many deliveries may wait their turn. 10,000 by default. Beyond that packets are refused for now. */
  readonly maxWaiting?: number;
}

/** The most minds a packet is forwarded to, whatever it asks (Layer 1, 19). */
const MOST = 50;

/** What a broker answers for a packet it took: how many minds it goes to. */
export interface Forwarding {
  readonly forwarding: number;
}

/** Layer 1, 18.5: a broker. */
export class Broker {
  readonly #options: BrokerOptions;
  readonly #waiting: (() => Promise<void>)[] = [];
  #running = 0;
  #idle: (() => void)[] = [];
  readonly #deliveries;

  constructor(options: BrokerOptions) {
    this.#options = options;
    this.#deliveries = options.metrics.counter(
      "oip_indexer_deliveries_total",
      "Forwarded packets, by what became of each delivery.",
      ["outcome"],
    );
  }

  /**
   * Takes a packet that is addressed to a query, and forwards it.
   *
   * @param record - A record, already read.
   * @returns How many minds it goes to: at once, or once the sender's log
   *   has been asked after. The same packet again is answered the same, and
   *   forwarded no second time.
   * @throws OipError `invalid-record` for what is no packet; `forbidden`
   *   for one not addressed to a query, or that names other brokers;
   *   `expired`, `invalid-proof` or `stale-version` for one a receiver may
   *   not accept (12.4); `rate-limited` for a sender that has sent too much.
   * @throws Unavailable if it could not be judged just now, or too many deliveries wait.
   */
  accept(record: OipRecord): Forwarding | Promise<Forwarding> {
    try {
      return this.#accept(record);
    } catch (error) {
      const { lookup } = this.#options;
      const learnable =
        error instanceof OipError && ["stale-version", "invalid-proof"].includes(error.code);
      if (lookup === undefined || !learnable) throw error;
      return lookup.learn((record as { from?: unknown }).from as string).then((learned) => {
        if (!learned) throw error;
        return this.#accept(record);
      });
    }
  }

  #accept(record: OipRecord): Forwarding {
    const { indexer, archive } = this.#options;
    const formed = standing(() => validateRecordOfType("Packet", record));
    if (!formed.ok) {
      const [first] = formed.issues;
      throw new OipError("invalid-record", first.message, {
        clause: first.clause,
        issues: formed.issues,
      });
    }
    const packet: Packet = formed.value;
    const to = packet.to as {
      query?: CapabilityQuery;
      brokers?: readonly string[];
      maxFanout?: number;
    };
    if (Array.isArray(packet.to) || to.query === undefined) {
      throw new OipError("forbidden", "an indexer forwards packets that are addressed to a query", {
        clause: "L1 18.5",
      });
    }
    if (to.brokers !== undefined && !to.brokers.includes(indexer.address)) {
      throw new OipError(
        "forbidden",
        "the packet names its brokers, and this indexer is not among them",
        {
          clause: "L1 18.5",
        },
      );
    }
    const query = to.query;
    if (this.#waiting.length >= (this.#options.maxWaiting ?? 10_000)) {
      throw new Unavailable("as many deliveries wait as this indexer holds", 30);
    }
    const taken = archive.witnessing((seen, now) => {
      const dated = standing(() =>
        packetDates(packet, { now, window: 0n, holdsChain: () => false }),
      );
      if (!dated.ok) {
        const [first] = dated.issues;
        throw new OipError("expired", first.message, {
          clause: first.clause,
          issues: dated.issues,
        });
      }
      const judged = standing(() => judgeRecord(record));
      const view = archive.view(now);
      const digests = new Set(judged.ok ? judged.value.proofs.map((proof) => proof.digest) : []);
      const own = overlaid(view, seenAt(digests, now));
      if (
        !judged.ok ||
        standing(() => ownSignedTime(judged.value, packet.from, own)) === undefined
      ) {
        // Without the sender's log the indexer cannot tell a forgery from a stranger.
        throw view.log(packet.from).ok
          ? new OipError(
              "invalid-proof",
              "the packet carries no proof that counts by its sender's own authority",
              { clause: "L1 12.4" },
            )
          : new OipError(
              "stale-version",
              "the indexer holds no log of the packet's sender that verifies",
              { clause: "L1 12.4" },
            );
      }
      const id = contentId(packet);
      const before = indexer.store.forwardedTo(id);
      if (before !== undefined) return { forwarding: before, wrapped: [] };
      const allowed = this.#options.perSender.take(packet.from);
      if (!allowed.ok) {
        throw new OipError(
          "rate-limited",
          "this sender has had as much forwarded as a broker forwards for one",
        );
      }
      // The sender's own number, the indexer's where it gives none, and never more than fifty.
      const most = Math.min(to.maxFanout ?? this.#options.fanout ?? 10, MOST);
      const minds = indexer
        .matching(query, most + 1)
        .filter((mind) => mind !== packet.from)
        .slice(0, most);
      witnessRecord(judged.value, now, seen);
      indexer.store.forward(id, dated.value, minds.length);
      const wrapped = minds.map((mind) => ({
        mind,
        record: indexer.signed(
          {
            oip: "1",
            type: "Forwarded",
            broker: indexer.address,
            to: mind,
            packet: record as unknown as JsonObject,
            created: formatTimestamp(now),
          },
          now,
        ),
      }));
      return { forwarding: minds.length, wrapped };
    });
    for (const { mind, record: wrapper } of taken.wrapped) {
      this.#waiting.push(() => this.#deliver(mind, wrapper));
    }
    this.#next();
    return { forwarding: taken.forwarding };
  }

  /** Starts as many of the deliveries that wait as may be under way at once. */
  #next(): void {
    while (this.#running < (this.#options.maxAtOnce ?? 16)) {
      const delivery = this.#waiting.shift();
      if (delivery === undefined) break;
      this.#running++;
      void delivery().finally(() => {
        this.#running--;
        this.#next();
      });
    }
    if (this.#running === 0) for (const told of this.#idle.splice(0)) told();
  }

  /** One wrapper to one mind: the inboxes of its current location record, in the order it gives. */
  async #deliver(mind: string, wrapper: JsonObject): Promise<void> {
    const { archive, log, post } = this.#options;
    let outcome = "nowhere";
    try {
      const location = archive.resolve(mindId(mind) ?? "")?.location;
      const body = utf8(JSON.stringify(wrapper));
      // A wrapper is no packet a mailbox takes (13.5): only an inbox will do.
      const inboxes = (location === undefined ? [] : endpointsToTry(location))
        .filter((endpoint) => endpoint.binding === "https")
        .flatMap((endpoint) => postUrl(endpoint) ?? []);
      for (const url of inboxes) {
        outcome = "refused";
        try {
          const answer = await post(url, body, MEDIA_TYPE);
          if (answer.status >= 200 && answer.status < 300) {
            outcome = "delivered";
            break;
          }
        } catch (error) {
          // The kind of failure, and nothing it carried.
          log.event("warn", "delivery failed", {
            reason: error instanceof Error ? error.name : "unknown",
          });
        }
      }
    } catch (error) {
      outcome = "failed";
      log.failure("delivery failed", error, {});
    }
    this.#deliveries.add({ outcome });
  }

  /** Resolves when no delivery is under way or waits: for a service that stops, and for tests. */
  idle(): Promise<void> {
    if (this.#running === 0 && this.#waiting.length === 0) return Promise.resolve();
    return new Promise((resolve) => this.#idle.push(resolve));
  }
}
