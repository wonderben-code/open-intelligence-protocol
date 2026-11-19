// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The host's WebSocket binding (Layer 1, 13.4), without the socket: what is
 * said over a connection, and what is done with each message. The library
 * that speaks WebSocket is bound to this in `main.ts`; a test speaks to it
 * directly.
 *
 * The server speaks first, with a challenge. The client answers with a
 * `Hello` (13.3), and the server welcomes the mind it authenticates or
 * closes with 4401. After that each message is one record:
 *
 * - **To the host**, a `Packet` or a `Sealed` record is delivered as at the
 *   inbox (13.2). If the host signs for the mind, the `Ack` is sent back.
 * - **To the mind's own instance**, the host sends what is in the mind's
 *   mailbox, in the order it came, and what arrives while the socket is
 *   open. A record stays in the mailbox until the mind says it has it: with
 *   an `Ack` over the socket, or by removing it over HTTP (13.5). So a
 *   socket that drops loses nothing.
 *
 * A message that is refused closes the connection, with the code of its
 * problem (core 10.2) as the reason: there is no record that says no.
 */

import { bytesToBase64url, MAX_TEXT_LENGTH, OipError, utf8 } from "@oip/core";
import { FirstSeen } from "@oip/identity";
import { Challenges, verifyHello } from "@oip/net";
import {
  addressKey,
  type Clock,
  HttpFailure,
  type Log,
  type LogArchive,
  type Metrics,
  type Randomness,
  type RateLimiter,
  recordFrom,
  Unavailable,
} from "@oip/server";

import type { Answer, Host } from "./host.ts";
import { overlaid, standing } from "./judging.ts";
import { deliverLearning, type Lookup } from "./lookup.ts";

/** The subprotocol a client asks for (13.4). */
export const SUBPROTOCOL = "oip.v1";

/** The close codes the binding uses. Those from 4000 are an application's own (RFC 6455, 7.4.2). */
export const CLOSE = {
  /** The service is stopping. */
  goingAway: 1001,
  /** A message was refused. */
  refused: 1008,
  /** Something failed that nobody expected. */
  failed: 1011,
  /** The host cannot do it just now: ask again. */
  later: 1013,
  /** 13.4: the client did not authenticate. */
  unauthenticated: 4401,
} as const;

/** A connection, as the binding uses one. */
export interface Wire {
  /** Sends a text message. */
  send(text: string): void;
  /** Closes the connection. Nothing is sent after it. */
  close(code: number, reason: string): void;
  /** How many bytes have been handed over and not yet sent. */
  readonly buffered: number;
}

/** What the binding is told of a connection. */
export interface Connection {
  /** A text message arrived. */
  message(text: string): void;
  /** What was buffered has been sent. */
  drained(): void;
  /** The connection closed, whoever closed it. */
  closed(): void;
}

/** What the binding is made with. */
export interface SocketsOptions {
  readonly host: Host;
  /** The identity logs the host holds: the same archive the host was made with. */
  readonly archive: LogArchive;
  readonly clock: Clock;
  readonly randomness: Randomness;
  readonly log: Log;
  readonly metrics: Metrics;
  /** The origin clients reach the host at, as it is configured. A `Hello` names it (13.3). */
  readonly origin: string;
  /** The limit on what one address may deliver: the same as for the inbox. */
  readonly deliver: RateLimiter;
  /** How the host learns the log of a sender it cannot judge, as at the inbox. */
  readonly lookup?: Lookup;
  /** How many messages may wait on one connection while a resolver is asked. 64 by default. */
  readonly maxWaiting?: number;
  /** The most connections open at once. 1,024 by default. */
  readonly maxSockets?: number;
  /** How long a client has to answer the challenge, in milliseconds. 10,000 by default. */
  readonly helloMs?: number;
  /** The most bytes of a message that are read. `MAX_TEXT_LENGTH` of `@oip/core` by default. */
  readonly maxRecordBytes?: number;
  /** The host stops sending a mind its mail while this many bytes wait to be sent. 1 MiB by default. */
  readonly maxBuffered?: number;
}

/** How many records of a mailbox are read at a time to be sent. */
const BATCH = 16;

/** Layer 1, 13.4: the host's WebSocket binding. */
export class Sockets {
  readonly #options: SocketsOptions;
  readonly #challenges = new Challenges();
  readonly #open = new Set<() => void>();
  readonly #gauge;
  readonly #messages;

  constructor(options: SocketsOptions) {
    this.#options = options;
    this.#gauge = options.metrics.gauge("oip_host_sockets_open", "WebSocket connections open.");
    this.#messages = options.metrics.counter(
      "oip_host_socket_messages_total",
      "Messages received over WebSocket connections, by what became of each.",
      ["outcome"],
    );
  }

  /** How many connections are open. */
  get open(): number {
    return this.#open.size;
  }

  /** Whether there is room for one more connection. */
  get room(): boolean {
    return this.#open.size < (this.#options.maxSockets ?? 1024);
  }

  /** Closes every connection: the service is stopping. */
  closeAll(): void {
    for (const end of [...this.#open]) end();
  }

  /**
   * A connection that was opened at a mind's WebSocket URL. The challenge
   * is sent at once.
   *
   * @param mind - The mind the URL names, which the host serves.
   * @param address - The client's IP address, for the limit on what it delivers.
   */
  connect(mind: string, wire: Wire, address: string | undefined): Connection {
    const { host, archive, clock, log, origin } = this.#options;
    const maxRecordBytes = this.#options.maxRecordBytes ?? MAX_TEXT_LENGTH;
    const maxBuffered = this.#options.maxBuffered ?? 1024 * 1024;
    const client = addressKey(address ?? "") ?? "unknown";
    /** The mind that authenticated, once one has. */
    let who: string | undefined;
    let over = false;
    let stopMail: (() => void) | undefined;
    /** The cursor of the last item of the mailbox that was sent. */
    let cursor = 0;

    // 13.4: at least 16 random bytes. A challenge is good for 300 seconds and for one Hello.
    const now = clock.now();
    this.#challenges.forget(now);
    const nonce = bytesToBase64url(this.#options.randomness.bytes(24));
    this.#challenges.issue(nonce, now);
    const timer = setTimeout(() => {
      close(CLOSE.unauthenticated, "no Hello in time");
    }, this.#options.helloMs ?? 10_000);

    const finish = (): void => {
      if (over) return;
      over = true;
      clearTimeout(timer);
      stopMail?.();
      this.#open.delete(end);
      this.#gauge.set(this.#open.size);
    };
    const close = (code: number, reason: string): void => {
      if (over) return;
      finish();
      wire.close(code, reason);
    };
    const end = (): void => {
      close(CLOSE.goingAway, "the host is stopping");
    };
    this.#open.add(end);
    this.#gauge.set(this.#open.size);

    wire.send(JSON.stringify({ type: "Challenge", nonce, domain: origin }));

    /** Sends the mind what waits in its mailbox, as far as the connection takes it. */
    const mail = (): void => {
      while (!over && wire.buffered < maxBuffered) {
        const { items } = host.drain(mind, cursor, BATCH);
        if (items.length === 0) return;
        for (const item of items) {
          cursor = item.cursor;
          wire.send(JSON.stringify(item.record));
        }
      }
    };

    /** Whatever was thrown, as the end of the connection. */
    const failed = (error: unknown, outcome: string): void => {
      this.#messages.add({ outcome });
      if (error instanceof OipError) close(CLOSE.refused, error.code);
      else if (error instanceof HttpFailure) {
        close(error.status === 507 ? CLOSE.later : CLOSE.refused, error.message);
      } else if (error instanceof Unavailable) close(CLOSE.later, "ask again");
      else {
        log.failure("socket failed", error, {});
        close(CLOSE.failed, "internal error");
      }
    };

    /** The mind a Hello authenticates now, judged as first seen now. */
    const judge = (value: unknown): ReturnType<typeof verifyHello> => {
      const at = clock.now();
      // The proof answers a challenge made a moment ago. The host is no witness of it,
      // and keeps no record of that.
      const seen = new FirstSeen();
      return standing(() =>
        verifyHello(value, {
          origin,
          now: at,
          challenges: this.#challenges,
          seen,
          view: overlaid(archive.view(at), (digest) => seen.proofSeen(digest)),
        }),
      );
    };

    /** Welcomes the mind, or closes. */
    const settle = (judged: ReturnType<typeof verifyHello>): void => {
      if (over) return;
      if (!judged.ok) {
        this.#messages.add({ outcome: "unauthenticated" });
        close(CLOSE.unauthenticated, "the Hello does not authenticate a mind");
        return;
      }
      clearTimeout(timer);
      who = judged.value.mind;
      this.#messages.add({ outcome: "welcomed" });
      wire.send(JSON.stringify({ type: "Welcome", mind: who }));
      if (who !== mind) return;
      // The mind's own instance: it is sent its mail, and what arrives from now on.
      stopMail = host.subscribe(mind, () => {
        try {
          mail();
        } catch (error) {
          failed(error, "failed");
        }
      });
      mail();
    };

    /** The first message. A promise where a resolver is asked for the mind's log first. */
    const hello = (text: string): Promise<void> | undefined => {
      let value: unknown;
      try {
        value = JSON.parse(text);
      } catch {
        close(CLOSE.unauthenticated, "no Hello");
        return undefined;
      }
      const judged = judge(value);
      const lookup = this.#options.lookup;
      const author =
        typeof value === "object" && value !== null
          ? (value as { author?: unknown }).author
          : undefined;
      if (judged.ok || lookup === undefined || typeof author !== "string") {
        settle(judged);
        return undefined;
      }
      // A mind the host has not met, or whose log has grown. A Hello that failed left its
      // challenge as it was, so it is judged again with what was learned.
      return lookup.learn(author).then((learned) => {
        settle(learned && !over ? judge(value) : judged);
      });
    };

    const delivered = (answer: Answer): void => {
      this.#messages.add({ outcome: "delivered" });
      if (!over && answer["type"] === "Ack") wire.send(JSON.stringify(answer));
    };

    /** One record. A promise where a resolver is asked for its sender's log first. */
    const record = (text: string): Promise<void> | undefined => {
      const taken = this.#options.deliver.take(client);
      if (!taken.ok) {
        this.#messages.add({ outcome: "rate-limited" });
        close(CLOSE.later, "rate-limited");
        return undefined;
      }
      const read = recordFrom(utf8(text), maxRecordBytes);
      if (read.type === "Ack") {
        if (who !== mind) throw new OipError("forbidden", "only the mind itself acknowledges here");
        host.acknowledge(mind, read);
        this.#messages.add({ outcome: "acknowledged" });
        return undefined;
      }
      if (read.type !== "Packet" && read.type !== "Sealed") {
        throw new OipError("invalid-record", "a message is a Packet, a Sealed record or an Ack", {
          clause: "L1 13.4",
        });
      }
      const answer = deliverLearning(host, this.#options.lookup, mind, read);
      if (answer instanceof Promise) return answer.then(delivered);
      delivered(answer);
      return undefined;
    };

    /** The messages that wait behind one whose sender is being asked after, in order. */
    let tail: Promise<void> | undefined;
    let waiting = 0;
    const maxWaiting = this.#options.maxWaiting ?? 64;
    const heard = (text: string): Promise<void> | undefined => {
      return who === undefined ? hello(text) : record(text);
    };
    const outcome = (): string => (who === undefined ? "unauthenticated" : "refused");
    /** Puts work behind what the connection is waiting on, which stays one chain. */
    const behind = (work: () => Promise<void> | undefined): void => {
      const link: Promise<void> = (tail ?? Promise.resolve())
        .then(() => (over ? undefined : work()))
        .catch((error: unknown) => {
          failed(error, outcome());
        })
        .then(() => {
          if (tail === link) tail = undefined;
        });
      tail = link;
    };

    return {
      message: (text) => {
        if (over) return;
        if (tail !== undefined) {
          // Kept in the order they came, and no more of them than a connection may leave waiting.
          if (waiting >= maxWaiting) {
            this.#messages.add({ outcome: "refused" });
            close(CLOSE.refused, "too many messages at once");
            return;
          }
          waiting++;
          behind(() => {
            waiting--;
            return heard(text);
          });
          return;
        }
        try {
          const pending = heard(text);
          if (pending !== undefined) behind(() => pending);
        } catch (error) {
          failed(error, outcome());
        }
      },
      drained: () => {
        if (over || who !== mind) return;
        try {
          mail();
        } catch (error) {
          failed(error, "failed");
        }
      },
      closed: finish,
    };
  }
}
