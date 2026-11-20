// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A socket held open to the mind's own host (Layer 1, 13.4), so that
 * packets arrive when they are sent and not when the mind next looks.
 *
 * The host speaks first, with a challenge. The client answers with a
 * `Hello` it signs for the origin it connected to, and is welcomed as the
 * mind. From then on the host sends what the mind's mailbox holds and what
 * arrives. Each record is judged as an item of the mailbox is, and the mind
 * says it has one with an acknowledgement of its own, after which the host
 * keeps it no longer. A record stays with the host until then, so a
 * connection that drops loses nothing.
 *
 * A connection that ends is opened again, after a wait that grows.
 */

import { type JsonValue, OipError, parseJsonBytes, utf8 } from "@oip/core";
import { KeystoreError } from "@oip/keystore";
import { webSocketUrl } from "@oip/net";
import type { Ack } from "@oip/schema";

import type { Inbox } from "./messages.ts";
import { homeEndpoints, type Own } from "./publish.ts";
import { DEFAULT_MAX_BYTES, TransportError } from "./transport.ts";

/** Layer 1, 13.4: the subprotocol of the WebSocket binding. */
const SUBPROTOCOL = "oip.v1";

/**
 * A WebSocket, as the client uses one. The `WebSocket` of a browser, and of
 * Node.js, is one.
 */
export interface SocketLike {
  /** Sends a text message. */
  send(data: string): void;
  /** Closes the connection. */
  close(code?: number, reason?: string): void;
  /** Called when the connection is open. */
  onopen: ((event: unknown) => void) | null;
  /** Called with each message. */
  onmessage: ((event: { readonly data: unknown }) => void) | null;
  /** Called once when the connection has closed, whoever closed it. */
  onclose: ((event: { readonly code?: number; readonly reason?: string }) => void) | null;
  /** Called when the connection fails. A close follows. */
  onerror: ((event: unknown) => void) | null;
}

/** Opens a WebSocket to a URL, with a subprotocol. */
export type OpenSocket = (url: string, protocol: string) => SocketLike;

/** Where a connection to the mind's host stands. */
export type SocketState =
  | {
      /** A connection is being opened, and the mind is not yet welcomed on it. */
      readonly state: "connecting";
      readonly url: string;
    }
  | {
      /** The host has welcomed the mind: what arrives is sent to it as it arrives. */
      readonly state: "open";
      readonly url: string;
    }
  | {
      /** The connection ended, or could not be opened. Another is opened after a wait. */
      readonly state: "closed";
      readonly url: string;
      /** The code the connection closed with (RFC 6455), if it closed with one. */
      readonly code?: number;
      /** Why: the host's reason, or what failed here. A stranger's words, cut to 123 bytes by the protocol. */
      readonly reason?: string;
      /** How long until the next connection is tried, in milliseconds. */
      readonly retryIn: number;
    }
  | {
      /** The mind names no endpoint that has a socket. Its location is read again after a wait. */
      readonly state: "nowhere";
      readonly retryIn: number;
    };

/** What a mind listens with. */
export interface ListenOptions {
  /**
   * Called with what arrived, each time something did: as `Mind.receive`
   * returns it. It is called for one batch after another, never for two at
   * once. What it throws ends the listening, and is thrown by `closed`.
   */
  readonly received: (inbox: Inbox) => void | Promise<void>;
  /** Called when the connection is opened, welcomed, or ended. */
  readonly changed?: (state: SocketState) => void;
  /** The wait before a connection is tried again, at first, in milliseconds. Default: 1,000. */
  readonly retryMs?: number;
  /** The longest such wait: it doubles up to this. Default: 60,000. */
  readonly maxRetryMs?: number;
}

/** A mind that is listening. */
export interface Listening {
  /** Stops listening: closes the connection, and opens no other. */
  close(): Promise<void>;
  /**
   * Settles when the listening has ended: when `close` was called, or with
   * the error that ended it. A connection that drops does not end it.
   */
  readonly closed: Promise<void>;
}

/** What listening needs besides the mind. */
export interface Listener {
  readonly own: Own;
  readonly open: OpenSocket;
  /** Waits. A test gives its own. */
  readonly sleep: (ms: number) => Promise<void>;
  /** Judges what the host sent: `Messaging.take`. */
  readonly take: (records: readonly JsonValue[]) => Promise<{
    readonly inbox: Inbox;
    readonly acks: readonly Ack[];
    readonly refused: boolean;
  }>;
  /** Reads the mailboxes over HTTP: `Messaging.receive`. */
  readonly receive: () => Promise<Inbox>;
  /** Tries again what waits to be sent, if it is due: `Messaging.retry`. */
  readonly retry: () => Promise<Inbox["retried"]>;
}

const DEFAULT_RETRY_MS = 1000;
const DEFAULT_MAX_RETRY_MS = 60_000;
/** RFC 6455, 7.4.1: codes a client closes with. */
const CLOSE = { normal: 1000, protocol: 1002, tooBig: 1009, failed: 1011 } as const;

/** The WebSocket of the platform. */
export const platformSocket: OpenSocket = (url, protocol) => {
  const Platform = (
    globalThis as { WebSocket?: new (url: string, protocols: string) => SocketLike }
  ).WebSocket;
  if (Platform === undefined) {
    throw new TypeError("this platform has no WebSocket: give the client one, as `webSocket`");
  }
  return new Platform(url, protocol);
};

/** Waits with the platform's timer. */
export const platformSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

/** A message as an object with a `type`, or `undefined`. */
function messageOf(text: string): Readonly<Record<string, JsonValue>> | undefined {
  const parsed = parseJsonBytes(utf8(text));
  return parsed.ok &&
    typeof parsed.value === "object" &&
    parsed.value !== null &&
    !Array.isArray(parsed.value)
    ? (parsed.value as Readonly<Record<string, JsonValue>>)
    : undefined;
}

/** Whether there is something in a reading worth telling the application. */
const hasNews = (inbox: Inbox): boolean =>
  inbox.received.length > 0 ||
  inbox.refused.length > 0 ||
  inbox.sessions.length > 0 ||
  inbox.retried.length > 0 ||
  inbox.waiting > 0;

/** How one connection ended. */
interface Ended {
  /** Whether the host welcomed the mind on it. */
  readonly welcomed: boolean;
  readonly code?: number;
  readonly reason?: string;
}

/** Starts listening: see `Mind.listen`. */
export function listen(listener: Listener, options: ListenOptions): Listening {
  const { own } = listener;
  const first = options.retryMs ?? DEFAULT_RETRY_MS;
  const longest = options.maxRetryMs ?? DEFAULT_MAX_RETRY_MS;
  for (const ms of [first, longest]) {
    if (!Number.isSafeInteger(ms) || ms < 1) {
      throw new TypeError("a wait is a whole number of milliseconds, of at least 1");
    }
  }
  let stopped = false;
  /** Asked after every wait: `close` may have been called meanwhile. */
  const isStopped = (): boolean => stopped;
  let current: SocketLike | undefined;
  /** Ends a wait early: the listening was closed. */
  let wake: (() => void) | undefined;

  /** The URLs of the mind's own sockets, as its location stands now. */
  const urls = async (): Promise<string[]> => {
    const resolved = await own.refresh();
    // Every endpoint the mind names, whatever its status says to those who send to it: a
    // mind that is paused still reads what its host keeps for it.
    const endpoints =
      resolved.location?.record.endpoints ?? homeEndpoints(own.address, resolved.state.homes);
    return [
      ...new Set(
        endpoints
          .toSorted((a, b) => (a.priority ?? 0) - (b.priority ?? 0))
          .flatMap((endpoint) => {
            const url = webSocketUrl(endpoint as Parameters<typeof webSocketUrl>[0]);
            return url === undefined ? [] : [url];
          }),
      ),
    ];
  };

  /** One connection, from its opening to its end. It rejects with what the application threw. */
  const connection = (url: string): Promise<Ended> =>
    new Promise<Ended>((resolve, reject) => {
      let socket: SocketLike;
      try {
        socket = listener.open(url, SUBPROTOCOL);
      } catch (error) {
        if (error instanceof TypeError) {
          reject(error);
          return;
        }
        resolve({ welcomed: false, reason: "the connection could not be opened" });
        return;
      }
      current = socket;
      let phase: "challenge" | "welcome" | "open" | "over" = "challenge";
      /** Asked after every wait: the connection may have ended meanwhile. */
      const isOpen = (): boolean => phase === "open";
      let welcomed = false;
      /** The records that arrived and are not yet judged. */
      let waiting: JsonValue[] = [];
      /** The judging of what arrived, one batch after another. */
      let working: Promise<void> | undefined;

      const end = (code: number, reason: string): void => {
        if (phase === "over") return;
        phase = "over";
        current = undefined;
        socket.onmessage = null;
        socket.onclose = null;
        socket.onerror = null;
        try {
          socket.close(code, reason);
        } catch {
          // It is closed already, or was never open.
        }
        resolve({ welcomed, code, reason });
      };

      const work = async (): Promise<void> => {
        while (waiting.length > 0 && isOpen()) {
          const batch = waiting;
          waiting = [];
          const { inbox, acks, refused } = await listener.take(batch);
          // The host is told once what was kept: see `Messaging.take`.
          for (const ack of acks) {
            if (isOpen()) socket.send(JSON.stringify(ack));
          }
          if (!refused) {
            if (hasNews(inbox)) await options.received(inbox);
            continue;
          }
          // What was refused stays with the host, which cannot be told so over the socket.
          // Reading the mailbox removes it. What that reading refuses was refused just now,
          // and is told once: the rest of what it finds is told with this batch.
          const rest = await listener.receive();
          await options.received({
            received: [...inbox.received, ...rest.received],
            refused: inbox.refused,
            sessions: [...inbox.sessions, ...rest.sessions],
            retried: rest.retried,
            waiting: rest.waiting,
            sources: [],
          });
        }
      };

      const heard = (text: string): void => {
        if (text.length > DEFAULT_MAX_BYTES) {
          end(CLOSE.tooBig, "the message is larger than the client reads");
          return;
        }
        const message = messageOf(text);
        if (message === undefined) {
          end(CLOSE.protocol, "the message is no JSON object");
          return;
        }
        if (phase === "challenge") {
          const { nonce } = message;
          if (message["type"] !== "Challenge" || typeof nonce !== "string" || nonce === "") {
            end(CLOSE.protocol, "the host did not begin with a challenge");
            return;
          }
          phase = "welcome";
          // The origin is the one this client connected to, whatever the host says of
          // itself: a host that passes the Hello on finds it of no use elsewhere (13.3).
          own.hello(nonce, `https://${new URL(url).host}`).then(
            (hello) => {
              if (phase === "welcome") socket.send(JSON.stringify(hello));
            },
            () => {
              end(CLOSE.failed, "the mind has no key to answer with");
            },
          );
          return;
        }
        if (phase === "welcome") {
          if (message["type"] !== "Welcome" || message["mind"] !== own.address) {
            end(CLOSE.protocol, "the host did not welcome the mind");
            return;
          }
          phase = "open";
          welcomed = true;
          options.changed?.({ state: "open", url });
          // The network is there: what waits to be sent is tried again, if it is due.
          working = settle(
            listener.retry().then(async (retried) => {
              const news = {
                received: [],
                refused: [],
                sessions: [],
                retried,
                waiting: 0,
                sources: [],
              };
              if (hasNews(news)) await options.received(news);
              await work();
            }),
          );
          return;
        }
        waiting.push(message);
        working ??= settle(work());
      };

      /** Follows work on what arrived to its end: whatever it throws ends the connection. */
      const settle = (work: Promise<void>): Promise<void> =>
        work.then(
          () => {
            working = undefined;
          },
          (error: unknown) => {
            working = undefined;
            // A reading that another process of the mind was ahead of, or a service that
            // could not be asked: the connection is opened again, and judges afresh.
            if (error instanceof KeystoreError || error instanceof TransportError) {
              end(CLOSE.failed, error instanceof KeystoreError ? error.code : error.failure);
              return;
            }
            // Anything else is the application's own failure, or the client's: the listening
            // ends with it. It is thrown first, so that the connection's end does not hide it.
            reject(error instanceof Error ? error : new Error(String(error)));
            end(CLOSE.failed, "the application failed");
          },
        );

      socket.onmessage = (event) => {
        if (typeof event.data === "string") heard(event.data);
        else end(CLOSE.protocol, "the message is no text");
      };
      socket.onerror = () => {
        // A close follows, and says no more than this would.
      };
      socket.onclose = (event) => {
        if (phase === "over") return;
        phase = "over";
        current = undefined;
        resolve({
          welcomed,
          ...(event.code === undefined ? {} : { code: event.code }),
          ...(event.reason === undefined || event.reason === "" ? {} : { reason: event.reason }),
        });
      };
    });

  /** Waits before the next connection, unless the listening is closed first. */
  const pause = (ms: number): Promise<void> =>
    isStopped()
      ? Promise.resolve()
      : Promise.race([
          listener.sleep(ms),
          new Promise<void>((resolve) => {
            wake = resolve;
          }),
        ]);

  /** A wait between half of `ms` and all of it, so that many clients do not return as one. */
  const jittered = (ms: number): number => {
    const [byte = 0] = own.randomness.bytes(1);
    return Math.max(1, Math.round(ms * (0.5 + byte / 510)));
  };

  const run = async (): Promise<void> => {
    let wait = first;
    /** Which of the mind's sockets is tried next. */
    let turn = 0;
    while (!isStopped()) {
      let sockets: string[];
      try {
        sockets = await urls();
      } catch (error) {
        // The resolvers cannot be asked where the mind is, or what they say does not hold:
        // that may pass, and is waited out.
        if (!(error instanceof TransportError || error instanceof OipError)) throw error;
        sockets = [];
      }
      const url = sockets[turn++ % Math.max(sockets.length, 1)];
      if (isStopped()) break;
      if (url === undefined) {
        const retryIn = jittered(wait);
        options.changed?.({ state: "nowhere", retryIn });
        await pause(retryIn);
        wait = Math.min(wait * 2, longest);
        continue;
      }
      options.changed?.({ state: "connecting", url });
      const ended = await connection(url);
      if (isStopped()) break;
      // A connection that was welcomed shows the host is there: the next wait is short again.
      if (ended.welcomed) wait = first;
      const retryIn = jittered(wait);
      options.changed?.({
        state: "closed",
        url,
        ...(ended.code === undefined ? {} : { code: ended.code }),
        ...(ended.reason === undefined ? {} : { reason: ended.reason }),
        retryIn,
      });
      await pause(retryIn);
      wait = Math.min(wait * 2, longest);
    }
  };

  const closed = run();
  // Whoever listens for the end is told. Nobody has to.
  closed.catch(() => undefined);
  return {
    closed,
    close: async () => {
      stopped = true;
      wake?.();
      const socket = current;
      current = undefined;
      if (socket !== undefined) {
        // Its end is of the client's own making: what the socket says next is not waited for.
        const { onclose } = socket;
        try {
          socket.close(CLOSE.normal, "the mind stops listening");
        } catch {
          // It never opened.
        }
        onclose?.({ code: CLOSE.normal });
      }
      await closed.catch(() => undefined);
    },
  };
}
