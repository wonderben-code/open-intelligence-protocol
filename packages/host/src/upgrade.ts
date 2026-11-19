// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The host's WebSocket binding on a real socket: an HTTP server's upgrade
 * requests, handed to `Sockets` (Layer 1, 13.4).
 *
 * A request is refused before the handshake where it can be: at a URL that
 * names no mind the host serves, without the subprotocol `oip.v1`, beyond
 * what its address may open, or when there is no room. What speaks
 * WebSocket is the `ws` library, with a bound on the size of a message and
 * no compression (ADR-0012).
 */

import type { IncomingMessage, Server } from "node:http";
import type { Duplex } from "node:stream";

import { isContentId, mindAddress } from "@oip/core";
import { addressKey, type Log, type RateLimiter } from "@oip/server";
import { type WebSocket, WebSocketServer } from "ws";

import type { Host } from "./host.ts";
import { type Connection, type Sockets, SUBPROTOCOL, type Wire } from "./sockets.ts";

/** What the upgrade is made with. */
export interface UpgradeOptions {
  readonly host: Host;
  readonly sockets: Sockets;
  readonly log: Log;
  /** The limit on how many connections one address may open. */
  readonly limiter: RateLimiter;
  /** The address a request came from, as the service reads it behind its proxies. */
  readonly address: (request: IncomingMessage) => string | undefined;
  /** Whether the service is stopping: no connection is opened then. */
  readonly stopping: () => boolean;
  /** The most bytes of a message. */
  readonly maxRecordBytes: number;
  /** The bytes waiting to be sent at which a connection counts as full. 1 MiB by default, as in `Sockets`. */
  readonly maxBuffered?: number;
  /** How often each connection is asked whether it is there, in milliseconds. 30,000 by default. */
  readonly pingMs?: number;
}

const PATH = /^\/oip\/v1\/minds\/([^/]+)\/ws$/u;

/** A WebSocket, as far as sending over it needs. */
export interface Sending {
  send(text: string, sent: () => void): void;
  close(code: number, reason: string): void;
  readonly bufferedAmount: number;
}

/**
 * A connection as the binding uses one, made of a WebSocket. It says when
 * a connection that was full has room again: once, when what waits to be
 * sent has fallen to half of `maxBuffered`.
 */
export function wireFor(ws: Sending, maxBuffered: number, drained: () => void): Wire {
  let full = false;
  return {
    send: (text) => {
      ws.send(text, () => {
        if (full && ws.bufferedAmount < maxBuffered / 2) {
          full = false;
          drained();
        }
      });
      if (ws.bufferedAmount >= maxBuffered) full = true;
    },
    close: (code, reason) => {
      ws.close(code, reason);
    },
    get buffered() {
      return ws.bufferedAmount;
    },
  };
}

/**
 * Hands a server's upgrade requests to the binding.
 *
 * @returns How to stop: every connection is closed, and one that has not
 *   gone within `graceMs` is cut.
 */
export function attachSockets(
  server: Server,
  options: UpgradeOptions,
): (graceMs: number) => Promise<void> {
  const { host, sockets, log } = options;
  const maxBuffered = options.maxBuffered ?? 1024 * 1024;
  const wss = new WebSocketServer({
    noServer: true,
    maxPayload: options.maxRecordBytes,
    perMessageDeflate: false,
    handleProtocols: () => SUBPROTOCOL,
  });
  /** Whether each connection has answered since it was last asked. */
  const alive = new Map<WebSocket, boolean>();

  const bind = (ws: WebSocket, mind: string, address: string | undefined): void => {
    const connection: Connection = sockets.connect(
      mind,
      wireFor(ws, maxBuffered, () => {
        connection.drained();
      }),
      address,
    );
    alive.set(ws, true);
    ws.on("message", (data: Buffer, binary: boolean) => {
      if (binary) ws.close(1003, "a message is text");
      else connection.message(data.toString("utf8"));
    });
    ws.on("pong", () => alive.set(ws, true));
    ws.on("close", () => {
      alive.delete(ws);
      connection.closed();
    });
    // A connection that fails is over: `close` follows.
    ws.on("error", () => {
      ws.terminate();
    });
  };

  server.on("upgrade", (request: IncomingMessage, socket: Duplex, head: Buffer) => {
    const refuse = (status: number, title: string, more = ""): void => {
      socket.end(
        `HTTP/1.1 ${status} ${title}\r\nConnection: close\r\nContent-Length: 0\r\n${more}\r\n`,
      );
    };
    try {
      const id = PATH.exec((request.url ?? "").split("?")[0] ?? "")?.[1];
      if (id === undefined || !isContentId(id) || !host.hosts(mindAddress(id))) {
        refuse(404, "Not Found");
        return;
      }
      const offered = (request.headers["sec-websocket-protocol"] ?? "")
        .split(",")
        .map((protocol) => protocol.trim());
      if (!offered.includes(SUBPROTOCOL)) {
        refuse(400, "Bad Request");
        return;
      }
      if (options.stopping() || !sockets.room) {
        refuse(503, "Service Unavailable", "Retry-After: 30\r\n");
        return;
      }
      const address = options.address(request);
      const allowed = options.limiter.take(addressKey(address ?? "") ?? "unknown");
      if (!allowed.ok) {
        refuse(429, "Too Many Requests", `Retry-After: ${allowed.retryAfter}\r\n`);
        return;
      }
      wss.handleUpgrade(request, socket, head, (ws) => {
        bind(ws, mindAddress(id), address);
      });
    } catch (error) {
      log.failure("upgrade failed", error, {});
      refuse(500, "Internal Server Error");
    }
  });

  const ping = setInterval(() => {
    for (const [ws, answered] of alive) {
      if (!answered) {
        ws.terminate();
        continue;
      }
      alive.set(ws, false);
      ws.ping();
    }
  }, options.pingMs ?? 30_000);
  // A timer does not keep a process alive that has nothing else to do.
  ping.unref();

  return async (graceMs) => {
    clearInterval(ping);
    sockets.closeAll();
    const until = Date.now() + graceMs;
    while (wss.clients.size > 0 && Date.now() < until) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    for (const ws of wss.clients) ws.terminate();
    wss.close();
  };
}
