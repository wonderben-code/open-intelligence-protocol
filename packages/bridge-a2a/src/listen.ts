// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The A2A interface on a port of this machine, and the reading of the
 * gateway's mailbox that keeps its tasks moving.
 *
 * This is plain HTTP, for a reverse proxy to stand in front of: TLS, and
 * who may connect at all, are the proxy's. What arrives is read up to the
 * size a request may have, and no further.
 */

import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";

import type { Front } from "./front.ts";
import { type A2aServer, MAX_REQUEST_BYTES } from "./server.ts";

/** How the interface is served. */
export interface Listening {
  /** The port to listen on. 0, for one the system chooses. */
  readonly port: number;
  /** The address to listen on. Default: this machine alone, `127.0.0.1`. */
  readonly host?: string;
  /** How long to rest between two readings of the gateway's mailbox, in milliseconds. Default: 500. */
  readonly everyMs?: number;
  /** Told of what went wrong in a reading of the mailbox, to log it. The next reading is made all the same. */
  readonly failed?: (error: unknown) => void;
}

/** An interface that is served. */
export interface Served {
  /** The port it listens on. */
  readonly port: number;
  /** Stops listening and reading, once what is under way has ended. */
  readonly close: () => Promise<void>;
}

const DEFAULT_EVERY_MS = 500;

/** How much of a request that is too large is read and let go, so that its sender can be told: 16 MiB. */
const MAX_LET_GO_BYTES = 16 * MAX_REQUEST_BYTES;

/**
 * The body of a request, up to one byte more than a request may have:
 * enough to tell that it is too large. The rest is read and let go, so
 * that its sender hears the answer, unless there is far too much of it.
 */
function bodyOf(request: IncomingMessage): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let kept = 0;
    let read = 0;
    request.on("data", (chunk: Buffer) => {
      read += chunk.length;
      const room = MAX_REQUEST_BYTES + 1 - kept;
      if (room > 0) {
        chunks.push(chunk.subarray(0, room));
        kept += Math.min(chunk.length, room);
      }
      if (read > MAX_LET_GO_BYTES) request.destroy(new Error("a request was far too large"));
    });
    request.on("end", () => {
      resolve(new Uint8Array(Buffer.concat(chunks)));
    });
    request.on("error", reject);
  });
}

/**
 * Serves the A2A interface of a front's minds over HTTP, and reads the
 * gateway's mailbox again and again while it does.
 *
 * @returns Once it listens.
 * @throws What keeps the port from being listened on.
 */
export async function listen(server: A2aServer, front: Front, options: Listening): Promise<Served> {
  const failed = options.failed ?? ((): void => undefined);
  const http = createServer((request, response) => {
    void (async (): Promise<void> => {
      // A header that came more than once is one value, as HTTP reads it.
      const headers: Record<string, string> = {};
      for (const [name, values] of Object.entries(request.headersDistinct)) {
        headers[name] = (values ?? []).join(", ");
      }
      const answer = await server.handle({
        // A request that reached a server has both.
        method: String(request.method),
        path: String(request.url),
        headers,
        body: await bodyOf(request),
      });
      response.writeHead(answer.status, {
        ...answer.headers,
        "content-length": String(answer.body.length),
      });
      response.end(answer.body);
    })().catch((error: unknown) => {
      // The connection went away, or what was sent could not be read: there is nobody to answer.
      failed(error);
      response.destroy();
    });
  });
  await new Promise<void>((resolve, reject) => {
    http.once("error", reject);
    http.listen(options.port, options.host ?? "127.0.0.1", () => {
      http.off("error", reject);
      resolve();
    });
  });

  let stopped = false;
  let timer: NodeJS.Timeout | undefined;
  let reading: Promise<void> = Promise.resolve();
  const read = (): void => {
    reading = front
      .pump()
      .then(
        () => undefined,
        (error: unknown) => {
          failed(error);
        },
      )
      .then(() => {
        if (!stopped) timer = setTimeout(read, options.everyMs ?? DEFAULT_EVERY_MS);
      });
  };
  read();

  return {
    port: (http.address() as AddressInfo).port,
    close: async (): Promise<void> => {
      stopped = true;
      clearTimeout(timer);
      await reading;
      await new Promise<void>((resolve) => {
        http.close(() => {
          resolve();
        });
        http.closeAllConnections();
      });
    },
  };
}
