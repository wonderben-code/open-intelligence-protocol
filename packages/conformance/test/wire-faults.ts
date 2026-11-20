// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Planted faults for the suite over the wire. A fault stands between the
 * suite and a reference service and changes what the service is asked or
 * what it answers, as an implementation with that fault would. A check that
 * no fault can make fail checks nothing.
 */

import type { WireReport } from "../src/index.ts";

/** A request as a fault sees it. */
export interface Asked {
  readonly method: string;
  /** The path and query. */
  readonly path: string;
  readonly headers: Headers;
  /** The body as text, or `""`. */
  readonly body: string;
}

/** What a fault does. Each part is left out where the fault changes nothing there. */
export interface Fault {
  /** Changes the request before the service sees it. */
  readonly ask?: (asked: Asked) => Partial<Asked> | undefined;
  /** Changes the answer. `undefined` leaves it as it is. */
  readonly answer?: (
    asked: Asked,
    response: Response,
  ) => Response | undefined | Promise<Response | undefined>;
}

/** `fetch` with a fault in the way. */
export function faulty(fault: Fault): typeof fetch {
  return async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const body = init?.body;
    const first: Asked = {
      method: init?.method ?? "GET",
      path: `${url.pathname}${url.search}`,
      headers: new Headers(init?.headers),
      body: body instanceof Uint8Array ? new TextDecoder().decode(body) : "",
    };
    const asked = { ...first, ...fault.ask?.(first) };
    const response = await fetch(`${url.origin}${asked.path}`, {
      ...init,
      method: asked.method,
      headers: asked.headers,
      ...(asked.body === "" ? {} : { body: asked.body }),
    });
    return (await fault.answer?.(asked, response)) ?? response;
  };
}

/** An answer with the same status and headers, and a body made from the JSON of the one given. */
export async function rewritten(
  response: Response,
  change: (body: Record<string, unknown>) => unknown,
): Promise<Response> {
  const body = (await response.json()) as Record<string, unknown>;
  return new Response(JSON.stringify(change(body)), {
    status: response.status,
    headers: response.headers,
  });
}

/** An answer of JSON. */
export function answered(status: number, body: unknown, type = "application/json"): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": type } });
}

/** A stream with each chunk of its text changed. */
export function restreamed(response: Response, change: (text: string) => string): Response {
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  const body = response.body?.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        controller.enqueue(encoder.encode(change(decoder.decode(chunk, { stream: true }))));
      },
    }),
  );
  return new Response(body ?? null, { status: response.status, headers: response.headers });
}

/** What a fault does to a WebSocket. Each part is left out where the fault changes nothing there. */
export interface SocketFault {
  /** Changes a message from the server. `undefined` drops it. */
  readonly incoming?: (text: string) => string | undefined;
  /**
   * Changes a message to the server. `undefined` drops it. `reply` gives the
   * client a message as if the server had sent it.
   */
  readonly outgoing?: (text: string, reply: (text: string) => void) => string | undefined;
  /** Changes the close the client is told of. */
  readonly closed?: (code: number, reason: string) => { code: number; reason: string };
  /** The subprotocol the client is told the server chose. */
  readonly protocol?: string;
}

/** The `WebSocket` class with a fault in the way: as much of it as the suite uses. */
export function faultySocket(fault: SocketFault): typeof WebSocket {
  class Faulty {
    readonly #real: WebSocket;
    readonly #listeners = new Map<string, ((event: unknown) => void)[]>();

    constructor(url: string, protocol: string) {
      this.#real = new WebSocket(url, protocol);
      this.#real.addEventListener("open", (event) => {
        this.#tell("open", event);
      });
      this.#real.addEventListener("error", (event) => {
        this.#tell("error", event);
      });
      this.#real.addEventListener("message", (event: MessageEvent) => {
        const text = String(event.data);
        const changed = fault.incoming === undefined ? text : fault.incoming(text);
        if (changed !== undefined) this.#tell("message", { data: changed });
      });
      this.#real.addEventListener("close", (event: CloseEvent) => {
        const { code, reason } = event;
        this.#tell("close", fault.closed?.(code, reason) ?? { code, reason });
      });
    }

    #tell(type: string, event: unknown): void {
      for (const listener of this.#listeners.get(type) ?? []) listener(event);
    }

    get protocol(): string {
      return fault.protocol ?? this.#real.protocol;
    }

    addEventListener(type: string, listener: (event: unknown) => void): void {
      this.#listeners.set(type, [...(this.#listeners.get(type) ?? []), listener]);
    }

    send(text: string): void {
      const changed =
        fault.outgoing === undefined
          ? text
          : fault.outgoing(text, (reply) => {
              this.#tell("message", { data: reply });
            });
      if (changed !== undefined) this.#real.send(changed);
    }

    close(): void {
      this.#real.close();
    }
  }
  return Faulty as unknown as typeof WebSocket;
}

/** The checks of a report that failed, by the part of their name after the profile. */
export function failed(report: WireReport): string[] {
  return report.checks
    .filter((check) => check.outcome === "fail")
    .map((check) => check.id.slice(check.id.indexOf("/") + 1));
}

/** The checks of a report that did not pass, each in a line. */
export function notPassed(report: WireReport): string[] {
  return report.checks
    .filter((check) => check.outcome !== "pass")
    .map((check) => `${check.id}: ${check.outcome}: ${check.detail ?? ""}`);
}
