// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * How a service says it is alive and ready, and how it stops (BUILD.md, M5).
 *
 * A service that is told to stop does so in order: it says it is no longer
 * ready, stops taking requests, lets those it has finish, and closes its
 * database last, so that nothing it acknowledged is lost. Each step has
 * what is left of a grace period. A step that fails or runs out of time is
 * logged, and the steps after it still run.
 */

import type { Log } from "./log.ts";

/** Something a service stops when it stops. */
export type Stop = () => void | Promise<void>;

/** How a shutdown is set up. */
export interface ShutdownOptions {
  readonly log: Log;
  /** How long all the steps together may take, in milliseconds. 10,000 by default. */
  readonly graceMs?: number;
}

/** What a process is told to stop with. */
export type StopSignal = "SIGTERM" | "SIGINT";

/** The orderly stopping of a service. */
export class Shutdown {
  readonly #log: Log;
  readonly #graceMs: number;
  readonly #steps: { name: string; stop: Stop }[] = [];
  #running: Promise<boolean> | undefined;

  constructor(options: ShutdownOptions) {
    this.#log = options.log;
    this.#graceMs = options.graceMs ?? 10_000;
    if (!Number.isSafeInteger(this.#graceMs) || this.#graceMs < 0) {
      throw new TypeError("a grace period is a whole number of milliseconds");
    }
  }

  /**
   * Adds something to stop. What was added last is stopped first: a
   * service adds its database when it opens it and its listener when it
   * listens, and stops them the other way round.
   */
  add(name: string, stop: Stop): void {
    if (this.#running !== undefined) throw new TypeError("the service is stopping already");
    this.#steps.push({ name, stop });
  }

  /** Whether the service has begun to stop. It is not ready from then on. */
  get stopping(): boolean {
    return this.#running !== undefined;
  }

  /**
   * Stops everything, once. Called again, it gives the same promise.
   *
   * @returns When every step has ended, or the grace period has: whether
   *   every step ended within it. It never rejects.
   */
  run(reason: string): Promise<boolean> {
    this.#running ??= this.#stop(reason);
    return this.#running;
  }

  async #stop(reason: string): Promise<boolean> {
    this.#log.event("info", "stopping", { reason, steps: this.#steps.length });
    let expire = (): void => undefined;
    const expired = new Promise<"expired">((resolve) => {
      const timer = setTimeout(() => {
        resolve("expired");
      }, this.#graceMs);
      expire = () => {
        clearTimeout(timer);
      };
    });
    let late = false;
    for (const { name, stop } of this.#steps.toReversed()) {
      try {
        // Started even when the time has run out: a database is closed late and not left open.
        const stopped = Promise.resolve().then(stop);
        if (late || (await Promise.race([stopped, expired])) === "expired") {
          late = true;
          this.#log.event("warn", "stopped late", { step: name });
          // What it does when it fails is nobody's to wait for now.
          stopped.catch(() => undefined);
        }
      } catch (error) {
        this.#log.failure("stop failed", error, { step: name });
      }
    }
    expire();
    this.#log.event("info", "stopped", { clean: !late });
    return !late;
  }

  /**
   * Stops the service when the process is told to stop, and then ends the
   * process: with 0, or with 1 if the grace period ran out.
   *
   * @param signals - The process, or what stands in for it in a test.
   * @param exit - How the process ends.
   */
  listen(
    signals: { once(signal: StopSignal, handler: () => void): unknown },
    exit: (code: number) => void,
  ): void {
    for (const signal of ["SIGTERM", "SIGINT"] as const) {
      signals.once(signal, () => {
        void this.run(signal).then((clean) => {
          exit(clean ? 0 : 1);
        });
      });
    }
  }
}

/** The answer of `/healthz`: the process is running and answers. */
export function healthResponse(): Response {
  return new Response('{"status":"ok"}', {
    status: 200,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

/**
 * The answer of `/readyz`: whether the service can do its work now. It
 * cannot once it has begun to stop, or while one of its checks fails: a
 * database that does not answer, for one.
 *
 * @param checks - What must hold, each by a name. A check that throws has failed.
 * @returns 200, or 503 with the names of what does not hold.
 */
export function readyResponse(
  checks: Readonly<Record<string, () => boolean>>,
  stopping: boolean,
): Response {
  const failing = stopping ? ["stopping"] : [];
  for (const [name, holds] of Object.entries(checks)) {
    let ok = false;
    try {
      ok = holds();
    } catch {
      // Why it failed is in the service's log, where the check itself logs it.
    }
    if (!ok) failing.push(name);
  }
  return new Response(
    JSON.stringify(failing.length === 0 ? { status: "ready" } : { status: "not ready", failing }),
    {
      status: failing.length === 0 ? 200 : 503,
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    },
  );
}
