// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Load for a service that runs as a process of its own: the service is
 * started from its source, asked at a steady rate, and each answer is timed
 * from the moment its request was due.
 *
 * The rate does not slow down when the service does (an open loop): a
 * request that had to wait for the one before it has waited, and its wait
 * is counted. A loop that sends the next request when the last is answered
 * hides exactly the stalls a percentile is there to show.
 */

import { type ChildProcess, spawn } from "node:child_process";
import { appendFileSync } from "node:fs";

/** A service that runs as a process of its own. */
export interface StartedService {
  /** Where it listens: `http://127.0.0.1:<port>`. */
  readonly http: string;
  /** The same place for a WebSocket: `ws://127.0.0.1:<port>`. */
  readonly ws: string;
  /** Ends the process, and waits until it has ended. */
  stop(signal?: NodeJS.Signals): Promise<void>;
}

/**
 * Starts a service from its source, with an environment of its own, and
 * waits until it says that it listens.
 *
 * @param bin - The path of the service's `src/bin.ts`.
 * @param environment - Its settings. `PATH` is added.
 * @throws If the process ends before it listens.
 */
export function startService(
  bin: string,
  environment: Readonly<Record<string, string>>,
): Promise<StartedService> {
  return new Promise((resolve, reject) => {
    const child: ChildProcess = spawn(process.execPath, ["--conditions=@oip/source", bin], {
      // Nothing of this process's environment is the service's.
      env: { PATH: process.env["PATH"] ?? "", ...environment },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    child.stdout?.on("data", (chunk: Buffer) => {
      out += chunk.toString("utf8");
      const port = /"event":"listening".*?"port":(\d+)/u.exec(out)?.[1];
      if (port === undefined) return;
      resolve({
        http: `http://127.0.0.1:${port}`,
        ws: `ws://127.0.0.1:${port}`,
        stop: (signal = "SIGTERM") =>
          new Promise((stopped) => {
            if (child.exitCode !== null || child.signalCode !== null) {
              stopped();
              return;
            }
            child.once("close", () => {
              stopped();
            });
            child.kill(signal);
          }),
      });
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      err += chunk.toString("utf8");
    });
    child.once("error", reject);
    child.once("close", () => {
      reject(new Error(`the service ended before it listened: ${err || out}`));
    });
  });
}

/** How a load is made. */
export interface Load {
  /** Requests a second. */
  readonly rate: number;
  /** How many requests are sent. */
  readonly count: number;
  /**
   * Sends request `n` and resolves when it has been answered. A rejection,
   * or an answer the caller takes for a failure, fails the load.
   */
  readonly send: (n: number) => Promise<unknown>;
}

/**
 * Sends requests at a steady rate and gives how long each took, in
 * milliseconds from when it was due, in ascending order.
 *
 * @throws What a `send` rejected with.
 */
export async function steadyLoad(load: Load): Promise<number[]> {
  const latencies: number[] = [];
  const pending: Promise<void>[] = [];
  const interval = 1000 / load.rate;
  const start = performance.now();
  let sent = 0;
  while (sent < load.count) {
    const elapsed = performance.now() - start;
    while (sent < load.count && sent * interval <= elapsed) {
      const due = start + sent * interval;
      pending.push(
        load.send(sent).then(() => {
          latencies.push(performance.now() - due);
        }),
      );
      sent++;
    }
    // The loop turns as fast as it can, so that a request leaves when it is due.
    await new Promise<void>((resolve) => {
      setImmediate(resolve);
    });
  }
  await Promise.all(pending);
  return latencies.toSorted((a, b) => a - b);
}

/**
 * The value below which a share of sorted values lie: the 99th percentile for `0.99`.
 *
 * @throws RangeError if there are no values.
 */
export function percentile(sorted: readonly number[], share: number): number {
  const value = sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * share) - 1)];
  if (value === undefined) throw new RangeError("a percentile is of at least one value");
  return value;
}

/** What a round of load measured: the median and the 99th percentile, in milliseconds. */
export interface Round {
  readonly p50: number;
  readonly p99: number;
}

/** The median and the 99th percentile of a round's latencies, to a hundredth of a millisecond. */
export function roundOf(sorted: readonly number[]): Round {
  const to = (value: number): number => Math.round(value * 100) / 100;
  return { p50: to(percentile(sorted, 0.5)), p99: to(percentile(sorted, 0.99)) };
}

/** The rounds in a line, for the message of a budget that was missed. */
export function told(rounds: readonly Round[]): string {
  return `p50/p99 of each round, in ms: ${rounds.map((round) => `${round.p50}/${round.p99}`).join(", ")}`;
}

/**
 * Keeps what a load measured, where `OIP_LOAD_REPORT` names a file: a line
 * of JSON is added to it. It is how the figures of an ADR are taken.
 */
export function recorded(name: string, rounds: readonly Round[]): void {
  const file = process.env["OIP_LOAD_REPORT"];
  if (file !== undefined) appendFileSync(file, `${JSON.stringify({ name, rounds })}\n`);
}

/** The middle of an odd number of values. */
export function middle(values: readonly number[]): number {
  const sorted = values.toSorted((a, b) => a - b);
  const value = sorted[(sorted.length - 1) / 2];
  if (value === undefined) throw new RangeError("the middle is of an odd number of values");
  return value;
}
