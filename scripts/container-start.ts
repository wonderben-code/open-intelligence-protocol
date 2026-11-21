// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * BUILD.md 3.8: a server container starts within two seconds.
 *
 * For each service of the Compose stack, this stops its container, starts it
 * again, and measures the time from asking Docker to start it until `/readyz`
 * answers 200. It does so three times and holds the fastest to the budget: on
 * a shared machine other work only ever adds time, so the fastest is the
 * steadiest measure of what a start costs (ADR-0006).
 *
 * A start is everything Compose does when asked for the service. For the
 * indexer that includes the container that makes its mind where there is
 * none, which runs first and takes most of the time.
 *
 * The stack must be up already: `docker compose up --build --wait`. It is
 * left up, each service started.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { repoRoot } from "./lib/spec.ts";

const BUDGET_MS = 2000;
const RUNS = 3;
/** How long one start may take before the measurement gives up. */
const GIVE_UP_MS = 30_000;
const POLL_MS = 10;

interface Service {
  readonly name: string;
  /** Where it answers on this machine (compose.yaml). */
  readonly ready: string;
}

const SERVICES: readonly Service[] = [
  { name: "resolver", ready: "http://127.0.0.1:8081/readyz" },
  { name: "host", ready: "http://127.0.0.1:8082/readyz" },
  { name: "indexer", ready: "http://127.0.0.1:8083/readyz" },
];

const run = promisify(execFile);

async function compose(...args: string[]): Promise<void> {
  await run("docker", ["compose", ...args], { cwd: repoRoot });
}

async function isReady(service: Service): Promise<boolean> {
  try {
    const response = await fetch(service.ready, { signal: AbortSignal.timeout(500) });
    await response.body?.cancel();
    return response.status === 200;
  } catch {
    // Nothing listens yet.
    return false;
  }
}

/** Milliseconds from asking Docker to start a stopped service to its first 200 from `/readyz`. */
async function start(service: Service): Promise<number> {
  await compose("stop", service.name);
  if (await isReady(service)) {
    throw new Error(`${service.name} still answers after it was stopped`);
  }
  const began = performance.now();
  // Not awaited yet: the service can be ready before the command returns.
  const asked = compose("start", service.name);
  try {
    while (!(await isReady(service))) {
      if (performance.now() - began > GIVE_UP_MS) {
        throw new Error(`${service.name} was not ready within ${String(GIVE_UP_MS / 1000)} s`);
      }
      await new Promise((resolve) => setTimeout(resolve, POLL_MS));
    }
    return performance.now() - began;
  } finally {
    await asked;
  }
}

let late = 0;
for (const service of SERVICES) {
  const runs: number[] = [];
  for (let index = 0; index < RUNS; index++) runs.push(await start(service));
  const fastest = Math.min(...runs);
  const within = fastest <= BUDGET_MS;
  if (!within) late++;
  console.log(
    `${service.name}: ready in ${runs.map((ms) => ms.toFixed(0)).join(", ")} ms; ` +
      `the fastest is ${within ? "within" : "over"} the budget of ${String(BUDGET_MS)} ms`,
  );
}
if (late > 0) {
  console.error(`${String(late)} of ${String(SERVICES.length)} services started too slowly.`);
  process.exit(1);
}
