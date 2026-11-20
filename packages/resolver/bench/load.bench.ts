// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The resolver under load, as a process of its own on one core, asked over
 * a socket of this machine. BUILD.md 3.8 gives it two budgets:
 *
 * - resolve a known mind: a 99th percentile of 25 ms at 500 requests a second;
 * - accept a published bundle: a 99th percentile of 100 ms.
 *
 * Each is measured in three rounds, and the middle is compared: other work
 * on the machine during one round moves that round and leaves the middle.
 * ADR-0015 has what was measured.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { MEDIA_TYPE, mindId } from "@oip/core";
import { repoRoot } from "@oip/testkit";
import {
  middle,
  recorded,
  type Round,
  roundOf,
  type StartedService,
  startService,
  steadyLoad,
  told,
} from "@oip/testkit/load";
import { KeyMind, type Mind } from "@oip/testkit/minds";
import { afterAll, beforeAll, describe, expect, test } from "vitest";

/** The budgets of BUILD.md 3.8, in milliseconds at the 99th percentile. */
export const BUDGETS = { resolve: 25, publish: 100 } as const;

/** The loads: BUILD.md gives the rate of the first. A bundle is published by its mind, now and then. */
const RESOLVE = { rate: 500, seconds: 6 } as const;
const PUBLISH = { rate: 20, seconds: 5 } as const;
const ROUNDS = 3;

let directory: string;
let service: StartedService;

const idOf = (mind: Mind): string => mindId(mind.address) ?? "";
const bundleOf = (mind: Mind): string =>
  JSON.stringify({ oip: "1", type: "Bundle", mind: mind.address, log: mind.events });

async function publish(mind: Mind): Promise<void> {
  const response = await fetch(`${service.http}/oip/v1/resolve/${idOf(mind)}`, {
    method: "PUT",
    headers: { "content-type": MEDIA_TYPE },
    body: bundleOf(mind),
  });
  await response.arrayBuffer();
  if (response.status !== 202) throw new Error(`a bundle was answered ${response.status}`);
}

beforeAll(async () => {
  directory = mkdtempSync(join(tmpdir(), "oip-resolver-load-"));
  service = await startService(join(repoRoot, "packages", "resolver", "src", "bin.ts"), {
    OIP_RESOLVER_ORIGIN: "https://resolver.example",
    OIP_RESOLVER_HOST: "127.0.0.1",
    OIP_RESOLVER_PORT: "0",
    OIP_RESOLVER_DATABASE: join(directory, "resolver.db"),
    // The load comes from one address. What is measured is the work, not the limit on it.
    OIP_RESOLVER_READ_BURST: "100000",
    OIP_RESOLVER_READ_PER_MINUTE: "1000000",
    OIP_RESOLVER_PUBLISH_BURST: "100000",
    OIP_RESOLVER_PUBLISH_PER_MINUTE: "1000000",
    // `OIP_LOAD_ED25519=portable` measures the service without OpenSSL (ADR-0015, ADR-0016).
    ...(process.env["OIP_LOAD_ED25519"] === undefined
      ? {}
      : { OIP_RESOLVER_ED25519: process.env["OIP_LOAD_ED25519"] }),
  });
});
afterAll(async () => {
  await service.stop();
  rmSync(directory, { recursive: true, force: true });
});

describe("the resolver under load", () => {
  test("resolves a known mind within its budget at 500 requests a second", async () => {
    // Fifty minds, each with a log of three events and a bundle of about 2 kB.
    const minds = Array.from({ length: 50 }, (_, n) =>
      new KeyMind(`known-${n}`).update(10).update(20),
    );
    for (const mind of minds) await publish(mind);
    const paths = minds.map((mind) => `${service.http}/oip/v1/resolve/${idOf(mind)}`);
    const rounds: Round[] = [];
    for (let round = 0; round < ROUNDS; round++) {
      const latencies = await steadyLoad({
        rate: RESOLVE.rate,
        count: RESOLVE.rate * RESOLVE.seconds,
        send: async (n) => {
          const response = await fetch(paths[n % paths.length] ?? "");
          await response.arrayBuffer();
          if (response.status !== 200)
            throw new Error(`a known mind was answered ${response.status}`);
        },
      });
      rounds.push(roundOf(latencies));
    }
    recorded("resolver: resolve a known mind at 500 requests a second", rounds);
    expect(middle(rounds.map((round) => round.p99)), told(rounds)).toBeLessThan(BUDGETS.resolve);
  }, 120_000);

  test("accepts a published bundle within its budget", async () => {
    const count = PUBLISH.rate * PUBLISH.seconds;
    const rounds: Round[] = [];
    for (let round = 0; round < ROUNDS; round++) {
      // Minds the resolver has not seen: a genesis and an update, each with a signature to check.
      const fresh = Array.from({ length: count }, (_, n) =>
        new KeyMind(`fresh-${round}-${n}`).update(10),
      );
      const latencies = await steadyLoad({
        rate: PUBLISH.rate,
        count,
        send: (n) => publish(fresh[n] as Mind),
      });
      rounds.push(roundOf(latencies));
    }
    recorded("resolver: accept a published bundle", rounds);
    expect(middle(rounds.map((round) => round.p99)), told(rounds)).toBeLessThan(BUDGETS.publish);
  }, 120_000);
});
