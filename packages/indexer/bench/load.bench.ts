// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The indexer under load, as a process of its own, asked over a socket of
 * this machine. BUILD.md 3.8 gives it one budget: a capability query over
 * 100,000 profiles, with a 99th percentile of 100 ms.
 *
 * The index is filled without the indexer: 100,000 signatures would take
 * minutes to check, and what is measured here is a query, which checks
 * none. Each profile has a text of twelve words out of five thousand, some
 * common and most rare, and three tags. A query asks for two words, and
 * one in four also for a tag. The answer is signed, as every answer is.
 *
 * It is measured in three rounds, and the middle is compared. ADR-0015 has
 * what was measured.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { contentId, mindAddress } from "@oip/core";
import { Database, systemClock, systemRandomness } from "@oip/server";
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
import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { INDEXER_MIGRATIONS, IndexStore, init } from "../src/index.ts";

/** The budget of BUILD.md 3.8, in milliseconds at the 99th percentile. */
export const BUDGETS = { query: 100 } as const;

const PROFILES = 100_000;
const WORDS = 5000;
const QUERY = { rate: 50, seconds: 6 } as const;
const ROUNDS = 3;

let directory: string;
let service: StartedService;

/** Numbers that are the same in every run: a generator that is good enough to pick words. */
function numbers(seed: number): () => number {
  let state = seed;
  return () => {
    state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
    return state / 2 ** 32;
  };
}
/** A word of the vocabulary: the squares of a uniform number make a few words common and most rare. */
const word = (random: () => number): string => `w${Math.floor(random() ** 2 * WORDS)}`;
const tag = (random: () => number): string => `oasf:skill-${Math.floor(random() * 200)}`;

beforeAll(async () => {
  directory = mkdtempSync(join(tmpdir(), "oip-indexer-load-"));
  const made = init({
    directory: join(directory, "mind"),
    created: "2026-11-20T00:00:00Z",
    randomness: systemRandomness,
  });
  const path = join(directory, "indexer.db");
  const db = Database.open({ path, durable: false }, INDEXER_MIGRATIONS, systemClock);
  const store = new IndexStore(db);
  const random = numbers(20_261_120);
  const now = systemClock.now();
  db.transaction(() => {
    for (let n = 0; n < PROFILES; n++) {
      store.add(
        {
          mind: mindAddress(contentId({ mind: n })),
          record: contentId({ record: n }),
          kind: "Participant",
          capability: "work",
          text: Array.from({ length: 12 }, () => word(random)).join(" "),
          tags: [tag(random), tag(random), `lang:${n % 2 === 0 ? "en" : "nl"}`],
        },
        now,
      );
    }
  });
  db.close();
  service = await startService(join(repoRoot, "packages", "indexer", "src", "bin.ts"), {
    OIP_INDEXER_ORIGIN: "https://indexer.example",
    OIP_INDEXER_HOST: "127.0.0.1",
    OIP_INDEXER_PORT: "0",
    OIP_INDEXER_DATABASE: path,
    OIP_INDEXER_BUNDLE_FILE: made.bundleFile,
    OIP_INDEXER_KEY_FILE: made.keyFile,
    // The load comes from one address. What is measured is the work, not the limit on it.
    OIP_INDEXER_QUERY_BURST: "100000",
    OIP_INDEXER_QUERY_PER_MINUTE: "1000000",
  });
}, 300_000);
afterAll(async () => {
  await service.stop();
  rmSync(directory, { recursive: true, force: true });
});

describe("the indexer under load", () => {
  test("answers a capability query over 100,000 profiles within its budget", async () => {
    const random = numbers(7);
    const count = QUERY.rate * QUERY.seconds;
    const queries = Array.from({ length: count * ROUNDS }, (_, n) =>
      JSON.stringify({
        want: `${word(random)} ${word(random)}`,
        ...(n % 4 === 0 ? { tags: [tag(random)] } : {}),
      }),
    );
    let found = 0;
    const rounds: Round[] = [];
    for (let round = 0; round < ROUNDS; round++) {
      const latencies = await steadyLoad({
        rate: QUERY.rate,
        count,
        send: async (n) => {
          const response = await fetch(`${service.http}/oip/v1/query`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: queries[round * count + n] ?? "{}",
          });
          const result = (await response.json()) as { results?: unknown[]; proof?: unknown[] };
          if (response.status !== 200 || result.proof?.length !== 1) {
            throw new Error(`a query was answered ${response.status}`);
          }
          found += result.results?.length ?? 0;
        },
      });
      rounds.push(roundOf(latencies));
    }
    // The queries found something: an index that matched nothing would answer fast and prove nothing.
    expect(found).toBeGreaterThan(count * ROUNDS);
    recorded("indexer: a capability query over 100,000 profiles", rounds);
    expect(middle(rounds.map((round) => round.p99)), told(rounds)).toBeLessThan(BUDGETS.query);
  }, 300_000);
});
