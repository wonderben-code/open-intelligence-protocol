// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { type SyncSigner } from "@oip/core";
import { judgeRecord } from "@oip/identity";
import { type Clock, Database, Log, LogArchive, Metrics, RateLimiter, Shutdown } from "@oip/server";

import { Broker, Indexer, INDEXER_MIGRATIONS, indexerApp } from "@oip/indexer";

const ORIGIN = "https://indexer.example";

/**
 * An indexer in memory, asked as its clients would ask one over HTTP.
 * Records are submitted, a capability query is answered, and the answer is
 * checked to be the indexer's own.
 *
 * @param own - The indexer's own mind: its address, its `Bundle`, and an operational key of it.
 * @param records - What is submitted: the `Bundle`s of some minds, and their profiles.
 * @param query - A capability query (Layer 1, 18.2).
 */
export async function example(
  own: { readonly address: string; readonly bundle: unknown; readonly signer: SyncSigner },
  records: readonly unknown[],
  query: unknown,
  clock: Clock,
): Promise<string[]> {
  const db = Database.open({ path: ":memory:" }, INDEXER_MIGRATIONS, clock);
  const log = new Log({ service: "indexer", clock, sink: () => undefined });
  const metrics = new Metrics();
  const archive = new LogArchive({ db, clock });
  const limiter = (): RateLimiter => new RateLimiter({ burst: 100, perMinute: 600 }, clock);
  // The indexer holds its own log, as it holds any: what verifies of it.
  archive.publish(own.address.slice("did:oip:".length), own.bundle as never);
  const indexer = new Indexer({ db, archive, clock, address: own.address, signer: own.signer });
  const app = indexerApp({
    indexer,
    // This example forwards nothing: its broker has nowhere to post.
    broker: new Broker({
      indexer,
      archive,
      log,
      metrics,
      post: () => Promise.resolve({ status: 503 }),
      perSender: limiter(),
    }),
    archive,
    clock,
    log,
    metrics,
    limits: { query: limiter(), submit: limiter(), deliver: limiter() },
    shutdown: new Shutdown({ log }),
    ready: {},
  });
  const post = (path: string, body: unknown): Promise<Response> =>
    Promise.resolve(
      app.fetch(
        new Request(`${ORIGIN}${path}`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        }),
        {},
      ),
    );

  const lines: string[] = [];
  const submitted = await post("/oip/v1/submit", { records });
  const { taken, refused } = (await submitted.json()) as { taken: number; refused: unknown[] };
  lines.push(`submitted: ${submitted.status}, ${taken} taken, ${refused.length} refused`);

  const answered = await post("/oip/v1/query", query);
  const result = (await answered.json()) as {
    author: string;
    results: { mind: string; capability?: string; score: string }[];
  };
  // A client verifies the answer's proof, by the log the indexer serves of itself.
  const judged = judgeRecord(result);
  lines.push(
    `answered: ${answered.status}, by the indexer: ${String(result.author === own.address)}, with a proof that verifies: ${String(judged.ok && judged.value.proofs.length === 1)}`,
  );
  for (const [place, found] of result.results.entries()) {
    lines.push(`${place + 1}. ${found.capability ?? "(the profile)"}, score ${found.score}`);
  }
  db.close();
  return lines;
}
