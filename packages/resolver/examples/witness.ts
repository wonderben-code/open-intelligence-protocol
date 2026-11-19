// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { formatTimestamp, MEDIA_TYPE, mindId } from "@oip/core";
import {
  type Clock,
  Database,
  Log,
  Metrics,
  RateLimiter,
  Shutdown,
  StoredNonces,
} from "@oip/server";

import { RESOLVER_MIGRATIONS, Resolver, resolverApp } from "@oip/resolver";

/**
 * A resolver in memory, asked as a client would ask one over HTTP: a log is
 * published, then another event for the same position of it, and the
 * resolver says what it holds.
 *
 * @param logs - Two logs of one mind that part at their second event, as arrays of events.
 */
export async function example(
  mind: string,
  logs: readonly [readonly unknown[], readonly unknown[]],
  clock: Clock & { at: bigint },
): Promise<string[]> {
  const db = Database.open({ path: ":memory:" }, RESOLVER_MIGRATIONS, clock);
  const log = new Log({ service: "resolver", clock, sink: () => undefined });
  const limiter = (): RateLimiter => new RateLimiter({ burst: 100, perMinute: 600 }, clock);
  const app = resolverApp({
    resolver: new Resolver({ db, clock }),
    clock,
    log,
    metrics: new Metrics(),
    origin: "https://resolver.example",
    nonces: new StoredNonces(db),
    authenticatedPublication: false,
    limits: { read: limiter(), publish: limiter() },
    shutdown: new Shutdown({ log }),
    ready: {},
  });
  const path = `/oip/v1/resolve/${mindId(mind) ?? ""}`;
  const ask = (at: string, init?: RequestInit): Promise<Response> =>
    Promise.resolve(app.fetch(new Request(`https://resolver.example${at}`, init), {}));
  const lines: string[] = [];
  for (const events of logs) {
    const response = await ask(path, {
      method: "PUT",
      headers: { "content-type": MEDIA_TYPE },
      body: JSON.stringify({ oip: "1", type: "Bundle", mind, log: events }),
    });
    const answer = (await response.json()) as { added?: number; type?: string };
    lines.push(
      `published at ${formatTimestamp(clock.now())}: ${response.status} ${answer.type ?? `added ${answer.added ?? 0}`}`,
    );
    // An hour passes between the two.
    clock.at += 3_600_000_000_000n;
  }
  const bundle = (await (await ask(path)).json()) as {
    log: unknown[];
    firstSeen: Record<string, string>;
  };
  lines.push(
    `serves ${bundle.log.length} events, the second of them the one it saw first: ${String(
      JSON.stringify(bundle.log[1]) === JSON.stringify(logs[0][1]),
    )}`,
    `first seen: ${Object.values(bundle.firstSeen).join(", ")}`,
  );
  const evidence = (await (await ask(path.replace("/resolve/", "/duplicity/"))).json()) as {
    pairs: unknown[];
  };
  lines.push(`pairs of conflicting events held as evidence: ${evidence.pairs.length}`);
  db.close();
  return lines;
}
