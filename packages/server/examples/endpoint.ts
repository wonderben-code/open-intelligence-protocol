// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, formatTimestamp, MEDIA_TYPE, OipError } from "@oip/core";
import {
  appendOnly,
  type Clock,
  Database,
  integer,
  RateLimiter,
  readConfig,
  readRecord,
  recordResponse,
  responseFor,
} from "@oip/server";

const SETTINGS = {
  BURST: integer("how many requests one client may send at once", {
    min: 1,
    max: 100,
    fallback: 3,
  }),
  MAX_BYTES: integer("the most bytes of a record that are read", { min: 1, max: 8_388_608 }),
};

/**
 * An endpoint that takes a record and says when it first saw it. It is not
 * a service of the protocol: it shows what `@oip/server` gives one.
 */
export function endpoint(environment: Record<string, string | undefined>, clock: Clock) {
  // Everything wrong with the configuration is said here, and nothing starts.
  const config = readConfig("OIP_EXAMPLE_", SETTINGS, environment);
  const db = Database.open(
    { path: ":memory:" },
    [
      {
        version: 1,
        name: "first sight",
        sql: `CREATE TABLE seen (id TEXT PRIMARY KEY, at INTEGER NOT NULL) STRICT;\n${appendOnly("seen")}`,
      },
    ],
    clock,
  );
  const limiter = new RateLimiter({ burst: config.BURST, perMinute: 60 }, clock);

  return async (request: Request, client: string): Promise<Response> => {
    try {
      const allowed = limiter.take(client);
      if (!allowed.ok) throw new OipError("rate-limited", "too many requests: ask again later");
      // Bounded before it is read, and read by the reader of the JSON profile.
      const id = contentId(await readRecord(request, config.MAX_BYTES));
      const seen = db.transaction(() => {
        // Recorded once. The table lets no row be changed, so the first time stands.
        db.prepare("INSERT OR IGNORE INTO seen (id, at) VALUES (?, ?)").run(id, clock.now());
        return db.prepareWithTimes("SELECT at FROM seen WHERE id = ?").get(id) as { at: bigint };
      });
      return recordResponse({ record: id, firstSeen: formatTimestamp(seen.at) }, 202);
    } catch (error) {
      // An error of the caller's is said in the terms of core 10.2. Any other says nothing.
      return responseFor(error).response;
    }
  };
}

/** What the endpoint answers to a record sent twice, to what is no record, and to one request more than a burst of three. */
export async function example(record: object, clock: Clock & { at: bigint }): Promise<string[]> {
  const handle = endpoint({ OIP_EXAMPLE_MAX_BYTES: "1048576" }, clock);
  const post = (body: string): Request =>
    new Request("https://example.org/records", {
      method: "POST",
      headers: { "content-type": MEDIA_TYPE },
      body,
    });
  const lines: string[] = [];
  const sent = JSON.stringify(record);
  for (const body of [sent, sent, "{", sent, sent]) {
    const response = await handle(post(body), "203.0.113.7");
    const answer = (await response.json()) as { firstSeen?: string; type?: string };
    lines.push(`${response.status} ${answer.firstSeen ?? answer.type ?? ""}`);
    // A minute passes after the first request, and none after that.
    if (lines.length === 1) clock.at += 60_000_000_000n;
  }
  return lines;
}
