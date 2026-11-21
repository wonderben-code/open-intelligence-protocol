// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The resolver's HTTP interface, asked anything at all. Whatever arrives,
 * the answer is one the resolver means: a status it gives on purpose, and
 * for an error the problem details of core 10.2. Nothing fails unseen.
 *
 * `OIP_FUZZ_RUNS` sets the length of the campaign.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { formatKeyRef, MEDIA_TYPE, mindId, utf8 } from "@oip/core";
import { signRequest } from "@oip/net";
import {
  Database,
  Log,
  LogArchive,
  Metrics,
  RateLimiter,
  Shutdown,
  StoredNonces,
} from "@oip/server";
import { clause } from "@oip/testkit";
import {
  anyRequest,
  campaign as campaignOf,
  campaignTimeout,
  requestOf,
  type Seed,
  Statuses,
  wrongWith,
} from "@oip/testkit/http-fuzz";
import { at, KeyMind, locationBy, type Mind } from "@oip/testkit/minds";
import fc from "fast-check";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { RESOLVER_MIGRATIONS, resolverApp } from "../src/index.ts";

const ORIGIN = "https://resolver.example";

let directory: string;
let db: Database;
let lines: Record<string, unknown>[];
const clock = { now: () => at(110) };

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "oip-resolver-fuzz-"));
  db = Database.open(
    { path: join(directory, "resolver.db"), durable: false },
    RESOLVER_MIGRATIONS,
    clock,
  );
  lines = [];
});
afterEach(() => {
  db.close();
  rmSync(directory, { recursive: true, force: true });
});

const idOf = (mind: Mind): string => mindId(mind.address) ?? "";
const bundleOf = (mind: Mind, more: object = {}): object => ({
  oip: "1",
  type: "Bundle",
  mind: mind.address,
  log: mind.events,
  ...more,
});

/** The resolver's interface, as a function from a request to a response. */
function service(authenticatedPublication: boolean) {
  const log = new Log({
    service: "resolver",
    clock,
    sink: (line) => lines.push(JSON.parse(line) as Record<string, unknown>),
  });
  const generous = (): RateLimiter => new RateLimiter({ burst: 1e6, perMinute: 1e6 }, clock);
  const archive = new LogArchive({ db, clock });
  const app = resolverApp({
    resolver: archive,
    clock,
    log,
    metrics: new Metrics(),
    origin: ORIGIN,
    nonces: new StoredNonces(db),
    authenticatedPublication,
    limits: { read: generous(), publish: generous() },
    shutdown: new Shutdown({ log }),
    ready: { database: () => true },
  });
  return { app, archive };
}

/** A campaign against a resolver that holds two minds, one of them duplicitous. */
async function campaign(authenticatedPublication: boolean): Promise<number[]> {
  const statuses = new Statuses();
  const ada = new KeyMind("ada").update(10);
  const bob = new KeyMind("bob");
  const twin = new KeyMind("bob").update(20);
  bob.update(30);
  const eve = new KeyMind("eve");
  const { app, archive } = service(authenticatedPublication);
  for (const mind of [ada, bob, twin]) archive.publish(idOf(mind), bundleOf(mind) as never);
  let nonce = 0;
  /** A publication signed by a mind, as 13.3 asks. */
  const signed = async (mind: Mind, bundle: object, by: Mind = mind): Promise<Seed> => {
    const path = `/oip/v1/resolve/${idOf(mind)}`;
    const headers: [string, string][] = [["content-type", MEDIA_TYPE]];
    const added = await signRequest(
      { method: "PUT", url: `${ORIGIN}${path}`, headers, body: utf8(JSON.stringify(bundle)) },
      {
        keyRef: formatKeyRef(by.address, by.versionId(), by.operational().publicKey),
        created: clock.now(),
        nonce: `fuzz-nonce-${++nonce}`,
      },
      by.operational(),
    );
    return { method: "PUT", path, headers: [...headers, ...added], json: bundle };
  };
  const located = bundleOf(ada, { location: ada.sign(locationBy(ada, 100)) });
  const seeds: Seed[] = [
    { method: "GET", path: `/oip/v1/resolve/${idOf(ada)}` },
    { method: "GET", path: `/oip/v1/resolve/${idOf(eve)}` },
    { method: "GET", path: `/oip/v1/duplicity/${idOf(bob)}` },
    { method: "GET", path: `/oip/v1/duplicity/${idOf(ada)}` },
    { method: "GET", path: "/oip/v1/stream?since=1" },
    { method: "GET", path: "/oip/v1/stream", headers: [["last-event-id", "2"]] },
    { method: "GET", path: "/healthz" },
    { method: "GET", path: "/readyz" },
    { method: "GET", path: "/metrics" },
    { method: "OPTIONS", path: `/oip/v1/resolve/${idOf(ada)}` },
    {
      method: "PUT",
      path: `/oip/v1/resolve/${idOf(ada)}`,
      headers: [["content-type", MEDIA_TYPE]],
      json: bundleOf(ada),
    },
    {
      method: "PUT",
      path: `/oip/v1/resolve/${idOf(ada)}`,
      headers: [["content-type", MEDIA_TYPE]],
      json: located,
    },
    {
      method: "PUT",
      path: `/oip/v1/resolve/${idOf(eve)}`,
      headers: [["content-type", MEDIA_TYPE]],
      json: bundleOf(eve),
    },
    await signed(ada, located),
    await signed(eve, bundleOf(eve)),
    await signed(eve, bundleOf(eve), ada),
  ];
  const segments = [idOf(ada), idOf(bob), idOf(eve), "resolve", "duplicity", "stream", "oip", "v1"];
  await fc.assert(
    fc.asyncProperty(anyRequest({ seeds, segments }), async (fuzzed) => {
      const request = requestOf("http://10.0.0.7:8080", fuzzed);
      if (request === undefined) return;
      const response = await app.fetch(request, { address: "203.0.113.7" });
      statuses.note(response.status);
      expect(await wrongWith(response, fuzzed.method), `${fuzzed.method} ${fuzzed.path}`).toEqual(
        [],
      );
    }),
    campaignOf(400),
  );
  // Nothing failed in a way the resolver did not expect, and what it holds still verifies.
  expect(lines.filter((line) => line["level"] === "error")).toEqual([]);
  expect(archive.resolve(idOf(ada))?.log.length).toBeGreaterThanOrEqual(2);
  expect(archive.resolve(idOf(bob))?.log).toHaveLength(2);
  return statuses.seen;
}

describe(`${clause("core 10.2")} the resolver, asked anything at all`, () => {
  it(
    "answers as it means to, and fails at nothing",
    async () => {
      // The campaign went deep: bundles were taken, refused and not found, and minds were served.
      expect(await campaign(false)).toEqual(expect.arrayContaining([200, 202, 204, 400, 404, 415]));
    },
    campaignTimeout(400),
  );

  it(
    "does the same where publication must be signed",
    async () => {
      expect(await campaign(true)).toEqual(expect.arrayContaining([200, 202, 400, 401, 404]));
    },
    campaignTimeout(400),
  );
});
