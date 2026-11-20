// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The indexer's HTTP interface, asked anything at all. Whatever arrives,
 * the answer is one the indexer means: a status it gives on purpose, and
 * for an error the problem details of core 10.2. Nothing fails unseen, and
 * nothing of the indexer's key is in an answer or in its log.
 *
 * `OIP_FUZZ_RUNS` sets the length of the campaign.
 */

import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { bytesToBase64url, bytesToHex, MEDIA_TYPE, mindId } from "@oip/core";
import { Database, Log, LogArchive, Metrics, RateLimiter, Shutdown } from "@oip/server";
import { clause } from "@oip/testkit";
import {
  anyRequest,
  campaign,
  campaignTimeout,
  requestOf,
  type Seed,
  Statuses,
  wrongWith,
} from "@oip/testkit/http-fuzz";
import { at, intentBy, KeyMind, locationBy, type Mind, T } from "@oip/testkit/minds";
import fc from "fast-check";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { Broker, Indexer, INDEXER_MIGRATIONS, indexerApp } from "../src/index.ts";

let directory: string;
let db: Database;
let lines: string[];
const clock = { now: () => at(110) };

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "oip-indexer-fuzz-"));
  db = Database.open(
    { path: join(directory, "indexer.db"), durable: false },
    INDEXER_MIGRATIONS,
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

describe(`${clause("core 10.2")} the indexer, asked anything at all`, () => {
  it(
    "answers as it means to, fails at nothing, and says nothing of its key",
    async () => {
      const ian: Mind = new KeyMind("ian");
      const ada: Mind = new KeyMind("ada");
      const bob: Mind = new KeyMind("bob");
      const eve: Mind = new KeyMind("eve");
      // The private key the test kit makes for Ian from his name: a fixture, and here the
      // thing that must be nowhere but in the signer.
      const seed = createHash("sha256").update("ian/operational/0").digest();
      const log = new Log({ service: "indexer", clock, sink: (line) => lines.push(line) });
      const metrics = new Metrics();
      const archive = new LogArchive({ db, clock });
      archive.publish(idOf(ian), bundleOf(ian) as never);
      const indexer = new Indexer({
        db,
        archive,
        clock,
        address: ian.address,
        signer: ian.operational(),
      });
      const generous = (): RateLimiter => new RateLimiter({ burst: 1e6, perMinute: 1e6 }, clock);
      const posted: string[] = [];
      const broker = new Broker({
        indexer,
        archive,
        log,
        metrics,
        post: (url) => {
          posted.push(url);
          return Promise.resolve({ status: 202 });
        },
        perSender: generous(),
      });
      const app = indexerApp({
        indexer,
        broker,
        archive,
        clock,
        log,
        metrics,
        limits: { query: generous(), submit: generous(), deliver: generous() },
        shutdown: new Shutdown({ log }),
        ready: { database: () => true },
      });

      const profile = (mind: Mind, name: string, summary: string, signer: Mind = mind): object =>
        signer.sign({
          oip: "1",
          type: "Participant",
          author: mind.address,
          created: T(100),
          name,
          kind: "agent",
          capabilities: [{ id: "work", summary, tags: ["oasf:nlp/translation", "lang:en"] }],
        });
      const offer = ada.sign({
        oip: "1",
        type: "Offer",
        author: ada.address,
        created: T(100),
        provides: "Translation of leases",
        terms: { summary: "By the hour." },
      });
      const located = bundleOf(bob, { location: bob.sign(locationBy(bob, 100)) });
      const records = [
        bundleOf(ada),
        located,
        profile(ada, "Ada", "Translates leases"),
        profile(bob, "Bob", "Translates contracts"),
        profile(bob, "Not Bob", "Bakes", ada),
        offer,
        ada.sign(intentBy(ada, 100)),
      ];
      const packet = (to: object, n: number): object =>
        ada.sign({
          oip: "1",
          type: "Packet",
          from: ada.address,
          to,
          created: T(100),
          expires: T(1900),
          nonce: `nonce-${String(n).padStart(4, "0")}`,
          purpose: { verb: "request" },
          content: { mediaType: "text/plain", body: "Who translates?" },
        });
      const json = [["content-type", "application/json"]] as const;
      const record = [["content-type", MEDIA_TYPE]] as const;
      const seeds: Seed[] = [
        { method: "POST", path: "/oip/v1/submit", headers: json, json: { records } },
        {
          method: "POST",
          path: "/oip/v1/submit",
          headers: json,
          json: { records: [bundleOf(eve)] },
        },
        {
          method: "POST",
          path: "/oip/v1/query",
          headers: json,
          json: { want: "translates leases" },
        },
        {
          method: "POST",
          path: "/oip/v1/query",
          headers: json,
          json: {
            want: "translate",
            tags: ["oasf:nlp/*", "lang:en"],
            kinds: ["Participant", "Offer"],
            limit: 5,
          },
        },
        {
          method: "POST",
          path: "/oip/v1/query",
          headers: json,
          json: { want: "lease", constraints: { maxPrice: "10" }, evidence: { minReceipts: 2 } },
        },
        {
          method: "POST",
          path: "/oip/v1/inbox",
          headers: record,
          json: packet({ query: { want: "translates" }, brokers: [ian.address], maxFanout: 2 }, 1),
        },
        {
          method: "POST",
          path: "/oip/v1/inbox",
          headers: record,
          json: packet({ query: { want: "contracts" } }, 2),
        },
        {
          method: "POST",
          path: "/oip/v1/inbox",
          headers: record,
          json: packet({ query: { want: "leases" }, brokers: [eve.address] }, 3),
        },
        { method: "GET", path: `/.well-known/oip/mind/${idOf(ian)}` },
        { method: "GET", path: `/.well-known/oip/mind/${idOf(ada)}` },
        { method: "GET", path: "/healthz" },
        { method: "GET", path: "/readyz" },
        { method: "GET", path: "/metrics" },
        { method: "OPTIONS", path: "/oip/v1/query" },
      ];
      const segments = [idOf(ian), idOf(ada), "submit", "query", "inbox", "oip", "v1"];
      const answers: string[] = [];

      // What the campaign starts from is there: the records are listed before anything else is asked.
      expect(indexer.submit(records).taken).toBe(6);
      const statuses = new Statuses();
      await fc.assert(
        fc.asyncProperty(anyRequest({ seeds, segments }), async (fuzzed) => {
          const request = requestOf("https://indexer.example", fuzzed);
          if (request === undefined) return;
          const response = await app.fetch(request, { address: "203.0.113.7" });
          statuses.note(response.status);
          answers.push(await response.clone().text());
          expect(
            await wrongWith(response, fuzzed.method),
            `${fuzzed.method} ${fuzzed.path}`,
          ).toEqual([]);
        }),
        campaign(600),
      );
      // The campaign went deep: it was taken, refused, forbidden and not found.
      expect(statuses.seen).toEqual(expect.arrayContaining([200, 202, 204, 400, 404, 415]));
      await broker.idle();
      expect(
        lines
          .map((line) => JSON.parse(line) as { level: string })
          .filter((line) => line.level === "error"),
      ).toEqual([]);
      // The key is in no answer and in no line of the log, in any of the ways bytes are written.
      for (const form of [bytesToBase64url(seed), bytesToHex(seed), seed.toString("base64")]) {
        expect(answers.some((text) => text.includes(form))).toBe(false);
        expect(lines.some((line) => line.includes(form))).toBe(false);
      }
      // The indexer forwards only to where a location record it verified says: Bob's endpoint.
      expect(new Set(posted)).toEqual(
        new Set(posted.filter((url) => url.startsWith("https://mind.example/oip/"))),
      );
      // A profile that its author did not sign was never listed.
      const found = indexer.query({ want: "bakes" }) as { results: unknown[] };
      expect(found.results).toEqual([]);
    },
    campaignTimeout(600),
  );
});
