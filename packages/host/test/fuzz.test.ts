// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The host's HTTP interface, asked anything at all. Whatever arrives, the
 * answer is one the host means: a status it gives on purpose, and for an
 * error the problem details of core 10.2. Nothing fails unseen, and nothing
 * a stranger sends changes what the host serves of a mind.
 *
 * `OIP_FUZZ_RUNS` sets the length of the campaign.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { contentId, formatKeyRef, MEDIA_TYPE, mindId, utf8 } from "@oip/core";
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

import { Host, HOST_MIGRATIONS, hostApp } from "../src/index.ts";

const ORIGIN = "https://host.example";

let directory: string;
let db: Database;
let lines: Record<string, unknown>[];
const clock = { now: () => at(110) };

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "oip-host-fuzz-"));
  db = Database.open({ path: join(directory, "host.db"), durable: false }, HOST_MIGRATIONS, clock);
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

describe(`${clause("core 10.2")} the host, asked anything at all`, () => {
  it(
    "answers as it means to, fails at nothing, and serves what it served",
    async () => {
      // Bob is served. Ada sends to him. Eve is known to nobody, and Zed may be taken on.
      const ada: Mind = new KeyMind("ada");
      const bob: Mind = new KeyMind("bob");
      const eve: Mind = new KeyMind("eve");
      const zed: Mind = new KeyMind("zed");
      const log = new Log({
        service: "host",
        clock,
        sink: (line) => lines.push(JSON.parse(line) as Record<string, unknown>),
      });
      const archive = new LogArchive({ db, clock });
      for (const mind of [ada, bob]) archive.publish(idOf(mind), bundleOf(mind) as never);
      const host = new Host({ db, archive });
      host.adopt(bob.address);
      const generous = (): RateLimiter => new RateLimiter({ burst: 1e6, perMinute: 1e6 }, clock);
      const app = hostApp({
        host,
        archive,
        clock,
        log,
        metrics: new Metrics(),
        origin: ORIGIN,
        nonces: new StoredNonces(db),
        admits: (mind) => mind === zed.address,
        limits: { read: generous(), deliver: generous(), owner: generous() },
        shutdown: new Shutdown({ log }),
        ready: { database: () => true },
      });

      const wellKnown = (mind: Mind, rest = ""): string =>
        `/.well-known/oip/mind/${idOf(mind)}${rest}`;
      const endpoint = (mind: Mind, rest = ""): string => `/oip/v1/minds/${idOf(mind)}${rest}`;
      let nonce = 0;
      /** A request a mind signs for the host's origin (Layer 1, 13.3). */
      const signed = async (
        by: Mind,
        method: string,
        path: string,
        json?: object,
      ): Promise<Seed> => {
        const body = json === undefined ? undefined : utf8(JSON.stringify(json));
        const headers: [string, string][] =
          body === undefined ? [] : [["content-type", MEDIA_TYPE]];
        const added = await signRequest(
          { method, url: `${ORIGIN}${path}`, headers, ...(body === undefined ? {} : { body }) },
          {
            keyRef: formatKeyRef(by.address, by.versionId(), by.operational().publicKey),
            created: clock.now(),
            nonce: `fuzz-nonce-${++nonce}`,
          },
          by.operational(),
        );
        return {
          method,
          path,
          headers: [...headers, ...added],
          ...(json === undefined ? {} : { json }),
        };
      };
      const packet = (from: Mind, to: Mind, n: number): object =>
        from.sign({
          oip: "1",
          type: "Packet",
          from: from.address,
          to: [to.address],
          created: T(100),
          expires: T(3700),
          nonce: `nonce-${String(n).padStart(4, "0")}`,
          purpose: { verb: "inform" },
          content: { mediaType: "text/plain", body: "Hello." },
        });
      const sealed = {
        oip: "1",
        type: "Sealed",
        to: bob.address,
        key: "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
        suite: "hpke-base-x25519-sha256-chacha20poly1305",
        enc: "AAAA",
        ciphertext: "AAAA",
      };
      const intent = bob.sign(intentBy(bob, 100));
      const entry = bob.sign({
        oip: "1",
        type: "Entry",
        author: bob.address,
        seq: 0,
        created: T(100),
        object: contentId(intent),
        objectType: "Intent",
      });
      const page = { oip: "1", type: "FeedPage", mind: bob.address, entries: [entry] };
      const record = [["content-type", MEDIA_TYPE]] as const;

      // What the host serves of Bob before the campaign: a feed, a record and some mail.
      for (const seed of [
        await signed(bob, "PUT", endpoint(bob, `/obj/${contentId(intent)}`), intent),
        await signed(bob, "POST", endpoint(bob, "/feed"), page),
      ]) {
        const request = requestOf("http://10.0.0.7:8080", {
          method: seed.method,
          path: seed.path,
          headers: seed.headers ?? [],
          body: utf8(JSON.stringify(seed.json)),
        });
        if (request === undefined) throw new Error("a seed is a request that can be sent");
        const response = await app.fetch(request, { address: "203.0.113.7" });
        expect(response.status).toBeLessThan(300);
      }
      host.deliver(bob.address, packet(ada, bob, 1) as never);

      const seeds: Seed[] = [
        { method: "GET", path: wellKnown(bob) },
        { method: "GET", path: wellKnown(eve) },
        { method: "GET", path: wellKnown(bob, "/log?after=0&limit=1") },
        { method: "GET", path: wellKnown(bob, "/feed?limit=1") },
        { method: "GET", path: wellKnown(bob, `/obj/${contentId(intent)}`) },
        { method: "GET", path: "/healthz" },
        { method: "GET", path: "/readyz" },
        { method: "GET", path: "/metrics" },
        { method: "OPTIONS", path: endpoint(bob, "/inbox") },
        {
          method: "POST",
          path: endpoint(bob, "/inbox"),
          headers: record,
          json: packet(ada, bob, 2),
        },
        {
          method: "POST",
          path: endpoint(bob, "/inbox"),
          headers: record,
          json: packet(ada, bob, 1),
        },
        {
          method: "POST",
          path: endpoint(bob, "/inbox"),
          headers: record,
          json: packet(eve, bob, 3),
        },
        { method: "POST", path: endpoint(bob, "/inbox"), headers: record, json: sealed },
        {
          method: "POST",
          path: endpoint(eve, "/inbox"),
          headers: record,
          json: packet(ada, eve, 4),
        },
        {
          method: "POST",
          path: endpoint(bob, "/mailbox"),
          headers: record,
          json: packet(ada, bob, 5),
        },
        { method: "POST", path: endpoint(bob, "/mailbox"), headers: record, json: sealed },
        { method: "GET", path: endpoint(bob, "/mailbox") },
        await signed(bob, "GET", endpoint(bob, "/mailbox")),
        await signed(bob, "GET", `${endpoint(bob, "/mailbox")}?after=1`),
        await signed(ada, "GET", endpoint(bob, "/mailbox")),
        await signed(bob, "DELETE", endpoint(bob, "/mailbox/1")),
        await signed(ada, "DELETE", endpoint(bob, "/mailbox/2")),
        await signed(
          bob,
          "PUT",
          endpoint(bob),
          bundleOf(bob, { location: bob.sign(locationBy(bob, 100)) }),
        ),
        await signed(zed, "PUT", endpoint(zed), bundleOf(zed)),
        await signed(eve, "PUT", endpoint(eve), bundleOf(eve)),
        await signed(ada, "PUT", endpoint(bob), bundleOf(bob)),
        await signed(bob, "PUT", endpoint(bob, `/obj/${contentId(intent)}`), intent),
        await signed(bob, "POST", endpoint(bob, "/feed"), page),
      ];
      const segments = [
        idOf(ada),
        idOf(bob),
        idOf(eve),
        contentId(intent),
        "inbox",
        "mailbox",
        "feed",
        "log",
        "obj",
        "minds",
        "1",
      ];
      const served = async (): Promise<unknown> =>
        (await app.fetch(new Request(`http://10.0.0.7:8080${wellKnown(bob)}`), {})).json();
      const before = (await served()) as { log: unknown };

      const statuses = new Statuses();
      await fc.assert(
        fc.asyncProperty(anyRequest({ seeds, segments }), async (fuzzed) => {
          const request = requestOf("http://10.0.0.7:8080", fuzzed);
          if (request === undefined) return;
          const response = await app.fetch(request, { address: "203.0.113.7" });
          statuses.note(response.status);
          expect(
            await wrongWith(response, fuzzed.method),
            `${fuzzed.method} ${fuzzed.path}`,
          ).toEqual([]);
        }),
        campaign(600),
      );
      // The campaign went deep: it was taken, refused, forbidden and not found.
      expect(statuses.seen).toEqual(
        expect.arrayContaining([200, 202, 204, 400, 401, 403, 404, 415]),
      );
      expect(lines.filter((line) => line["level"] === "error")).toEqual([]);
      // Bob's log is his own: nobody else's request changed it.
      expect(((await served()) as { log: unknown }).log).toEqual(before.log);
      // Eve was never taken on, whatever was sent in her name.
      expect(host.hosts(eve.address)).toBe(false);
    },
    campaignTimeout(600),
  );
});
