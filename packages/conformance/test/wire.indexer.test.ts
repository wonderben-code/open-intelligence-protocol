// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The Indexer profile over the wire, run against the reference indexer on a socket of this machine. */

import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { bytesToBase64url, contentId, formatTimestamp, type JsonObject } from "@oip/core";
import { type Running, start } from "@oip/indexer";
import { clause } from "@oip/testkit";
import { KeyMind } from "@oip/testkit/minds";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { indexerProfile, type WatchedInbox, type WireReport } from "../src/index.ts";
import {
  answered,
  type Asked,
  type Fault,
  failed,
  faulty,
  notPassed,
  rewritten,
} from "./wire-faults.ts";

const ORIGIN = "https://indexer.example";
const INBOX = "https://inbox.example/oip";

/** The indexer's own mind. Its key is made from its name by the test kit: a fixture, and no secret. */
const ian = new KeyMind("ian");
const keyOfIan = bytesToBase64url(createHash("sha256").update("ian/operational/0").digest());

let directory: string;
let running: Running[];
let target: string;
/** What the indexer posted to the inbox the suite watches. */
let posted: JsonObject[];

beforeAll(async () => {
  directory = mkdtempSync(join(tmpdir(), "oip-wire-indexer-"));
  posted = [];
  const file = (name: string, content: string, mode: number): string => {
    const path = join(directory, name);
    writeFileSync(path, content, { mode });
    chmodSync(path, mode);
    return path;
  };
  const bundle = { oip: "1", type: "Bundle", mind: ian.address, log: ian.events };
  const service = await start(
    {
      OIP_INDEXER_ORIGIN: ORIGIN,
      OIP_INDEXER_HOST: "127.0.0.1",
      OIP_INDEXER_PORT: "0",
      OIP_INDEXER_DATABASE: join(directory, "indexer.db"),
      OIP_INDEXER_BUNDLE_FILE: file("bundle.json", JSON.stringify(bundle), 0o644),
      OIP_INDEXER_KEY_FILE: file("key", `${keyOfIan}\n`, 0o600),
      // Every run of the suite is one address: the limits are not what is tested here.
      OIP_INDEXER_QUERY_BURST: "100000",
      OIP_INDEXER_SUBMIT_BURST: "100000",
      OIP_INDEXER_DELIVER_BURST: "100000",
      OIP_INDEXER_SENDER_BURST: "100000",
    },
    {
      sink: () => undefined,
      post: (url, body) => {
        if (url !== `${INBOX}/inbox`) return Promise.resolve({ status: 404 });
        posted.push(JSON.parse(new TextDecoder().decode(body)) as JsonObject);
        return Promise.resolve({ status: 202 });
      },
    },
  );
  running = [service];
  target = `http://127.0.0.1:${service.port}`;
});
afterAll(async () => {
  for (const service of running) await service.stop("test over");
  rmSync(directory, { recursive: true, force: true });
});

const inbox: WatchedInbox = { endpoint: INBOX, taken: () => posted };

/** The profile run against the indexer with a fault in the way, and what the watched inbox is seen to hold. */
const against = (
  fault: Fault,
  seen: (records: readonly JsonObject[]) => readonly unknown[] = (records) => records,
): Promise<WireReport> =>
  indexerProfile({
    target,
    origin: ORIGIN,
    fetch: faulty(fault),
    timeoutMs: 1500,
    inbox: { endpoint: INBOX, taken: () => seen(posted) },
  });

const outcome = (report: WireReport, id: string): string | undefined =>
  report.checks.find((check) => check.id === `indexer/${id}`)?.outcome;

const isQuery = (asked: Asked): boolean => asked.path === "/oip/v1/query";
const isInbox = (asked: Asked): boolean => asked.path === "/oip/v1/inbox";

/** Asks the indexer a query, as the fault's own question. */
const queried = async (query: unknown): Promise<{ results: unknown[] }> => {
  const response = await fetch(`${target}/oip/v1/query`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(query),
  });
  return (await response.json()) as { results: unknown[] };
};
/** A `QueryResult` for a query, signed with the indexer's key: what an indexer with a fault signs. */
const signed = (query: unknown, results: readonly unknown[]): Response => {
  const created = formatTimestamp(BigInt(Date.now()) * 1_000_000n);
  return answered(
    200,
    ian.sign({ oip: "1", type: "QueryResult", author: ian.address, created, query, results }),
    "application/oip+json",
  );
};
/**
 * An indexer that answers a query with the results of other queries, under
 * its own signature.
 */
const answering = (others: (query: JsonObject) => readonly unknown[] | undefined): Fault => ({
  answer: async (asked, response) => {
    if (!isQuery(asked) || response.status !== 200) return undefined;
    const query = JSON.parse(asked.body) as JsonObject;
    const asks = others(query);
    if (asks === undefined) return undefined;
    const all = new Map<string, unknown>();
    for (const other of asks) {
      for (const found of (await queried(other)).results) {
        all.set((found as { record: string }).record, found);
      }
    }
    return signed(query, [...all.values()]);
  },
});

describe("the Indexer profile over the wire", () => {
  it(`passes against the reference indexer ${clause("L1 18.1", "L1 18.2", "L1 18.3", "L1 18.5")}`, async () => {
    const report = await indexerProfile({ target, origin: ORIGIN, inbox });
    expect(notPassed(report)).toEqual([]);
    expect(report.conforms).toBe(true);
    expect(report.profile).toBe("indexer");
    expect(new Set(report.checks.map((check) => check.id)).size).toBe(report.checks.length);
  });

  it("says what it could not see where it is given no inbox to watch", async () => {
    const report = await indexerProfile({ target, origin: ORIGIN });
    expect(failed(report)).toEqual([]);
    expect(notPassed(report)).toEqual([
      expect.stringMatching(/^indexer\/broker-forwards: skipped: the suite was given no inbox/u),
      expect.stringMatching(/^indexer\/broker-fanout: skipped: /u),
      expect.stringMatching(/^indexer\/broker-once: skipped: /u),
    ]);
    // What was not checked is not said to conform.
    expect(report.conforms).toBe(false);
  });

  it(`passes an indexer that forwards no packets, which an indexer need not ${clause("L1 18.5")}`, async () => {
    const report = await against({
      answer: (asked) =>
        isInbox(asked)
          ? answered(
              404,
              { type: "urn:oip:error:not-found", status: 404 },
              "application/problem+json",
            )
          : undefined,
    });
    expect(failed(report)).toEqual([]);
    expect(report.conforms).toBe(true);
    for (const id of ["broker-not-listed", "broker-forwards", "broker-fanout", "broker-once"]) {
      expect(outcome(report, id)).toBe("not-applicable");
    }
  });

  it("gets the indexer's own log another way where it is told one", async () => {
    const elsewhere = await indexerProfile({
      target,
      origin: ORIGIN,
      inbox,
      fetch: faulty({
        answer: (asked) =>
          asked.path.startsWith("/.well-known/")
            ? answered(
                404,
                { type: "urn:oip:error:not-found", status: 404 },
                "application/problem+json",
              )
            : undefined,
      }),
      bundle: (address) =>
        Promise.resolve({ oip: "1", type: "Bundle", mind: address, log: ian.events }),
    });
    expect(notPassed(elsewhere)).toEqual([]);
    const nowhere = await against({
      answer: (asked) =>
        asked.path.startsWith("/.well-known/")
          ? answered(
              404,
              { type: "urn:oip:error:not-found", status: 404 },
              "application/problem+json",
            )
          : undefined,
    });
    expect(outcome(nowhere, "query-signed")).toBe("skipped");
    expect(outcome(nowhere, "broker-forwards")).toBe("skipped");
    expect(nowhere.conforms).toBe(false);
  });
});

describe.concurrent("an indexer with a fault fails the checks that the fault breaks", () => {
  it(`one that answers a submission 200, or says what it refused in a form of its own ${clause("L1 18.1")}`, async () => {
    const ok = await against({
      answer: (asked, response) =>
        asked.path === "/oip/v1/submit" && response.status === 202
          ? answered(200, { taken: 0 })
          : undefined,
    });
    expect(failed(ok)).toEqual(expect.arrayContaining(["submit"]));
    expect(outcome(ok, "query")).toBe("skipped");
    for (const body of [{ refused: [{ record: 3 }] }, { taken: -1 }]) {
      const report = await against({
        answer: (asked, response) =>
          asked.path === "/oip/v1/submit" && response.status === 202
            ? answered(202, body)
            : undefined,
      });
      expect(failed(report)).toEqual(["submit"]);
    }
  });

  it(`one whose result is not signed, or was changed after it was signed ${clause("L1 18.3")}`, async () => {
    const unsigned = await against({
      answer: (asked, response) =>
        isQuery(asked) && response.status === 200
          ? rewritten(response, ({ proof: _, ...result }) => result)
          : undefined,
    });
    expect(failed(unsigned)).toEqual(["query-signed"]);
    expect(outcome(unsigned, "broker-forwards")).toBe("skipped");
    const changed = await against({
      answer: (asked, response) =>
        isQuery(asked) && response.status === 200
          ? rewritten(response, (result) => ({ ...result, created: "2026-01-01T00:00:00Z" }))
          : undefined,
    });
    expect(failed(changed)).toEqual(["query-signed"]);
  });

  it(`one whose result has not the form of a QueryResult ${clause("L1 18.3")}`, async () => {
    const forms: ((result: Record<string, unknown>) => unknown)[] = [
      (result) => ({ ...result, query: { want: "another" } }),
      (result) => ({ ...result, author: "the indexer" }),
      (result) => ({ ...result, created: "today" }),
      (result) => ({ ...result, results: {} }),
      (result) => ({ ...result, results: [{ mind: ian.address }] }),
      ...[1, "1.5", "-0.1", "high"].map((score) => (result: Record<string, unknown>) => ({
        ...result,
        results: (result["results"] as object[]).map((found) => ({ ...found, score })),
      })),
      (result) => ({
        ...result,
        results: (result["results"] as object[]).map((found) => ({ ...found, hints: "here" })),
      }),
      (result) => ({
        ...result,
        results: (result["results"] as object[]).map((found) => ({ ...found, capability: 1 })),
      }),
    ];
    for (const form of forms) {
      const report = await against({
        answer: (asked, response) =>
          isQuery(asked) && response.status === 200 ? rewritten(response, form) : undefined,
      });
      expect(failed(report)).toEqual(expect.arrayContaining(["query"]));
    }
  });

  it(`one that finds nothing ${clause("L1 18.1", "L1 18.2")}`, async () => {
    const report = await against(answering(() => []));
    expect(failed(report)).toEqual([
      "query-finds",
      "query-kinds",
      "query-tags",
      "query-verified",
      "query-limit",
    ]);
  });

  it(`one that searches every kind whatever a query names ${clause("L1 18.2")}`, async () => {
    const report = await against(
      answering(({ kinds: _, ...query }) => [
        { ...query, kinds: ["Participant", "Offer", "Intent"] },
      ]),
    );
    expect(failed(report)).toEqual(["query-finds", "query-kinds"]);
  });

  it(`one that names another mind for a record ${clause("L1 18.3")}`, async () => {
    const report = await against({
      answer: async (asked, response) => {
        if (!isQuery(asked) || response.status !== 200) return undefined;
        const result = (await response.json()) as { query: unknown; results: object[] };
        return signed(
          result.query,
          result.results.map((found) => ({ ...found, mind: ian.address })),
        );
      },
    });
    expect(failed(report)).toEqual(expect.arrayContaining(["query-finds"]));
  });

  it(`one that reads a tag prefix as any tag that starts alike ${clause("L1 18.2")}`, async () => {
    const report = await against(
      answering((query) => {
        const tags = query["tags"] as string[] | undefined;
        const [first] = tags ?? [];
        if (!first?.endsWith("/*")) return undefined;
        const stem = first.slice(0, -2);
        return [query, { tags: [stem] }, { tags: [`${stem}x`] }];
      }),
    );
    expect(failed(report)).toEqual(["query-tags"]);
  });

  it(`one that matches any tag of a query and not every one ${clause("L1 18.2")}`, async () => {
    const report = await against(
      answering((query) => {
        const tags = query["tags"] as string[] | undefined;
        return tags === undefined || tags.length < 2
          ? undefined
          : tags.map((tag) => ({ tags: [tag] }));
      }),
    );
    expect(failed(report)).toEqual(["query-tags"]);
  });

  it(`one that lists what it was sent without verifying it ${clause("L1 18.1")}`, async () => {
    // Every Participant record submitted, whoever signed it.
    const sent: { mind: string; record: string; text: string }[] = [];
    const report = await against({
      answer: (asked, response) => {
        if (asked.path === "/oip/v1/submit") {
          const { records } = JSON.parse(asked.body) as { records?: unknown };
          for (const record of Array.isArray(records) ? (records as JsonObject[]) : []) {
            if (record["type"] !== "Participant") continue;
            sent.push({
              mind: record["author"] as string,
              record: contentId(record),
              text: JSON.stringify(record),
            });
          }
          return undefined;
        }
        if (!isQuery(asked) || response.status !== 200) return undefined;
        const query = JSON.parse(asked.body) as { want?: string; tags?: unknown };
        if (query.want === undefined || query.tags !== undefined) return undefined;
        const { want } = query;
        return signed(
          query,
          sent
            .filter((record) => record.text.includes(want))
            .map(({ mind, record }) => ({ mind, record, score: "1", hints: [] })),
        );
      },
    });
    expect(failed(report)).toEqual(expect.arrayContaining(["query-verified"]));
  });

  it(`one that weighs no constraints and no evidence, and answers all the same ${clause("L1 18.2")}`, async () => {
    const report = await against(
      answering(({ constraints, evidence, ...query }) =>
        constraints === undefined && evidence === undefined ? undefined : [query],
      ),
    );
    expect(failed(report)).toEqual(["query-unchecked"]);
  });

  it(`one that takes no notice of a limit ${clause("L1 18.2")}`, async () => {
    const report = await against({
      ...answering(({ limit, ...query }) => (limit === undefined ? undefined : [query])),
      ask: (asked) =>
        isQuery(asked) && asked.body.includes('"limit":101')
          ? { body: asked.body.replace('"limit":101', '"limit":100') }
          : undefined,
    });
    expect(failed(report)).toEqual(["query-limit"]);
    const large = await against({
      ask: (asked) =>
        isQuery(asked) && asked.body.includes('"limit":101')
          ? { body: asked.body.replace('"limit":101', '"limit":100') }
          : undefined,
      answer: async (asked, response) =>
        isQuery(asked) && asked.body.includes('"limit":100') && response.status === 200
          ? signed(
              JSON.parse(asked.body.replace('"limit":100', '"limit":101')),
              ((await response.json()) as { results: unknown[] }).results,
            )
          : undefined,
    });
    expect(failed(large)).toEqual(["query-limit"]);
  });

  it(`one that answers what is no query and takes what is no submission ${clause("core 10.2")}`, async () => {
    const report = await against({
      answer: (asked, response) => {
        if (response.status !== 400) return undefined;
        if (isQuery(asked) && !asked.body.includes('"limit"')) return signed({}, []);
        return asked.path === "/oip/v1/submit" ? answered(202, { taken: 0 }) : undefined;
      },
    });
    expect(failed(report)).toEqual(["malformed"]);
  });

  it(`one that forwards a packet that names another broker ${clause("L1 18.5")}`, async () => {
    const report = await against({
      answer: (asked, response) =>
        isInbox(asked) && response.status >= 400 ? answered(202, { stored: true }) : undefined,
    });
    expect(failed(report)).toEqual(["broker-not-listed"]);
    expect(outcome(report, "broker-forwards")).toBe("skipped");
  });

  it(`one that does not say it stored a packet, or says it goes to more minds than it may ${clause("L1 18.5")}`, async () => {
    for (const body of [
      { forwarding: 2 },
      { stored: true, forwarding: 3 },
      { stored: true, forwarding: "two" },
    ]) {
      const report = await against({
        answer: (asked, response) =>
          isInbox(asked) && response.status === 202 ? answered(202, body) : undefined,
      });
      expect(failed(report)).toEqual(["broker-forwards"]);
    }
  });

  it(`one that forwards nothing, or what it forwards is not as 18.5 says ${clause("L1 18.5")}`, async () => {
    const wrong: ((record: JsonObject) => unknown)[] = [
      (record) => ({ ...record, broker: "did:oip:another" }),
      (record) => ({ ...record, packet: { ...(record["packet"] as JsonObject), hints: {} } }),
      ({ created: _, ...record }) => record,
      (record) => ({ ...record, to: (record["packet"] as JsonObject)["from"] }),
      ({ proof: _, ...record }) => record,
      (record) => ({ ...record, oip: "2" }),
    ];
    const nothing = await against({}, () => []);
    expect(failed(nothing)).toEqual(["broker-forwards"]);
    for (const change of wrong) {
      const report = await against({}, (records) =>
        // The packet is the same packet, so the record is still one for it.
        records.map((record) => {
          const changed = change(record) as JsonObject;
          return contentId(changed["packet"]) === contentId(record["packet"])
            ? changed
            : { ...changed, packet: record["packet"], hint: "changed" };
        }),
      );
      expect(failed(report)).toEqual(expect.arrayContaining(["broker-forwards"]));
    }
  });

  it(`one that forwards a packet to more minds than maxFanout, or to one mind twice ${clause("L1 18.5")}`, async () => {
    /**
     * A run in which the inbox is seen to hold something else once the suite
     * has judged what was forwarded: it has then asked for the indexer's log
     * twice, once for each record, since its packet was taken.
     */
    const afterwards = (change: (records: readonly JsonObject[]) => unknown[]) => {
      let judged: number | undefined;
      return against(
        {
          answer: (asked, response) => {
            if (isInbox(asked) && response.status === 202) judged ??= 0;
            else if (asked.path.startsWith("/.well-known/") && judged !== undefined) judged += 1;
            return undefined;
          },
        },
        (records) => ((judged ?? 0) >= 2 ? change(records) : records),
      );
    };
    const more = await afterwards((records) => [
      ...records,
      ...records.map((record) => ({ ...record, to: "did:oip:one-more" })),
    ]);
    expect(failed(more)).toEqual(["broker-fanout"]);
    const twice = await afterwards((records) => {
      // One record of each packet, twice: as many as maxFanout allows, to one mind.
      const one = new Map(records.map((record) => [contentId(record["packet"] as object), record]));
      return [...one.values(), ...one.values()];
    });
    expect(failed(twice)).toEqual(["broker-fanout"]);
  });

  it(`one that forwards a packet again, or answers it otherwise the second time ${clause("L1 18.5")}`, async () => {
    const delivered = new Set<string>();
    const otherwise = await against({
      answer: (asked, response) => {
        if (!isInbox(asked) || response.status !== 202) return undefined;
        if (delivered.has(asked.body)) return answered(202, { stored: true, forwarding: 0 });
        delivered.add(asked.body);
        return undefined;
      },
    });
    expect(failed(otherwise)).toEqual(["broker-once"]);
    // After the packet has come twice, the inbox holds each of its records twice.
    const times = new Map<string, number>();
    const again = await against(
      {
        answer: (asked) => {
          if (isInbox(asked)) times.set(asked.body, (times.get(asked.body) ?? 0) + 1);
          return undefined;
        },
      },
      (records) =>
        records.flatMap((record) =>
          [...times].some(
            ([body, count]) =>
              count > 1 &&
              contentId(JSON.parse(body) as object) === contentId(record["packet"]),
          )
            ? [record, record]
            : [record],
        ),
    );
    expect(failed(again)).toEqual(["broker-once"]);
  });
});
