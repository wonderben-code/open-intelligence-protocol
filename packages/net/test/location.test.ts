// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId } from "@oip/core";
import { type IdentityView, type JudgedRecord, judgeRecord } from "@oip/identity";
import type { Location } from "@oip/schema";
import { clause, type JsonObject, readVectors } from "@oip/testkit";
import { at, bookOf, Collective, KeyMind, type Mind, T } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import {
  currentLocation,
  endpointsToTry,
  isStale,
  type KnownEndpoint,
  postUrl,
  webSocketUrl,
} from "../src/index.ts";

type Signed = JsonObject & { proof: JsonObject[] };

/** A location record of a mind, not yet signed. */
const draft = (author: Mind, seq: number, seconds: number, more: JsonObject = {}): JsonObject => ({
  oip: "1",
  type: "Location",
  author: author.address,
  seq,
  created: T(seconds),
  ttl: 900,
  status: "active",
  endpoints: [{ binding: "https", url: "https://ada.example/oip", priority: 10 }],
  ...more,
});

const judged = (record: object): JudgedRecord => {
  const result = judgeRecord(record);
  if (!result.ok) throw new Error(JSON.stringify(result.issues));
  return result.value;
};

/** The current location record of a mind for a verifier that holds these records and the minds' logs. */
function current(mind: Mind, records: readonly object[], minds: readonly Mind[] = [mind]) {
  const view: IdentityView = bookOf(minds, records);
  return currentLocation(
    records.map((record) => judged(record)),
    mind.address,
    view,
  );
}

describe(`${clause("L1 15.2")} the current location record`, () => {
  const ada = new KeyMind("ada");
  const bob = new KeyMind("bob");
  const [one, two, three] = [1, 2, 3].map(
    (seq) => ada.sign(draft(ada, seq, 10 * seq)) as Signed,
  ) as [Signed, Signed, Signed];

  it("is the one with the highest seq, in whatever order the records are held", () => {
    for (const records of [
      [one, two, three],
      [three, one, two],
      [two, three, one, three],
    ]) {
      const found = current(ada, records);
      expect(found?.id).toBe(contentId(three));
      expect(found?.record.seq).toBe(3);
      expect(found?.time).toBe(at(30));
    }
    expect(current(ada, [one])?.id).toBe(contentId(one));
    expect(current(ada, [])).toBeUndefined();
    // A seq may be any integer, and need not go up by one.
    const low = ada.sign(draft(ada, -5, 40)) as Signed;
    const high = ada.sign(draft(ada, 2 ** 40, 5)) as Signed;
    expect(current(ada, [low, one])?.id).toBe(contentId(one));
    expect(current(ada, [three, high, one])?.id).toBe(contentId(high));
  });

  it("is, of two with the highest seq, the one with the lower content ID", () => {
    const pair = ["https://a.example/oip", "https://b.example/oip"].map(
      (url) => ada.sign(draft(ada, 7, 50, { endpoints: [{ binding: "https", url }] })) as Signed,
    );
    const lower = pair.map((record) => contentId(record)).sort()[0];
    for (const records of [pair, pair.toReversed()]) {
      expect(current(ada, [one, ...records])?.id).toBe(lower);
    }
  });

  it("is a location record of that mind, signed by its own authority", () => {
    const bobs = bob.sign(draft(bob, 9, 10)) as Signed;
    // In Ada's name, by Bob.
    const forged = bob.sign(draft(ada, 9, 10)) as Signed;
    const profile = ada.sign({
      oip: "1",
      type: "Participant",
      author: ada.address,
      created: T(10),
      name: "Ada",
      kind: "agent",
    });
    expect(current(ada, [bobs, forged, profile, one], [ada, bob])?.id).toBe(contentId(one));
    expect(current(ada, [bobs, forged, profile], [ada, bob])).toBeUndefined();
    // Bob's record with Ada's signature on it is Bob's record still, and no location of hers.
    const cosigned = ada.sign(draft(bob, 9, 10)) as Signed;
    expect(current(ada, [cosigned, one], [ada, bob])?.id).toBe(contentId(one));
    expect(current(ada, [cosigned], [ada, bob])).toBeUndefined();
    // Not signed at all, as far as the verifier has evidence.
    expect(currentLocation([judged(three)], ada.address, bookOf([ada], []))).toBeUndefined();
  });

  it("is no longer a record signed with a key the mind has removed, however high its seq", () => {
    // A host that held Ada's first key publishes seq 1,000,000. Ada replaces the key and
    // publishes seq 4 with the new one.
    const eve = new KeyMind("eve");
    const hosts = eve.sign(draft(eve, 1_000_000, 20)) as Signed;
    const before = current(eve, [hosts]);
    expect(before?.id).toBe(contentId(hosts));
    eve.update(100, { keys: [{ key: eve.operational(1).publicKey }] });
    const own = eve.sign(draft(eve, 4, 110), { key: 1 }) as Signed;
    expect(current(eve, [hosts, own])?.id).toBe(contentId(own));
    expect(current(eve, [hosts])).toBeUndefined();
  });

  it(`${clause("L1 9.5")} is a collective's while its signers meet the threshold of its latest membership`, () => {
    const [ann, bo, cy] = [new KeyMind("ann"), new KeyMind("bo"), new KeyMind("cy")];
    const club = new Collective("club", [ann, bo, cy], 2, 5).update(6, [ann, bo], { keys: [] });
    const content = draft(club, 1, 10);
    const byTwo = bo.sign(ann.sign(content)) as Signed;
    const byOne = ann.sign(draft(club, 2, 20)) as Signed;
    const minds = [ann, bo, cy, club];
    expect(current(club, [byTwo, byOne], minds)?.id).toBe(contentId(byTwo));
    // Bo leaves. The record that Ann and Bo signed no longer meets the threshold.
    club.update(50, [ann, cy], {
      controller: { members: [ann.address, cy.address], threshold: 2 },
    });
    expect(current(club, [byTwo, byOne], minds)).toBeUndefined();
    const byNew = cy.sign(ann.sign(draft(club, 3, 60))) as Signed;
    expect(current(club, [byTwo, byOne, byNew], minds)?.id).toBe(contentId(byNew));
  });

  it("stands for the location record of the test vectors", () => {
    const cases = (readVectors() as unknown as { cases: Record<string, JsonObject> }).cases;
    const record = judged(cases["location"]!).record as Location;
    expect(endpointsToTry(record).map((endpoint) => endpoint.binding)).toStrictEqual([
      "https",
      "wss",
      "mailbox",
    ]);
    expect(postUrl(endpointsToTry(record)[0]!)).toBe("https://lexis.example/oip/inbox");
    expect(webSocketUrl(endpointsToTry(record)[1]!)).toBe("wss://lexis.example/oip/ws");
  });
});

describe(`${clause("L1 15.2")} a stale location record`, () => {
  const ada = new KeyMind("ada");
  const record = judged(ada.sign(draft(ada, 1, 100, { ttl: 60 }))).record as Location;

  it("is one read later than its created plus its ttl, and not at that moment", () => {
    expect(isStale(record, at(100))).toBe(false);
    expect(isStale(record, at(160))).toBe(false);
    expect(isStale(record, at(160.000000001))).toBe(true);
    expect(isStale(record, at(100_000))).toBe(true);
    // Read before it was made, it is not stale.
    expect(isStale(record, at(0))).toBe(false);
    // The ttl is in seconds, up to a day.
    const day = judged(ada.sign(draft(ada, 2, 100, { ttl: 86_400 }))).record as Location;
    expect(isStale(day, at(86_500))).toBe(false);
    expect(isStale(day, at(86_501))).toBe(true);
  });

  it("is one whose created is no time at all", () => {
    expect(isStale({ ...record, created: "soon" }, at(0))).toBe(true);
  });
});

describe(`${clause("L1 15.1", "L1 15.3")} the endpoints a sender tries`, () => {
  const ada = new KeyMind("ada");
  const endpoint = (binding: string, name: string, priority?: number) => ({
    binding,
    url: `${binding === "wss" ? "wss" : "https"}://${name}.example/oip`,
    ...(priority === undefined ? {} : { priority }),
  });
  const tried = (endpoints: readonly object[], more: JsonObject = {}) =>
    endpointsToTry(
      judged(ada.sign(draft(ada, 1, 10, { endpoints: endpoints, ...more }))).record as Location,
    ).map((found) => found.url.split("//")[1]?.split(".")[0]);

  it("come in priority order, lower first, and as listed where that does not tell", () => {
    expect(
      tried([endpoint("https", "c", 30), endpoint("wss", "a", 10), endpoint("https", "b", 20)]),
    ).toStrictEqual(["a", "b", "c"]);
    expect(
      tried([endpoint("https", "x", 5), endpoint("https", "y", 5), endpoint("wss", "z", 5)]),
    ).toStrictEqual(["x", "y", "z"]);
    // One without a priority comes after those with one, and a priority may be negative.
    expect(
      tried([
        endpoint("https", "none"),
        endpoint("https", "late", 900),
        endpoint("https", "other"),
        endpoint("wss", "first", -1),
      ]),
    ).toStrictEqual(["first", "late", "none", "other"]);
    expect(tried([])).toStrictEqual([]);
  });

  it("leave out an endpoint whose binding has no meaning yet", () => {
    expect(
      tried([
        endpoint("libp2p", "p", 1),
        endpoint("https", "h", 2),
        endpoint("HTTPS", "upper", 1),
        endpoint("", "empty", 1),
      ]),
    ).toStrictEqual(["h"]);
  });

  it("end with the mailboxes, which are all there is to try while the mind is paused", () => {
    const endpoints = [
      endpoint("mailbox", "box", 1),
      endpoint("https", "h", 50),
      endpoint("mailbox", "spare", 0),
      endpoint("wss", "w", 40),
    ];
    expect(tried(endpoints)).toStrictEqual(["w", "h", "spare", "box"]);
    expect(tried(endpoints, { status: "migrating" })).toStrictEqual(["w", "h", "spare", "box"]);
    expect(tried(endpoints, { status: "paused" })).toStrictEqual(["spare", "box"]);
    expect(tried([endpoint("https", "h", 1)], { status: "paused" })).toStrictEqual([]);
  });
});

describe(`${clause("L1 15.1")} what an endpoint's URL means`, () => {
  const endpoint = (binding: KnownEndpoint["binding"], url: string): KnownEndpoint => ({
    binding,
    url,
  });

  it("is a base for the inbox and the WebSocket, for the https binding", () => {
    const base = endpoint("https", "https://ada.example/oip");
    expect(postUrl(base)).toBe("https://ada.example/oip/inbox");
    expect(webSocketUrl(base)).toBe("wss://ada.example/oip/ws");
    // With or without a slash at its end, or a path.
    expect(postUrl(endpoint("https", "https://ada.example/oip/"))).toBe(
      "https://ada.example/oip/inbox",
    );
    expect(postUrl(endpoint("https", "https://ada.example"))).toBe("https://ada.example/inbox");
    expect(webSocketUrl(endpoint("https", "https://ada.example:8443/"))).toBe(
      "wss://ada.example:8443/ws",
    );
  });

  it("is the WebSocket itself for wss, and the mailbox itself for mailbox", () => {
    const socket = endpoint("wss", "wss://ada.example/oip/ws");
    expect(webSocketUrl(socket)).toBe("wss://ada.example/oip/ws");
    expect(postUrl(socket)).toBeUndefined();
    const box = endpoint("mailbox", "https://mailbox.example/oip/mbox/abc");
    expect(postUrl(box)).toBe("https://mailbox.example/oip/mbox/abc");
    expect(webSocketUrl(box)).toBeUndefined();
  });

  it("is no base when it is not an https URL, or has a query or a fragment", () => {
    for (const url of [
      "http://ada.example/oip",
      "https://ada.example/oip?x=1",
      "https://ada.example/oip#top",
      "https://ada.example/o ip",
      "ada.example/oip",
      "https://",
      "",
    ]) {
      expect(postUrl(endpoint("https", url)), url).toBeUndefined();
      expect(webSocketUrl(endpoint("https", url)), url).toBeUndefined();
    }
  });
});
