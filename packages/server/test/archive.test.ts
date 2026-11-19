// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  contentId,
  type JsonObject,
  mindId,
  OipError,
  parseTimestamp,
  proofDigest,
} from "@oip/core";
import { FirstSeen, verifyLog } from "@oip/identity";
import type { Bundle, Proof } from "@oip/schema";
import { clause } from "@oip/testkit";
import {
  at,
  Collective,
  intentBy,
  KeyMind,
  locationBy,
  type Mind,
  rawSign,
  T,
} from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { ARCHIVE_SQL, Database, LogArchive } from "../src/index.ts";

const MIGRATIONS = [{ version: 1, name: "archive", sql: ARCHIVE_SQL }];

let directory: string;
let db: Database;
/** The clock of the resolver, which a test moves. */
let clock: { at: bigint; now: () => bigint };

const open = (): Database =>
  Database.open({ path: join(directory, "archive.db"), durable: false }, MIGRATIONS, clock);

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "oip-archive-"));
  clock = { at: at(100), now: () => clock.at };
  db = open();
});
afterEach(() => {
  db.close();
  rmSync(directory, { recursive: true, force: true });
});

const idOf = (mind: Mind): string => mindId(mind.address) ?? "";
const bundleOf = (mind: Mind, events: readonly unknown[] = mind.events): Bundle =>
  ({ oip: "1", type: "Bundle", mind: mind.address, log: events }) as unknown as Bundle;
const ids = (events: readonly unknown[]): string[] =>
  events.map((event) => contentId(event as object));
/** The times a bundle gives, by content ID, as instants. */
const seenIn = (bundle: Bundle | undefined): Record<string, bigint | undefined> =>
  Object.fromEntries(
    Object.entries(bundle?.firstSeen ?? {}).map(([id, time]) => [id, parseTimestamp(time)]),
  );

describe(`${clause("L1 17.1", "L1 17.2")} a log published to a resolver`, () => {
  it("is served as it verified, with the time each event was first seen", () => {
    const ada = new KeyMind("ada").update(10);
    const resolver = new LogArchive({ db, clock });
    expect(resolver.resolve(idOf(ada))).toBeUndefined();
    expect(resolver.publish(idOf(ada), bundleOf(ada))).toStrictEqual({
      outcome: "merged",
      added: 2,
    });
    const bundle = resolver.resolve(idOf(ada));
    expect(bundle).toMatchObject({ oip: "1", type: "Bundle", mind: ada.address });
    expect(bundle?.log).toStrictEqual(ada.events);
    expect(seenIn(bundle)).toStrictEqual(
      Object.fromEntries(ids(ada.events).map((id) => [id, at(100)])),
    );
    // A client that trusts the resolver's times verifies the log with them.
    const evidence = new FirstSeen();
    for (const [id, time] of Object.entries(seenIn(bundle))) evidence.sawEvent(id, time ?? 0n);
    expect(verifyLog(bundle?.log, { evidence, asOf: at(200) }).ok).toBe(true);
  });

  it("keeps the time an event was first seen, whatever is published after", () => {
    const ada = new KeyMind("ada");
    const resolver = new LogArchive({ db, clock });
    resolver.publish(idOf(ada), bundleOf(ada));
    clock.at = at(200);
    expect(resolver.publish(idOf(ada), bundleOf(ada))).toStrictEqual({
      outcome: "merged",
      added: 0,
    });
    ada.update(150);
    clock.at = at(300);
    expect(resolver.publish(idOf(ada), bundleOf(ada))).toStrictEqual({
      outcome: "merged",
      added: 1,
    });
    const [genesis, update] = ids(ada.events) as [string, string];
    expect(seenIn(resolver.resolve(idOf(ada)))).toStrictEqual({
      [genesis]: at(100),
      [update]: at(300),
    });
    // A shorter copy takes nothing away.
    clock.at = at(400);
    resolver.publish(idOf(ada), bundleOf(ada, ada.events.slice(0, 1)));
    expect(resolver.resolve(idOf(ada))?.log).toHaveLength(2);
  });

  it("is what the resolver serves after it has restarted, times and all", () => {
    const ada = new KeyMind("ada").update(10);
    const [a, b, c] = ["a", "b", "c"].map((name) => new KeyMind(name)) as [
      KeyMind,
      KeyMind,
      KeyMind,
    ];
    const club = new Collective("club", [a, b, c], 2, 5).update(20, [a, b]);
    let resolver = new LogArchive({ db, clock });
    for (const mind of [ada, a, b, c, club]) {
      clock.at += 1_000_000_000n;
      expect(resolver.publish(idOf(mind), bundleOf(mind)).outcome).toBe("merged");
    }
    const before = [ada, a, b, c, club].map((mind) => resolver.resolve(idOf(mind)));
    expect(before.map((bundle) => bundle?.log.length)).toStrictEqual([2, 1, 1, 1, 2]);
    db.close();
    clock.at = at(9000);
    db = open();
    resolver = new LogArchive({ db, clock });
    expect([ada, a, b, c, club].map((mind) => resolver.resolve(idOf(mind)))).toStrictEqual(before);
  });

  it("is served with the proofs that sign it, and none a stranger added", () => {
    const ada = new KeyMind("ada").update(10);
    const eve = new KeyMind("eve");
    const [genesis, update] = ada.events as unknown as [
      JsonObject & { proof: Proof[] },
      JsonObject,
    ];
    const crowded = {
      ...genesis,
      proof: [
        ...genesis.proof,
        ...rawSign(genesis, [{ control: eve.control(0) }, eve.asMember()]).proof,
      ],
    };
    const resolver = new LogArchive({ db, clock });
    expect(resolver.publish(idOf(ada), bundleOf(ada, [crowded, update])).outcome).toBe("merged");
    expect(resolver.resolve(idOf(ada))?.log).toStrictEqual(ada.events);
  });

  it("is not taken under another mind's name", () => {
    const [ada, bob] = [new KeyMind("ada"), new KeyMind("bob")];
    const resolver = new LogArchive({ db, clock });
    for (const [id, bundle] of [
      [idOf(ada), bundleOf(bob)],
      [idOf(ada), bundleOf(ada, bob.events)],
    ] as const) {
      let thrown: unknown;
      try {
        resolver.publish(id, bundle);
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(OipError);
      expect((thrown as OipError).code).toBe("invalid-record");
    }
    expect(resolver.resolve(idOf(ada))).toBeUndefined();
    expect(resolver.resolve(idOf(bob))).toBeUndefined();
  });
});

describe(`${clause("L1 17.2", "L1 4.9")} an event that does not verify`, () => {
  it("is not stored or served, and what verified before it is", () => {
    const ada = new KeyMind("ada").update(10);
    const eve = new KeyMind("eve");
    const [genesis, update] = ada.events;
    const forged = rawSign(update as object, [{ control: eve.control(0) }]);
    const resolver = new LogArchive({ db, clock });
    const published = resolver.publish(idOf(ada), bundleOf(ada, [genesis, forged]));
    expect(published).toMatchObject({
      outcome: "refused",
      added: 1,
      refused: { position: 1, undecided: false },
    });
    expect(resolver.resolve(idOf(ada))?.log).toStrictEqual([genesis]);
    // The mind's own event is taken afterwards.
    expect(resolver.publish(idOf(ada), bundleOf(ada))).toStrictEqual({
      outcome: "merged",
      added: 1,
    });
  });

  it("is called undecided where the resolver lacks what would judge it: a member's log", () => {
    const [a, b, c] = ["a", "b", "c"].map((name) => new KeyMind(name)) as [
      KeyMind,
      KeyMind,
      KeyMind,
    ];
    const club = new Collective("club", [a, b, c], 2, 5);
    const resolver = new LogArchive({ db, clock });
    expect(resolver.publish(idOf(club), bundleOf(club))).toMatchObject({
      outcome: "refused",
      added: 0,
      refused: { position: 0, undecided: true },
    });
    expect(resolver.resolve(idOf(club))).toBeUndefined();
    for (const member of [a, b, c]) resolver.publish(idOf(member), bundleOf(member));
    expect(resolver.publish(idOf(club), bundleOf(club))).toStrictEqual({
      outcome: "merged",
      added: 1,
    });
    expect(resolver.resolve(idOf(club))?.log).toStrictEqual(club.events);
  });
});

describe(`${clause("L1 7.2", "L1 7.3", "L1 17.1")} two valid events for one position`, () => {
  /** Ada's log, and another second event signed by the same control key. */
  function parted() {
    const first = new KeyMind("ada").update(10);
    const other = new KeyMind("ada").update(11);
    expect(first.events[0]).toStrictEqual(other.events[0]);
    return { first, other };
  }

  it("are kept as evidence, and the one seen first has the position", () => {
    const { first, other } = parted();
    const resolver = new LogArchive({ db, clock });
    expect(resolver.duplicity(idOf(first))).toBeUndefined();
    resolver.publish(idOf(first), bundleOf(first));
    expect(resolver.duplicity(idOf(first))).toStrictEqual({
      oip: "1",
      type: "DuplicityEvidence",
      mind: first.address,
      pairs: [],
    });
    clock.at = at(200);
    expect(resolver.publish(idOf(other), bundleOf(other))).toStrictEqual({
      outcome: "duplicity",
      added: 1,
      position: 1,
    });
    // Not chosen by which came later, and not by length.
    other.update(20);
    clock.at = at(300);
    expect(resolver.publish(idOf(other), bundleOf(other)).outcome).toBe("duplicity");
    expect(resolver.resolve(idOf(first))?.log).toStrictEqual(first.events);
    expect(resolver.duplicity(idOf(first))?.pairs).toStrictEqual([
      [first.events[1], other.events[1]],
    ]);
  });

  it("are still told apart after the resolver has restarted", () => {
    const { first, other } = parted();
    let resolver = new LogArchive({ db, clock });
    resolver.publish(idOf(first), bundleOf(first));
    clock.at = at(200);
    resolver.publish(idOf(other), bundleOf(other));
    db.close();
    clock.at = at(5000);
    db = open();
    resolver = new LogArchive({ db, clock });
    expect(resolver.resolve(idOf(first))?.log).toStrictEqual(first.events);
    expect(resolver.duplicity(idOf(first))?.pairs).toStrictEqual([
      [first.events[1], other.events[1]],
    ]);
  });

  it("are never first seen at one reading of the clock: the one published first was seen first", () => {
    const { first, other } = parted();
    const resolver = new LogArchive({ db, clock });
    // The clock does not move between the two.
    resolver.publish(idOf(first), bundleOf(first));
    expect(resolver.publish(idOf(other), bundleOf(other)).outcome).toBe("duplicity");
    expect(resolver.resolve(idOf(first))?.log).toStrictEqual(first.events);
    const seen = seenIn(resolver.resolve(idOf(first)));
    expect(seen[contentId(first.events[1] as object)]).toBe(at(100));
    // Nor does a clock that has gone back put a later event before an earlier one.
    const bob = new KeyMind("bob");
    clock.at = at(50);
    resolver.publish(idOf(bob), bundleOf(bob));
    expect((seenIn(resolver.resolve(idOf(bob)))[idOf(bob)] ?? 0n) > at(100)).toBe(true);
  });
});

describe(`${clause("L1 17.1")} the stream of what a resolver took in`, () => {
  it("gives each event once, in the order it came, from a cursor on", () => {
    const [ada, bob] = [new KeyMind("ada").update(10), new KeyMind("bob")];
    const resolver = new LogArchive({ db, clock });
    expect(resolver.stream(0, 10)).toStrictEqual([]);
    resolver.publish(idOf(ada), bundleOf(ada));
    resolver.publish(idOf(bob), bundleOf(bob));
    resolver.publish(idOf(ada), bundleOf(ada));
    expect(resolver.stream(0, 10)).toStrictEqual([
      { cursor: 1, mind: ada.address, record: ada.events[0] },
      { cursor: 2, mind: ada.address, record: ada.events[1] },
      { cursor: 3, mind: bob.address, record: bob.events[0] },
    ]);
    expect(resolver.stream(2, 10).map((entry) => entry.cursor)).toStrictEqual([3]);
    expect(resolver.stream(0, 2).map((entry) => entry.cursor)).toStrictEqual([1, 2]);
    expect(resolver.stream(3, 10)).toStrictEqual([]);
  });
});

describe(`${clause("L1 15.2", "L1 17.1", "L1 17.2")} the location record a bundle carries`, () => {
  /** A signed location record of a mind, and the digest its proof is known by. */
  function located(mind: Mind, seconds: number, more: JsonObject = {}, by: Mind = mind) {
    const record = by.sign({ ...locationBy(mind, seconds), ...more }) as JsonObject & {
      proof: Proof[];
    };
    return { record, digest: proofDigest(record.proof[0]!) };
  }
  const withLocation = (mind: Mind, location: unknown, more: JsonObject = {}): Bundle =>
    ({ ...bundleOf(mind), location, ...more }) as unknown as Bundle;

  it("is served as the mind's current one, with the time its proof was first seen", () => {
    const ada = new KeyMind("ada");
    const resolver = new LogArchive({ db, clock });
    const first = located(ada, 90);
    expect(resolver.publish(idOf(ada), withLocation(ada, first.record))).toStrictEqual({
      outcome: "merged",
      added: 1,
    });
    const bundle = resolver.resolve(idOf(ada));
    expect(bundle?.location).toStrictEqual(first.record);
    expect(seenIn(bundle)[first.digest]).toBe(at(100));
    // One with a higher `seq` takes its place. The one before it stays held.
    clock.at = at(200);
    const second = located(ada, 190, { seq: 2 });
    resolver.publish(idOf(ada), withLocation(ada, second.record));
    clock.at = at(300);
    resolver.publish(idOf(ada), withLocation(ada, first.record));
    const later = resolver.resolve(idOf(ada));
    expect(later?.location).toStrictEqual(second.record);
    expect(seenIn(later)).toStrictEqual({ [idOf(ada)]: at(100), [second.digest]: at(200) });
  });

  it("is not kept where the mind's own authority did not sign it, and the log is merged all the same", () => {
    const [ada, eve] = [new KeyMind("ada"), new KeyMind("eve")];
    const resolver = new LogArchive({ db, clock });
    resolver.publish(idOf(eve), bundleOf(eve));
    for (const location of [
      // Signed by another mind, for Ada or for itself, and what is no location record at all.
      located(ada, 90, {}, eve).record,
      located(eve, 90).record,
      ada.sign(intentBy(ada, 90)),
      { type: "Location" },
    ]) {
      expect(resolver.publish(idOf(ada), withLocation(ada, location))).toMatchObject({
        outcome: "not-counted",
        record: "location",
      });
    }
    const bundle = resolver.resolve(idOf(ada));
    expect(bundle?.log).toStrictEqual(ada.events);
    expect(bundle).not.toHaveProperty("location");
    // No time was recorded for a proof on a record that was not kept.
    expect(Object.keys(seenIn(bundle))).toStrictEqual([idOf(ada)]);
    expect(db.prepare("SELECT COUNT(*) AS n FROM seen_proofs").get()).toEqual({ n: 0 });
  });

  it("counts no longer once the key that signed it is removed, however high its `seq`", () => {
    const ada = new KeyMind("ada");
    const resolver = new LogArchive({ db, clock });
    const { record } = located(ada, 90, { seq: 1000 });
    resolver.publish(idOf(ada), withLocation(ada, record));
    expect(resolver.resolve(idOf(ada))?.location).toStrictEqual(record);
    // An update that lists no operational key.
    ada.update(150, { keys: [] });
    clock.at = at(200);
    expect(resolver.publish(idOf(ada), bundleOf(ada)).outcome).toBe("merged");
    expect(resolver.resolve(idOf(ada))).not.toHaveProperty("location");
    // Published again, it is refused as any record the removed key signs.
    expect(resolver.publish(idOf(ada), withLocation(ada, record)).outcome).toBe("not-counted");
  });

  it("is held after a restart, and told of in the stream after the events", () => {
    const ada = new KeyMind("ada");
    let resolver = new LogArchive({ db, clock });
    const { record } = located(ada, 90);
    resolver.publish(idOf(ada), withLocation(ada, record));
    const before = resolver.resolve(idOf(ada));
    expect(resolver.stream(0, 10)).toStrictEqual([
      { cursor: 1, mind: ada.address, record: ada.events[0] },
      { cursor: 2, mind: ada.address, record },
    ]);
    db.close();
    db = open();
    resolver = new LogArchive({ db, clock });
    expect(resolver.resolve(idOf(ada))).toStrictEqual(before);
    expect(resolver.stream(1, 10)).toStrictEqual([{ cursor: 2, mind: ada.address, record }]);
  });

  it("brings the profile it names, where the bundle carries that and the mind signed it", () => {
    const ada = new KeyMind("ada");
    const resolver = new LogArchive({ db, clock });
    const profile = ada.sign({
      oip: "1",
      type: "Participant",
      author: ada.address,
      created: T(80),
      name: "ada",
      kind: "agent",
    }) as JsonObject & { proof: Proof[] };
    // A profile that no location record names is held, and not served.
    resolver.publish(
      idOf(ada),
      withLocation(ada, located(ada, 90).record, { participant: profile }),
    );
    expect(resolver.resolve(idOf(ada))).not.toHaveProperty("participant");
    clock.at = at(200);
    const naming = located(ada, 190, { seq: 2, participant: contentId(profile) });
    resolver.publish(idOf(ada), withLocation(ada, naming.record));
    const bundle = resolver.resolve(idOf(ada));
    expect(bundle?.participant).toStrictEqual(profile);
    expect(seenIn(bundle)[proofDigest(profile.proof[0]!)]).toBe(at(100));
    // One that another mind signed is not kept.
    const eve = new KeyMind("eve");
    resolver.publish(idOf(eve), bundleOf(eve));
    const { proof: _, ...unsigned } = profile;
    const forged = eve.sign({ ...unsigned, name: "eve as ada" });
    expect(
      resolver.publish(idOf(ada), { ...bundleOf(ada), participant: forged } as unknown as Bundle),
    ).toMatchObject({ outcome: "not-counted", record: "participant" });
  });
});

describe("a resolver whose database fails", () => {
  it("has merged nothing, in memory or on disk, and says the failure", () => {
    const ada = new KeyMind("ada").update(10);
    const resolver = new LogArchive({ db, clock });
    // The stream's table is gone: the last write of the transaction fails.
    db.exec("DROP TABLE stream");
    expect(() => resolver.publish(idOf(ada), bundleOf(ada))).toThrow(/no such table/u);
    expect(resolver.resolve(idOf(ada))).toBeUndefined();
    expect(db.prepare("SELECT COUNT(*) AS n FROM events").get()).toEqual({ n: 0 });
    expect(db.prepare("SELECT COUNT(*) AS n FROM seen_events").get()).toEqual({ n: 0 });
  });
});
