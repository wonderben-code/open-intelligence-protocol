// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Recording first sight. Evidence for an identity event is evidence that it
 * existed with proofs that make it valid (core 9.5), so nothing is recorded
 * before it has verified.
 */

import { contentId, proofDigest } from "@oip/core";
import { clause } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import {
  draftUpdate,
  FirstSeen,
  judgeRecord,
  LogBook,
  verifyLog,
  witnessLog,
  witnessRecord,
} from "../src/index.ts";
import {
  at,
  Collective,
  intentBy,
  KeyMind,
  rawGenesis,
  rawSign,
  signer,
  T,
} from "@oip/testkit/minds";

const idOf = (event: object): string => contentId(event);

describe(`${clause("core 9.5")} a verifier's own first sight of a log`, () => {
  it("is recorded for each event that verifies, at the time the log was obtained", () => {
    const ada = new KeyMind("ada").update(10).update(20);
    const seen = new FirstSeen();
    const witnessed = witnessLog(ada.events, at(50), seen);
    expect(witnessed.failure).toBeUndefined();
    expect(witnessed.log?.entries.map((entry) => entry.time)).toStrictEqual([
      at(50),
      at(50),
      at(50),
    ]);
    expect(witnessed.log?.asOf).toBe(at(50));
    expect(ada.events.map((event) => seen.eventSeen(idOf(event)))).toStrictEqual([
      at(50),
      at(50),
      at(50),
    ]);
    // What was recorded is what the log is verified with from then on.
    const again = verifyLog(ada.events, { evidence: seen, asOf: at(50) });
    expect(again.ok && again.value.entries.map((entry) => entry.time)).toStrictEqual(
      witnessed.log?.entries.map((entry) => entry.time),
    );
  });

  it("keeps the earlier time for an event seen before, and records only what is new", () => {
    const ada = new KeyMind("ada").update(10);
    const seen = new FirstSeen();
    witnessLog(ada.events, at(50), seen);
    ada.update(60);
    const witnessed = witnessLog(ada.events, at(70), seen);
    expect(witnessed.failure).toBeUndefined();
    expect(witnessed.log?.entries.map((entry) => entry.time)).toStrictEqual([
      at(50),
      at(50),
      at(70),
    ]);
    expect(seen.eventSeen(idOf(ada.events[1]!))).toBe(at(50));
    expect(seen.eventSeen(idOf(ada.events[2]!))).toBe(at(70));
  });

  it("records the events that verify and stops at the first that does not", () => {
    const ada = new KeyMind("ada").update(10);
    // The key whose turn it is is revealed, and another signs.
    const forged = rawSign(draftUpdate(ada.head, T(20), { controller: ada.controller(2) }), [
      { control: signer("thief") },
    ]);
    const after = new KeyMind("ada").update(10).update(20).update(30);
    const events = [...ada.events, forged, after.events[3]];
    const seen = new FirstSeen();
    const witnessed = witnessLog(events, at(50), seen);
    expect(witnessed.failure).toMatchObject({ ok: false, issues: [{ clause: "L1 4.3" }] });
    expect(witnessed.failure?.issues[0].path.startsWith("/2")).toBe(true);
    // The events before it verified, and are a log to hold.
    expect(witnessed.log?.entries).toHaveLength(2);
    expect(events.map((event) => seen.eventSeen(idOf(event as object)))).toStrictEqual([
      at(50),
      at(50),
      undefined,
      undefined,
    ]);
  });

  it("does not record an event dated more than 300 seconds after the verifier's clock", () => {
    const ada = new KeyMind("ada").update(400);
    const seen = new FirstSeen();
    const early = witnessLog(ada.events, at(99), seen);
    expect(early.failure).toMatchObject({ issues: [{ clause: "core 9.5", path: "/1" }] });
    expect(seen.eventSeen(idOf(ada.events[1]!))).toBeUndefined();
    expect(witnessLog(ada.events, at(100), seen).failure).toBeUndefined();
    expect(seen.eventSeen(idOf(ada.events[1]!))).toBe(at(100));
  });

  it("judges an event by the earlier time another source of evidence shows, and still records its own", () => {
    const ada = new KeyMind("ada").update(10);
    const resolver = new FirstSeen();
    resolver.sawEvent(idOf(ada.events[0]!), at(1));
    resolver.sawEvent(idOf(ada.events[1]!), at(11));
    const seen = new FirstSeen();
    const witnessed = witnessLog(ada.events, at(50), seen, { evidence: resolver });
    expect(witnessed.log?.entries.map((entry) => entry.time)).toStrictEqual([at(1), at(11)]);
    expect(seen.eventSeen(idOf(ada.events[1]!))).toBe(at(50));
    // The verifier's own earlier record counts against a later one of the other source, too.
    const late = new FirstSeen();
    late.sawEvent(idOf(ada.events[1]!), at(90));
    const own = witnessLog(ada.events, at(95), seen, { evidence: late });
    expect(own.log?.entries.map((entry) => entry.time)).toStrictEqual([at(50), at(50)]);
  });

  it("answers and does not throw, whatever it is given, and records nothing then", () => {
    const seen = new FirstSeen();
    for (const junk of [undefined, null, 5, "log", {}, [], [null], [{ type: "Genesis" }]]) {
      const witnessed = witnessLog(junk, at(50), seen);
      expect(witnessed.log).toBeUndefined();
      expect(witnessed.failure?.ok).toBe(false);
    }
    const ada = new KeyMind("ada");
    expect(witnessLog(ada.events, 50 as never, seen).failure).toMatchObject({
      issues: [{ clause: "core 9.4" }],
    });
    expect(seen.eventSeen(idOf(ada.events[0]!))).toBeUndefined();
    expect(witnessLog(ada.events, at(50), seen, null as never).failure).toBeUndefined();
  });
});

describe(`${clause("core 8.3", "L1 4.7")} what a verifier does not judge, it does not record`, () => {
  it("records no event that depends on an extension the verifier does not implement", () => {
    const genesis = rawGenesis("ada", {
      ext: { "com.example.recovery": { v: 1 } },
      critical: ["com.example.recovery"],
    });
    const seen = new FirstSeen();
    const refused = witnessLog([genesis], at(50), seen);
    expect(refused.log).toBeUndefined();
    expect(refused.failure).toMatchObject({
      issues: [{ clause: "core 8.3", path: "/0/critical" }],
    });
    expect(seen.eventSeen(idOf(genesis))).toBeUndefined();
    // A verifier that implements it witnesses the event like any other.
    const witnessed = witnessLog([genesis], at(60), seen, { understood: ["com.example.recovery"] });
    expect(witnessed.failure).toBeUndefined();
    expect(seen.eventSeen(idOf(genesis))).toBe(at(60));
  });

  it("records the events it reads of a log longer than it was set to read, and says there are more", () => {
    const ada = new KeyMind("ada");
    // Only the count matters here: what follows the genesis is never reached.
    const long = Array.from({ length: 1001 }, () => ada.events[0]);
    const seen = new FirstSeen();
    const witnessed = witnessLog(long, at(50), seen, { maxEvents: 1000 });
    expect(witnessed.log?.entries).toHaveLength(1);
    expect(witnessed.failure).toMatchObject({ issues: [{ clause: "L1 4.6", path: "/1/type" }] });
    expect(seen.eventSeen(idOf(ada.events[0]!))).toBe(at(50));
    // A log whose events all verify, and that has more than were read.
    const bea = new KeyMind("bea").update(10).update(20);
    const cut = witnessLog(bea.events, at(50), seen, { maxEvents: 1000 });
    expect(cut.failure).toBeUndefined();
    expect(cut.log?.entries).toHaveLength(3);
  });
});

describe(`${clause("L1 9.6")} a signature added later does not ride on an earlier sight`, () => {
  // A collective of three, threshold two. A thief has the invocation key b removed at 20.
  const people = () =>
    ["a", "b", "c"].map((name) => new KeyMind(name)) as [KeyMind, KeyMind, KeyMind];

  function scene() {
    const [a, b, c] = people();
    const club = new Collective("club", [a, b, c], 2, 5);
    const takeover = draftUpdate(club.head, T(10), {
      keys: [{ key: signer("thief").publicKey }],
    });
    // At 10 the event exists with one member's proof: not yet valid.
    const half = rawSign(takeover, [a.asMember()]);
    // b's key, as it stood before b removed it, signs at 30.
    const stale = b.asMember();
    b.update(20, { invocation: [] });
    const full = rawSign(takeover, [a.asMember(), stale]);
    return { a, b, c, club, half, full };
  }

  function verifier(minds: readonly KeyMind[], now: number) {
    const seen = new FirstSeen();
    const book = new LogBook(seen);
    for (const mind of minds) {
      const witnessed = witnessLog(mind.events, at(now), seen);
      if (witnessed.log === undefined) throw new Error("a member's log does not verify");
      book.hold(mind.events, at(now));
    }
    return { seen, book };
  }

  it("leaves no trace of an event that is not yet validly signed", () => {
    const { a, b, c, club, half, full } = scene();
    const early = [new KeyMind("a"), new KeyMind("b"), new KeyMind("c")];
    const { seen, book } = verifier(early, 6);
    const memberLog = (mind: string) => book.log(mind);
    expect(witnessLog(club.events, at(6), seen, { memberLog }).failure).toBeUndefined();
    // At 10: one proof where two are needed. The members' logs are known up to then.
    for (const mind of early) book.hold(mind.events, at(10));
    const first = witnessLog([...club.events, half], at(10), seen, { memberLog });
    expect(first.failure).toMatchObject({ issues: [{ clause: "L1 4.4" }] });
    expect(first.log?.entries).toHaveLength(1);
    expect(seen.eventSeen(idOf(half))).toBeUndefined();
    // At 30 the verifier knows b's removal, and the event arrives with the stale key's proof.
    for (const mind of [a, b, c]) {
      witnessLog(mind.events, at(30), seen);
      book.hold(mind.events, at(30));
    }
    const second = witnessLog([...club.events, full], at(30), seen, { memberLog });
    expect(second.failure).toMatchObject({ issues: [{ clause: "L1 6.4", path: "/1/proof/1" }] });
    expect(seen.eventSeen(idOf(full))).toBeUndefined();
    book.hold([...club.events, full], at(30));
    expect(book.log(club.address).ok).toBe(false);
  });

  it("which noting the time an unsigned copy was seen would have let through", () => {
    // The mistake `witnessLog` exists to prevent: evidence recorded for content, not for a valid event.
    const { a, b, c, club, half, full } = scene();
    expect(idOf(half)).toBe(idOf(full));
    const seen = new FirstSeen();
    for (const mind of [a, b, c, club]) {
      for (const event of mind.events) seen.sawEvent(idOf(event), at(6));
    }
    seen.sawEvent(idOf(b.events[1]!), at(20));
    seen.sawEvent(idOf(half), at(10));
    const book = new LogBook(seen);
    for (const mind of [a, b, c]) book.hold(mind.events, at(30));
    book.hold([...club.events, full], at(30));
    const taken = book.log(club.address);
    expect(taken.ok && taken.value.entries.at(-1)?.state.keys).toContain(signer("thief").publicKey);
  });
});

describe(`${clause("core 9.4")} a verifier's own first sight of a record`, () => {
  it("is recorded for each proof that verifies, and for no other", () => {
    const ada = new KeyMind("ada");
    const signed = ada.sign(intentBy(ada, 10));
    const [good] = signed.proof;
    const junk = { ...good!, proofValue: `${good!.proofValue.slice(0, -2)}11` };
    const judged = judgeRecord({ ...signed, proof: [good, junk] });
    if (!judged.ok) throw new Error(JSON.stringify(judged.issues));
    const seen = new FirstSeen();
    witnessRecord(judged.value, at(50), seen);
    expect(seen.proofSeen(proofDigest(good!))).toBe(at(50));
    expect(seen.proofSeen(proofDigest(junk))).toBeUndefined();
    // An earlier time stays.
    witnessRecord(judged.value, at(40), seen);
    witnessRecord(judged.value, at(60), seen);
    expect(seen.proofSeen(proofDigest(good!))).toBe(at(40));
  });
});
