// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Recording first sight. Evidence for an identity event is evidence that it
 * existed with proofs that make it valid (core 9.5), so nothing is recorded
 * before it has verified.
 */

import { contentId, proofDigest } from "@oip/core";
import { clause, type JsonObject } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import {
  draftUpdate,
  FirstSeen,
  judgeRecord,
  LogBook,
  ownSignedTime,
  verifyLog,
  witnessLog,
  witnessRecord,
} from "../src/index.ts";
import {
  at,
  Collective,
  intentBy,
  KeyMind,
  LATER,
  rawGenesis,
  rawSign,
  signer,
  T,
  unchecked,
  witness,
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

describe(`${clause("L1 4.9")} an event that is invalid, and one the verifier cannot judge`, () => {
  const critical = {
    ext: { "com.example.recovery": { v: 1 } },
    critical: ["com.example.recovery"],
  };

  /** What `witnessLog` says of a log of two good events and a third that does not verify. */
  function third(last: (ada: KeyMind) => unknown, now = 50) {
    const ada = new KeyMind("ada").update(10);
    const seen = new FirstSeen();
    const witnessed = witnessLog([...ada.events, last(ada)], at(now), seen);
    expect(witnessed.log?.entries, "the two events before it verify").toHaveLength(2);
    expect(witnessed.failure?.issues[0].path.startsWith("/2")).toBe(true);
    return { clause: witnessed.failure?.issues[0].clause, undecided: witnessed.undecided };
  }
  /** The third event the mind would write next, with these members set or changed. */
  const next = (members: JsonObject = {}) =>
    new KeyMind("ada").update(10).raw(20, "Update", members).events[2]!;
  const withoutMember = (event: object, name: string) =>
    Object.fromEntries(Object.entries(event).filter(([member]) => member !== name));

  it("calls invalid what is wrong whoever looks: its form, its place, or the keys that signed it", () => {
    const invalid: [string, (ada: KeyMind) => unknown, string][] = [
      ["not an event", () => ({ junk: true }), "L1 4.6"],
      ["not an object", () => 5, "L1 3.1"],
      [
        "a number that is no integer",
        () => ({ ...next(), ext: { "com.example": { n: 0.5 } } }),
        "core 1.2",
      ],
      [
        "nine homes",
        () => next({ homes: Array.from({ length: 9 }, (_, n) => `https://h${n}.example`) }),
        "L1 3.7",
      ],
      ["out of place", () => next({ seq: 7 }), "L1 4.2"],
      [
        "signed by a key that was not committed to",
        (ada) =>
          rawSign(draftUpdate(ada.head, T(20), { controller: ada.controller(2) }), [
            { control: signer("thief") },
          ]),
        "L1 4.3",
      ],
      // No version and no type: it names nothing a later revision could define.
      ["without a version", () => withoutMember(next(), "oip"), "core 7"],
      ["with a version that is no string", () => ({ ...next(), oip: 2 }), "core 7"],
      ["with a type that is no string", () => ({ ...next(), type: 7 }), "L1 4.6"],
    ];
    for (const [name, last, expected] of invalid) {
      expect(third(last), name).toStrictEqual({ clause: expected, undecided: false });
    }
  });

  it("calls undecided what a later revision, an extension or other evidence might judge otherwise", () => {
    const undecided: [string, (ada: KeyMind) => unknown, string, number?][] = [
      ["the mind's own event, with a critical extension", () => next(critical), "core 8.3"],
      ["a Merge", () => next({ type: "Merge" }), "L1 3.9"],
      ["a type no revision has defined yet", () => next({ type: "Rename" }), "L1 4.6"],
      ["the reserved member", () => next({ recovery: {} }), "L1 3.12"],
      ["another version of the protocol", () => next({ oip: "2" }), "core 7"],
      ["another version, whatever else it holds", () => ({ oip: "2", type: 7 }), "core 7"],
      // Asked before anything else is, of whatever was given: even a number that is no integer.
      ["another version, outside the JSON of this one", () => ({ oip: "2", n: 0.5 }), "core 7"],
      ["a Merge outside the JSON of this revision", () => ({ type: "Merge", n: 0.5 }), "L1 3.9"],
      // An extension listed in `critical` may change what makes an event valid: its form, its
      // place and its signatures. Without the extension, nothing else about the event is a finding.
      [
        "unsigned, with a critical extension",
        (ada) =>
          rawSign(draftUpdate(ada.head, T(20), { controller: ada.controller(2), ...critical }), [
            { control: signer("thief") },
          ]),
        "core 8.3",
      ],
      ["out of place, with a critical extension", () => next({ seq: 7, ...critical }), "core 8.3"],
      [
        "malformed, with a critical extension",
        () => ({ ...next(critical), homes: "https://a.example" }),
        "core 8.3",
      ],
      // A `critical` that is no list of names is read as naming what nobody implements.
      ["with a critical that is no list", () => ({ ...next(), critical: "all" }), "core 8.3"],
      // Dated more than 300 seconds after this verifier's clock: one that sees it later accepts it.
      [
        "dated after the evidence",
        () => new KeyMind("ada").update(10).update(400).events[2],
        "core 9.5",
        50,
      ],
      ["expired, for a verifier that sees it now", () => next({ expires: T(30) }), "core 9.6", 500],
      [
        "a proof dated after the evidence",
        (ada) =>
          rawSign(
            draftUpdate(ada.head, T(20), { controller: ada.controller(2) }),
            [{ control: ada.control(2) }],
            { created: T(400) },
          ),
        "L1 4.3",
        50,
      ],
    ];
    for (const [name, last, expected, now] of undecided) {
      expect(third(last, now), name).toStrictEqual({ clause: expected, undecided: true });
    }
  });

  it("calls undecided a collective's event that waits on a member's log, and invalid one no member signed", () => {
    const [a, b, n] = [new KeyMind("a"), new KeyMind("b"), new KeyMind("n")];
    const club = () => new Collective("club", [a, b], 2, 5);
    const admits = club().update(20, [a, b, n], {
      controller: { members: [a.address, b.address, n.address], threshold: 2 },
    });
    const witnessedBy = (
      minds: readonly KeyMind[],
      events: readonly unknown[],
      membersAsOf = 50,
    ) => {
      const seen = new FirstSeen();
      const book = new LogBook(seen);
      for (const mind of minds) {
        witnessLog(mind.events, at(membersAsOf), seen);
        book.hold(mind.events, at(membersAsOf));
      }
      const witnessed = witnessLog(events, at(50), seen, { memberLog: (mind) => book.log(mind) });
      return { clause: witnessed.failure?.issues[0].clause, undecided: witnessed.undecided };
    };
    // The verifier has not fetched the log of the member the event admits.
    expect(witnessedBy([a, b], admits.events)).toStrictEqual({ clause: "L1 6.3", undecided: true });
    expect(witnessedBy([a, b, n], admits.events)).toStrictEqual({
      clause: undefined,
      undecided: false,
    });
    // The members' logs are known up to 40, and the event is first seen at 50.
    expect(witnessedBy([a, b, n], admits.events, 40)).toStrictEqual({
      clause: "core 9.4",
      undecided: true,
    });
    // A proof pinned to a version of a member that the verifier's copy of its log does not have:
    // the member may publish it yet, or a fuller copy may hold it.
    const ahead = new KeyMind("b").update(15);
    const pinnedAhead = rawSign(draftUpdate(club().head, T(20)), [a.asMember(), ahead.asMember()]);
    expect(witnessedBy([a, b], [...club().events, pinnedAhead])).toStrictEqual({
      clause: "L1 6.4",
      undecided: true,
    });
    expect(witnessedBy([a, ahead], [...club().events, pinnedAhead]).undecided).toBe(false);
    // A member removed its key at 30: which came first is a matter of evidence.
    const removed = new KeyMind("b").update(30, { invocation: [] });
    expect(witnessedBy([a, removed, n], admits.events)).toStrictEqual({
      clause: "L1 6.4",
      undecided: true,
    });
    // Signed by nobody the collective knows: no member has a proof on it at all, and that is a
    // fact about the event.
    const stranger = rawSign(draftUpdate(club().head, T(20)), [{ control: signer("thief") }]);
    expect(witnessedBy([a, b], [...club().events, stranger])).toStrictEqual({
      clause: "L1 4.4",
      undecided: false,
    });
    const alone = rawSign(draftUpdate(club().head, T(20)), [a.asMember()]);
    expect(witnessedBy([a, b], [...club().events, alone]).undecided).toBe(false);
    // Signed under the members' names by keys that are not theirs. What a key is worth is read
    // from the member's log, and a verifier's copy of a log is not a fact about the event.
    const impostor = rawSign(draftUpdate(club().head, T(20)), [
      { member: a.address, versionId: a.versionId(), invocation: signer("thief") },
      { member: b.address, versionId: b.versionId(), invocation: signer("thief") },
    ]);
    expect(witnessedBy([a, b], [...club().events, impostor])).toStrictEqual({
      clause: "L1 6.4",
      undecided: true,
    });
    // A member's own proof, made for another, is no proof of the member's (Layer 1, 6.4).
    // With the other member's proof beside it, one member has signed, and two must.
    const delegated = rawSign(draftUpdate(club().head, T(20)), [b.asMember()], {
      authority: [`${b.address}/${contentId(b.events[0])}`],
    });
    const both = { ...delegated, proof: [...delegated.proof, ...alone.proof] };
    expect(witnessedBy([a, b], [...club().events, both])).toStrictEqual({
      clause: "L1 6.4",
      undecided: false,
    });
    // A member the event admits has no proof on it; nor has a founder on a genesis.
    const unasked = rawSign(
      draftUpdate(club().head, T(20), {
        controller: { members: [a.address, b.address, n.address], threshold: 2 },
      }),
      [a.asMember(), b.asMember()],
    );
    expect(witnessedBy([a, b, n], [...club().events, unasked])).toStrictEqual({
      clause: "L1 4.4",
      undecided: false,
    });
    const founded = rawSign(club().events[0] as object, [a.asMember()]);
    expect(witnessedBy([a, b], [founded])).toStrictEqual({ clause: "L1 4.1", undecided: false });
    // An outsider's event that is also dated ahead of the evidence is junk first.
    const early = rawSign(draftUpdate(club().head, T(900)), [{ control: signer("thief") }]);
    expect(witnessedBy([a, b], [...club().events, early])).toStrictEqual({
      clause: "L1 4.4",
      undecided: false,
    });
  });

  it("calls invalid an event that brings back a key the log revoked, evidence or none", () => {
    const ada = new KeyMind("ada");
    const key = ada.operational().publicKey;
    const revoking = () =>
      new KeyMind("ada").update(10, {
        keys: [{ key: ada.operational(1).publicKey }],
        revoked: [{ key }],
      });
    for (const seconds of [20, 5000]) {
      // Dated 5000, the event is also far ahead of the evidence. It is junk first.
      const log = revoking().raw(seconds, "Update", { keys: [{ key }] }).events;
      const witnessed = witnessLog(log, at(50), new FirstSeen());
      expect(witnessed.log?.entries).toHaveLength(2);
      expect(witnessed.failure).toMatchObject({ issues: [{ clause: "L1 4.5", path: "/2" }] });
      expect(witnessed.undecided).toBe(false);
    }
    // And one that makes a key both operational and for other minds' events.
    const both = new KeyMind("ada").raw(20, "Update", { invocation: [{ key }] }).events;
    expect(witnessLog(both, at(50), new FirstSeen())).toMatchObject({
      undecided: false,
      failure: { issues: [{ clause: "L1 3.5" }] },
    });
  });

  it("asks what cannot be read of the copy it judges, as of the value it was given", () => {
    // A value that shows its `critical` only the second time it is looked at.
    const ada = new KeyMind("ada").update(10);
    const event = next(critical);
    let looked = 0;
    const twoFaced = new Proxy(event, {
      getOwnPropertyDescriptor(target, key) {
        if (key === "critical" && looked++ === 0) return undefined;
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
    });
    const witnessed = witnessLog([...ada.events, twoFaced], at(50), new FirstSeen());
    expect(witnessed.log?.entries).toHaveLength(2);
    expect(witnessed.failure).toMatchObject({ issues: [{ clause: "core 8.3" }] });
    expect(witnessed.undecided).toBe(true);
  });

  it("calls undecided a log that cannot be read at all, and a time that is no time", () => {
    const ada = new KeyMind("ada");
    const throwing = new Proxy(ada.events, {
      get() {
        throw new Error("boom");
      },
    });
    for (const witnessed of [
      witnessLog(throwing, at(50), new FirstSeen()),
      witnessLog(ada.events, "now" as never, new FirstSeen()),
    ]) {
      expect(witnessed.failure).toBeDefined();
      expect(witnessed.undecided).toBe(true);
      expect(witnessed.log).toBeUndefined();
    }
  });

  it("calls undecided a log longer than it reads", { timeout: 120_000 }, () => {
    const long = unchecked(() => {
      const ada = new KeyMind("ada");
      for (let n = 1; n <= 1000; n++) ada.update(n);
      return ada;
    });
    const witnessed = witnessLog(long.events, at(5000), new FirstSeen(), { maxEvents: 1000 });
    expect(witnessed.log?.entries).toHaveLength(1000);
    expect(witnessed.failure?.issues[0].clause).toBe("implementation limit");
    expect(witnessed.undecided).toBe(true);
  });

  it("judges a copy alone, and leaves what to hold to the book: the copy as it came", () => {
    const ada = new KeyMind("ada").update(10);
    const seen = new FirstSeen();
    const held = (events: unknown) => {
      const book = new LogBook(seen);
      witnessLog(events, at(50), seen);
      book.hold(events, at(50));
      return book.log(ada.address);
    };
    // An invalid event ends the copy: the events before it are the log, and a book finds so.
    const junk = [...ada.events, { junk: true }];
    expect(witnessLog(junk, at(50), seen)).toMatchObject({
      undecided: false,
      log: { entries: { length: 2 } },
    });
    expect(held(junk)).toMatchObject({ ok: true, value: { entries: { length: 2 } } });
    // An undecided event ends it too, and a book refuses the log until it can judge.
    const waiting = [...ada.events, next(critical)];
    expect(witnessLog(waiting, at(50), seen).undecided).toBe(true);
    expect(held(waiting)).toMatchObject({
      ok: false,
      issues: [{ clause: "core 8.3", path: "/2/critical" }],
    });
    // What it answers with is frozen, and is no more than what it found.
    const found = witnessLog(ada.events, at(50), seen);
    expect(Object.isFrozen(found)).toBe(true);
    expect(Object.keys(found).sort()).toStrictEqual(["failure", "log", "undecided"]);
  });

  it(`${clause("L1 7.1")} calls invalid, for the proofs one copy lacks, an event that a book verifies with the proofs of two`, () => {
    // A collective of three with a threshold of two removes its operational key. Each
    // copy of that event carries one member's proof.
    const [a, b, c] = ["a", "b", "c"].map((name) => new KeyMind(name)) as [
      KeyMind,
      KeyMind,
      KeyMind,
    ];
    const club = new Collective("club", [a, b, c], 2, 5);
    const removal = draftUpdate(club.head, T(20), { keys: [] });
    const half = (member: KeyMind) => [...club.events, rawSign(removal, [member.asMember()])];
    const record = judgeRecord(club.sign(intentBy(club, 30), { position: 0 }));
    if (!record.ok) throw new Error(JSON.stringify(record.issues));
    // A witness the verifier trusts saw every event, the removal among them.
    const seen = witness([a.events, b.events, c.events, club.events]);
    seen.sawEvent(contentId(removal), at(20));
    for (const proof of record.value.proofs) seen.sawProof(proof.digest, at(31));
    const book = new LogBook(seen);
    for (const member of [a, b, c]) book.hold(member.events, LATER);
    const memberLog = (mind: string) => book.log(mind);
    for (const member of [a, b]) {
      // By its own proofs, each copy has an event that too few members signed.
      expect(witnessLog(half(member), at(40), seen, { memberLog })).toMatchObject({
        undecided: false,
        log: { entries: { length: 1 } },
        failure: { issues: [{ clause: "L1 4.4" }] },
      });
      book.hold(half(member), LATER);
    }
    // The book holds both copies as they came, and the event has both proofs.
    expect(book.log(club.address)).toMatchObject({ ok: true, value: { entries: { length: 2 } } });
    expect(ownSignedTime(record.value, club.address, book)).toBeUndefined();
    // Holding only what each copy verified alone would have lost the removal.
    const short = new LogBook(seen);
    for (const member of [a, b, c]) short.hold(member.events, LATER);
    short.hold(club.events, LATER);
    expect(ownSignedTime(record.value, club.address, short)).toBeDefined();
  });

  it("does not go on counting a key that an event it cannot judge removed", () => {
    // At 20 ada replaces her operational key, in an event that depends on an extension.
    const ada = new KeyMind("ada").update(10);
    const log = new KeyMind("ada").update(10).raw(20, "Update", {
      keys: [{ key: ada.operational(1).publicKey }],
      ...critical,
    }).events;
    const seen = new FirstSeen();
    const witnessed = witnessLog(log, at(30), seen);
    expect(witnessed).toMatchObject({ undecided: true, log: { entries: { length: 2 } } });
    // The key she removed signs at 25.
    const judged = judgeRecord(ada.sign(intentBy(ada, 25), { position: 1 }));
    if (!judged.ok) throw new Error(JSON.stringify(judged.issues));
    witnessRecord(judged.value, at(26), seen);
    const book = new LogBook(seen);
    book.hold(log, at(30));
    expect(ownSignedTime(judged.value, ada.address, book)).toBeUndefined();
    // Holding the events that verified, as known up to now, is the mistake: the removal is lost.
    const short = new LogBook(seen);
    short.hold(
      witnessed.log?.entries.map((entry) => entry.event),
      at(30),
    );
    expect(ownSignedTime(judged.value, ada.address, short)).toBe(at(26));
  });

  it("says nothing is undecided of a log that verifies, or of what is no log", () => {
    const ada = new KeyMind("ada");
    expect(witnessLog(ada.events, at(50), new FirstSeen()).undecided).toBe(false);
    expect(witnessLog("log", at(50), new FirstSeen()).undecided).toBe(false);
    expect(witnessLog([], at(50), new FirstSeen()).undecided).toBe(false);
    // A time that is no time is the caller's fault, and nothing was judged.
    expect(witnessLog(ada.events, 50 as never, new FirstSeen()).undecided).toBe(true);
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
