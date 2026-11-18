// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, formatVersionId, keyHash, parseTimestamp } from "@oip/core";
import type { Issue, Validation } from "@oip/schema";
import { clause, copy, type JsonObject, withStackSpent } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import {
  childrenAt,
  compromisedSince,
  draftGenesis,
  draftUpdate,
  FirstSeen,
  latestState,
  LogBook,
  MAX_LOG_EVENTS,
  MIN_ACCEPTED_LOG_EVENTS,
  revokedAt,
  signEventSync,
  stateAt,
  type VerifiedLog,
  verifyLog,
} from "../src/index.ts";
import {
  agreementKey,
  at,
  bookOf,
  Collective,
  KeyMind,
  LATER,
  type Mind,
  rawGenesis,
  rawSign,
  signer,
  T,
  verifyMind,
  witness,
} from "@oip/testkit/minds";

function verified(mind: Mind, others: readonly Mind[] = []): VerifiedLog {
  const result = verifyMind(mind, others);
  if (!result.ok) throw new Error(JSON.stringify(result.issues));
  return result.value;
}

const states = (log: VerifiedLog) => log.entries.map((entry) => entry.state);
const events = (log: VerifiedLog) => log.entries.map((entry) => entry.event);

function refusal(result: Validation<unknown>): Issue {
  if (result.ok) throw new Error("the log verified");
  // A refusal says why, in words, wherever it comes from.
  expect(result.issues[0].message.length).toBeGreaterThan(8);
  return result.issues[0];
}

/** Why a mind's log does not verify, as it stands. */
const refused = (mind: Mind, others: readonly Mind[] = []): Issue =>
  refusal(verifyMind(mind, others));

/** Verifies bare events, with a witness that saw each when it was made. */
const verifyEvents = (events: readonly unknown[]): Validation<VerifiedLog> =>
  verifyLog(events, { evidence: witness([events as JsonObject[]]), asOf: LATER });

describe(`${clause("L1 2.1", "L1 2.2")} mind addresses`, () => {
  it("is did:oip: and the content ID of the genesis", () => {
    const ada = new KeyMind("ada").update(10);
    const log = verified(ada);
    expect(log.mind).toBe(`did:oip:${contentId(ada.events[0])}`);
    expect(log.mind).toMatch(/^did:oip:bciq[a-z2-7]{52}$/);
    expect(states(log).map((state) => state.mind)).toEqual([log.mind, log.mind]);
  });

  it("changes with any member of the genesis, so no two minds share one", () => {
    expect(new KeyMind("ada").address).not.toBe(new KeyMind("ada", 1).address);
    expect(new KeyMind("ada").address).not.toBe(new KeyMind("ada", 0, { kind: "human" }).address);
  });
});

describe(`${clause("L1 2.3")} the operations of the DID method`, () => {
  it("creates with a Genesis, updates with an Update or a Fork, and deactivates with a Retire", () => {
    const ada = new KeyMind("ada");
    expect(events(verified(ada)).map((event) => event.type)).toEqual(["Genesis"]);
    ada.update(10).fork(20, { child: new KeyMind("child").address });
    expect(latestState(verified(ada)).retired).toBe(false);
    ada.retire(30);
    const log = verified(ada);
    expect(events(log).map((event) => event.type)).toEqual(["Genesis", "Update", "Fork", "Retire"]);
    expect(latestState(log).retired).toBe(true);
  });
});

describe(`${clause("L1 3.1")} an identity log is an ordered array of events`, () => {
  it("is not empty, and is an array of objects", () => {
    for (const notLog of [[], {}, null, "log", 1, undefined]) {
      const result = verifyLog(notLog, { evidence: new FirstSeen(), asOf: LATER });
      expect(refusal(result).clause).toBe("L1 3.1");
    }
    const ada = new KeyMind("ada");
    for (const notEvent of [null, "event", 1, [ada.events[0]]]) {
      const issue = refusal(
        verifyLog([ada.events[0], notEvent], { evidence: witness([ada.events]), asOf: LATER }),
      );
      expect(issue).toMatchObject({ clause: "L1 3.1", path: "/1" });
    }
  });

  it(`${clause("L1 4.1", "L1 4.6")} starts with a Genesis, and has no other`, () => {
    const ada = new KeyMind("ada").update(10);
    expect(refusal(verifyEvents(ada.events.slice(1)))).toMatchObject({
      clause: "L1 4.1",
      path: "/0/type",
    });
    const twice = [ada.events[0], new KeyMind("ada", 5).events[0]];
    expect(refusal(verifyEvents(twice))).toMatchObject({ clause: "L1 4.6", path: "/1/type" });
  });

  it("keeps its order: events moved, dropped from the middle or repeated are refused", () => {
    const ada = new KeyMind("ada").update(10).update(20).update(30);
    const [genesis, first, second, third] = ada.events;
    expect(verifyEvents(ada.events).ok).toBe(true);
    for (const changed of [
      [genesis, second, first, third],
      [genesis, second, third],
      [genesis, first, first, second, third],
      [genesis, first, third],
    ]) {
      expect(refusal(verifyEvents(changed)).clause).toBe("L1 4.2");
    }
  });

  it("verifies as far as it goes: the first events of a log are a log", () => {
    const ada = new KeyMind("ada").update(10).update(20);
    for (let length = 1; length <= 3; length++) {
      const log = verifyEvents(ada.events.slice(0, length));
      expect(log.ok && states(log.value)).toHaveLength(length);
    }
  });
});

describe(`${clause("L1 3.2", "L1 4.2")} the members that chain an event to the one before`, () => {
  const other = new KeyMind("other");

  it("requires mind, seq and prev to follow from the log", () => {
    const wrong: [JsonObject, string][] = [
      [{ mind: other.address }, "/1/mind"],
      [{ seq: 2 }, "/1/seq"],
      [{ seq: 0 }, "/1/seq"],
      [{ prev: contentId(other.events[0]) }, "/1/prev"],
    ];
    for (const [members, path] of wrong) {
      const ada = new KeyMind("ada").raw(10, "Update", members);
      // seq 0 is refused by the schema, which knows a later event starts at 1.
      expect(refused(ada), path).toMatchObject({ path });
    }
    const ada = new KeyMind("ada").raw(10, "Update", { seq: 2 });
    expect(refused(ada).clause).toBe("L1 4.2");
  });

  it("requires each of them in a later event, and none of them in a genesis", () => {
    for (const missing of ["mind", "seq", "prev"]) {
      const ada = new KeyMind("ada").raw(10, "Update", { [missing]: undefined });
      expect(refused(ada).path, missing).toBe("/1");
    }
    const ada = new KeyMind("ada");
    for (const extra of [
      { mind: other.address },
      { seq: 0 },
      { prev: contentId(other.events[0]) },
    ]) {
      const genesis = rawSign({ ...ada.events[0], ...extra }, [{ control: ada.control(0) }]);
      expect(refusal(verifyEvents([genesis])).path).toBe("/0");
    }
  });

  it("refuses a created earlier than the event before, and accepts the same instant", () => {
    expect(refused(new KeyMind("ada", 10).update(9.999999999))).toMatchObject({
      clause: "L1 4.2",
      path: "/1/created",
    });
    expect(states(verified(new KeyMind("ada", 10).update(10)))).toHaveLength(2);
  });
});

describe(`${clause("L1 3.3")} version identifiers`, () => {
  it("is the position and the content ID of the event, 0 for the genesis", () => {
    const ada = new KeyMind("ada").update(10).update(20);
    expect(states(verified(ada)).map((state) => state.versionId)).toEqual(
      ada.events.map((event, position) => formatVersionId(position, contentId(event))),
    );
    expect(states(verified(ada)).map((state) => [state.seq, state.head])).toEqual(
      ada.events.map((event, position) => [position, contentId(event)]),
    );
  });
});

describe(`${clause("L1 3.4")} controllers`, () => {
  it("fixes the kind of controller at genesis", () => {
    const ada = new KeyMind("ada");
    const bob = new KeyMind("bob");
    ada.raw(10, "Update", { controller: { members: [bob.address], threshold: 1 } });
    expect(refused(ada, [bob])).toMatchObject({ clause: "L1 3.4", path: "/1/controller" });

    const club = new Collective("club", [bob], 1);
    const turned = rawSign(
      { ...draftUpdate(latestState(verified(club, [bob])), T(10)), controller: bob.controller(1) },
      [bob.asMember()],
    );
    club.events.push(turned);
    expect(refused(club, [bob])).toMatchObject({ clause: "L1 3.4", path: "/1/controller" });
  });

  it("requires a key-controlled mind's later event to carry a controller", () => {
    const ada = new KeyMind("ada").raw(10, "Update", { controller: undefined });
    expect(refused(ada)).toMatchObject({ clause: "L1 3.7", path: "/1/controller" });
  });

  it("takes nextThreshold as 1 when it is absent, and as 0 when nothing is committed", () => {
    const ada = new KeyMind("ada");
    expect(latestState(verified(ada)).controller).toEqual({
      kind: "key",
      next: [keyHash(ada.control(1).publicKey)],
      nextThreshold: 1,
    });
    const last = new KeyMind("last", 0, { controller: new KeyMind("last").controller(0, true) });
    expect(latestState(verified(last)).controller).toEqual({
      kind: "key",
      next: [],
      nextThreshold: 0,
    });
  });

  it("refuses a threshold that is not a majority, of keys or of members", () => {
    const keys = [1, 2, 3].map((n) => keyHash(signer(`ada/control/${n}`).publicKey));
    for (const [nextThreshold, accepted] of [
      [1, false],
      [2, true],
      [3, true],
      [4, false],
    ] as const) {
      const controller = { keys: new KeyMind("ada").controller(0).keys, next: keys, nextThreshold };
      const result = verifyEvents([rawGenesis("ada", { controller })]);
      expect(result.ok, `${nextThreshold} of 3`).toBe(accepted);
      if (!result.ok) expect(result.issues[0].clause).toBe("L1 3.4");
    }
    const members = ["a", "b", "c", "d"].map((name) => new KeyMind(name));
    for (const [threshold, accepted] of [
      [2, false],
      [3, true],
      [4, true],
    ] as const) {
      const club = new Collective("club", members, 3);
      const genesis = rawSign(
        { ...club.events[0], controller: { members: members.map((m) => m.address), threshold } },
        members.map((member) => member.asMember()),
      );
      const book = bookOf(members);
      const result = verifyLog([genesis], {
        evidence: witness([[genesis], ...members.map((member) => member.events)]),
        asOf: LATER,
        memberLog: (member) => book.log(member),
      });
      expect(result.ok, `${threshold} of 4`).toBe(accepted);
      if (!result.ok) expect(result.issues[0].clause).toBe("L1 3.4");
    }
  });

  it("refuses nextThreshold where nothing is committed", () => {
    const controller = { keys: new KeyMind("ada").controller(0).keys, next: [], nextThreshold: 1 };
    expect(refusal(verifyEvents([rawGenesis("ada", { controller })]))).toMatchObject({
      clause: "L1 3.4",
      path: "/0/controller/nextThreshold",
    });
  });

  it("refuses a mind as a member of itself", () => {
    const bob = new KeyMind("bob");
    const club = new Collective("club", [bob], 1);
    const state = latestState(verified(club, [bob]));
    const event = rawSign(
      {
        ...draftUpdate(state, T(10)),
        controller: { members: [bob.address, club.address], threshold: 2 },
      },
      [bob.asMember()],
    );
    club.events.push(event);
    expect(refused(club, [bob])).toMatchObject({
      clause: "L1 3.4",
      path: "/1/controller/members/1",
    });
  });

  it("refuses repeated keys, repeated members and unknown members of a controller", () => {
    const base = new KeyMind("ada");
    const key = base.control(0).publicKey;
    for (const controller of [
      { keys: [key, key], next: [] },
      { keys: [key], next: [keyHash(key), keyHash(key)], nextThreshold: 2 },
      { keys: [key], next: [], other: 1 },
    ]) {
      const genesis = rawSign({ ...base.events[0], controller }, [{ control: base.control(0) }]);
      expect(refusal(verifyEvents([genesis])).path).toMatch(/^\/0\/controller/);
    }
    const bob = new KeyMind("bob");
    const twice = new Collective("club", [bob], 1).events[0] as JsonObject;
    const genesis = rawSign(
      { ...twice, controller: { members: [bob.address, bob.address], threshold: 2 } },
      [bob.asMember()],
    );
    const book = bookOf([bob]);
    expect(
      refusal(
        verifyLog([genesis], {
          evidence: witness([[genesis as JsonObject], bob.events]),
          asOf: LATER,
          memberLog: (member) => book.log(member),
        }),
      ).path,
    ).toMatch(/^\/0\/controller/);
  });
});

describe(`${clause("L1 3.5")} key entries`, () => {
  it("keeps the three sets apart: no key is both operational and invocation", () => {
    const ada = new KeyMind("ada");
    const shared = ada.operational().publicKey;
    const within = rawGenesis("ada", { invocation: [{ key: shared }] });
    expect(refusal(verifyEvents([within]))).toMatchObject({ clause: "L1 3.5" });
    // Across events: the invocation set of the genesis still stands.
    ada.update(10, { keys: [{ key: ada.invocation().publicKey }] });
    expect(refused(ada)).toMatchObject({ clause: "L1 3.5", path: "/1" });
  });

  it("refuses a key twice in a set, a label over 64 characters and an unknown member", () => {
    const ada = new KeyMind("ada");
    const key = ada.operational().publicKey;
    for (const keys of [
      [{ key }, { key }],
      [{ key, label: "x".repeat(65) }],
      [{ key, colour: "red" }],
      [{ label: "no key" }],
    ]) {
      const genesis = rawSign({ ...ada.events[0], keys }, [{ control: ada.control(0) }]);
      expect(refusal(verifyEvents([genesis])).path).toMatch(/^\/0\/keys/);
    }
    const labelled = new KeyMind("ada", 0, { keys: [{ key, label: "x".repeat(64) }] });
    expect(latestState(verified(labelled)).keys).toEqual([key]);
  });

  it("holds at most 64 operational, 16 invocation and 16 agreement keys", () => {
    const many = (count: number, kind: string) =>
      Array.from({ length: count }, (_, n) => ({
        key: kind === "agreement" ? agreementKey(`k${n}`) : signer(`${kind}${n}`).publicKey,
      }));
    for (const [set, most] of [
      ["keys", 64],
      ["invocation", 16],
      ["agreement", 16],
    ] as const) {
      const within = new KeyMind("ada", 0, { [set]: many(most, set) });
      expect(latestState(verified(within))[set], set).toHaveLength(most);
      const base = new KeyMind("ada");
      const over = rawSign({ ...base.events[0], [set]: many(most + 1, set) }, [
        { control: base.control(0) },
      ]);
      expect(refusal(verifyEvents([over])).path, set).toBe(`/0/${set}`);
    }
  });

  it(`${clause("core 4.4")} refuses a key that is not a point of order L, wherever it is listed`, () => {
    // The identity point, as a Multikey: a well-formed string and no key.
    const identity = "z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP";
    for (const set of ["keys", "invocation"] as const) {
      const base = new KeyMind("ada");
      const genesis = rawSign({ ...base.events[0], [set]: [{ key: identity }] }, [
        { control: base.control(0) },
      ]);
      const issue = refusal(verifyEvents([genesis]));
      expect(issue, set).toMatchObject({ clause: "core 4.4", path: `/0/${set}/0/key` });
    }
  });
});

describe(`${clause("L1 3.6")} Genesis`, () => {
  it("names a kind: one of the five, or any other string of 1 to 64 characters", () => {
    for (const kind of ["human", "agent", "institution", "service", "robot", "x".repeat(64)]) {
      expect(latestState(verified(new KeyMind("ada", 0, { kind }))).kind).toBe(kind);
    }
    const base = new KeyMind("ada");
    for (const kind of ["", "x".repeat(65), 1, null]) {
      const genesis = rawSign({ ...base.events[0], kind }, [{ control: base.control(0) }]);
      expect(refusal(verifyEvents([genesis])).path).toBe("/0/kind");
    }
  });

  it("requires a collective to be member-controlled", () => {
    const base = new KeyMind("ada");
    const genesis = rawSign({ ...base.events[0], kind: "collective" }, [
      { control: base.control(0) },
    ]);
    expect(verifyEvents([genesis]).ok).toBe(false);
    const bob = new KeyMind("bob");
    // A member-controlled mind need not call itself a collective.
    const circle = new Collective("circle", [bob], 1, 0, { kind: "institution" });
    expect(latestState(verified(circle, [bob])).kind).toBe("institution");
  });

  it("allows height only in the genesis of a member-controlled mind", () => {
    const base = new KeyMind("ada");
    const genesis = rawSign({ ...base.events[0], height: 1 }, [{ control: base.control(0) }]);
    expect(verifyEvents([genesis]).ok).toBe(false);
    expect(refused(new KeyMind("ada").raw(10, "Update", { height: 1 })).path).toBe("/1");
  });

  it("starts the state from the genesis", () => {
    const parent = new KeyMind("parent");
    const ada = new KeyMind("ada", 0, {
      homes: ["https://ada.example", "https://backup.example:8443"],
      alsoKnownAs: ["dns:ada.example"],
      parents: [{ mind: parent.address, at: parent.versionId() }],
    });
    expect(latestState(verified(ada))).toMatchObject({
      kind: "agent",
      keys: [ada.operational().publicKey],
      invocation: [ada.invocation().publicKey],
      agreement: [agreementKey("ada/agreement/0")],
      homes: ["https://ada.example", "https://backup.example:8443"],
      alsoKnownAs: ["dns:ada.example"],
      parents: [{ mind: parent.address, at: parent.versionId() }],
      retired: false,
      seq: 0,
    });
  });
});

describe(`${clause("L1 3.7", "L1 4.5")} Update`, () => {
  it("replaces each set it states and leaves the others as they were", () => {
    const ada = new KeyMind("ada", 0, { homes: ["https://one.example"] });
    const before = latestState(verified(ada));
    ada.update(10, { keys: [{ key: ada.operational(1).publicKey }] });
    expect(latestState(verified(ada))).toMatchObject({
      keys: [ada.operational(1).publicKey],
      invocation: before.invocation,
      agreement: before.agreement,
      homes: before.homes,
    });
    ada.update(20, {
      invocation: [],
      agreement: [{ key: agreementKey("ada/agreement/1") }],
      homes: [],
      alsoKnownAs: ["dns:ada.example"],
    });
    expect(latestState(verified(ada))).toMatchObject({
      keys: [ada.operational(1).publicKey],
      invocation: [],
      agreement: [agreementKey("ada/agreement/1")],
      homes: [],
      alsoKnownAs: ["dns:ada.example"],
    });
  });

  it("removes a revoked key from the sets the event leaves out, and never lets it back", () => {
    const ada = new KeyMind("ada");
    const operational = ada.operational().publicKey;
    const invocation = ada.invocation().publicKey;
    ada.update(10, { revoked: [{ key: operational }, { key: invocation }] });
    const log = verified(ada);
    const state = latestState(log);
    expect(state.keys).toEqual([]);
    expect(state.invocation).toEqual([]);
    expect([...revokedAt(log, 1).keys()]).toEqual([operational, invocation]);
    expect(revokedAt(log, 0).size).toBe(0);
    expect(log.revocations).toEqual([
      { position: 1, key: operational, compromisedSince: undefined },
      { position: 1, key: invocation, compromisedSince: undefined },
    ]);
    for (const set of ["keys", "invocation"] as const) {
      for (const key of [operational, invocation]) {
        const again = new KeyMind("ada")
          .update(10, { revoked: [{ key: operational }, { key: invocation }] })
          .update(20, { [set]: [{ key }] });
        expect(refused(again), set).toMatchObject({ clause: "L1 4.5", path: "/2" });
      }
    }
  });

  it("refuses an event that revokes a key and keeps it", () => {
    const ada = new KeyMind("ada");
    const key = ada.operational().publicKey;
    ada.raw(10, "Update", { keys: [{ key }], revoked: [{ key }] });
    expect(refused(ada)).toMatchObject({ clause: "L1 4.5" });
  });

  it("keeps the earliest compromisedSince when a key is revoked more than once", () => {
    const ada = new KeyMind("ada");
    const key = ada.operational().publicKey;
    ada
      .update(10, { revoked: [{ key, compromisedSince: T(5) }] })
      .update(20, { revoked: [{ key, compromisedSince: T(3) }] })
      .update(30, { revoked: [{ key, compromisedSince: T(4) }] })
      .update(40, { revoked: [{ key }] });
    const log = verified(ada);
    expect([0, 1, 2, 3, 4].map((position) => revokedAt(log, position).get(key))).toEqual([
      undefined,
      parse(T(5)),
      parse(T(3)),
      parse(T(3)),
      parse(T(3)),
    ]);
    expect(compromisedSince(log, key)).toBe(parse(T(3)));
    expect(compromisedSince(log, ada.invocation().publicKey)).toBeUndefined();
    const plain = new KeyMind("bea");
    const other = plain.operational().publicKey;
    plain.update(10, { revoked: [{ key: other }] }).update(20, { revoked: [{ key: other }] });
    const revoked = revokedAt(verified(plain), 2);
    expect(revoked.has(other)).toBe(true);
    expect(revoked.get(other)).toBeUndefined();
    expect(compromisedSince(verified(plain), other)).toBeUndefined();
    // A time given once stands, whether the entry without one comes before or after.
    const late = new KeyMind("cy");
    const third = late.operational().publicKey;
    late
      .update(10, { revoked: [{ key: third }] })
      .update(20, { revoked: [{ key: third, compromisedSince: T(7) }] });
    expect(revokedAt(verified(late), 1).get(third)).toBeUndefined();
    expect(revokedAt(verified(late), 2).get(third)).toBe(parse(T(7)));
  });

  it("ignores revoked in a genesis, where there is nothing to revoke", () => {
    const base = new KeyMind("ada");
    const genesis = rawSign(
      { ...base.events[0], revoked: [{ key: base.operational().publicKey }] },
      [{ control: base.control(0) }],
    );
    const log = verifyEvents([genesis]);
    expect(log.ok && latestState(log.value).keys).toEqual([base.operational().publicKey]);
  });
});

describe(`${clause("L1 3.8")} Fork`, () => {
  it("records the child in the parent's own log", () => {
    const one = new KeyMind("one").address;
    const two = new KeyMind("two").address;
    const ada = new KeyMind("ada").fork(10, { child: one }).update(20).fork(30, { child: two });
    const log = verified(ada);
    expect(log.children).toEqual([
      { position: 1, child: one },
      { position: 3, child: two },
    ]);
    expect([0, 1, 2, 3].map((position) => childrenAt(log, position))).toEqual([
      [],
      [one],
      [one],
      [one, two],
    ]);
  });

  it("requires a child, and changes the sets an Update may change", () => {
    const ada = new KeyMind("ada").raw(10, "Fork", {});
    expect(refused(ada).path).toBe("/1");
    const bea = new KeyMind("bea");
    bea.fork(10, { child: ada.address, homes: ["https://bea.example"], terms: { funds: "half" } });
    expect(latestState(verified(bea)).homes).toEqual(["https://bea.example"]);
  });
});

describe(`${clause("L1 3.9")} Merge is reserved`, () => {
  it("refuses a log that contains a Merge", () => {
    const ada = new KeyMind("ada").raw(10, "Merge", { from: new KeyMind("other").address });
    expect(refused(ada)).toMatchObject({ clause: "L1 3.9", path: "/1/type" });
  });
});

describe(`${clause("L1 3.10", "L1 4.6")} Retire, and the types of events`, () => {
  it("ends the log: no event follows a Retire", () => {
    const ada = new KeyMind("ada").retire(10, {
      reason: "done",
      successor: new KeyMind("next").address,
    });
    expect(latestState(verified(ada)).retired).toBe(true);
    for (const type of ["Update", "Fork", "Retire"]) {
      const after = new KeyMind("ada").retire(10);
      after.raw(20, type, { child: after.address, controller: after.controller(2, true) });
      expect(refused(after), type).toMatchObject({ clause: "L1 4.6", path: "/2" });
    }
  });

  it("commits a key-controlled mind to no further keys", () => {
    const ada = new KeyMind("ada");
    ada.raw(10, "Retire", { controller: ada.controller(1) });
    expect(refused(ada).path).toMatch(/^\/1/);
  });

  it("retires a member-controlled mind by its threshold", () => {
    const members = [new KeyMind("a"), new KeyMind("b"), new KeyMind("c")];
    const club = new Collective("club", members, 2).retire(10, members.slice(0, 2));
    expect(latestState(verified(club, members)).retired).toBe(true);
    club.update(20, members);
    expect(refused(club, members)).toMatchObject({ clause: "L1 4.6" });
  });

  it("refuses an event of any other type", () => {
    for (const type of ["Rename", "genesis", "Intent", "", 1, null, undefined]) {
      const ada = new KeyMind("ada").raw(10, type as string);
      expect(refused(ada), String(type)).toMatchObject({ clause: "L1 4.6", path: "/1/type" });
    }
  });
});

describe(`${clause("L1 3.12")} recovery is reserved`, () => {
  it("refuses an event that contains it, whatever its value", () => {
    for (const recovery of [null, true, {}, "later"]) {
      const ada = new KeyMind("ada").raw(10, "Update", { recovery });
      expect(refused(ada)).toMatchObject({ clause: "L1 3.12", path: "/1/recovery" });
      const base = new KeyMind("bea");
      const genesis = rawSign({ ...base.events[0], recovery }, [{ control: base.control(0) }]);
      expect(refusal(verifyEvents([genesis]))).toMatchObject({ clause: "L1 3.12" });
    }
  });

  it("is reserved at the top of an event only", () => {
    const ada = new KeyMind("ada", 0, { inherits: { recovery: "a word like any other" } });
    expect(states(verified(ada))).toHaveLength(1);
  });
});

describe(`${clause("L1 4", "L1 4.1")} the genesis is signed by everyone it names`, () => {
  it("requires a proof by every control key, each with its own control-key-ref", () => {
    const base = new KeyMind("ada");
    const second = signer("ada/second");
    const controller = { keys: [base.control(0).publicKey, second.publicKey], next: [] };
    const draft = draftGenesis(T(0), { kind: "agent", controller });
    const both = signEventSync(draft, [{ control: base.control(0) }, { control: second }]);
    expect(verifyEvents([both]).ok).toBe(true);
    for (const by of [base.control(0), second]) {
      const one = signEventSync(draft, [{ control: by }]);
      expect(refusal(verifyEvents([one]))).toMatchObject({ clause: "L1 4.1", path: "/0/proof" });
    }
  });

  it(`${clause("core 6.2")} does not take a key-ref, or another purpose, for a control key's proof`, () => {
    const ada = new KeyMind("ada");
    const genesis = ada.events[0] as JsonObject;
    const asMember = rawSign(genesis, [
      { member: ada.address, versionId: ada.versionId(), invocation: ada.control(0) },
    ]);
    expect(refusal(verifyEvents([asMember])).clause).toBe("L1 4.1");
    const asserted = rawSign(genesis, [{ control: ada.control(0) }], {
      purpose: "assertionMethod",
    });
    expect(refusal(verifyEvents([asserted])).clause).toBe("L1 4.1");
  });

  it("does not verify once any member of the genesis is changed", () => {
    const ada = new KeyMind("ada", 0, { homes: ["https://ada.example"] });
    for (const change of [{ kind: "human" }, { homes: [] }, { created: T(1) }]) {
      const changed = { ...copy(ada.events[0]), ...change };
      expect(refusal(verifyEvents([changed])).clause).toBe("L1 4.1");
    }
  });

  it("requires a proof by every founding member, with one of its invocation keys", () => {
    const members = [new KeyMind("a"), new KeyMind("b"), new KeyMind("c")];
    const club = new Collective("club", members, 2);
    expect(states(verified(club, members))).toHaveLength(1);
    // The threshold is for later events. A founder cannot be named without its consent.
    const genesis = club.events[0] as JsonObject;
    const two = rawSign(
      genesis,
      members.slice(0, 2).map((member) => member.asMember()),
    );
    const book = bookOf(members);
    const context = {
      evidence: witness([[two], ...members.map((member) => member.events)]),
      asOf: LATER,
      memberLog: (member: string) => book.log(member),
    };
    expect(refusal(verifyLog([two], context))).toMatchObject({
      clause: "L1 4.1",
      path: "/0/proof",
    });
    // Without the members' logs nothing can be judged.
    const { memberLog: _, ...alone } = context;
    expect(refusal(verifyLog([genesis], alone)).clause).toBe("L1 6.3");
  });
});

describe(`${clause("L1 4.3")} a key-controlled mind's events are signed by the keys committed before`, () => {
  it("refuses a key that was not committed to, however well it signs", () => {
    const ada = new KeyMind("ada");
    const intruder = signer("intruder");
    const forged = draftUpdate(latestState(verified(ada)), T(10), {
      controller: { keys: [intruder.publicKey], next: [] },
      keys: [{ key: intruder.publicKey }],
    });
    ada.events.push(signEventSync(forged, [{ control: intruder }]));
    expect(refused(ada)).toMatchObject({ clause: "L1 4.3", path: "/1/controller/keys/0" });
  });

  it("refuses a committed key that did not sign", () => {
    const ada = new KeyMind("ada");
    const event = draftUpdate(latestState(verified(ada)), T(10), { controller: ada.controller(1) });
    ada.events.push(signEventSync(event, [{ control: ada.control(0) }]));
    expect(refused(ada)).toMatchObject({ clause: "L1 4.3", path: "/1/proof" });
  });

  it("refuses to extend a log whose last event committed to nothing", () => {
    const base = new KeyMind("ada");
    const ada = new KeyMind("ada", 0, { controller: base.controller(0, true) });
    ada.raw(10, "Update", { controller: { keys: [ada.control(1).publicKey], next: [] } });
    expect(refused(ada)).toMatchObject({ clause: "L1 4.3", path: "/1" });
  });

  it("counts distinct keys against the threshold: 2 of 3, in any order", () => {
    const keys = [1, 2, 3].map((n) => signer(`ada/next/${n}`));
    const base = new KeyMind("ada");
    const ada = new KeyMind("ada", 0, {
      controller: {
        keys: base.controller(0).keys,
        next: keys.map((key) => keyHash(key.publicKey)),
        nextThreshold: 2,
      },
    });
    const state = latestState(verified(ada));
    const update = (revealed: typeof keys, signers = revealed) =>
      verifyEvents([
        ada.events[0],
        rawSign(
          draftUpdate(state, T(10), {
            controller: { keys: revealed.map((key) => key.publicKey), next: [] },
          }),
          signers.map((control) => ({ control })),
        ),
      ]);
    const [one, two, three] = keys as [(typeof keys)[0], (typeof keys)[0], (typeof keys)[0]];
    expect(update([one, two]).ok).toBe(true);
    expect(update([three, one]).ok).toBe(true);
    expect(update([one, two, three]).ok).toBe(true);
    expect(refusal(update([two]))).toMatchObject({ clause: "L1 4.3", path: "/1/controller/keys" });
    // Revealed and not signing: every revealed key signs.
    expect(refusal(update([one, two], [one]))).toMatchObject({
      clause: "L1 4.3",
      path: "/1/proof",
    });
    // One key listed twice is one key. The schema refuses the list.
    expect(update([one, one]).ok).toBe(false);
  });

  it("takes the next commitment from each event in turn", () => {
    const ada = new KeyMind("ada").update(10).update(20);
    expect(states(verified(ada)).map((state) => state.controller)).toEqual(
      [1, 2, 3].map((n) => ({
        kind: "key",
        next: [keyHash(ada.control(n).publicKey)],
        nextThreshold: 1,
      })),
    );
    // A control key signs one event: the one after next refuses it.
    const stale = new KeyMind("bea").update(10);
    stale.raw(20, "Update", { controller: stale.controller(1) });
    expect(refused(stale).clause).toBe("L1 4.3");
  });
});

describe(`${clause("L1 4.4")} a member-controlled mind's events are signed by its members`, () => {
  const [a, b, c, d] = ["a", "b", "c", "d"].map((name) => new KeyMind(name)) as [
    KeyMind,
    KeyMind,
    KeyMind,
    KeyMind,
  ];
  const everyone = [a, b, c, d];

  it("requires the threshold of the current members", () => {
    const club = () => new Collective("club", [a, b, c], 2);
    expect(states(verified(club().update(10, [a, b]), everyone))).toHaveLength(2);
    expect(states(verified(club().update(10, [c, a, b]), everyone))).toHaveLength(2);
    expect(refused(club().update(10, [a]), everyone)).toMatchObject({
      clause: "L1 4.4",
      path: "/1/proof",
    });
    // An outsider's proof is not a member's, and one member signing twice is one member.
    expect(refused(club().update(10, [a, d]), everyone).clause).toBe("L1 4.4");
    expect(refused(club().update(10, [a, a]), everyone).clause).toBe("L1 4.4");
  });

  it("requires every added member to sign, and no member that leaves", () => {
    const controller = { members: [a.address, b.address, d.address], threshold: 2 };
    const club = () => new Collective("club", [a, b, c], 2);
    const joined = club().update(10, [a, b, d], { controller });
    expect(latestState(verified(joined, everyone)).controller).toEqual({
      kind: "member",
      ...controller,
    });
    expect(refused(club().update(10, [a, b], { controller }), everyone)).toMatchObject({
      clause: "L1 4.4",
      path: "/1/proof",
    });
    // The added member's proof does not count towards the threshold of the members before it.
    expect(refused(club().update(10, [a, d], { controller }), everyone).clause).toBe("L1 4.4");
    // From the next event on, the new membership signs.
    expect(states(verified(joined.update(20, [b, d]), everyone))).toHaveLength(3);
    const gone = club().update(10, [a, b, d], { controller }).update(20, [a, c]);
    expect(refused(gone, everyone)).toMatchObject({ clause: "L1 4.4", path: "/2/proof" });
  });

  it("keeps the members when an event carries no controller", () => {
    const club = new Collective("club", [a, b, c], 2).update(10, [a, b], {
      homes: ["https://club.example"],
    });
    const log = verified(club, everyone);
    expect(states(log)[1]?.controller).toEqual(states(log)[0]?.controller);
    expect(latestState(log).homes).toEqual(["https://club.example"]);
  });
});

describe(`${clause("L1 4.7")} nesting and work`, () => {
  const people = ["a", "b", "c"].map((name) => new KeyMind(name));

  it("gives a key-controlled mind height 0 and a collective one more than its tallest founder", () => {
    const [a, b] = people as [KeyMind, KeyMind, KeyMind];
    expect(verified(a).height).toBe(0);
    const club = new Collective("club", [a, b], 2);
    expect(verified(club, people).height).toBe(1);
    const league = new Collective("league", [club, a], 2);
    expect(verified(league, [club, ...people]).height).toBe(2);
  });

  it("lets a genesis declare a greater height, up to 4, and never a lesser one", () => {
    const [a, b] = people as [KeyMind, KeyMind, KeyMind];
    for (const height of [1, 2, 3, 4]) {
      const club = new Collective("club", [a, b], 2, 0, { height });
      expect(verified(club, people).height).toBe(height);
    }
    const club = new Collective("club", [a, b], 2);
    const low = new Collective("league", [club, a], 2, 0, { height: 1 });
    expect(refused(low, [club, ...people])).toMatchObject({ clause: "L1 4.7", path: "/0/height" });
    for (const height of [0, 5]) {
      const genesis = rawSign({ ...club.events[0], height }, [a.asMember(), b.asMember()]);
      const book = bookOf(people);
      const result = verifyLog([genesis], {
        evidence: witness([[genesis], a.events, b.events]),
        asOf: LATER,
        memberLog: (member) => book.log(member),
      });
      expect(refusal(result).path, `${height}`).toBe("/0/height");
    }
  });

  it("refuses a later event that relies on a member as tall as the collective", () => {
    const [a, b, c] = people as [KeyMind, KeyMind, KeyMind];
    const inner = new Collective("inner", [c], 1);
    const outer = () => new Collective("outer", [a, b], 2);
    const controller = { members: [a.address, b.address, inner.address], threshold: 2 };
    const all = [inner, ...people];
    // inner has height 1, and so has outer: inner cannot join it.
    expect(refused(outer().update(10, [a, b, inner], { controller }), all)).toMatchObject({
      clause: "L1 4.7",
      path: "/1/proof",
    });
    const roomy = new Collective("outer", [a, b], 2, 0, { height: 2 });
    expect(verified(roomy.update(10, [a, b, inner], { controller }), all).height).toBe(2);
  });

  it("verifies four levels of member logs, and no collective that contains itself", () => {
    const [a] = people as [KeyMind, KeyMind, KeyMind];
    const levels: Mind[] = [a];
    for (let height = 1; height <= 4; height++) {
      levels.push(new Collective(`level ${height}`, [levels[height - 1]!], 1));
    }
    expect(verified(levels[4]!, levels).height).toBe(4);
    // A fifth level would need height 5.
    const fifth = new Collective("level 5", [levels[4]!], 1);
    expect(refused(fifth, levels)).toMatchObject({ clause: "L1 4.7" });

    // Two collectives that each admit the other: neither can be verified.
    const [b, c] = [people[1]!, people[2]!];
    const left = new Collective("left", [b], 1, 0, { height: 3 });
    const right = new Collective("right", [c], 1, 0, { height: 2 });
    left.update(10, [b, right], {
      controller: { members: [b.address, right.address], threshold: 2 },
    });
    right.update(20, [c, left], {
      controller: { members: [c.address, left.address], threshold: 2 },
    });
    const all = [left, right, b, c];
    expect(refused(right, all).clause).toBe("L1 4.7");
    expect(refused(left, all).clause).toBe("L1 4.7");
    // Asked in the other order, the answers are the same.
    const book = bookOf(all);
    expect(refusal(book.log(left.address)).clause).toBe("L1 4.7");
    expect(refusal(book.log(right.address)).clause).toBe("L1 4.7");
  });

  it("reads logs of 1,000 events at least, and as many as it is set to", () => {
    expect(MIN_ACCEPTED_LOG_EVENTS).toBe(1000);
    expect(MAX_LOG_EVENTS).toBeGreaterThanOrEqual(MIN_ACCEPTED_LOG_EVENTS);
    const ada = new KeyMind("ada");
    // Only the count is judged here: the events after the first are never read.
    const long = (length: number) => Array.from({ length }, () => ada.events[0]);
    const context = { evidence: witness([ada.events]), asOf: LATER };
    const limit = (events: unknown[], maxEvents?: number) =>
      refusal(verifyLog(events, maxEvents === undefined ? context : { ...context, maxEvents }));
    expect(limit(long(MAX_LOG_EVENTS + 1)).clause).toBe("implementation limit");
    expect(limit(long(MAX_LOG_EVENTS)).clause).toBe("L1 4.6");
    expect(limit(long(1001), 1000).clause).toBe("implementation limit");
    // A verifier may not be set to refuse a log of 1,000 events.
    expect(limit(long(1000), 10).clause).toBe("L1 4.6");
    expect(limit(long(1001), 10).clause).toBe("implementation limit");
    for (const notCount of [-1, 1.5, Number.NaN, "5"]) {
      expect(limit(long(MAX_LOG_EVENTS + 1), notCount as number).clause).toBe(
        "implementation limit",
      );
      expect(limit(long(MAX_LOG_EVENTS), notCount as number).clause).toBe("L1 4.6");
    }
    // A book keeps the events before an invalid one: here that is the first, whatever the length.
    const book = new LogBook(witness([ada.events]), { maxEvents: 1000 });
    book.hold(long(1001), LATER);
    expect(book.log(ada.address)).toMatchObject({ ok: true, value: { entries: { length: 1 } } });
  });
});

describe(`${clause("L1 6.4", "L1 9.2", "L1 9.3")} the members' proofs on a collective's events`, () => {
  const [a, b, c] = ["a", "b", "c"].map((name) => new KeyMind(name)) as [KeyMind, KeyMind, KeyMind];

  it("refuses a proof pinned to a version the member's log does not have", () => {
    const longer = new KeyMind("a").update(5);
    const genesis = signEventSync(
      draftGenesis(T(10), {
        kind: "collective",
        controller: { members: [a.address, b.address], threshold: 2 },
      }),
      [longer.asMember(), b.asMember()],
    );
    const book = bookOf([a, b]);
    const context = {
      evidence: witness([[genesis], longer.events, b.events]),
      asOf: LATER,
      memberLog: (member: string) => book.log(member),
    };
    expect(refusal(verifyLog([genesis], context))).toMatchObject({
      clause: "L1 6.4",
      path: "/0/proof/0",
    });
    const known = bookOf([longer, b]);
    expect(verifyLog([genesis], { ...context, memberLog: (member) => known.log(member) }).ok).toBe(
      true,
    );
  });

  it("counts a member once, by its first proof that counts, and reports its first that does not", () => {
    const club = new Collective("club", [a, b, c], 2);
    const head = { mind: club.address, seq: 0, head: contentId(club.events[0]) };
    const operational = {
      member: a.address,
      versionId: a.versionId(),
      invocation: a.operational(),
    };
    const stranger = { member: a.address, versionId: a.versionId(), invocation: signer("x") };
    const event = (signers: Parameters<typeof signEventSync>[1]) => {
      const tried = new Collective("club", [a, b, c], 2);
      tried.events.push(signEventSync(draftUpdate(head, T(10)), signers));
      return verifyMind(tried, [a, b, c]);
    };
    // Two proofs of a's that do not count: the first is the one reported.
    expect(refusal(event([operational, stranger, b.asMember()]))).toMatchObject({
      clause: "L1 6.4",
      path: "/1/proof/0",
    });
    // With a's proofs alone, one member has signed where two must: the event shows that much itself.
    expect(refusal(event([operational, stranger]))).toMatchObject({
      clause: "L1 4.4",
      path: "/1/proof",
    });
    // A bad proof beside a good one by the same member does no harm, in either order.
    expect(event([operational, a.asMember(), b.asMember()]).ok).toBe(true);
    expect(event([a.asMember(), operational, b.asMember()]).ok).toBe(true);
    // One good proof is not a threshold of two, and nothing was refused: the count is the reason.
    expect(refusal(event([a.asMember()]))).toMatchObject({ clause: "L1 4.4", path: "/1/proof" });
  });

  it("refuses a height that is not declared and would be over 4", () => {
    const tall = new Collective("tall", [a], 1, 0, { height: 4 });
    const over = new Collective("over", [tall], 1, 10);
    expect(refused(over, [tall, a])).toMatchObject({ clause: "L1 4.7", path: "/0" });
  });
});

describe(`${clause("L1 4.8")} every event is a well-formed record`, () => {
  it("refuses a log with an event that breaks a limit of Section 3, whoever signed it", () => {
    const origins = (count: number) =>
      Array.from({ length: count }, (_, n) => `https://home${n}.example`);
    const aliases = (count: number) =>
      Array.from({ length: count }, (_, n) => `dns:name${n}.example`);
    const accepted: JsonObject[] = [
      { homes: origins(8) },
      { alsoKnownAs: aliases(16) },
      { expires: "2027-01-01T00:00:00Z" },
      { note: "a member no reader of this revision knows" },
    ];
    const broken: [JsonObject, string][] = [
      [{ homes: origins(9) }, "/homes"],
      [{ alsoKnownAs: aliases(17) }, "/alsoKnownAs"],
      [{ expires: "2026-13-01T00:00:00Z" }, "/expires"],
      [{ ext: { "not a namespace": {} } }, "/ext"],
      [{ parents: [{ mind: "did:oip:nobody", at: "0-x" }] }, "/parents/0/mind"],
      [{ inherits: "everything" }, "/inherits"],
    ];
    for (const members of accepted) {
      // In the genesis, and in a later event.
      expect(verifyEvents([rawGenesis("ada", members)]).ok, JSON.stringify(members)).toBe(true);
    }
    for (const [members, path] of broken) {
      expect(refusal(verifyEvents([rawGenesis("ada", members)])).path).toBe(`/0${path}`);
    }
    for (const [members, path] of broken.slice(0, 4)) {
      const ada = new KeyMind("ada").raw(10, "Update", members);
      expect(refused(ada).path, path).toBe(`/1${path}`);
    }
  });

  it(`${clause("L1 3.7", "L1 19")} refuses an event that revokes more than 80 keys`, () => {
    const revoking = (count: number) =>
      new KeyMind("ada").raw(10, "Update", {
        revoked: Array.from({ length: count }, (_, n) => ({ key: signer(`old/${n}`).publicKey })),
      });
    expect(verifyEvents(revoking(80).events).ok).toBe(true);
    expect(refused(revoking(81))).toMatchObject({ path: "/1/revoked" });
  });

  it("applies the rules of core to each event: the JSON profile, the size, the proof set", () => {
    const ada = new KeyMind("ada").update(10);
    const context = { evidence: witness([ada.events]), asOf: LATER };
    const second = ada.events[1] as unknown as JsonObject;
    for (const [event, clauseId] of [
      [{ ...second, ext: { "com.example": { n: 1.5 } } }, "core 1.2"],
      [{ ...second, proof: [] }, "core 5.1"],
      [{ ...second, proof: "signed" }, "core 5.1"],
      [{ ...second, oip: "2" }, "core 7"],
    ] as const) {
      expect(refusal(verifyLog([ada.events[0], event], context)).clause).toBe(clauseId);
    }
  });
});

describe(`${clause("L1 3.13")} HTTPS origins`, () => {
  it("is https://, a host and an optional port, in ASCII letters, digits and . - : [ ]", () => {
    for (const home of [
      "https://example.com",
      "https://EXAMPLE.com",
      "https://example.com:8443",
      "https://example.com:443",
      "https://xn--bcher-kva.example",
      "https://127.0.0.1",
      "https://[2001:db8::1]:8443",
      "https://localhost",
    ]) {
      expect(verifyEvents([rawGenesis("ada", { homes: [home] })]).ok, home).toBe(true);
    }
    for (const home of [
      "http://example.com",
      "https://",
      "https://example.com/",
      "https://example.com/path",
      "https://example.com?q=1",
      "https://example.com#f",
      "https://user@example.com",
      "https://example.com ",
      " https://example.com",
      "https://bücher.example",
      "https://exa_mple.com",
      "https://example.com\n",
      "HTTPS://example.com",
      "example.com",
      "",
      5,
    ]) {
      const result = verifyEvents([rawGenesis("ada", { homes: [home] })]);
      expect(refusal(result).path, String(home)).toBe("/0/homes/0");
    }
  });
});

describe("what a long log costs", () => {
  it("keeps each state of bounded size: what grows with the log is held once, by the log", () => {
    const ada = new KeyMind("ada");
    const child = new KeyMind("child").address;
    for (let n = 1; n <= 60; n++) {
      const revoked = [{ key: signer(`ada/old/${n}`).publicKey }];
      if (n % 2 === 0) ada.fork(n, { child, revoked });
      else ada.update(n, { revoked });
    }
    const log = verified(ada);
    expect(log.children).toHaveLength(30);
    expect(log.revocations).toHaveLength(60);
    expect(revokedAt(log, 60).size).toBe(60);
    // The last state is no larger than the first: no state carries the history.
    const size = (state: object) =>
      JSON.stringify(state, (_, value: unknown) => (typeof value === "bigint" ? `${value}` : value))
        .length;
    const sizes = states(log).map(size);
    expect(Math.max(...sizes) - Math.min(...sizes)).toBeLessThan(8);
    expect(Object.keys(latestState(log)).sort()).toEqual(Object.keys(states(log)[0] ?? {}).sort());
    // Sets that an event does not state are the same arrays as before, not copies.
    expect(states(log)[60]?.agreement).toBe(states(log)[0]?.agreement);
    expect(states(log)[60]?.parents).toBe(states(log)[0]?.parents);
  });
});

describe("a log is judged, never trusted", () => {
  it("answers and does not throw, whatever it is given", () => {
    const hostile = new Proxy([], {
      get() {
        throw new Error("boom");
      },
    });
    const evidence = new FirstSeen();
    for (const events of [
      hostile,
      [hostile],
      [
        {
          get type() {
            throw new Error("boom");
          },
        },
      ],
    ]) {
      expect(verifyLog(events, { evidence, asOf: LATER }).ok).toBe(false);
    }
    const book = new LogBook(evidence);
    expect(book.hold(hostile, LATER).ok).toBe(false);
    expect(book.hold([{ a: 0.5 }], LATER).ok).toBe(false);
    expect(book.hold([], LATER).ok).toBe(false);
  });

  it("returns copies: changing the events given afterwards changes nothing verified", () => {
    const ada = new KeyMind("ada").update(10);
    const given = copy(ada.events) as unknown as JsonObject[];
    const log = verifyEvents(given);
    if (!log.ok) throw new Error("the log does not verify");
    (given[1] as { created: string }).created = T(99);
    expect(events(log.value)[1]?.created).toBe(T(10));
  });

  it(`${clause("core 1.4")} refuses an event dated on a day that does not exist`, () => {
    const ada = new KeyMind("ada");
    const genesis = rawSign({ ...ada.events[0], created: "2026-02-30T00:00:00Z" }, [
      { control: ada.control(0) },
    ]);
    const evidence = new FirstSeen();
    evidence.sawEvent(contentId(genesis), 0n);
    expect(refusal(verifyLog([genesis], { evidence, asOf: LATER }))).toMatchObject({
      clause: "core 1.4",
    });
  });

  it("answers and does not throw with the stack all but spent", () => {
    const ada = new KeyMind("ada").update(10);
    const evidence = witness([ada.events]);
    const answers = withStackSpent(() => verifyLog(ada.events, { evidence, asOf: LATER }));
    expect(answers).toHaveLength(200);
    for (const answer of answers) {
      if (!answer.ok) expect(answer.issues[0].message.length).toBeGreaterThan(0);
    }
    expect(verifyLog(ada.events, { evidence, asOf: LATER }).ok).toBe(true);
  });

  it("refuses a log whose size or shape breaks the rules for any record", () => {
    const ada = new KeyMind("ada");
    ada.raw(10, "Update", { ext: { "com.example.padding": { blob: "x".repeat(1_100_000) } } });
    expect(refused(ada)).toMatchObject({ clause: "core 1.6", path: "/1" });
    // A number that is not an integer has no canonical form, so nothing signs it.
    const bea = new KeyMind("bea").update(10);
    const float = { ...bea.events[1], ext: { "com.example": { n: 0.5 } } };
    const context = { evidence: witness([bea.events]), asOf: LATER };
    expect(refusal(verifyLog([bea.events[0], float], context))).toMatchObject({
      clause: "core 1.2",
      path: "/1",
    });
  });
});

const parse = (timestamp: string) => parseTimestamp(timestamp);

describe(`${clause("core 8.3")} an event that depends on an extension the verifier does not implement`, () => {
  const extension = { ext: { "com.example.recovery": { v: 1 } } };
  const critical = { ...extension, critical: ["com.example.recovery"] };

  it("is not treated as valid, so its log is rejected", () => {
    const genesis = rawGenesis("ada", critical);
    const evidence = witness([[genesis]]);
    expect(refusal(verifyLog([genesis], { evidence, asOf: LATER }))).toMatchObject({
      clause: "core 8.3",
      path: "/0/critical",
    });
    // In a later event, whose keys would otherwise be the mind's.
    const bea = new KeyMind("bea").raw(10, "Update", {
      ...critical,
      keys: [{ key: signer("thief").publicKey }],
    });
    expect(refused(bea)).toMatchObject({ clause: "core 8.3", path: "/1/critical" });
    // An extension that is not critical changes nothing (core 8.4).
    expect(verifyEvents([rawGenesis("ada", extension)]).ok).toBe(true);
  });

  it("is accepted by a verifier that says it implements the extension, and by no other", () => {
    const genesis = rawGenesis("ada", critical);
    const evidence = witness([[genesis]]);
    const verify = (understood: unknown) =>
      verifyLog([genesis], { evidence, asOf: LATER, understood: understood as string[] }).ok;
    expect(verify(["com.example.recovery"])).toBe(true);
    expect(verify(new Set(["com.example.other", "com.example.recovery"]))).toBe(true);
    expect(verify(["com.example.other"])).toBe(false);
    expect(verify([])).toBe(false);
    // What is no list of names names nothing.
    for (const junk of [5, "com.example.recovery".length, null, { length: 1 }, [["x"]]]) {
      expect(verify(junk)).toBe(false);
    }
    const book = new LogBook(evidence, { understood: ["com.example.recovery"] });
    book.hold([genesis], LATER);
    expect(book.log(`did:oip:${contentId(genesis)}`).ok).toBe(true);
    const strict = new LogBook(evidence);
    strict.hold([genesis], LATER);
    expect(refusal(strict.log(`did:oip:${contentId(genesis)}`)).clause).toBe("core 8.3");
  });
});

describe(`${clause("core 9.3", "core 9.6")} the proofs on an event are judged at the event's time`, () => {
  it("does not count a proof dated more than 300 seconds after the evidence for its event", () => {
    const ada = new KeyMind("ada");
    const update = draftUpdate(ada.head, T(10), { controller: ada.controller(1) });
    const dated = (seconds: number) =>
      rawSign(update, [{ control: ada.control(1) }], { created: T(seconds) });
    // The event was seen at 10. A proof dated 310 is at the limit; one a nanosecond later is past it.
    expect(verifyEvents([ada.events[0], dated(310)]).ok).toBe(true);
    expect(refusal(verifyEvents([ada.events[0], dated(310.000000001)]))).toMatchObject({
      clause: "L1 4.3",
      path: "/1/proof",
    });
    // A member's proof likewise.
    const [a, b] = [new KeyMind("a"), new KeyMind("b")];
    const club = new Collective("club", [a, b], 2);
    const change = draftUpdate(club.head, T(10));
    const signed = (seconds: number) => [
      ...club.events,
      {
        ...change,
        proof: [
          ...rawSign(change, [a.asMember()]).proof,
          ...rawSign(change, [b.asMember()], { created: T(seconds) }).proof,
        ],
      },
    ];
    const verify = (events: readonly unknown[]) => {
      const book = bookOf([a, b]);
      return verifyLog(events, {
        evidence: witness([events as JsonObject[]]),
        asOf: LATER,
        memberLog: (mind) => book.log(mind),
      });
    };
    expect(verify(signed(310)).ok).toBe(true);
    expect(refusal(verify(signed(310.000000001)))).toMatchObject({
      clause: "L1 4.4",
      path: "/1/proof",
    });
  });

  it("refuses an event evaluated more than 300 seconds after it expires", () => {
    const expiring = (expires: number) => rawGenesis("ada", { expires: T(expires) }, 1000);
    // Seen when it was made, at 1000.
    expect(verifyEvents([expiring(2000)]).ok).toBe(true);
    expect(verifyEvents([expiring(700)]).ok).toBe(true);
    expect(refusal(verifyEvents([expiring(699.999999999)]))).toMatchObject({
      clause: "core 9.6",
      path: "/0/expires",
    });
    // The time is the evidence's, not the one the signer wrote.
    const genesis = rawGenesis("ada", { expires: T(100) });
    const seenAt = (seconds: number) => {
      const evidence = new FirstSeen();
      evidence.sawEvent(contentId(genesis), at(seconds));
      return verifyLog([genesis], { evidence, asOf: LATER });
    };
    expect(seenAt(400).ok).toBe(true);
    expect(refusal(seenAt(400.000000001))).toMatchObject({
      clause: "core 9.6",
      path: "/0/expires",
    });
    // A later event that expires does not take the log's earlier events with it, but the log is refused.
    const bea = new KeyMind("bea").raw(1000, "Update", { expires: T(600) });
    expect(refused(bea)).toMatchObject({ clause: "core 9.6", path: "/1/expires" });
  });

  it("measures a proof's date from the evidence for the event, not from the event's time", () => {
    // Dated 300 and seen at 100: the evidence is 100, and the event's time is 300.
    const ada = new KeyMind("ada");
    const update = draftUpdate(ada.head, T(300), { controller: ada.controller(1) });
    const proved = (seconds: number) => {
      const events = [
        ada.events[0],
        rawSign(update, [{ control: ada.control(1) }], { created: T(seconds) }),
      ];
      const evidence = witness([[ada.events[0] as JsonObject]]);
      evidence.sawEvent(contentId(update), at(100));
      return verifyLog(events, { evidence, asOf: LATER });
    };
    expect(proved(400).ok).toBe(true);
    // 300 seconds after the event's own time would be 600.
    expect(refusal(proved(400.000000001))).toMatchObject({ clause: "L1 4.3", path: "/1/proof" });
  });

  it("measures expiry from the event's time, which the event before it can make later", () => {
    // The third event is dated 20, seen at 20, and expires at 100.
    const ada = new KeyMind("ada").update(10).raw(20, "Update", { expires: T(100) });
    const secondSeenAt = (seconds: number) => {
      const evidence = witness([[ada.events[0] as JsonObject, ada.events[2] as JsonObject]]);
      evidence.sawEvent(contentId(ada.events[1]!), at(seconds));
      return verifyLog(ada.events, { evidence, asOf: LATER });
    };
    // No event takes effect before the one it follows (core 9.5), so the third is judged then.
    expect(secondSeenAt(400).ok).toBe(true);
    expect(refusal(secondSeenAt(400.000000001))).toMatchObject({
      clause: "core 9.6",
      path: "/2/expires",
    });
  });
});

describe(`${clause("L1 9.5", "core 9.5")} the state of a mind at a time`, () => {
  it("is the state after the last event at or before that time, in a log of any length", () => {
    for (let length = 1; length <= 9; length++) {
      const ada = new KeyMind("ada");
      for (let n = 1; n < length; n++) ada.update(n * 10);
      const log = verified(ada);
      expect(stateAt(log, at(0) - 1n), "before the mind existed").toBeUndefined();
      log.entries.forEach((entry, n) => {
        expect(stateAt(log, entry.time)).toBe(entry.state);
        expect(stateAt(log, entry.time + 1n)).toBe(entry.state);
        expect(stateAt(log, entry.time - 1n)).toBe(log.entries[n - 1]?.state);
      });
      expect(stateAt(log, LATER)).toBe(log.entries.at(-1)?.state);
    }
  });

  it("is the later state, where two events take effect at one time", () => {
    // The second event was first seen at 400, so the third, dated 20, takes effect then too.
    const ada = new KeyMind("ada").update(10).update(20);
    const evidence = witness([[ada.events[0] as JsonObject, ada.events[2] as JsonObject]]);
    evidence.sawEvent(contentId(ada.events[1]!), at(400));
    const result = verifyLog(ada.events, { evidence, asOf: LATER });
    if (!result.ok) throw new Error(JSON.stringify(result.issues));
    const [first, second, third] = result.value.entries;
    expect([second?.time, third?.time]).toStrictEqual([at(400), at(400)]);
    expect(stateAt(result.value, at(400))).toBe(third?.state);
    expect(stateAt(result.value, at(400) - 1n)).toBe(first.state);
  });
});

describe(`${clause("L1 6.4", "core 9.4")} whose proof counts on a collective's event`, () => {
  const people = () =>
    ["a", "b", "c"].map((name) => new KeyMind(name)) as [KeyMind, KeyMind, KeyMind];

  it("is not a proof that names an authority: that one is made for another", () => {
    const [a, b, c] = people();
    const club = new Collective("club", [a, b, c], 2);
    const change = draftUpdate(club.head, T(10));
    const authority = [`${b.address}/${contentId(b.events[0])}`];
    const forItself = b.sign(change, { by: b.invocation() });
    const forAnother = b.sign(change, { by: b.invocation(), more: { authority } });
    const verify = (event: object) => {
      const tried = new Collective("club", [a, b, c], 2);
      tried.events.push(a.sign(event, { by: a.invocation() }) as never);
      return verifyMind(tried, [a, b, c]);
    };
    expect(verify(forItself).ok).toBe(true);
    expect(refusal(verify(forAnother))).toMatchObject({ clause: "L1 6.4", path: "/1/proof/0" });
  });

  it("asks for each member's log once, however many proofs the member has made", () => {
    const [a, b, c] = people();
    const club = new Collective("club", [a, b, c], 2).update(10, [a, b]).update(20, [a, b, c]);
    const book = bookOf([a, b, c]);
    const asked: string[] = [];
    const result = verifyLog(club.events, {
      evidence: witness([club.events]),
      asOf: LATER,
      memberLog: (mind) => {
        asked.push(mind);
        return book.log(mind);
      },
    });
    expect(result.ok).toBe(true);
    expect([...asked].sort()).toStrictEqual([a.address, b.address, c.address].sort());
  });

  it("stops at the first member whose log does not verify, and gives that reason", () => {
    const [a, b, c] = people();
    const draft = new Collective("club", [a, b, c], 2).events[0]!;
    // Four proofs by a, then b's and c's.
    const genesis = rawSign(draft, [
      a.asMember(),
      a.asMember(),
      a.asMember(),
      a.asMember(),
      b.asMember(),
      c.asMember(),
    ]);
    const book = bookOf([c]);
    const asked: string[] = [];
    const result = verifyLog([genesis], {
      evidence: witness([[genesis]]),
      asOf: LATER,
      memberLog: (mind) => {
        asked.push(mind);
        return book.log(mind);
      },
    });
    const issue = refusal(result);
    expect(issue).toMatchObject({ clause: "L1 6.3", path: "/0/proof/0" });
    expect(issue.message).toContain(`the proof by member ${a.address} does not count`);
    // One member's log was asked for, once: neither a's again, nor b's, which is not held either.
    expect(asked).toStrictEqual([a.address]);
  });

  it("needs the member's log known as far as the evidence for the event before goes", () => {
    const [a, b, c] = people();
    const club = new Collective("club", [a, b, c], 2, 5).update(6, [a, b]).update(7, [a, c]);
    const [genesis, first, second] = club.events.map((event) => contentId(event));
    // The first update was seen at 30, and the second, which follows it, at 10 by another source.
    const evidence = witness([a.events, b.events, c.events]);
    evidence.sawEvent(genesis!, at(5));
    evidence.sawEvent(first!, at(30));
    evidence.sawEvent(second!, at(10));
    const verify = (cAsOf: number, cLog: KeyMind = c) => {
      const book = new LogBook(evidence);
      book.hold(a.events, LATER);
      book.hold(b.events, LATER);
      book.hold(cLog.events, at(cAsOf));
      book.hold(club.events, LATER);
      return book.log(club.address);
    };
    const fresh = verify(30);
    expect(fresh.ok && fresh.value.entries.map((entry) => entry.time)).toStrictEqual([
      at(5),
      at(30),
      at(30),
    ]);
    // Known to 15: after the second update's own evidence, and before the time it takes effect.
    expect(refusal(verify(29.999999999))).toMatchObject({ clause: "core 9.4", path: "/2/proof/1" });
    expect(refusal(verify(15))).toMatchObject({ clause: "core 9.4", path: "/2/proof/1" });
    // What the stale copy hid: c removed the key at 20, before the update took effect.
    const removed = new KeyMind("c").update(20, { invocation: [] });
    evidence.sawEvent(contentId(removed.events[1]), at(20));
    expect(refusal(verify(30, removed))).toMatchObject({ clause: "L1 6.4", path: "/2/proof/1" });
  });
});

describe("what a verifier is told about time", () => {
  it(`${clause("core 9.4")} refuses a log known up to something that is not a time`, () => {
    const ada = new KeyMind("ada");
    const evidence = witness([ada.events]);
    for (const notATime of [5, "2026-01-01T00:00:00Z", null, undefined, {}]) {
      const result = verifyLog(ada.events, { evidence, asOf: notATime as never });
      expect(refusal(result)).toMatchObject({ clause: "core 9.4", path: "" });
      const book = new LogBook(evidence);
      expect(refusal(book.hold(ada.events, notATime as never)).clause).toBe("core 9.4");
      expect(refusal(book.hold(ada.events, notATime as never)).clause).toBe("core 9.4");
      expect(refusal(book.log(ada.address)).clause).toBe("L1 6.3");
    }
  });
});

describe("what a verified log is", () => {
  it("is frozen, with everything in it: what is handed out is also what is kept", () => {
    const [a, b] = [new KeyMind("a"), new KeyMind("b")];
    const club = new Collective("club", [a, b], 2).update(10, [a, b], {
      homes: ["https://club.example"],
    });
    const log = verified(club, [a, b]);
    const frozen = (value: unknown): boolean =>
      typeof value !== "object" ||
      value === null ||
      (Object.isFrozen(value) && Object.values(value).every(frozen));
    expect(frozen(log)).toBe(true);
    expect(() => {
      (log.entries as unknown as unknown[]).push({});
    }).toThrow(TypeError);
    expect(() => {
      (latestState(log).homes as string[]).push("https://thief.example");
    }).toThrow(TypeError);
    expect(() => {
      (events(log)[0] as { kind: string }).kind = "human";
    }).toThrow(TypeError);
    // The copy of the book is the one it gave out, unchanged.
    const book = bookOf([club, a, b]);
    expect(book.log(club.address)).toBe(book.log(club.address));
  });

  it("reads each event it is given once", () => {
    const ada = new KeyMind("ada").update(10).update(20);
    const reads = new Map<string, number>();
    const counting = new Proxy(ada.events, {
      get(target, name, receiver) {
        if (typeof name === "string") reads.set(name, (reads.get(name) ?? 0) + 1);
        return Reflect.get(target, name, receiver) as unknown;
      },
    });
    expect(verifyLog(counting, { evidence: witness([ada.events]), asOf: LATER }).ok).toBe(true);
    expect(reads.get("length")).toBe(1);
    expect([reads.get("0"), reads.get("1"), reads.get("2")]).toStrictEqual([1, 1, 1]);
  });
});
