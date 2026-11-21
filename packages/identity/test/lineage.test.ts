// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { clause } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import { type JudgedRecord, judgeRecord, lineage, ownSignedTime } from "../src/index.ts";
import { bookOf, Collective, intentBy, KeyMind, lineageBy, type Mind } from "@oip/testkit/minds";

function judged(record: unknown): JudgedRecord {
  const result = judgeRecord(record);
  if (!result.ok) throw new Error(JSON.stringify(result.issues));
  return result.value;
}

/** The lineage of a child, for a verifier that holds the logs and records given. */
function lineageOf(child: Mind, minds: readonly Mind[], records: readonly object[] = []) {
  const book = bookOf([child, ...minds], records);
  const log = book.log(child.address);
  if (!log.ok) throw new Error(JSON.stringify(log.issues));
  return lineage(
    log.value,
    book,
    records.map((record) => judged(record)),
  );
}

const childOf = (parent: Mind, name = "child", position?: number) =>
  new KeyMind(name, 5, { parents: [{ mind: parent.address, at: parent.versionId(position) }] });

describe(`${clause("L1 8.1", "L1 8.2")} lineage`, () => {
  it("is claimed when only the child says so", () => {
    const parent = new KeyMind("parent");
    const child = childOf(parent);
    expect(lineageOf(child, [parent])).toEqual([
      { mind: parent.address, at: parent.versionId(), status: "claimed" },
    ]);
    // A mind with no parents has no lineage.
    expect(lineageOf(parent, [])).toEqual([]);
  });

  it("is acknowledged by a Fork event for the child, at or after the version it names", () => {
    const parent = new KeyMind("parent").update(3);
    const child = childOf(parent, "child", 1);
    parent.fork(10, { child: child.address });
    expect(lineageOf(child, [parent])).toEqual([
      { mind: parent.address, at: parent.versionId(1), status: "acknowledged" },
    ]);
    parent.update(20);
    expect(lineageOf(child, [parent])[0]?.status).toBe("acknowledged");
    // A Fork for some other child acknowledges nothing here.
    const stranger = childOf(parent, "stranger", 1);
    expect(lineageOf(stranger, [parent])[0]?.status).toBe("claimed");
  });

  it("is claimed when the parent's log lacks the version the child names, or is not held", () => {
    const parent = new KeyMind("parent").update(4);
    const unknown = new KeyMind("child", 5, {
      parents: [{ mind: parent.address, at: new KeyMind("other").versionId() }],
    });
    parent.fork(10, { child: unknown.address });
    expect(lineageOf(unknown, [parent])[0]?.status).toBe("claimed");
    // A Fork for the child cannot come before the version the child names: the
    // child's address commits to that version, and the Fork to the address.
    const child = childOf(parent, "child", 1);
    const book = bookOf([child]);
    const log = book.log(child.address);
    expect(log.ok && lineage(log.value, book)[0]?.status).toBe("claimed");
  });

  it("answers for each parent, in the order the genesis names them", () => {
    const one = new KeyMind("one");
    const two = new KeyMind("two");
    const child = new KeyMind("child", 5, {
      parents: [
        { mind: two.address, at: two.versionId() },
        { mind: one.address, at: one.versionId() },
      ],
    });
    one.fork(10, { child: child.address });
    expect(lineageOf(child, [one, two]).map((parent) => [parent.mind, parent.status])).toEqual([
      [two.address, "claimed"],
      [one.address, "acknowledged"],
    ]);
  });
});

describe(`${clause("L1 8.3")} a Lineage record`, () => {
  it("acknowledges a child without the parent's control keys", () => {
    const parent = new KeyMind("parent");
    const child = childOf(parent);
    const record = parent.sign(lineageBy(parent, child.address, 10));
    expect(lineageOf(child, [parent], [record])[0]?.status).toBe("acknowledged");
  });

  it("must be by the parent, name the child, and be signed by the parent's own authority", () => {
    const parent = new KeyMind("parent");
    const other = new KeyMind("other");
    const child = childOf(parent);
    const stranger = childOf(parent, "stranger");
    for (const record of [
      // Signed by someone else, in the parent's name.
      other.sign(lineageBy(parent, child.address, 10)),
      // Signed by someone else, in their own name.
      other.sign(lineageBy(other, child.address, 10)),
      // Signed by the parent, in someone else's name.
      parent.sign(lineageBy(other, child.address, 10)),
      // By the parent, for another child.
      parent.sign(lineageBy(parent, stranger.address, 10)),
      // By the parent, and not a Lineage record.
      parent.sign(intentBy(parent, 10, { child: child.address })),
      // By a key the parent does not have.
      parent.sign(lineageBy(parent, child.address, 10), { key: 3 }),
    ]) {
      expect(lineageOf(child, [parent, other], [record])[0]?.status).toBe("claimed");
    }
  });

  it("is signed for a collective by its threshold", () => {
    const members = [new KeyMind("a"), new KeyMind("b"), new KeyMind("c")] as const;
    const [a, b] = members;
    // The collective has no operational keys of its own here.
    const club = new Collective("club", members, 2, 0, { keys: [] });
    const child = childOf(club);
    const one = a.sign(lineageBy(club, child.address, 10));
    expect(lineageOf(child, [club, ...members], [one])[0]?.status).toBe("claimed");
    const two = b.sign(one);
    expect(lineageOf(child, [club, ...members], [two])[0]?.status).toBe("acknowledged");
  });
});

describe(`${clause("L1 8.4")} what a fork does not inherit`, () => {
  it("has none of its parent's keys: the parent's signature is not the child's", () => {
    const parent = new KeyMind("parent");
    const child = childOf(parent);
    parent.fork(10, { child: child.address });
    const book = bookOf([parent, child]);
    const byParent = parent.sign(intentBy(child, 20));
    const sees = bookOf([parent, child], [byParent]);
    expect(ownSignedTime(judged(byParent), child.address, sees)).toBeUndefined();
    expect(ownSignedTime(judged(byParent), parent.address, sees)).toBeDefined();
    const [parentLog, childLog] = [book.log(parent.address), book.log(child.address)];
    if (!parentLog.ok || !childLog.ok) throw new Error("the logs do not verify");
    const parentKeys = parentLog.value.entries[0].state.keys;
    expect(childLog.value.entries[0].state.keys.some((key) => parentKeys.includes(key))).toBe(
      false,
    );
  });
});

describe(`${clause("L1 8.5", "L1 3.9")} merges`, () => {
  it("are reserved: a log that records one does not verify", () => {
    const other = new KeyMind("other");
    const ada = new KeyMind("ada").raw(10, "Merge", { from: other.address });
    expect(bookOf([ada, other]).log(ada.address)).toMatchObject({
      ok: false,
      issues: [{ clause: "L1 3.9" }],
    });
  });
});
