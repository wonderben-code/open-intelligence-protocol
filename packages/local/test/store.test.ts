// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, readdirSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { Store } from "../src/store.ts";

let root: string;
let dir: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "oip-local-store-"));
  dir = join(root, "tasks");
});
afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe("what a program remembers of its work between its runs", () => {
  it("is kept by key, replaced by what is kept next under the key, and gone once removed", () => {
    const store = new Store<{ state: string }>(dir);
    expect(store.get("task-1")).toBeUndefined();
    expect(store.all()).toStrictEqual([]);
    store.put("task-1", { state: "working" });
    store.put("task-2", { state: "working" });
    store.put("task-1", { state: "done" });
    expect(store.get("task-1")).toStrictEqual({ state: "done" });
    expect(store.all().sort((one, other) => (one.key < other.key ? -1 : 1))).toStrictEqual([
      { key: "task-1", value: { state: "done" } },
      { key: "task-2", value: { state: "working" } },
    ]);
    store.delete("task-1");
    expect(store.get("task-1")).toBeUndefined();
    expect(store.all()).toStrictEqual([{ key: "task-2", value: { state: "working" } }]);
    // What is not there is removed without complaint.
    store.delete("task-1");
    // Another store on the directory finds what this one kept.
    expect(new Store(dir).get("task-2")).toStrictEqual({ state: "working" });
  });

  it("is in files that no key names: a key is any text a stranger chooses", () => {
    const store = new Store<number>(dir);
    const keys = ["../../escape", "/etc/passwd", "a\u0000b", "", "x".repeat(4096), "task/1"];
    for (const [index, key] of keys.entries()) store.put(key, index);
    for (const [index, key] of keys.entries()) expect(store.get(key)).toBe(index);
    // Each is a file of the directory, named by forty digits of a digest, and nothing is beside it.
    const names = readdirSync(dir);
    expect(names).toHaveLength(keys.length);
    for (const name of names) expect(name).toMatch(/^[0-9a-f]{40}\.json$/u);
    expect(readdirSync(root)).toStrictEqual(["tasks"]);
  });

  it("is for its owner alone to read", () => {
    const store = new Store<number>(dir);
    store.put("task-1", 1);
    const [name = ""] = readdirSync(dir);
    expect(statSync(join(dir, name)).mode & 0o777).toBe(0o600);
    expect(statSync(dir).mode & 0o777).toBe(0o700);
  });

  it("passes over a file that holds no such thing", () => {
    const store = new Store<number>(dir);
    store.put("task-1", 1);
    const [name = ""] = readdirSync(dir);
    // What is no JSON, what has no key, a file of another kind, and one under a name that is another key's.
    writeFileSync(join(dir, `${"0".repeat(40)}.json`), "{ no json");
    writeFileSync(join(dir, `${"1".repeat(40)}.json`), JSON.stringify({ value: 2 }));
    writeFileSync(join(dir, "notes.txt"), "not the store's");
    expect(store.all()).toStrictEqual([{ key: "task-1", value: 1 }]);
    writeFileSync(join(dir, name), JSON.stringify({ key: "task-2", value: 3 }));
    expect(store.get("task-1")).toBeUndefined();
    writeFileSync(join(dir, name), "{ no json");
    expect(store.get("task-1")).toBeUndefined();
  });

  it("says that a file is there though it cannot be read: not read is not the same as not there", () => {
    const store = new Store<number>(dir);
    expect(store.has("task-1")).toBe(false);
    store.put("task-1", 1);
    expect(store.has("task-1")).toBe(true);
    const [name = ""] = readdirSync(dir);
    // What is there is no JSON any more: it is not read, and it is there.
    writeFileSync(join(dir, name), "");
    expect(store.get("task-1")).toBeUndefined();
    expect(store.all()).toStrictEqual([]);
    expect(store.has("task-1")).toBe(true);
    store.delete("task-1");
    expect(store.has("task-1")).toBe(false);
  });

  it("keeps two keys apart that differ in half a pair of surrogates alone", () => {
    // No such text has an encoding of its own: an encoder writes the same bytes for each half.
    const store = new Store<string>(dir);
    const [high, other, low] = [0xd800, 0xd801, 0xdc00].map((unit) => String.fromCharCode(unit));
    const keys = [
      `task-${high}`,
      `task-${other}`,
      `task-${low}`,
      `task-${String.fromCodePoint(0xfffd)}`,
    ];
    for (const key of keys) store.put(key, `value of ${JSON.stringify(key)}`);
    for (const key of keys) expect(store.get(key)).toBe(`value of ${JSON.stringify(key)}`);
    expect(readdirSync(dir)).toHaveLength(keys.length);
    expect(store.all()).toHaveLength(keys.length);
  });

  it("reads no file but those it wrote whole, and clears away what a stop left half written", () => {
    const store = new Store<number>(dir);
    store.put("task-1", 1);
    const [name = ""] = readdirSync(dir);
    // A stop between the writing and the naming leaves a file that is nobody's value.
    const old = join(dir, `${"2".repeat(40)}.json.partial`);
    const fresh = join(dir, `${"3".repeat(40)}.json.partial`);
    for (const left of [old, fresh]) writeFileSync(left, JSON.stringify({ key: "left", value: 9 }));
    const longAgo = new Date(Date.now() - 120_000);
    utimesSync(old, longAgo, longAgo);
    expect(store.all()).toStrictEqual([{ key: "task-1", value: 1 }]);
    expect(store.get("left")).toBeUndefined();
    // One that is being written now is let be. One of minutes ago is gone.
    expect(readdirSync(dir).sort()).toStrictEqual([name, `${"3".repeat(40)}.json.partial`].sort());
  });

  it("writes a value whole or not at all: no reader finds half of one", () => {
    const store = new Store<{ text: string }>(dir);
    const large = { text: "x".repeat(200_000) };
    store.put("task-1", { text: "first" });
    store.put("task-1", large);
    expect(store.get("task-1")).toStrictEqual(large);
    // Nothing is left beside it.
    expect(readdirSync(dir)).toHaveLength(1);
  });
});
