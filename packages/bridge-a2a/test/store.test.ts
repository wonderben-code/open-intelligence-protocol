// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { Store } from "../src/store.ts";

let root: string;
let dir: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "oip-bridge-store-"));
  dir = join(root, "tasks");
});
afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe("what a gateway remembers of its work for an agent", () => {
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

  it("is in files that no key names: a key is any text an agent chooses", () => {
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
});
