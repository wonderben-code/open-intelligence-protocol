// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { KeystoreError, type KeyStorage, memoryStorage } from "../src/index.ts";
import { fileStorage } from "../src/node.ts";

let directory: string;
beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "oip-keystore-"));
});
afterEach(() => {
  rmSync(directory, { recursive: true, force: true });
});

async function refusal(work: () => unknown): Promise<string> {
  try {
    await work();
  } catch (error) {
    if (error instanceof KeystoreError) return error.code;
    throw error;
  }
  throw new Error("nothing was refused");
}

const bytes = (...values: number[]): Uint8Array => new Uint8Array(values);

/** Each kind of storage, and a second handle on what the first one holds where that means something. */
const KINDS: [string, () => { storage: KeyStorage; again?: () => KeyStorage }][] = [
  ["in memory", () => ({ storage: memoryStorage() })],
  [
    "in a directory",
    () => {
      const path = join(directory, "keys");
      return { storage: fileStorage(path), again: () => fileStorage(path) };
    },
  ],
];

describe.each(KINDS)("a storage %s", (_kind, make) => {
  it("keeps a document under its name, and gives it back as it was", async () => {
    const { storage } = make();
    expect(await storage.get("control")).toBeUndefined();
    expect(await storage.list()).toStrictEqual([]);
    const first = await storage.put("control", bytes(1, 2, 3), undefined);
    expect(await storage.get("control")).toStrictEqual({ value: bytes(1, 2, 3), version: first });
    await storage.put("meta", bytes(), undefined);
    expect((await storage.list()).sort()).toStrictEqual(["control", "meta"]);
    expect((await storage.get("meta"))?.value).toStrictEqual(bytes());
  });

  it("replaces a document only for a writer that names the version it replaces", async () => {
    const { storage } = make();
    const first = await storage.put("control", bytes(1), undefined);
    // There is one already.
    expect(await refusal(() => storage.put("control", bytes(9), undefined))).toBe("changed");
    const second = await storage.put("control", bytes(2), first);
    expect(second).not.toBe(first);
    // The first version is no longer what is stored.
    expect(await refusal(() => storage.put("control", bytes(9), first))).toBe("changed");
    expect(await refusal(() => storage.put("control", bytes(9), "no version"))).toBe("changed");
    expect(await refusal(() => storage.put("agreement", bytes(9), second))).toBe("changed");
    expect(await storage.get("control")).toStrictEqual({ value: bytes(2), version: second });
  });

  it("lets one of several writers of a version through, and tells the others", async () => {
    const { storage } = make();
    const first = await storage.put("control", bytes(0), undefined);
    const outcomes = await Promise.allSettled(
      [1, 2, 3, 4, 5, 6].map((n) => storage.put("control", bytes(n), first)),
    );
    const won = outcomes.filter((outcome) => outcome.status === "fulfilled");
    expect(won).toHaveLength(1);
    for (const outcome of outcomes) {
      if (outcome.status === "rejected") {
        expect(outcome.reason).toMatchObject({ code: "changed" });
      }
    }
    const stored = await storage.get("control");
    expect(stored?.version).toBe(won[0]?.value);
    expect(stored?.value).toHaveLength(1);
    expect(stored?.value[0]).not.toBe(0);
  });

  it("removes a document for one that names its version", async () => {
    const { storage } = make();
    const first = await storage.put("control", bytes(1), undefined);
    const second = await storage.put("control", bytes(2), first);
    expect(await refusal(() => storage.delete("control", first))).toBe("changed");
    expect(await refusal(() => storage.delete("meta", first))).toBe("changed");
    await storage.delete("control", second);
    expect(await storage.get("control")).toBeUndefined();
    expect(await storage.list()).toStrictEqual([]);
    expect(await refusal(() => storage.delete("control", second))).toBe("changed");
    // And it can be made again.
    await storage.put("control", bytes(3), undefined);
    expect((await storage.get("control"))?.value).toStrictEqual(bytes(3));
  });

  it("keeps its own copy of what it is given, and gives a copy of what it holds", async () => {
    const { storage } = make();
    const given = bytes(1, 2, 3);
    await storage.put("control", given, undefined);
    given.fill(0);
    const got = await storage.get("control");
    expect(got?.value).toStrictEqual(bytes(1, 2, 3));
    got?.value.fill(0);
    expect((await storage.get("control"))?.value).toStrictEqual(bytes(1, 2, 3));
  });

  it("takes no name that is not a short lower-case word", async () => {
    const { storage } = make();
    for (const name of [
      "",
      "Control",
      "../control",
      "a/b",
      "control.json",
      "1st",
      "a".repeat(33),
      "a b",
    ]) {
      expect(await refusal(() => storage.get(name)), name).toBe("argument");
      expect(await refusal(() => storage.put(name, bytes(1), undefined)), name).toBe("argument");
      expect(await refusal(() => storage.delete(name, "1")), name).toBe("argument");
    }
    expect(await storage.list()).toStrictEqual([]);
  });

  it("is one storage for every handle on it", async () => {
    const { storage, again } = make();
    if (again === undefined) return;
    const other = again();
    const first = await storage.put("control", bytes(1), undefined);
    expect(await other.get("control")).toStrictEqual({ value: bytes(1), version: first });
    const second = await other.put("control", bytes(2), first);
    // The first handle read version one, and the other has replaced it.
    expect(await refusal(() => storage.put("control", bytes(3), first))).toBe("changed");
    expect(await storage.get("control")).toStrictEqual({ value: bytes(2), version: second });
  });
});

describe("a storage in a directory", () => {
  const filesIn = (path: string): string[] => readdirSync(path).sort();

  it("makes its directory for its owner alone, and each file too", async () => {
    const path = join(directory, "deep", "keys");
    const storage = fileStorage(path);
    await storage.put("control", bytes(1), undefined);
    if (process.platform === "win32") return;
    expect(statSync(path).mode & 0o777).toBe(0o700);
    expect(filesIn(path)).toStrictEqual(["control.1.json"]);
    expect(statSync(join(path, "control.1.json")).mode & 0o777).toBe(0o600);
  });

  it("refuses a directory that others can read or enter", async () => {
    if (process.platform === "win32") return;
    for (const mode of [0o750, 0o705, 0o701, 0o777]) {
      const path = join(directory, `open-${mode.toString(8)}`);
      mkdirSync(path);
      chmodSync(path, mode);
      const storage = fileStorage(path);
      expect(await refusal(() => storage.list()), mode.toString(8)).toBe("unsafe");
      expect(await refusal(() => storage.get("control"))).toBe("unsafe");
      expect(await refusal(() => storage.put("control", bytes(1), undefined))).toBe("unsafe");
      expect(filesIn(path)).toStrictEqual([]);
    }
  });

  it("checks no modes on Windows, which has none", async () => {
    const path = join(directory, "open");
    mkdirSync(path);
    chmodSync(path, 0o755);
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { value: "win32" });
    try {
      const storage = fileStorage(path);
      await storage.put("control", bytes(1), undefined);
      expect((await storage.get("control"))?.value).toStrictEqual(bytes(1));
    } finally {
      if (platform !== undefined) Object.defineProperty(process, "platform", platform);
    }
    expect(process.platform).not.toBe("win32");
  });

  it("holds one file for each document after a write, and no temporary file", async () => {
    const path = join(directory, "keys");
    const storage = fileStorage(path);
    let version = await storage.put("control", bytes(1), undefined);
    for (let n = 2; n <= 5; n++) version = await storage.put("control", bytes(n), version);
    await storage.put("meta", bytes(7), undefined);
    expect(filesIn(path)).toStrictEqual(["control.5.json", "meta.1.json"]);
    // A write that is refused leaves nothing behind either.
    expect(await refusal(() => storage.put("control", bytes(9), "1"))).toBe("changed");
    expect(filesIn(path)).toStrictEqual(["control.5.json", "meta.1.json"]);
  });

  it("reads the latest version where a writer stopped before it removed the one before", async () => {
    const path = join(directory, "keys");
    const storage = fileStorage(path);
    const first = await storage.put("control", bytes(1), undefined);
    // A writer linked version 2 and stopped: version 1 is still there, with a temporary file.
    writeFileSync(join(path, "control.2.json"), bytes(2), { mode: 0o600 });
    writeFileSync(join(path, ".control.abandoned.tmp"), bytes(9), { mode: 0o600 });
    expect(await storage.get("control")).toStrictEqual({ value: bytes(2), version: "2" });
    // The older version went when the newer was read: a destroyed key does not linger in it.
    expect(filesIn(path)).toStrictEqual([".control.abandoned.tmp", "control.2.json"]);
    expect(await storage.list()).toStrictEqual(["control"]);
    // The writer that read version 1 does not write over version 2.
    expect(await refusal(() => storage.put("control", bytes(3), first))).toBe("changed");
  });

  it("sees nothing in files that are not its documents", async () => {
    const path = join(directory, "keys");
    const storage = fileStorage(path);
    await storage.put("control", bytes(1), undefined);
    for (const name of [
      "control.json",
      "control.0.json",
      "control.x.json",
      "Control.2.json",
      "notes.txt",
    ]) {
      writeFileSync(join(path, name), bytes(9));
    }
    expect(await storage.list()).toStrictEqual(["control"]);
    expect(await storage.get("control")).toStrictEqual({ value: bytes(1), version: "1" });
  });

  it("lets one of two processes through when both write the version after the one they read", async () => {
    const path = join(directory, "keys");
    const one = fileStorage(path);
    const two = fileStorage(path);
    let version = await one.put("control", bytes(0), undefined);
    for (let round = 0; round < 20; round++) {
      const outcomes = await Promise.allSettled([
        one.put("control", bytes(1), version),
        two.put("control", bytes(2), version),
      ]);
      const won = outcomes.filter((outcome) => outcome.status === "fulfilled");
      expect(won, `round ${String(round)}`).toHaveLength(1);
      version = won[0]?.value ?? "";
      expect(filesIn(path)).toStrictEqual([`control.${version}.json`]);
    }
  });
});
