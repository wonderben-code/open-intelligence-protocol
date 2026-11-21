// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A storage in a directory, on a file system that fails. Each test plants one
 * failure under `fileStorage` and says what is stored afterwards: the
 * document as it was, or the document as it was written, and never a part.
 */

import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import type * as FileSystem from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { fileStorage } from "../src/node.ts";

type Fault = (path: string) => Error | undefined;

const faults = vi.hoisted(() => ({
  unlink: undefined as Fault | undefined,
  readFile: undefined as Fault | undefined,
  link: undefined as Fault | undefined,
  open: undefined as Fault | undefined,
  write: undefined as Fault | undefined,
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const real = await importOriginal<typeof FileSystem>();
  const failing = (fault: Fault | undefined, path: unknown): void => {
    const error = fault?.(String(path));
    if (error !== undefined) throw error;
  };
  return {
    ...real,
    unlink: async (path: string) => {
      failing(faults.unlink, path);
      return real.unlink(path);
    },
    readFile: async (path: string) => {
      failing(faults.readFile, path);
      return real.readFile(path);
    },
    link: async (from: string, to: string) => {
      failing(faults.link, to);
      return real.link(from, to);
    },
    open: async (path: string, flags?: number, mode?: number) => {
      failing(faults.open, path);
      const handle = await real.open(path, flags, mode);
      const error = faults.write?.(path);
      if (error !== undefined) handle.writeFile = () => Promise.reject(error);
      return handle;
    },
  };
});

const failure = (code: string): Error => Object.assign(new Error(code), { code });
const bytes = (...values: number[]): Uint8Array => new Uint8Array(values);

let directory: string;
beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "oip-keystore-faults-"));
});
afterEach(() => {
  for (const name of Object.keys(faults) as (keyof typeof faults)[]) faults[name] = undefined;
  rmSync(directory, { recursive: true, force: true });
});

const files = (): string[] => readdirSync(directory).sort();

describe("a storage in a directory, when the file system fails", () => {
  it("fails a write whose document cannot be written out, and leaves the document as it was", async () => {
    const storage = fileStorage(directory);
    const first = await storage.put("control", bytes(1), undefined);
    faults.write = (path) => (path.endsWith(".tmp") ? failure("ENOSPC") : undefined);
    await expect(storage.put("control", bytes(2), first)).rejects.toMatchObject({ code: "ENOSPC" });
    faults.write = undefined;
    // No part of the new document is there, and no temporary file.
    expect(files()).toStrictEqual(["control.1.json"]);
    expect(await storage.get("control")).toStrictEqual({ value: bytes(1), version: first });
    // The writer may try again with the version it read.
    expect(await storage.put("control", bytes(2), first)).toBe("2");
  });

  it("fails a write whose temporary file cannot be made", async () => {
    const storage = fileStorage(directory);
    faults.open = (path) => (path.endsWith(".tmp") ? failure("EMFILE") : undefined);
    await expect(storage.put("control", bytes(1), undefined)).rejects.toMatchObject({
      code: "EMFILE",
    });
    expect(files()).toStrictEqual([]);
  });

  it("fails a write that cannot be linked, for whatever reason but a name that is taken", async () => {
    const storage = fileStorage(directory);
    const first = await storage.put("control", bytes(1), undefined);
    faults.link = () => failure("EPERM");
    await expect(storage.put("control", bytes(2), first)).rejects.toMatchObject({ code: "EPERM" });
    expect(files()).toStrictEqual(["control.1.json"]);
    // A name that is taken is a document that changed, and nothing else.
    faults.link = () => failure("EEXIST");
    await expect(storage.put("control", bytes(2), first)).rejects.toMatchObject({
      code: "changed",
    });
    expect(files()).toStrictEqual(["control.1.json"]);
  });

  it("has the new document, whole, where the version before it could not be removed", async () => {
    const storage = fileStorage(directory);
    const first = await storage.put("control", bytes(1), undefined);
    faults.unlink = (path) => (path.endsWith("control.1.json") ? failure("EACCES") : undefined);
    // The write says that it failed: the old version, and a key destroyed in the new, is still there.
    await expect(storage.put("control", bytes(2), first)).rejects.toMatchObject({ code: "EACCES" });
    expect(files()).toStrictEqual(["control.1.json", "control.2.json"]);
    // A read cannot remove it either, and says so.
    await expect(storage.get("control")).rejects.toMatchObject({ code: "EACCES" });
    faults.unlink = undefined;
    // Once it can be removed, the next read removes it.
    expect(await storage.get("control")).toStrictEqual({ value: bytes(2), version: "2" });
    expect(files()).toStrictEqual(["control.2.json"]);
  });

  it("fails a write whose temporary file cannot be removed, and the document is the new one", async () => {
    const storage = fileStorage(directory);
    faults.unlink = (path) => (path.endsWith(".tmp") ? failure("EACCES") : undefined);
    await expect(storage.put("control", bytes(1), undefined)).rejects.toMatchObject({
      code: "EACCES",
    });
    faults.unlink = undefined;
    expect(await storage.get("control")).toStrictEqual({ value: bytes(1), version: "1" });
    // What was left behind is no document.
    expect(await storage.list()).toStrictEqual(["control"]);
  });

  it("fails a read that the file system fails, and calls a document that keeps vanishing changed", async () => {
    const storage = fileStorage(directory);
    await storage.put("control", bytes(1), undefined);
    faults.readFile = () => failure("EIO");
    await expect(storage.get("control")).rejects.toMatchObject({ code: "EIO" });
    // Listed, and gone when it is read, again and again: writers are busy with it.
    let reads = 0;
    faults.readFile = () => {
      reads += 1;
      return failure("ENOENT");
    };
    await expect(storage.get("control")).rejects.toMatchObject({ code: "changed" });
    expect(reads).toBe(8);
    // Gone once, it is read at the next look.
    reads = 0;
    faults.readFile = () => (++reads === 1 ? failure("ENOENT") : undefined);
    expect((await storage.get("control"))?.value).toStrictEqual(bytes(1));
  });

  it("fails a removal that the file system fails", async () => {
    const storage = fileStorage(directory);
    const first = await storage.put("control", bytes(1), undefined);
    faults.unlink = () => failure("EACCES");
    await expect(storage.delete("control", first)).rejects.toMatchObject({ code: "EACCES" });
    faults.unlink = undefined;
    expect((await storage.get("control"))?.version).toBe(first);
    // A file that is gone already when it is removed was removed by someone else: no failure.
    faults.unlink = () => failure("ENOENT");
    await expect(storage.delete("control", first)).rejects.toMatchObject({ code: "changed" });
  });

  it("writes where the directory itself cannot be made durable", async () => {
    const storage = fileStorage(directory);
    faults.open = (path) => (path === directory ? failure("EISDIR") : undefined);
    const first = await storage.put("control", bytes(1), undefined);
    expect(await storage.put("control", bytes(2), first)).toBe("2");
    await storage.delete("control", "2");
    expect(files()).toStrictEqual([]);
  });
});
