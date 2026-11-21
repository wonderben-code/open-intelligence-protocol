// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** One process at a time for a piece of work in a directory. */

import { existsSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { hold, HOLD_STALE_MS, UsageError } from "../src/index.ts";

let root: string;
let count = 0;
beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "oip-local-hold-"));
});
afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

/** A directory of its own for a test. */
const fresh = (): string => join(root, `d${String(++count)}`);

/** Makes a file look as if it was last touched so long ago. */
function aged(file: string, ms: number): void {
  const then = new Date(Date.now() - ms);
  utimesSync(file, then, then);
}

describe("a hold on a directory", () => {
  it("is one process's at a time, and another's once it is let go", () => {
    const dir = fresh();
    const first = hold(dir, "serve.hold", "relays for this gateway");
    expect(first.held).toBe(true);
    expect(readFileSync(join(dir, "serve.hold"), "utf8")).toMatch(
      new RegExp(`^${String(process.pid)} [0-9a-f]{24}\\n$`, "u"),
    );
    expect(() => hold(dir, "serve.hold", "relays for this gateway")).toThrow(UsageError);
    expect(() => hold(dir, "serve.hold", "relays for this gateway")).toThrow(
      /another process relays for this gateway, in .*One at a time/u,
    );
    // Another name in the directory is another hold.
    const other = hold(dir, "other.hold", "does something else");
    other.release();
    first.release();
    expect(first.held).toBe(false);
    expect(existsSync(join(dir, "serve.hold"))).toBe(false);
    const second = hold(dir, "serve.hold", "relays for this gateway");
    expect(second.held).toBe(true);
    second.release();
    // Letting go twice lets nothing else go.
    const third = hold(dir, "serve.hold", "relays for this gateway");
    second.release();
    first.release();
    expect(third.held).toBe(true);
    third.release();
  });

  it("is kept by touching it, and taken over once nobody has touched it for half a minute", () => {
    const dir = fresh();
    const file = join(dir, "serve.hold");
    const left = hold(dir, "serve.hold", "relays");
    // Its holder is alive as long as it touches the file, however long it has had it.
    aged(file, HOLD_STALE_MS - 2000);
    expect(() => hold(dir, "serve.hold", "relays")).toThrow(UsageError);
    aged(file, HOLD_STALE_MS + 1000);
    left.beat();
    expect(() => hold(dir, "serve.hold", "relays")).toThrow(UsageError);
    // A holder that ended without letting go touches nothing.
    aged(file, HOLD_STALE_MS + 1000);
    const next = hold(dir, "serve.hold", "relays");
    expect(next.held).toBe(true);
    expect(existsSync(`${file}.taking`)).toBe(false);
    // The one that was taken over finds out at its next touch, and removes nothing of the other's.
    expect(left.held).toBe(true);
    left.beat();
    expect(left.held).toBe(false);
    left.release();
    expect(next.held).toBe(true);
    expect(() => hold(dir, "serve.hold", "relays")).toThrow(UsageError);
    next.release();
  });

  it("is taken over by one process, whoever else tries at the same moment", () => {
    const dir = fresh();
    const file = join(dir, "serve.hold");
    hold(dir, "serve.hold", "relays");
    aged(file, HOLD_STALE_MS + 1000);
    // Another process is taking it over just now.
    writeFileSync(`${file}.taking`, "1 another\n");
    expect(() => hold(dir, "serve.hold", "relays")).toThrow(UsageError);
    expect(existsSync(`${file}.taking`)).toBe(true);
    // That one ended in the middle of it: its mark is removed, and the next try takes the hold.
    aged(`${file}.taking`, HOLD_STALE_MS + 1000);
    expect(() => hold(dir, "serve.hold", "relays")).toThrow(UsageError);
    expect(existsSync(`${file}.taking`)).toBe(false);
    const taken = hold(dir, "serve.hold", "relays");
    expect(taken.held).toBe(true);
    taken.release();
  });

  it("is lost where its file is removed, and says so", () => {
    const dir = fresh();
    const mine = hold(dir, "serve.hold", "relays");
    rmSync(join(dir, "serve.hold"));
    mine.beat();
    expect(mine.held).toBe(false);
    mine.release();
    mine.beat();
    expect(mine.held).toBe(false);
  });
});
