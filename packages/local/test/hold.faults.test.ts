// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A hold, where another process acts between two of this one's steps, and on
 * a file system that fails. Each test plants one act or one failure under
 * `hold`, and says who has the hold afterwards: one process, and never two.
 */

import { existsSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import type * as FileSystem from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { hold, HOLD_STALE_MS, UsageError } from "../src/index.ts";

type Act = (path: string) => void;

/** What happens just before this process looks at a file, makes one or removes one, and just after it removed one. */
const acts = vi.hoisted(() => ({
  stat: undefined as Act | undefined,
  open: undefined as Act | undefined,
  unlink: undefined as Act | undefined,
  unlinked: undefined as Act | undefined,
}));

vi.mock("node:fs", async (importOriginal) => {
  const real = await importOriginal<typeof FileSystem>();
  return {
    ...real,
    statSync: (path: string) => {
      acts.stat?.(path);
      return real.statSync(path);
    },
    openSync: (path: string, flags: string, mode: number) => {
      acts.open?.(path);
      return real.openSync(path, flags, mode);
    },
    unlinkSync: (path: string) => {
      acts.unlink?.(path);
      real.unlinkSync(path);
      acts.unlinked?.(path);
    },
  };
});

const failure = (code: string): Error => Object.assign(new Error(code), { code });

let root: string;
let count = 0;
beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "oip-local-hold-faults-"));
});
afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});
afterEach(() => {
  acts.stat = undefined;
  acts.open = undefined;
  acts.unlink = undefined;
  acts.unlinked = undefined;
});

/** A directory of its own for a test, with the hold of a process that ended without letting go. */
function left(): { dir: string; file: string } {
  const dir = join(root, `d${String(++count)}`);
  const file = join(dir, "serve.hold");
  hold(dir, "serve.hold", "relays");
  const then = new Date(Date.now() - HOLD_STALE_MS - 1000);
  utimesSync(file, then, then);
  return { dir, file };
}

/** Another process's hold, as it writes one. */
const ANOTHER = "1 0123456789abcdef01234567\n";

describe("a hold, where another process acts between two steps", () => {
  it("is taken where its holder let go just after it was found held", () => {
    const { dir, file } = left();
    // The file is there when this process tries to make it, and gone when it looks how old it is.
    acts.stat = (path) => {
      if (path === file) rmSync(file, { force: true });
    };
    const taken = hold(dir, "serve.hold", "relays");
    expect(taken.held).toBe(true);
    expect(existsSync(`${file}.taking`)).toBe(false);
    taken.release();
    expect(existsSync(file)).toBe(false);
  });

  it("is refused where another process took a hold over, and was done, between two looks", () => {
    const { dir, file } = left();
    writeFileSync(`${file}.taking`, ANOTHER);
    // That one's mark is there when this process tries to make its own, and gone when it
    // looks how old the mark is: the hold is the other's now, and fresh.
    acts.stat = (path) => {
      if (path !== `${file}.taking`) return;
      writeFileSync(file, ANOTHER);
      rmSync(`${file}.taking`);
    };
    expect(() => hold(dir, "serve.hold", "relays")).toThrow(UsageError);
    expect(readFileSync(file, "utf8")).toBe(ANOTHER);
  });

  it("is refused where a process that has just started made the file first, once the old one was removed", () => {
    const { dir, file } = left();
    acts.unlinked = (path) => {
      if (path === file) writeFileSync(file, ANOTHER);
    };
    expect(() => hold(dir, "serve.hold", "relays")).toThrow(UsageError);
    // The other's hold is left as it is, and nothing says that a take-over is under way.
    expect(readFileSync(file, "utf8")).toBe(ANOTHER);
    expect(existsSync(`${file}.taking`)).toBe(false);
  });
});

describe("a hold on a file system that fails", () => {
  it("is not taken, and the failure is passed on as it is", () => {
    const { dir, file } = left();
    // The file cannot be looked at.
    acts.stat = () => {
      throw failure("EIO");
    };
    expect(() => hold(dir, "serve.hold", "relays")).toThrow("EIO");
    acts.stat = undefined;
    // It cannot be removed. The mark of the take-over is, so that the next try is not refused for it.
    acts.unlink = (path) => {
      if (path === file) throw failure("EPERM");
    };
    expect(() => hold(dir, "serve.hold", "relays")).toThrow("EPERM");
    expect(existsSync(`${file}.taking`)).toBe(false);
    acts.unlink = undefined;
    // No file can be made.
    acts.open = () => {
      throw failure("EACCES");
    };
    expect(() => hold(dir, "serve.hold", "relays")).toThrow("EACCES");
    expect(() => hold(dir, "other.hold", "does something else")).toThrow("EACCES");
    acts.open = undefined;
    // None of it was a refusal, and none of it took the hold: the next try does.
    const taken = hold(dir, "serve.hold", "relays");
    expect(taken.held).toBe(true);
    taken.release();
  });
});
