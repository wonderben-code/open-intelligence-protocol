// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * One process at a time for a piece of work in a directory: the relay of a
 * gateway, say. Two that read one mailbox would each answer what they read,
 * and a request would be acted on twice.
 *
 * A hold is a file. It is made only if it is not there, and the process
 * that made it touches it every few seconds. A hold that nobody has touched
 * for half a minute was left by a process that ended without letting go,
 * and is taken over.
 *
 * It is the time of the last touch that says whether a holder lives, and
 * not the holder's process number: two containers that share a volume each
 * have a process 1.
 */

import { randomBytes } from "node:crypto";
import {
  closeSync,
  mkdirSync,
  openSync,
  readFileSync,
  statSync,
  unlinkSync,
  utimesSync,
  writeSync,
} from "node:fs";
import { join } from "node:path";

import { UsageError } from "./errors.ts";

/** How often a holder touches its hold, in milliseconds. */
export const HOLD_BEAT_MS = 5000;
/** How long after its last touch a hold is taken to be left behind, in milliseconds. */
export const HOLD_STALE_MS = 30_000;

/** A hold that this process has. */
export interface Hold {
  /**
   * Whether the hold is still this process's. It is not once it is let go,
   * and not if another process took it over because this one did not touch
   * it in time: work under the hold is then to stop.
   */
  readonly held: boolean;
  /** Touches the hold now, and looks whether it is still this process's. A holder does it by itself every few seconds. */
  beat(): void;
  /** Lets the hold go. */
  release(): void;
}

const isCode = (error: unknown, code: string): boolean =>
  (error as { code?: unknown } | null)?.code === code;

/** How long ago a file was touched, or `undefined` if it is not there. */
function ageOf(file: string): number | undefined {
  try {
    return Date.now() - statSync(file).mtimeMs;
  } catch (error) {
    if (isCode(error, "ENOENT")) return undefined;
    throw error;
  }
}

/** Makes a file that must not be there, with what it is to say. @returns Whether it was made. */
function make(file: string, text: string): boolean {
  let made: number;
  try {
    made = openSync(file, "wx", 0o600);
  } catch (error) {
    if (isCode(error, "EEXIST")) return false;
    throw error;
  }
  try {
    writeSync(made, text);
  } finally {
    closeSync(made);
  }
  return true;
}

function remove(file: string): void {
  try {
    unlinkSync(file);
  } catch (error) {
    if (!isCode(error, "ENOENT")) throw error;
  }
}

/**
 * Takes the hold of a name in a directory.
 *
 * @param dir - The directory. It is made if it is not there.
 * @param name - The file's name: `serve.hold`, say.
 * @param what - What the hold is for, in words for whoever is refused: "relays for this gateway".
 * @throws UsageError if another process has the hold.
 */
export function hold(dir: string, name: string, what: string): Hold {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const file = join(dir, name);
  // What says that a hold is this process's: its number is for a person to read, the rest is the mark.
  const mark = `${String(process.pid)} ${randomBytes(12).toString("hex")}\n`;
  const refused = (): UsageError =>
    new UsageError(
      `another process ${what}, in ${dir}. One at a time: stop it first. ` +
        `If it has just ended without letting go, this one can take over in ${String(HOLD_STALE_MS / 1000)} seconds`,
    );
  if (!make(file, mark)) {
    const age = ageOf(file);
    if (age !== undefined && age < HOLD_STALE_MS) throw refused();
    // Left behind. One process takes it over: whoever makes the file that says so.
    const taking = `${file}.taking`;
    if (!make(taking, mark)) {
      // A process that ended while it took over left that file behind in its turn.
      if ((ageOf(taking) ?? 0) >= HOLD_STALE_MS) remove(taking);
      throw refused();
    }
    try {
      remove(file);
      if (!make(file, mark)) throw refused();
    } finally {
      remove(taking);
    }
  }

  let held = true;
  const beat = (): void => {
    if (!held) return;
    try {
      // Another process took the hold over, or somebody removed it: it is not this one's any more.
      if (readFileSync(file, "utf8") !== mark) {
        held = false;
        return;
      }
      const now = new Date();
      utimesSync(file, now, now);
    } catch {
      held = false;
    }
  };
  const beating = setInterval(beat, HOLD_BEAT_MS);
  // A hold does not keep a process alive.
  beating.unref();
  return {
    get held() {
      return held;
    },
    beat,
    release: () => {
      clearInterval(beating);
      if (!held) return;
      held = false;
      try {
        // Only what is this process's is removed.
        if (readFileSync(file, "utf8") === mark) remove(file);
      } catch {
        // It is gone already.
      }
    },
  };
}
