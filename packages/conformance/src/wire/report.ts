// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** What the suite over the wire reports: one check after another, each citing its clauses. */

import { formatTimestamp, type Instant } from "@oip/core";

/** The profiles of `spec/README.md` that are services, and so are tested over the wire. */
export type WireProfile = "resolver" | "host" | "indexer";

/** The profiles the suite tests over the wire. */
export const WIRE_PROFILES: readonly WireProfile[] = ["resolver", "host", "indexer"];

/**
 * - `pass`: the implementation did what the clauses ask.
 * - `fail`: it did not.
 * - `not-applicable`: the clauses ask it only of an implementation that offers
 *   something this one does not, such as a mailbox.
 * - `skipped`: the check could not be made, because a check it builds on did
 *   not pass or because the suite was not given what it needs.
 */
export type WireOutcome = "pass" | "fail" | "not-applicable" | "skipped";

/** One check and how it went. */
export interface WireCheck {
  /** A name that stays the same from one run to the next: `<profile>/<what>`. */
  readonly id: string;
  /** The clauses the check holds the implementation to, such as `L1 17.2`. */
  readonly clauses: readonly string[];
  /** Whether the clauses require it (`MUST`) or recommend it (`SHOULD`). */
  readonly level: "MUST" | "SHOULD";
  readonly title: string;
  readonly outcome: WireOutcome;
  /** For any outcome but `pass`: what was required and what happened, or why the check was not made. */
  readonly detail?: string;
}

/** The report of one profile against one implementation. It is JSON as it stands. */
export interface WireReport {
  readonly suite: "oip-conformance-wire";
  readonly oip: "1";
  readonly profile: WireProfile;
  /** Where the suite connected. */
  readonly target: string;
  readonly started: string;
  readonly finished: string;
  readonly checks: readonly WireCheck[];
  readonly summary: Readonly<Record<WireOutcome, number>>;
  /**
   * Whether every `MUST` check passed or did not apply. A check that was
   * skipped proves nothing, so a report with one does not say that the
   * implementation conforms.
   */
  readonly conforms: boolean;
}

/** The implementation did not do what a clause requires. The message says what was required and what happened. */
export class Failed extends Error {
  override readonly name = "Failed";
}

/** The check does not apply to this implementation. The message says why. */
export class NotApplicable extends Error {
  override readonly name = "NotApplicable";
}

/** The check could not be made. The message says why. */
export class Skipped extends Error {
  override readonly name = "Skipped";
}

/**
 * Fails the check unless `holds`.
 *
 * @throws Failed with `detail` if it does not hold.
 */
export function expect(holds: boolean, detail: string): asserts holds {
  if (!holds) throw new Failed(detail);
}

/**
 * What an earlier check gave, for a check that builds on it.
 *
 * @throws Skipped if the earlier check gave nothing.
 */
export function need<T>(value: T | undefined, what: string): T {
  if (value === undefined) throw new Skipped(`it builds on ${what}, which the suite did not get`);
  return value;
}

/**
 * A value that is there by how the suite is written: the first event of a
 * log it made, the proof it has just put on a record.
 *
 * @throws TypeError if it is not there, which is a mistake in the suite.
 */
export function present<T>(value: T | undefined): T {
  if (value === undefined) throw new TypeError("the suite counted on a value that is not there");
  return value;
}

/** What names a check before it is run. */
export interface CheckHead {
  readonly id: string;
  readonly clauses: readonly [string, ...string[]];
  readonly title: string;
  /** `MUST` unless given. */
  readonly level?: "MUST" | "SHOULD";
}

/** Runs the checks of a profile in turn and keeps how each went. */
export class Recorder {
  readonly #checks: WireCheck[] = [];
  readonly #profile: WireProfile;

  constructor(profile: WireProfile) {
    this.#profile = profile;
  }

  /**
   * Runs one check. It never throws: whatever `run` throws is how the check went.
   *
   * @returns What `run` returned, for the checks that build on it, or
   *   `undefined` if the check did not pass.
   */
  async check<T>(head: CheckHead, run: () => Promise<T> | T): Promise<T | undefined> {
    const named = {
      id: `${this.#profile}/${head.id}`,
      clauses: head.clauses,
      level: head.level ?? "MUST",
      title: head.title,
    } as const;
    try {
      const value = await run();
      this.#checks.push({ ...named, outcome: "pass" });
      return value;
    } catch (error) {
      this.#checks.push({ ...named, outcome: outcomeOf(error), detail: detailOf(error) });
      return undefined;
    }
  }

  /** The report of the checks run so far. */
  report(target: string, started: Instant, finished: Instant): WireReport {
    const summary = { pass: 0, fail: 0, "not-applicable": 0, skipped: 0 };
    for (const check of this.#checks) summary[check.outcome] += 1;
    return {
      suite: "oip-conformance-wire",
      oip: "1",
      profile: this.#profile,
      target,
      started: formatTimestamp(started),
      finished: formatTimestamp(finished),
      checks: [...this.#checks],
      summary,
      conforms: this.#checks.every(
        (check) =>
          check.level !== "MUST" || check.outcome === "pass" || check.outcome === "not-applicable",
      ),
    };
  }
}

function outcomeOf(error: unknown): WireOutcome {
  if (error instanceof NotApplicable) return "not-applicable";
  if (error instanceof Skipped) return "skipped";
  return "fail";
}

function detailOf(error: unknown): string {
  if (error instanceof Failed || error instanceof NotApplicable || error instanceof Skipped) {
    return error.message;
  }
  // The implementation hung up, answered what is not HTTP, or the like: it did not answer as required.
  const message = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
  return `the check could not be completed: ${message}`;
}
