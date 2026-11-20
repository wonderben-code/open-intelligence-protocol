// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What a tool is given, read with care.
 *
 * A host checks a call against the tool's schema before the tool runs.
 * These readers do not rely on that: whatever reaches a tool is checked
 * again here, and what is wrong is said in words an assistant can act on.
 */

import { isContentId, isMindAddress, parseTimestamp } from "@oip/core";
import { UsageError } from "@oip/local";

/** The arguments of a call. */
export type Given = Readonly<Record<string, unknown>>;

// Asked of a text, the guards of the core would leave nothing of it where they fail.
const isAddress = (value: string): boolean => isMindAddress(value);
const isId = (value: string): boolean => isContentId(value);

/** Refuses a call that names an argument the tool does not have. */
export function only(given: Given, names: readonly string[]): void {
  const unknown = Object.keys(given).filter((name) => !names.includes(name));
  if (unknown.length > 0) {
    throw new UsageError(
      `this tool has no argument named ${unknown.map((name) => JSON.stringify(name.slice(0, 64))).join(", ")}: it takes ${names.join(", ")}`,
    );
  }
}

/** A text, if it is given. An empty text is none. */
export function text(given: Given, name: string, most = 8192): string | undefined {
  const value = given[name];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") throw new UsageError(`\`${name}\` is a text`);
  if (value.length > most) {
    throw new UsageError(`\`${name}\` is at most ${String(most)} characters long`);
  }
  return value === "" ? undefined : value;
}

/** A list of texts. One that is not given is empty. */
export function texts(given: Given, name: string, most = 64): string[] {
  const value = given[name];
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string" && item !== "")) {
    throw new UsageError(`\`${name}\` is a list of texts`);
  }
  if (value.length > most) throw new UsageError(`\`${name}\` has at most ${String(most)} items`);
  return [...(value as string[])];
}

/** Whether a yes-or-no argument says yes. One that is not given says no. */
export function flag(given: Given, name: string): boolean {
  const value = given[name];
  if (value === undefined || value === null) return false;
  if (typeof value !== "boolean") throw new UsageError(`\`${name}\` is true or false`);
  return value;
}

/** A whole number within bounds, if it is given. */
export function count(given: Given, name: string, least: number, most: number): number | undefined {
  const value = given[name];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < least || value > most) {
    throw new UsageError(`\`${name}\` is a whole number from ${String(least)} to ${String(most)}`);
  }
  return value;
}

/** The arguments nested under a name, if they are given. */
export function part(given: Given, name: string): Given | undefined {
  const value = given[name];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new UsageError(`\`${name}\` is an object`);
  }
  return value as Given;
}

/** The address of a mind. */
export function addressOf(value: string, name: string): string {
  if (!isAddress(value)) {
    throw new UsageError(
      `\`${name}\` names a mind by its address, which begins did:oip: and is 67 characters long. ${JSON.stringify(value.slice(0, 80))} is none`,
    );
  }
  return value;
}

/** The addresses of minds. `me` is this mind, where `self` says who that is. */
export function addresses(given: Given, name: string, self?: string): string[] {
  return texts(given, name).map((value) =>
    value === "me" && self !== undefined ? self : addressOf(value, name),
  );
}

/** The content ID of a record, if it is given. A record is never named by a file. */
export function recordId(given: Given, name: string): string | undefined {
  const value = text(given, name, 128);
  if (value !== undefined && !isId(value)) {
    throw new UsageError(
      `\`${name}\` names a record by its content ID, which begins bciq and is 56 characters long. ${JSON.stringify(value.slice(0, 80))} is none`,
    );
  }
  return value;
}

/** The content IDs of records. */
export function recordIds(given: Given, name: string): string[] {
  return texts(given, name).map((value) => {
    if (!isId(value)) {
      throw new UsageError(
        `\`${name}\` names records by their content IDs, which begin bciq. ${JSON.stringify(value.slice(0, 80))} is none`,
      );
    }
    return value;
  });
}

/** A time, if it is given. */
export function time(given: Given, name: string): string | undefined {
  const value = text(given, name, 64);
  if (value !== undefined && parseTimestamp(value) === undefined) {
    throw new UsageError(
      `\`${name}\` is a time in UTC, written as 2026-01-31T12:00:00Z. ${JSON.stringify(value)} is none`,
    );
  }
  return value;
}

/** An amount, if it is given: a decimal, written as text. A record holds no floating-point number. */
export function amount(given: Given, name: string): string | undefined {
  const value = given[name];
  if (typeof value === "number") {
    throw new UsageError(
      `\`${name}\` is an amount written as text, as "120" or "99.50": pass it in quotes`,
    );
  }
  const written = text(given, name, 64);
  if (written !== undefined && !/^(0|[1-9][0-9]*)(\.[0-9]+)?$/u.test(written)) {
    throw new UsageError(
      `\`${name}\` is an amount written as text, as "120" or "99.50". ${JSON.stringify(written)} is none`,
    );
  }
  return written;
}
