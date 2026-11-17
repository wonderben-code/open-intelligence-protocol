// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Timestamps and durations (core 1.4, 1.5), and the clock-skew tolerance
 * (core 9.1). Nothing here reads a clock: the current time is always a
 * parameter (ADR-0003).
 */

import { patterns } from "@oip/schema";

/** An instant: whole nanoseconds since 1970-01-01T00:00:00Z. Instants are compared as numbers. */
export type Instant = bigint;

const NANOSECONDS_PER_SECOND = 1_000_000_000n;

/** core 9.1: the clock skew every implementation tolerates, 300 seconds, in nanoseconds. */
export const CLOCK_SKEW: bigint = 300n * NANOSECONDS_PER_SECOND;

const TIMESTAMP = new RegExp(patterns.timestamp);
const DURATION = new RegExp(patterns.duration);

/**
 * Days from 1970-01-01 to a date of the proleptic Gregorian calendar, which
 * is the calendar of RFC 3339. Year 0000 exists in it and is a leap year.
 */
function daysFromCivil(year: number, month: number, day: number): number {
  // Counting years from 1 March puts the leap day at the end of the year.
  const y = month <= 2 ? year - 1 : year;
  const era = Math.floor(y / 400);
  const yearOfEra = y - era * 400;
  const dayOfYear = Math.floor((153 * (month > 2 ? month - 3 : month + 9) + 2) / 5) + day - 1;
  const dayOfEra =
    yearOfEra * 365 + Math.floor(yearOfEra / 4) - Math.floor(yearOfEra / 100) + dayOfYear;
  return era * 146097 + dayOfEra - 719468;
}

/**
 * The instant a string names, for a string already known to be a timestamp.
 * The pattern fixes every position: YYYY-MM-DDTHH:MM:SS, then an optional
 * fraction of up to nine digits, then Z.
 */
export function instantOf(timestamp: string): Instant {
  const number = (from: number, to: number) => Number(timestamp.slice(from, to));
  const days = daysFromCivil(number(0, 4), number(5, 7), number(8, 10));
  const seconds = ((days * 24 + number(11, 13)) * 60 + number(14, 16)) * 60 + number(17, 19);
  const fraction = timestamp.slice(20, -1).padEnd(9, "0");
  return BigInt(seconds) * NANOSECONDS_PER_SECOND + BigInt(fraction);
}

/**
 * The instant a timestamp names, or `undefined` if the value is not a
 * timestamp: an RFC 3339 string in UTC that names a real date and time
 * (core 1.4). The instant keeps every digit, down to nanoseconds, so
 * `…00.1Z` and `…00.100Z` are the same instant and `…00.000000001Z` is
 * later than `…00Z`.
 */
export function parseTimestamp(value: unknown): Instant | undefined {
  return isTimestamp(value) ? instantOf(value) : undefined;
}

/** Whether a value is a timestamp (core 1.4). */
export function isTimestamp(value: unknown): value is string {
  return typeof value === "string" && TIMESTAMP.test(value);
}

const FIRST_INSTANT = -62_167_219_200n * NANOSECONDS_PER_SECOND; // 0000-01-01T00:00:00Z
const LAST_INSTANT = 253_402_300_800n * NANOSECONDS_PER_SECOND - 1n; // 9999-12-31T23:59:59.999999999Z

const pad = (value: number, width: number) => String(value).padStart(width, "0");

/**
 * Writes an instant as a timestamp (core 1.4), with the shortest fraction
 * that keeps its precision.
 *
 * @throws RangeError if the instant is outside years 0000 to 9999, which a
 * timestamp cannot name.
 */
export function formatTimestamp(instant: Instant): string {
  if (typeof instant !== "bigint" || instant < FIRST_INSTANT || instant > LAST_INSTANT) {
    throw new RangeError("a timestamp names an instant in the years 0000 to 9999");
  }
  let nanoseconds = instant % NANOSECONDS_PER_SECOND;
  let seconds = instant / NANOSECONDS_PER_SECOND;
  // BigInt division rounds towards zero; an instant before 1970 needs the floor.
  if (nanoseconds < 0n) {
    nanoseconds += NANOSECONDS_PER_SECOND;
    seconds -= 1n;
  }
  const total = Number(seconds);
  const days = Math.floor(total / 86400);
  const secondOfDay = total - days * 86400;
  // The inverse of daysFromCivil.
  const z = days + 719468;
  const era = Math.floor(z / 146097);
  const dayOfEra = z - era * 146097;
  const yearOfEra = Math.floor(
    (dayOfEra -
      Math.floor(dayOfEra / 1460) +
      Math.floor(dayOfEra / 36524) -
      Math.floor(dayOfEra / 146096)) /
      365,
  );
  const dayOfYear =
    dayOfEra - (365 * yearOfEra + Math.floor(yearOfEra / 4) - Math.floor(yearOfEra / 100));
  const shifted = Math.floor((5 * dayOfYear + 2) / 153);
  const day = dayOfYear - Math.floor((153 * shifted + 2) / 5) + 1;
  const month = shifted < 10 ? shifted + 3 : shifted - 9;
  const year = yearOfEra + era * 400 + (month <= 2 ? 1 : 0);
  const fraction =
    nanoseconds === 0n ? "" : `.${String(nanoseconds).padStart(9, "0").replace(/0+$/, "")}`;
  return (
    `${pad(year, 4)}-${pad(month, 2)}-${pad(day, 2)}T` +
    `${pad(Math.floor(secondOfDay / 3600), 2)}:${pad(Math.floor(secondOfDay / 60) % 60, 2)}:${pad(secondOfDay % 60, 2)}` +
    `${fraction}Z`
  );
}

const UNIT_SECONDS: ReadonlyMap<string, bigint> = new Map([
  ["D", 86400n],
  ["H", 3600n],
  ["M", 60n],
  ["S", 1n],
]);

/**
 * The length of a duration in nanoseconds, or `undefined` if the value is
 * not a duration (core 1.5): days, hours, minutes and seconds only, such as
 * `P30D` or `PT15M`. A day is 86,400 seconds. The arithmetic is exact,
 * however large the numbers.
 */
export function parseDuration(value: unknown): bigint | undefined {
  if (!isDuration(value)) return undefined;
  let seconds = 0n;
  let digits = "";
  for (const character of value) {
    if (character >= "0" && character <= "9") {
      digits += character;
      continue;
    }
    // After the pattern, every run of digits ends at its unit. "P" and "T" follow no digits.
    const unit = UNIT_SECONDS.get(character);
    if (unit !== undefined) seconds += BigInt(digits) * unit;
    digits = "";
  }
  return seconds * NANOSECONDS_PER_SECOND;
}

/** Whether a value is a duration (core 1.5). */
export function isDuration(value: unknown): value is string {
  return typeof value === "string" && DURATION.test(value);
}
