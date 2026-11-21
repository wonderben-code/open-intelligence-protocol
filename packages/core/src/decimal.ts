// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Decimal quantities (core 1.3). Decimals travel as strings and are compared
 * with exact arithmetic: no value here ever becomes a floating-point number.
 */

import { patterns } from "@oip/schema";

/** core 1.3: the longest decimal string, in characters. */
export const MAX_DECIMAL_LENGTH = 64;

const DECIMAL = new RegExp(patterns.decimal);
const AMOUNT = new RegExp(patterns.amount);

/**
 * Whether a value is a decimal quantity: a string of at most 64 characters
 * matching `-?(0|[1-9][0-9]*)(\.[0-9]+)?`. A string that does not match is
 * not a decimal, however it looks: `"1,000"`, `"1e2"`, `" 400 "`,
 * `"-Infinity"` and full-width digits are not decimals.
 */
export function isDecimal(value: unknown): value is string {
  return typeof value === "string" && value.length <= MAX_DECIMAL_LENGTH && DECIMAL.test(value);
}

/** Whether a value is an amount: a decimal that is never negative (core 1.3). */
export function isAmount(value: unknown): value is string {
  return typeof value === "string" && value.length <= MAX_DECIMAL_LENGTH && AMOUNT.test(value);
}

/** A decimal as an exact number: `units` divided by ten to the power `scale`. */
interface Exact {
  readonly units: bigint;
  readonly scale: number;
}

function exact(decimal: string): Exact {
  const point = decimal.indexOf(".");
  if (point === -1) return { units: BigInt(decimal), scale: 0 };
  return {
    units: BigInt(decimal.slice(0, point) + decimal.slice(point + 1)),
    scale: decimal.length - point - 1,
  };
}

/**
 * Compares two decimals numerically (core 1.3): negative if `a` is less than
 * `b`, zero if they are equal, positive if `a` is greater. `"1.50"` equals
 * `"1.5"`, and `"-0"` equals `"0"`.
 *
 * Ordering is defined only between decimals, so the answer is `undefined` if
 * either value is not one. A caller must treat that as an error, never as
 * "less" or "not less".
 */
export function compareDecimals(a: unknown, b: unknown): -1 | 0 | 1 | undefined {
  if (!isDecimal(a) || !isDecimal(b)) return undefined;
  const x = exact(a);
  const y = exact(b);
  const scale = Math.max(x.scale, y.scale);
  const left = x.units * 10n ** BigInt(scale - x.scale);
  const right = y.units * 10n ** BigInt(scale - y.scale);
  if (left < right) return -1;
  return left > right ? 1 : 0;
}
