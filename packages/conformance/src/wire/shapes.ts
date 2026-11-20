// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Reading what an implementation answered: nothing of it is trusted to have any shape. */

import {
  canonicalize,
  CLOCK_SKEW,
  contentId,
  type Instant,
  isTimestamp,
  type JsonObject,
  MEDIA_TYPE,
  parseTimestamp,
} from "@oip/core";
import { FirstSeen, LogBook } from "@oip/identity";

import type { WireAnswer } from "./client.ts";
import { describe } from "./client.ts";
import { expect } from "./report.ts";

/** Whether a value is a JSON object. */
export function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The content ID of a value, or `undefined` if it has none: it is no JSON object within the profile. */
export function idOf(value: unknown): string | undefined {
  try {
    return isObject(value) ? contentId(value) : undefined;
  } catch {
    return undefined;
  }
}

/** Whether two values are the same JSON: the same canonical form (core Section 2). */
export function same(one: unknown, other: unknown): boolean {
  try {
    return canonicalize(one) === canonicalize(other);
  } catch {
    return false;
  }
}

/**
 * The body of an answer as a record of a type, served as core 10.1 asks.
 *
 * @throws Failed if the answer is not `status` with such a record.
 */
export function recordOf(
  answer: WireAnswer,
  status: number,
  type: string,
  when: string,
): JsonObject {
  const body = answer.json;
  expect(
    answer.status === status && isObject(body) && body["oip"] === "1" && body["type"] === type,
    `${when}: required ${status} with a ${type}; got ${describe(answer)}`,
  );
  const served = (answer.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase();
  expect(
    served === MEDIA_TYPE,
    `${when}: a record is served as ${MEDIA_TYPE} (core 10.1); got "${served ?? ""}"`,
  );
  return body;
}

/**
 * Requires that a served log is these events, in order, each as it was signed.
 *
 * @throws Failed if it is not.
 */
export function expectLog(served: unknown, events: readonly object[], when: string): void {
  expect(
    Array.isArray(served) &&
      served.length === events.length &&
      served.every((event, at) => same(event, events[at])),
    `${when}: required the ${events.length} event(s) ${events.map((event) => idOf(event)).join(", ")}; got ${
      Array.isArray(served) ? served.map((event) => idOf(event) ?? "?").join(", ") : "no log"
    }`,
  );
}

/** Whether a log verifies by itself, first seen at `now` (Layer 1, Section 4). */
export function verifies(log: unknown, now: Instant): boolean {
  const seen = new FirstSeen();
  return new LogBook(seen).witness(log, now, seen).ok;
}

/**
 * The time a `firstSeen` map gives for a key.
 *
 * @throws Failed if it gives none, or one that is not within the clock skew
 *   of the span in which the suite sent what was seen.
 */
export function seenTime(
  firstSeen: unknown,
  key: string,
  span: readonly [Instant, Instant],
  when: string,
): Instant {
  const time = isObject(firstSeen) ? firstSeen[key] : undefined;
  const parsed = isTimestamp(time) ? parseTimestamp(time) : undefined;
  expect(
    parsed !== undefined,
    `${when}: firstSeen gives a timestamp for ${key}; got ${JSON.stringify(time)}`,
  );
  expect(
    parsed >= span[0] - CLOCK_SKEW && parsed <= span[1] + CLOCK_SKEW,
    `${when}: the time ${JSON.stringify(time)} for ${key} is within 300 seconds of when it was sent`,
  );
  return parsed;
}
