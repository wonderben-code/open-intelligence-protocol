// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The containers (core 1.6): records that carry other records. The limits on
 * size and on depth apply to each record a container carries, and to the
 * container without them, never to the two together.
 */

import type { OipRecord } from "./registry.ts";

/** A container taken apart. */
export interface ContainerParts {
  /** The records it carries, each with its path in the container. */
  readonly carried: readonly (readonly [path: string, record: OipRecord])[];
  /** The container without them. */
  readonly rest: Readonly<Record<string, unknown>>;
}

/**
 * The records a container carries and what remains of it without them, or
 * `undefined` for a record that is not a container. The record must have
 * passed its schema.
 */
export function containerParts(record: OipRecord): ContainerParts | undefined {
  switch (record.type) {
    case "Bundle": {
      const { log, location, participant, ...rest } = record;
      const carried: [string, OipRecord][] = log.map((event, i) => [`/log/${i}`, event]);
      if (location !== undefined) carried.push(["/location", location]);
      if (participant !== undefined) carried.push(["/participant", participant]);
      return { carried, rest };
    }
    case "LogPage": {
      const { events, ...rest } = record;
      return { carried: events.map((event, i) => [`/events/${i}`, event]), rest };
    }
    case "FeedPage": {
      const { entries, ...rest } = record;
      return { carried: entries.map((entry, i) => [`/entries/${i}`, entry]), rest };
    }
    case "DuplicityEvidence": {
      const { pairs, ...rest } = record;
      return {
        carried: pairs.flatMap((pair, i) =>
          pair.map((event, j): [string, OipRecord] => [`/pairs/${i}/${j}`, event]),
        ),
        rest,
      };
    }
    default:
      return undefined;
  }
}

/**
 * How deeply the arrays and objects of a value nest: 0 for a value that is
 * neither, 1 for an empty array or object. It does not recurse.
 */
export function depthOf(root: unknown): number {
  let deepest = 0;
  const pending: [value: unknown, depth: number][] = [[root, 1]];
  for (let next = pending.pop(); next !== undefined; next = pending.pop()) {
    const [value, depth] = next;
    if (typeof value !== "object" || value === null) continue;
    if (depth > deepest) deepest = depth;
    for (const member of Object.values(value)) pending.push([member, depth + 1]);
  }
  return deepest;
}
