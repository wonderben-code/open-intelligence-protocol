// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Extensions and forward compatibility (core Section 8). */

import { patterns, SHORT_NAMESPACES } from "@oip/schema";

const REVERSE_DNS = new RegExp(patterns.reverseDnsNamespace);
const OIP_PROFILE = new RegExp(patterns.oipNamespace);

/**
 * Whether a string is an extension namespace (core 8.1): a reverse-DNS name,
 * one of the short names this specification recognises, or a name beginning
 * `oip.`.
 */
export function isNamespace(value: unknown): value is string {
  return (
    typeof value === "string" &&
    (REVERSE_DNS.test(value) ||
      (SHORT_NAMESPACES as readonly string[]).includes(value) ||
      OIP_PROFILE.test(value))
  );
}

/**
 * The critical namespaces of a record that the caller does not understand
 * (core 8.3). If there is any, the record may be stored and forwarded but
 * must not be acted on or treated as valid for any decision; an HTTP service
 * answers `unsupported-critical` (core 10.2).
 *
 * `understood` holds the namespaces the caller implements; without it, the
 * caller implements none. The record should
 * have been validated; a `critical` that is not an array of strings is read
 * as naming something nobody understands.
 */
export function unsupportedCritical(
  record: Readonly<Record<string, unknown>>,
  understood?: Iterable<string>,
): string[] {
  try {
    return unsupportedIn(record["critical"], understood);
  } catch {
    // A record that cannot be read names nothing anybody understands.
    return ["critical"];
  }
}

function unsupportedIn(critical: unknown, understood: Iterable<string> | undefined): string[] {
  if (critical === undefined) return [];
  if (!Array.isArray(critical)) return ["critical"];
  const known = new Set(understood);
  const unsupported = new Set<string>();
  for (const namespace of critical as readonly unknown[]) {
    if (typeof namespace !== "string") unsupported.add("critical");
    else if (!known.has(namespace)) unsupported.add(namespace);
  }
  return [...unsupported];
}

/** Whether the caller may act on a record: it understands every critical extension (core 8.3). */
export function understandsCritical(
  record: Readonly<Record<string, unknown>>,
  understood?: Iterable<string>,
): boolean {
  return unsupportedCritical(record, understood).length === 0;
}
