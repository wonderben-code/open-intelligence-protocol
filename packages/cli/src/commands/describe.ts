// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** A mind as it was resolved, in the lines and the JSON that `show` and `resolve` print. */

import { type Lookup, type Publication, type Resolved, TransportError } from "@oip/client";
import { OipError } from "@oip/core";
import { type Lineage, lineage } from "@oip/identity";

import { counted } from "../text.ts";

/** A row of two columns: a name, and what is said of it. */
export const row = (name: string, value: string): string => `  ${name.padEnd(10)} ${value}`;

const listed = (values: readonly string[]): string =>
  values.length === 0 ? "none" : values.join(", ");

/**
 * The parents a mind names, each with whether the parent says so too
 * (Layer 1, 8.2). A parent that cannot be resolved is one that has not been
 * shown to: the lineage is then claimed, and no more.
 */
export async function lineageOf(lookup: Lookup, resolved: Resolved): Promise<Lineage[]> {
  for (const { mind } of resolved.state.parents) {
    try {
      await lookup.resolve(mind);
    } catch (error) {
      if (!(error instanceof OipError || error instanceof TransportError)) throw error;
    }
  }
  return lineage(resolved.log, lookup.view);
}

/** The lines that describe a mind. */
export function describe(resolved: Resolved, parents: readonly Lineage[]): string[] {
  const { state, location, participant } = resolved;
  const { children } = resolved.log;
  return [
    resolved.mind,
    row("kind", state.kind),
    row("log", counted(state.seq + 1, "event") + (state.retired ? ", and retired" : "")),
    row(
      "keys",
      `${String(state.keys.length)} to sign with, ${String(state.agreement.length)} to be sealed to`,
    ),
    row("homes", listed(state.homes)),
    row("names", listed(state.alsoKnownAs)),
    ...parents.map(({ mind, status }) =>
      row(
        "parent",
        `${mind} (${status === "acknowledged" ? "which says so too" : "by its own word alone"})`,
      ),
    ),
    ...children.map(({ child }) => row("child", child)),
    ...(resolved.duplicitous ? [row("warning", "its log has two events at one position")] : []),
    row(
      "location",
      location === undefined
        ? "none published"
        : `${location.record.status}, ${counted(location.record.endpoints.length, "endpoint")}${
            resolved.stale ? ", out of date" : ""
          }`,
    ),
    row(
      "profile",
      participant === undefined
        ? "none published"
        : `${participant.record.name}, ${counted(participant.record.capabilities?.length ?? 0, "capability", "capabilities")}`,
    ),
  ];
}

/** The same, for a program. */
export function described(
  resolved: Resolved,
  parents: readonly Lineage[],
): Record<string, unknown> {
  const { state } = resolved;
  return {
    mind: resolved.mind,
    kind: state.kind,
    seq: state.seq,
    retired: state.retired,
    duplicitous: resolved.duplicitous,
    keys: [...state.keys],
    agreement: [...state.agreement],
    homes: [...state.homes],
    alsoKnownAs: [...state.alsoKnownAs],
    parents: [...parents],
    children: resolved.log.children.map(({ child }) => child),
    location: resolved.location?.record ?? null,
    participant: resolved.participant?.record ?? null,
  };
}

/** What the services said when the mind last published: a line of how many took it, and one for each that did not. */
export function taken(publications: readonly Publication[]): string[] {
  const took = publications.filter((publication) => publication.taken).length;
  return [
    `Services that took it: ${String(took)} of ${String(publications.length)}.`,
    ...publications
      .filter((publication) => !publication.taken)
      .map(({ service, origin, failure }) =>
        row("not", `the ${service} ${origin} (${failure ?? "it did not say why"})`),
      ),
  ];
}
