// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Who may call which tool: the operator's checks (Layer 0, 2.1).
 *
 * A gateway holds the credentials of the server it bridges, so whoever it
 * calls a tool for uses them. It "MUST NOT perform an action for a
 * requester that the requester's authority (identity or delegation) does
 * not cover, where the gateway's operator has configured such checks".
 * This gateway is never without them: a tool that the operator has opened
 * to nobody is called for nobody.
 *
 * The checks are a file in the bridged mind's directory, `policy.json`:
 *
 *     { "allow": { "search": "anyone",
 *                  "send_email": ["did:oip:…"],
 *                  "*": ["did:oip:…"] } }
 *
 * A tool's own entry decides for it. `*` decides for every tool that has
 * none.
 */

import { existsSync } from "node:fs";
import { join } from "node:path";

import { isMindAddress } from "@oip/core";
import { readObject, UsageError } from "@oip/local";

/** The name of the file, in a bridged mind's directory. */
export const POLICY_FILE = "policy.json";
/** The entry for every tool that has none of its own. */
export const EVERY_TOOL = "*";
/** The word that opens a tool to every mind. */
export const ANYONE = "anyone";

/** The operator's checks: for each tool, the minds it is called for. */
export interface Policy {
  readonly allow: Readonly<Record<string, typeof ANYONE | readonly string[]>>;
}

/** The checks of a gateway whose operator has written none: nobody is allowed anything. */
export const NOBODY: Policy = { allow: {} };

const isObject = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * Reads the checks of a bridged mind.
 *
 * @param dir - The bridged mind's directory.
 * @returns The checks. `NOBODY` where there is no file.
 * @throws UsageError if the file is there and is no such checks. A gateway
 *   that cannot read its checks calls no tool: it does not guess.
 */
export function readPolicy(dir: string): Policy {
  const file = join(dir, POLICY_FILE);
  if (!existsSync(file)) return NOBODY;
  const read = readObject(file, "the policy");
  const { allow, ...more } = read;
  const unknown = Object.keys(more);
  if (!isObject(allow) || unknown.length > 0) {
    throw new UsageError(
      `${file} is no policy: it has one member, \`allow\`, an object from the names of tools to who may call each`,
    );
  }
  const entries: [string, typeof ANYONE | readonly string[]][] = [];
  for (const [tool, who] of Object.entries(allow)) {
    if (who === ANYONE) {
      entries.push([tool, ANYONE]);
    } else if (Array.isArray(who) && who.every((mind) => isMindAddress(mind))) {
      entries.push([tool, who]);
    } else {
      throw new UsageError(
        `${file} is no policy: who may call ${JSON.stringify(tool)} is "${ANYONE}", or a list of the addresses of minds`,
      );
    }
  }
  return { allow: Object.fromEntries(entries) };
}

/**
 * Whether a tool is called for a requester.
 *
 * @param minds - The minds whose authority the request has: its sender,
 *   and the mind it was sent for where a chain of delegations says so.
 */
export function allows(policy: Policy, tool: string, minds: readonly string[]): boolean {
  // Its own members only: a tool named `constructor` finds no entry the operator did not write.
  const own = (name: string): Policy["allow"][string] | undefined =>
    Object.hasOwn(policy.allow, name) ? policy.allow[name] : undefined;
  const who = own(tool) ?? own(EVERY_TOOL);
  if (who === undefined) return false;
  return who === ANYONE || minds.some((mind) => who.includes(mind));
}
