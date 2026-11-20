// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Running a profile over the wire by its name, and the command that does it. */

import type { WireOptions } from "./client.ts";
import { type HostOptions, hostProfile } from "./host.ts";
import { type IndexerOptions, indexerProfile } from "./indexer.ts";
import { WIRE_PROFILES, type WireProfile, type WireReport } from "./report.ts";
import { resolverProfile } from "./resolver.ts";

/**
 * Runs one profile against one implementation.
 *
 * @param options - What every profile takes, and what the profile named takes besides.
 */
export function runWire(
  profile: WireProfile,
  options: WireOptions & HostOptions & IndexerOptions,
): Promise<WireReport> {
  switch (profile) {
    case "resolver":
      return resolverProfile(options);
    case "host":
      return hostProfile(options);
    case "indexer":
      return indexerProfile(options);
  }
}

const MARK = { pass: "pass", fail: "FAIL", "not-applicable": "n/a ", skipped: "skip" } as const;

/** A report as text for a person: a line for each check, what went wrong under it, and the sum. */
export function formatReport(report: WireReport): string {
  const lines = [`OIP conformance over the wire: the ${report.profile} at ${report.target}`, ""];
  for (const check of report.checks) {
    const level = check.level === "MUST" ? "" : " (recommended)";
    lines.push(`${MARK[check.outcome]}  ${check.id}  [${check.clauses.join(", ")}]${level}`);
    lines.push(`      ${check.title}`);
    if (check.detail !== undefined) lines.push(`      -> ${check.detail}`);
  }
  const { pass, fail, skipped } = report.summary;
  lines.push(
    "",
    `${pass} passed, ${fail} failed, ${report.summary["not-applicable"]} not applicable, ${skipped} skipped.`,
    report.conforms
      ? `Every check that the ${report.profile} profile requires passed or did not apply.`
      : `This run does not show that the implementation conforms to the ${report.profile} profile.`,
    "",
  );
  return lines.join("\n");
}

/** How the command is used. */
export const USAGE = `Usage: oip-conformance <profile> <url> [options]

Runs the conformance checks of a profile against an implementation, over the wire.

  <profile>            ${WIRE_PROFILES.join(", ")}
  <url>                where the implementation is reached, such as https://resolver.example

Options:
  --origin <origin>    the origin the implementation knows itself by, if it is not that of <url>
  --timeout <ms>       how long one answer may take, in milliseconds (10000)
  --json               write the report as JSON

The suite makes minds of its own and publishes them to the implementation, so run it against
a deployment that may hold them. A host is asked through the reference host's own interface
and must take on any mind that brings its bundle (OIP_HOST_OPEN). What an indexer forwards is
checked only by a run that is given an inbox to watch, which the command is not: use the
library for that.

The command ends with 0 if every required check passed or did not apply, 1 if not, and 2 if
it was not used as above.
`;

/** What the command was asked to do. */
export interface WireCommand {
  readonly profile: WireProfile;
  readonly options: WireOptions;
  readonly json: boolean;
}

/**
 * Reads the command's arguments.
 *
 * @returns What was asked, or a sentence that says what is wrong with the arguments.
 */
export function readArguments(args: readonly string[]): WireCommand | string {
  const positional: string[] = [];
  let origin: string | undefined;
  let timeoutMs: number | undefined;
  let json = false;
  for (let at = 0; at < args.length; at++) {
    const arg = args[at] ?? "";
    if (arg === "--json") json = true;
    else if (arg === "--origin" || arg === "--timeout") {
      const value = args[++at];
      if (value === undefined) return `${arg} takes a value`;
      if (arg === "--origin") origin = value;
      else timeoutMs = Number(value);
    } else if (arg.startsWith("--")) return `${arg} is no option of this command`;
    else positional.push(arg);
  }
  const [profile, target, ...more] = positional;
  if (profile === undefined || target === undefined || more.length > 0) {
    return "give a profile and a URL";
  }
  if (!(WIRE_PROFILES as readonly string[]).includes(profile)) {
    return `${profile} is no profile: give one of ${WIRE_PROFILES.join(", ")}`;
  }
  for (const [name, url] of [
    ["the URL", target],
    ["--origin", origin],
  ] as const) {
    if (url !== undefined && !/^https?:\/\/[^/]/u.test(url)) {
      return `${name} is an http or https URL; got ${url}`;
    }
  }
  if (timeoutMs !== undefined && !(Number.isInteger(timeoutMs) && timeoutMs > 0)) {
    return "--timeout is a number of milliseconds";
  }
  return {
    profile: profile as WireProfile,
    options: {
      target,
      ...(origin === undefined ? {} : { origin }),
      ...(timeoutMs === undefined ? {} : { timeoutMs }),
    },
    json,
  };
}

/**
 * The command `oip-conformance`.
 *
 * @param args - The arguments after the command's name.
 * @param write - Writes to the standard output, and to the standard error.
 * @param run - Runs a profile. `runWire` unless given.
 * @returns The exit code: 0 if the implementation conforms, 1 if the run does not show that, 2 for wrong arguments.
 */
export async function command(
  args: readonly string[],
  write: { readonly out: (text: string) => void; readonly err: (text: string) => void },
  run: typeof runWire = runWire,
): Promise<number> {
  if (args.includes("--help") || args.includes("-h")) {
    write.out(USAGE);
    return 0;
  }
  const asked = readArguments(args);
  if (typeof asked === "string") {
    write.err(`oip-conformance: ${asked}\n\n${USAGE}`);
    return 2;
  }
  const report = await run(asked.profile, asked.options);
  write.out(asked.json ? `${JSON.stringify(report, undefined, 2)}\n` : formatReport(report));
  return report.conforms ? 0 : 1;
}
