// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `oip doctor`: looks at the mind's directory and at the services it names,
 * and says what is well, what is not, and what to do about it. It changes
 * nothing, and unlocks no key.
 */

import { statSync } from "node:fs";

import { type Fetch, Lookup, type Resolved, TransportError } from "@oip/client";
import { OipError } from "@oip/core";
import { Keystore, KeystoreError } from "@oip/keystore";
import { fileStorage } from "@oip/keystore/node";

import { type Command, type Context, UsageError } from "../command.ts";
import { type Config, Home, readNetwork } from "../home.ts";
import { fetchOf, lookupOptions } from "../mind.ts";
import { counted } from "../text.ts";
import { row } from "./describe.ts";

/** One thing that was looked at. */
interface Check {
  /** `ok`: it is well. `warn`: it works, and should be seen to. `fails`: the mind cannot do its work. */
  readonly state: "ok" | "warn" | "fails";
  /** What was looked at, and what was found. */
  readonly what: string;
  /** What to do about it. */
  readonly advice?: string;
}

const ok = (what: string): Check => ({ state: "ok", what });
const warn = (what: string, advice: string): Check => ({ state: "warn", what, advice });
const fails = (what: string, advice: string): Check => ({ state: "fails", what, advice });

/** Core 9.1: how far two clocks may differ, in milliseconds. */
const SKEW_MS = 300_000;

/** Why something could not be had: the code of a problem, or the failure of the transport. */
function codeOf(error: unknown): string | undefined {
  if (error instanceof OipError) return error.code;
  if (error instanceof TransportError) return error.failure;
  if (error instanceof KeystoreError) return error.code;
  return undefined;
}

/** Whether a service answers that it is ready, and the time by its clock, if it said. */
async function ready(fetch: Fetch, origin: string): Promise<{ ready: boolean; at?: number }> {
  try {
    const answer = await fetch(new Request(`${origin}/readyz`, { redirect: "manual" }));
    const said = Date.parse(answer.headers.get("date") ?? "");
    return { ready: answer.status === 200, ...(Number.isNaN(said) ? {} : { at: said }) };
  } catch {
    // Whatever went wrong, it did not answer.
    return { ready: false };
  }
}

/** What is looked at once the mind is known: its services, its log, and what it has published. */
async function checksOf(context: Context, home: Home, config: Config): Promise<Check[]> {
  const checks: Check[] = [];
  const options = lookupOptions(context, config);
  const fetch = fetchOf(context, config);
  let keystore: Keystore;
  try {
    keystore = await Keystore.open({ storage: fileStorage(home.keys) });
  } catch (error) {
    const code = codeOf(error);
    if (code === undefined) throw error;
    return [
      fails(
        `the keys in ${home.keys} cannot be read (${code})`,
        "restore a backup: oip keys restore <file>",
      ),
    ];
  }
  checks.push(
    ok(
      `the keys are in ${home.keys}, sealed with ${config.lock === "keychain" ? "a key in this machine's keychain" : "a passphrase"}`,
    ),
  );
  const address = keystore.mind;
  if (address === undefined) {
    return [
      ...checks,
      fails("the mind was never published", "run `oip init` again: it goes on with the same keys"),
    ];
  }
  const due = await keystore.backupDue();
  checks.push(
    due.length === 0
      ? ok("a backup holds every key")
      : warn(
          `no backup holds the keys as they are now (${due.join(", ")})`,
          "oip keys backup <file>",
        ),
  );
  if (config.resolvers.length === 1 && config.network === undefined) {
    checks.push(
      warn(
        "the mind trusts one resolver: a single resolver that serves a forked log is not found out",
        "name a second, run by someone else, in config.json",
      ),
    );
  }
  let resolved: Resolved;
  try {
    resolved = await new Lookup(options).resolve(address);
  } catch (error) {
    const code = codeOf(error);
    if (code === undefined) throw error;
    return [
      ...checks,
      fails(
        `no resolver serves the mind's log (${code})`,
        "see that the resolvers in config.json are right, and reachable",
      ),
    ];
  }
  for (const { resolver, events, failure } of resolved.sources) {
    checks.push(
      events === undefined
        ? warn(
            `${resolver} did not serve the mind's log (${failure ?? "no reason"})`,
            "it is asked again by the next command",
          )
        : ok(`${resolver} serves the mind's log: ${counted(events, "event")}`),
    );
  }
  const { state } = resolved;
  if (resolved.duplicitous) {
    checks.push(
      fails(
        "the mind's log has two events at one position: nothing after it is relied on",
        "this cannot be mended: retire the mind, and make another",
      ),
    );
  }
  if (state.retired)
    checks.push(
      warn(
        "the mind is retired: it signs nothing more",
        "make another with `oip init`, in a directory of its own",
      ),
    );
  // The clock: a signature dated more than 300 seconds off is refused (core 9.1).
  const [first] = config.resolvers;
  const theirs = first === undefined ? undefined : (await ready(fetch, first)).at;
  const ours =
    context.edges.clock === undefined ? Date.now() : Number(context.edges.clock.now() / 1_000_000n);
  if (theirs !== undefined) {
    const off = Math.round(Math.abs(ours - theirs) / 1000);
    checks.push(
      off * 1000 > SKEW_MS
        ? fails(
            `this machine's clock differs from ${String(first)}'s by ${counted(off, "second")}: what it signs now is refused`,
            "set the clock",
          )
        : ok("this machine's clock agrees with the resolver's"),
    );
  }
  if (state.homes.length === 0) {
    checks.push(
      warn(
        "the mind names no host: it takes no packets, and has no feed",
        "a mind is given hosts when it is made: oip init --host",
      ),
    );
  }
  for (const host of state.homes) {
    checks.push(
      (await ready(fetch, host)).ready
        ? ok(`${host} is ready`)
        : warn(
            `${host}, a host of the mind, does not answer`,
            "packets for the mind wait at its other hosts, or with their senders",
          ),
    );
  }
  if (state.homes.length > 0) {
    const { location } = resolved;
    if (location === undefined) {
      checks.push(warn("the mind has not said where it takes packets", "oip publish location"));
    } else if (resolved.stale) {
      checks.push(
        warn(
          "the mind's location record is out of date: senders may not rely on it",
          "oip publish location",
        ),
      );
    } else {
      checks.push(
        ok(
          `the mind is ${location.record.status}, at ${counted(location.record.endpoints.length, "endpoint")}`,
        ),
      );
    }
  }
  checks.push(
    resolved.participant === undefined
      ? warn(
          "the mind has no profile: nobody finds it by what it can do",
          "oip publish profile --name <name>",
        )
      : ok(`its profile is published: ${resolved.participant.record.name}`),
  );
  if (config.indexers.length === 0) {
    checks.push(
      warn("the mind names no indexer: `oip find` has nobody to ask", "name one in config.json"),
    );
  }
  for (const indexer of config.indexers) {
    checks.push(
      (await ready(fetch, indexer)).ready
        ? ok(`${indexer} is ready`)
        : warn(`${indexer}, an indexer, does not answer`, "`oip find` asks the others"),
    );
  }
  // What waits to be sent again is in the client's memory, by name: nothing of it is read.
  let waiting = 0;
  try {
    waiting = (await fileStorage(home.memory).list()).filter((name) =>
      name.startsWith("client-out-"),
    ).length;
  } catch (error) {
    if (codeOf(error) === undefined) throw error;
  }
  if (waiting > 0) {
    checks.push(
      warn(
        `${counted(waiting, "packet")} sent from here did not arrive yet: each is kept, to be sent again`,
        "`oip inbox` tries them when they are due",
      ),
    );
  }
  return checks;
}

const LABELS = { ok: "ok", warn: "warn", fails: "FAILS" } as const;

export const doctor: Command = {
  name: "doctor",
  summary: "Looks at the mind's directory and its services, and says what is well and what is not",
  flags: {},
  notes: [
    "It changes nothing, and unlocks no key: no passphrase is asked for.",
    "Each line is one thing it looked at. `warn` is what works and should be seen to. The",
    "command ends with 1 if anything fails: the mind then cannot do its work.",
  ],
  example: "oip doctor",
  async run(context, given) {
    if (given.positionals.length > 0) throw new UsageError("doctor takes no arguments");
    const home = new Home(context.dir);
    const checks: Check[] = [];
    let config: Config | undefined;
    try {
      config = home.read();
      checks.push(ok(`a mind's directory is at ${home.dir}`));
      if (process.platform !== "win32" && (statSync(home.dir).mode & 0o077) !== 0) {
        checks.push(
          warn("the directory can be read by other users of this machine", `chmod 700 ${home.dir}`),
        );
      }
    } catch (error) {
      if (!(error instanceof UsageError)) throw error;
      checks.push(fails(error.message, "oip init"));
    }
    if (config?.network !== undefined) {
      try {
        readNetwork(config.network);
        checks.push(ok(`the network on this machine is running, from ${config.network}`));
      } catch (error) {
        if (!(error instanceof UsageError)) throw error;
        checks.push(
          fails(
            `the mind's services are a network on this machine, and none is running from ${config.network}`,
            "start it in another terminal: oip demo",
          ),
        );
        config = undefined;
      }
    }
    if (config !== undefined) checks.push(...(await checksOf(context, home, config)));
    const failed = checks.some(({ state }) => state === "fails");
    const warned = checks.filter(({ state }) => state === "warn").length;
    return {
      lines: [
        ...checks.flatMap(({ state, what, advice }) => [
          row(LABELS[state], what),
          ...(advice === undefined ? [] : [row("", `do: ${advice}`)]),
        ]),
        failed
          ? "The mind cannot do its work until what fails is mended."
          : warned === 0
            ? "All is well."
            : `The mind works. ${counted(warned, "thing")} should be seen to.`,
      ],
      json: { directory: home.dir, well: !failed && warned === 0, failed, checks },
      failed,
    };
  },
};
