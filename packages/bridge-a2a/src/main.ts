// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `oip-bridge-a2a`: the gateway as a program.
 *
 * The gateway is a mind of its own, made with `oip init` and with a home:
 * its feed is where it attests the minds it makes. Its keys, and those of
 * the minds it makes, are opened by `OIP_PASSPHRASE` or by the machine's
 * keychain. The program takes no passphrase at a terminal.
 *
 * What it says to a person goes to the standard output for a command that
 * ends, and to the standard error while it serves.
 */

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { parseArgs } from "node:util";

import { DEFAULT_MAX_BYTES, type Fetch, systemClock, TransportError } from "@oip/client";
import { OipError } from "@oip/core";
import { KeystoreError } from "@oip/keystore";
import { systemKeychain } from "@oip/keystore/node";
import {
  counted,
  directoryOf,
  guardedReach,
  hold,
  type Machine,
  openMind,
  printable,
  UsageError,
  type Where,
} from "@oip/local";
import { GuardedFetcher } from "@oip/server";

import type { Ask, Get } from "./a2a.ts";
import { Front } from "./front.ts";
import { BridgeError, Gateway, type GatewayEdges } from "./gateway.ts";
import { listen, type Served } from "./listen.ts";
import { A2aServer } from "./server.ts";
import type { PublicJwk } from "./signature.ts";

/** The version of this program: what a card it serves gives as its own. */
export const VERSION = "0.0.0";

/** What the program has of the process it runs in: `process` is one. */
export interface Host {
  /** The environment's variables. */
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly stdout: { write(text: string): unknown };
  readonly stderr: { write(text: string): unknown };
  /** Calls `heard` once, when the process is asked to stop. */
  once(signal: "SIGINT" | "SIGTERM", heard: () => void): unknown;
}

/** What the program reaches outside itself with. A test gives its own. */
export interface Reach {
  /** Gets a URL of an agent's, under the guard against requests to where a stranger should not send one. */
  readonly get: Get;
  /** Makes a request of an agent, under the same guard. */
  readonly ask: Ask;
  /** The machine, for the gateway's mind and the minds it makes. */
  readonly machine: Machine;
}

/** A program that serves: it ends when it is asked to stop. */
export interface Serving {
  /** Ends once everything that was under way has ended. */
  readonly ended: Promise<void>;
}

const HELP = [
  "oip-bridge-a2a: a gateway between the Open Intelligence Protocol and A2A.",
  "",
  "  oip-bridge-a2a bridge <origin>",
  "      Reads the Agent Card of the A2A agent at an HTTPS origin, and makes the agent a",
  "      mind: a bridged mind, attested in the gateway's feed. Done again, it brings the",
  "      mind's profile up to the card.",
  "",
  "  oip-bridge-a2a agents",
  "      Lists the agents the gateway bridges.",
  "",
  "  oip-bridge-a2a serve [--base <url>] [--port <port>] [--host <address>] [--every <seconds>]",
  "      Relays between each bridged mind and its agent. With --base, serves every mind",
  "      that asks for it as an A2A agent under that URL as well: a mind asks by listing",
  "      <url>/<its ID>/.well-known/agent-card.json in its profile, under interfaces.a2a.",
  "",
  "  --dir <path>        The directory of the gateway's own mind. Default: OIP_DIR, or ~/.oip",
  "  --keys <file>       A JSON Web Key Set: keys that may verify the signatures on a card",
  "  --base <url>        The public URL the A2A interface is reached under, as a reverse",
  "                      proxy in front of this program serves it: https://gateway.example/a2a",
  "  --port <port>       The port to listen on. Default: 8780",
  "  --host <address>    The address to listen on. Default: 127.0.0.1",
  "  --every <seconds>   The rest between two readings of the mailboxes. Default: 5",
  "  --help              Show this",
  "  --version           Print the version",
  "",
  "The gateway's mind is made first, with `oip init`, and has a home. Its keys, and those",
  "of the minds it makes, are opened by OIP_PASSPHRASE, or by the machine's keychain.",
  "",
  "One `serve` at a time runs from a gateway's directory. The gateway, and the minds it",
  "makes, reach agents and requesters at public addresses alone. OIP_BRIDGE_FETCH_ALLOW",
  "names further ranges for a test network of the operator's own, as 10.0.0.0/8,fd00::/8.",
  "",
].join("\n");

const DEFAULT_PORT = 8780;
const DEFAULT_EVERY_SECONDS = 5;

const isObject = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** The keys of a JSON Web Key Set, as far as they are keys with a name. */
function keysIn(text: string): PublicJwk[] {
  const set: unknown = JSON.parse(text);
  const keys = isObject(set) ? set["keys"] : undefined;
  if (!Array.isArray(keys)) throw new SyntaxError("it has no list of keys");
  return (keys as readonly unknown[]).filter(
    (key): key is PublicJwk => isObject(key) && typeof key["kid"] === "string",
  );
}

/** The variable that names what the guard allows beside the public addresses. */
export const ALLOW_VARIABLE = "OIP_BRIDGE_FETCH_ALLOW";
/** The file that says a process serves from a gateway's directory (`hold` of `@oip/local`). */
export const HOLD_FILE = "serve.hold";
/** The most time one pass for one agent takes, in milliseconds: what is left then waits for the next. */
const PASS_MS = 30_000;
/** How many agents are relayed for at a time. */
const SIDE_BY_SIDE = 8;

/**
 * A guarded fetcher of this program's.
 *
 * @throws UsageError if the environment allows ranges that are none.
 */
function fetcherOf(
  env: Host["env"],
  limits: { readonly maxBytes?: number; readonly maxRedirects?: number } = {},
): GuardedFetcher {
  // The operator's own test network, and nothing in production: `10.0.0.0/8,fd00::/8`.
  const allow = (env[ALLOW_VARIABLE] ?? "")
    .split(",")
    .map((range) => range.trim())
    .filter((range) => range !== "");
  try {
    return new GuardedFetcher({ userAgent: `oip-bridge-a2a/${VERSION}`, allow, limits });
  } catch {
    throw new UsageError(
      `${ALLOW_VARIABLE} is a list of address ranges with commas between, as 10.0.0.0/8,fd00::/8`,
    );
  }
}

/**
 * How the gateway's minds ask where nobody says otherwise: under the guard
 * of `@oip/server`, like everything else the program fetches.
 *
 * A mind sends its answers where the requester's own records say it is
 * reached, and reads feeds where their authors' records say they are
 * served. Those are URLs that strangers chose. A network on this machine is
 * reached by its routes, which are the operator's own (`guardedReach`).
 */
export function mindsFetch(env: Host["env"] = {}): Fetch {
  // As much as a client reads of one answer, and no redirect: a client follows none.
  return guardedReach(fetcherOf(env, { maxBytes: DEFAULT_MAX_BYTES, maxRedirects: 0 }).fetch);
}

/** The machine the program runs on, where nobody gives it another. */
export function machineOf(host: Pick<Host, "env">): Machine {
  return {
    env: host.env,
    home: homedir(),
    keychain: systemKeychain,
    // What a mind of the gateway asks, it asks for whoever sent it a packet.
    fetch: mindsFetch(host.env),
  };
}

/** How the program reaches agents where nobody says otherwise: under the guard of `@oip/server`. */
export function guarded(env: Host["env"] = {}): Pick<Reach, "get" | "ask"> {
  const fetcher = fetcherOf(env);
  return {
    get: async (url) => {
      const { status, body } = await fetcher.get(url, "application/json, */*;q=0.5");
      return { status, body };
    },
    ask: async ({ url, body, headers }) => {
      const { "content-type": type = "application/json", ...further } = headers;
      const answer = await fetcher.post(url, body, type, "application/json", further);
      return { status: answer.status, body: answer.body };
    },
  };
}

/**
 * Where the keys that verify a card's signatures come from: the operator's
 * own file, and the key set an agent serves at its own origin, which says
 * no more than the card it comes with does, and no less.
 */
function keySource(own: readonly PublicJwk[], get: Get): GatewayEdges["keys"] {
  /** The key sets that were fetched, each once: a card may name one for each of its signatures. */
  const fetched = new Map<string, Promise<PublicJwk[]>>();
  const setAt = (jku: string): Promise<PublicJwk[]> => {
    const known = fetched.get(jku);
    if (known !== undefined) return known;
    const set = (async (): Promise<PublicJwk[]> => {
      try {
        const { status, body } = await get(jku);
        if (status !== 200) return [];
        return keysIn(new TextDecoder("utf-8", { fatal: true }).decode(body));
      } catch {
        // A key set that cannot be had, or is none, gives no key.
        return [];
      }
    })();
    fetched.set(jku, set);
    return set;
  };
  return async ({ kid, jku, origin }) => {
    // A name the operator has a key for is the operator's: no key an agent serves is taken for it.
    const named = own.filter((key) => key.kid === kid);
    if (named.length > 0 || jku === undefined) return named;
    if (!URL.canParse(jku) || new URL(jku).origin !== origin) return [];
    return (await setAt(jku)).filter((key) => key.kid === kid);
  };
}

/** A whole number an option gives, within what it may be. @throws UsageError */
function numberOf(
  given: string | undefined,
  name: string,
  least: number,
  most: number,
): number | undefined {
  if (given === undefined) return undefined;
  const value = Number(given);
  if (!/^\d{1,9}$/u.test(given) || value < least || value > most) {
    throw new UsageError(`--${name} is a whole number from ${String(least)} to ${String(most)}`);
  }
  return value;
}

/**
 * Runs the program.
 *
 * @param argv - Its arguments, without the program's own name.
 * @param reach - What it reaches outside itself with. Default: the
 *   machine's own, and the guarded fetcher.
 * @returns What it exits with, or what serves, where it serves.
 */
export async function main(
  argv: readonly string[],
  host: Host,
  reach: Partial<Reach> = {},
): Promise<number | Serving> {
  const say = (line: string): void => {
    host.stdout.write(`${printable(line)}\n`);
  };
  const log = (line: string): void => {
    host.stderr.write(`${printable(line)}\n`);
  };
  try {
    const { values, positionals } = parseArgs({
      args: [...argv],
      options: {
        dir: { type: "string" },
        keys: { type: "string" },
        base: { type: "string" },
        port: { type: "string" },
        host: { type: "string" },
        every: { type: "string" },
        help: { type: "boolean" },
        version: { type: "boolean" },
      },
      strict: true,
      allowPositionals: true,
    });
    if (values.help === true) {
      host.stdout.write(HELP);
      return 0;
    }
    if (values.version === true) {
      host.stdout.write(`${VERSION}\n`);
      return 0;
    }
    const [command, ...rest] = positionals;
    const machine: Machine = reach.machine ?? machineOf(host);
    const where: Where = { edges: machine, dir: directoryOf(values.dir, machine) };
    const { get, ask } = { ...guarded(host.env), ...reach };
    let own: PublicJwk[] = [];
    if (values.keys !== undefined) {
      try {
        own = keysIn(readFileSync(values.keys, "utf8"));
      } catch (error) {
        throw new UsageError(
          `${values.keys} is no JSON Web Key Set that can be read: ${(error as Error).message}`,
        );
      }
    }
    const gateway = new Gateway(where, { get, ask, keys: keySource(own, get) });

    if (command === "bridge") {
      const [origin, ...more] = rest;
      if (origin === undefined || more.length > 0) {
        throw new UsageError(
          "bridge takes one origin: oip-bridge-a2a bridge https://agent.example",
        );
      }
      const bridged = await gateway.bridge(origin);
      say(`${bridged.origin} is bridged as ${bridged.mind}`);
      say(
        bridged.signed
          ? "Its card is signed, by a key this gateway takes."
          : "Its card is not signed: the gateway read it over HTTPS, and says no more of it.",
      );
      return 0;
    }
    if (command === "agents" && rest.length === 0) {
      const agents = gateway.agents();
      for (const { origin, mind } of agents) say(`${origin}  ${mind}`);
      if (agents.length === 0)
        say("The gateway bridges no agent yet: `oip-bridge-a2a bridge <origin>`");
      return 0;
    }
    if (command !== "serve" || rest.length > 0) {
      throw new UsageError(
        command === undefined
          ? "say what to do: bridge, agents or serve. `oip-bridge-a2a --help` shows each"
          : `${command} is none of bridge, agents and serve, or takes no such argument`,
      );
    }

    const port = numberOf(values.port, "port", 0, 65_535) ?? DEFAULT_PORT;
    const every = (numberOf(values.every, "every", 1, 3600) ?? DEFAULT_EVERY_SECONDS) * 1000;
    const failed = (error: unknown): void => {
      log(`oip-bridge-a2a: ${error instanceof Error ? error.message : String(error)}`);
    };
    // One process serves from a directory. Two would each read the mailboxes, and each answer
    // what it read: an agent would be asked twice, and two Receipts signed for one request.
    const held = hold(where.dir, HOLD_FILE, "serves from this gateway's directory");
    let served: Served | undefined;
    let closeOwn: (() => void) | undefined;
    if (values.base !== undefined) {
      const base = values.base.replace(/\/+$/u, "");
      if (!URL.canParse(base) || !/^https?:$/u.test(new URL(base).protocol)) {
        held.release();
        throw new UsageError(
          "--base is the URL the interface is reached under: https://gateway.example/a2a",
        );
      }
      const opened = await openMind(where);
      closeOwn = (): void => {
        opened.mind.close();
      };
      try {
        const front = new Front({
          opened,
          base,
          version: VERSION,
          clock: machine.clock ?? systemClock,
        });
        served = await listen(new A2aServer(front, new URL(base).pathname, failed), front, {
          port,
          ...(values.host === undefined ? {} : { host: values.host }),
          everyMs: every,
          failed,
        });
      } catch (error) {
        closeOwn();
        held.release();
        // A port that is taken, or an address that is none of this machine's, is the operator's
        // to choose again.
        const { code, message } = error as NodeJS.ErrnoException;
        throw new UsageError(`the port ${String(port)} cannot be listened on: ${code ?? message}`);
      }
      log(
        `oip-bridge-a2a ${VERSION}: serving minds as A2A agents under ${base}, on port ${String(served.port)}`,
      );
    }

    // The relay: each bridged mind's mailbox is read, again and again.
    const run = { stopped: false };
    // Asked each time round: a signal changes the answer while the loop waits.
    const stopping = (): boolean => run.stopped;
    let wake: (() => void) | undefined;
    /** Ends the serving, as a signal does. */
    let stop = (): void => {
      run.stopped = true;
    };
    const relayFor = async (origin: string): Promise<void> => {
      try {
        // A pass has so long. What an agent that is slow, or many requests, leave undone waits
        // for the next pass, and the other agents are not kept waiting for it.
        const until = Date.now() + PASS_MS;
        const did = await gateway.relay(origin, () => stopping() || Date.now() > until);
        if (did.passed.length + did.sent.length + did.receipts.length + did.failed.length > 0) {
          log(
            `oip-bridge-a2a: ${origin}: ${counted(did.passed.length, "request")} passed on, ` +
              `${counted(did.sent.length, "packet")} sent, ${counted(did.receipts.length, "Receipt")} signed, ` +
              `${counted(did.open, "task")} open`,
          );
        }
        for (const { packet, task, message } of did.failed) {
          log(`oip-bridge-a2a: ${origin}: ${packet ?? `task ${JSON.stringify(task)}`}: ${message}`);
        }
      } catch (error) {
        failed(error);
      }
    };
    const relaying = (async (): Promise<void> => {
      while (!stopping()) {
        if (!held.held) {
          // Another process took this one for ended, and serves in its place.
          log(
            "oip-bridge-a2a: another process has taken over this gateway's directory. This one ends",
          );
          setImmediate(() => {
            stop();
          });
          break;
        }
        // Side by side, a few at a time: an agent that does not answer holds up nobody else.
        const origins = gateway.agents().map(({ origin }) => origin);
        const beside = Array.from({ length: Math.min(SIDE_BY_SIDE, origins.length) }, async () => {
          for (let origin = origins.shift(); origin !== undefined; origin = origins.shift()) {
            if (stopping()) return;
            await relayFor(origin);
          }
        });
        await Promise.all(beside);
        if (stopping()) break;
        await new Promise<void>((resolve) => {
          const timer = setTimeout(resolve, every);
          wake = (): void => {
            clearTimeout(timer);
            resolve();
          };
        });
      }
    })();
    log(
      `oip-bridge-a2a ${VERSION}: relaying for ${counted(gateway.agents().length, "bridged agent")}, every ${String(every / 1000)} s`,
    );
    const ended = new Promise<void>((resolve) => {
      let ending = false;
      stop = (): void => {
        if (ending) return;
        ending = true;
        run.stopped = true;
        wake?.();
        void (async (): Promise<void> => {
          await relaying;
          await served?.close();
          closeOwn?.();
        })()
          .catch(failed)
          .then(() => {
            held.release();
            resolve();
          });
      };
      host.once("SIGINT", stop);
      host.once("SIGTERM", stop);
    });
    return { ended };
  } catch (error) {
    if (error instanceof UsageError) {
      log(`oip-bridge-a2a: ${error.message}`);
      return 2;
    }
    // What went wrong with an agent, with the gateway's keys, or with a service of the network.
    if (
      error instanceof BridgeError ||
      error instanceof OipError ||
      error instanceof TransportError ||
      error instanceof KeystoreError
    ) {
      log(`oip-bridge-a2a: ${error.message}`);
      return 1;
    }
    if (error instanceof TypeError && "code" in error) {
      // What `parseArgs` says of arguments it does not know.
      log(`oip-bridge-a2a: ${error.message}. \`oip-bridge-a2a --help\` shows what it takes`);
      return 2;
    }
    throw error;
  }
}
