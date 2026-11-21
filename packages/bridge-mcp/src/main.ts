// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `oip-bridge-mcp`: the gateway as a program.
 *
 * The gateway is a mind of its own, made with `oip init` and with a home:
 * its feed is where it attests the minds it makes. Its keys, and those of
 * the minds it makes, are opened by `OIP_PASSPHRASE` or by the machine's
 * keychain. The program takes no passphrase at a terminal.
 *
 * What it says to a person goes to the standard output for a command that
 * ends, and to the standard error while it serves. It says nothing of a
 * credential, anywhere.
 */

import { homedir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";

import { TransportError } from "@oip/client";
import { OipError } from "@oip/core";
import { KeystoreError } from "@oip/keystore";
import { systemKeychain } from "@oip/keystore/node";
import {
  counted,
  directoryOf,
  type Machine,
  printable,
  printableJson,
  UsageError,
  type Where,
} from "@oip/local";

import { type Connect, connector, type Target } from "./connect.ts";
import { CREDENTIALS_FILE } from "./credentials.ts";
import { BridgeError, Gateway } from "./gateway.ts";
import { POLICY_FILE } from "./policy.ts";

/** The version of this program: what it tells a server it is. */
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
  /** Connects to an MCP server. */
  readonly connect: Connect;
  /** The machine, for the gateway's mind and the minds it makes. */
  readonly machine: Machine;
}

/** A program that serves: it ends when it is asked to stop. */
export interface Serving {
  /** Ends once everything that was under way has ended. */
  readonly ended: Promise<void>;
}

const HELP = [
  "oip-bridge-mcp: a gateway that makes MCP servers participants of the Open Intelligence Protocol.",
  "",
  "  oip-bridge-mcp bridge <url> [--name <name>] [--credentials <file>]",
  "      Lists the tools of the MCP server at a URL, and makes the server a mind: a bridged",
  "      mind, attested in the gateway's feed, with a capability for each tool. Done again,",
  "      it brings the mind's profile up to the tools.",
  "",
  "  oip-bridge-mcp bridge --stdio <label> [--name <name>] [--credentials <file>] -- <command> [<argument>...]",
  "      The same, for a server that is a command on this machine. The label names it in",
  "      the mind's records. The command is not published.",
  "",
  "  oip-bridge-mcp servers",
  "      Lists the servers the gateway bridges, each with its mind and its directory.",
  "",
  "  oip-bridge-mcp serve [--every <seconds>]",
  "      Relays: reads each bridged mind's mailbox, calls the tools that are asked for, and",
  "      answers. A tool is called only for a mind the policy in the bridged mind's",
  "      directory names, and that is nobody until the operator writes it:",
  '          { "allow": { "search": "anyone", "send_email": ["did:oip:..."], "*": [] } }',
  "",
  "  --dir <path>           The directory of the gateway's own mind. Default: OIP_DIR, or ~/.oip",
  "  --name <name>          The name the bridged mind's profile gives",
  "  --credentials <file>   What the server asks of whoever calls it: headers for a server at a",
  "                         URL, variables for a command. Readable by its owner alone. The",
  "                         gateway takes a copy into the bridged mind's directory",
  "  --every <seconds>      The rest between two readings of the mailboxes. Default: 5",
  "  --help                 Show this",
  "  --version              Print the version",
  "",
  "The gateway's mind is made first, with `oip init`, and has a home. Its keys, and those",
  "of the minds it makes, are opened by OIP_PASSPHRASE, or by the machine's keychain.",
  "",
].join("\n");

const DEFAULT_EVERY_SECONDS = 5;

/**
 * Runs the program.
 *
 * @param argv - Its arguments, without the program's own name.
 * @param reach - What it reaches outside itself with. Default: the
 *   machine's own, and the MCP project's client.
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
        name: { type: "string" },
        stdio: { type: "string" },
        credentials: { type: "string" },
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
    const machine: Machine = reach.machine ?? {
      env: host.env,
      home: homedir(),
      keychain: systemKeychain,
    };
    const where: Where = { edges: machine, dir: directoryOf(values.dir, machine) };
    const gateway = new Gateway(where, {
      connect: reach.connect ?? connector({ version: VERSION }),
    });

    if (command === "bridge") {
      let target: Target;
      if (values.stdio !== undefined) {
        const [program, ...args] = rest;
        if (program === undefined) {
          throw new UsageError(
            "bridge --stdio takes a command after `--`: oip-bridge-mcp bridge --stdio files -- npx a-server /srv/files",
          );
        }
        target = { kind: "stdio", label: values.stdio, command: program, args };
      } else {
        const [url, ...more] = rest;
        if (url === undefined || more.length > 0) {
          throw new UsageError(
            "bridge takes one URL: oip-bridge-mcp bridge https://tools.example/mcp",
          );
        }
        target = { kind: "http", url };
      }
      const bridged = await gateway.bridge(target, {
        ...(values.name === undefined ? {} : { name: values.name }),
        ...(values.credentials === undefined ? {} : { credentials: values.credentials }),
      });
      say(`${bridged.endpoint} is bridged as ${bridged.mind}`);
      say(
        `${counted(bridged.tools, "tool")} of it ${bridged.tools === 1 ? "is a capability" : "are capabilities"} of that mind` +
          (bridged.withoutSchema === 0
            ? "."
            : `, ${String(bridged.withoutSchema)} without an input schema: none that fits a profile.`),
      );
      for (const { name, why } of bridged.left) {
        say(`Left out: ${name === undefined ? "a tool" : printableJson(name)}: ${why}.`);
      }
      say(`Who may call them is the operator's to say, in ${join(bridged.directory, POLICY_FILE)}`);
      say(`Until it names a mind, the gateway calls no tool for anybody.`);
      return 0;
    }
    if (command === "servers" && rest.length === 0) {
      const servers = gateway.servers();
      for (const { endpoint, mind, tools } of servers) {
        say(`${endpoint}  ${mind}  ${counted(tools, "tool")}  ${gateway.directoryOf(endpoint)}`);
      }
      if (servers.length === 0)
        say("The gateway bridges no server yet: `oip-bridge-mcp bridge <url>`");
      return 0;
    }
    if (command !== "serve" || rest.length > 0) {
      throw new UsageError(
        command === undefined
          ? "say what to do: bridge, servers or serve. `oip-bridge-mcp --help` shows each"
          : `${command} is none of bridge, servers and serve, or takes no such argument`,
      );
    }

    const given = values.every;
    if (
      given !== undefined &&
      (!/^\d{1,4}$/u.test(given) || Number(given) < 1 || Number(given) > 3600)
    ) {
      throw new UsageError("--every is a whole number from 1 to 3600");
    }
    const every = (given === undefined ? DEFAULT_EVERY_SECONDS : Number(given)) * 1000;
    const failed = (error: unknown): void => {
      log(`oip-bridge-mcp: ${error instanceof Error ? error.message : String(error)}`);
    };

    // The relay: each bridged mind's mailbox is read, one server after another, again and again.
    const run = { stopped: false };
    // Asked each time round: a signal changes the answer while the loop waits.
    const stopping = (): boolean => run.stopped;
    let wake: (() => void) | undefined;
    const relaying = (async (): Promise<void> => {
      while (!stopping()) {
        for (const { endpoint } of gateway.servers()) {
          if (stopping()) break;
          try {
            const did = await gateway.relay(endpoint);
            if (did.called.length + did.sent.length + did.receipts.length > 0) {
              log(
                `oip-bridge-mcp: ${endpoint}: ${counted(did.called.length, "tool")} called, ` +
                  `${counted(did.declined.length, "request")} declined, ` +
                  `${counted(did.sent.length, "packet")} sent, ${counted(did.receipts.length, "Receipt")} signed`,
              );
            }
            for (const { packet, message } of did.failed) {
              log(`oip-bridge-mcp: ${endpoint}: ${packet}: ${message}`);
            }
          } catch (error) {
            failed(error);
          }
        }
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
      `oip-bridge-mcp ${VERSION}: relaying for ${counted(gateway.servers().length, "bridged server")}, every ${String(every / 1000)} s`,
    );
    const ended = new Promise<void>((resolve) => {
      const stop = (): void => {
        if (run.stopped) return;
        run.stopped = true;
        wake?.();
        void relaying.catch(failed).then(resolve);
      };
      host.once("SIGINT", stop);
      host.once("SIGTERM", stop);
    });
    return { ended };
  } catch (error) {
    if (error instanceof UsageError) {
      log(`oip-bridge-mcp: ${error.message}`);
      return 2;
    }
    // What went wrong with a server, with the gateway's keys, or with a service of the network.
    if (
      error instanceof BridgeError ||
      error instanceof OipError ||
      error instanceof TransportError ||
      error instanceof KeystoreError
    ) {
      log(`oip-bridge-mcp: ${error.message}`);
      return 1;
    }
    if (error instanceof TypeError && "code" in error) {
      // What `parseArgs` says of arguments it does not know.
      log(`oip-bridge-mcp: ${error.message}. \`oip-bridge-mcp --help\` shows what it takes`);
      return 2;
    }
    throw error;
  }
}

/** The name of the file of credentials, for whoever writes one by hand. */
export { CREDENTIALS_FILE };
