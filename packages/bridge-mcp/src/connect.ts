// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * An MCP server, as the gateway reaches one.
 *
 * MCP is spoken by the MCP project's own client: the handshake of the
 * older revisions and the stateless requests of the newer, over HTTP or
 * to a command on this machine. The gateway is a client that is nobody: it
 * has no person to ask and no model to lend, and says so. A tool that
 * wants either is told that it cannot have it.
 *
 * A server over HTTP is the operator's choice, and what it answers is its
 * own. Each request goes to the server's own origin and to no other, a
 * redirect is an error, and the operator's headers go where the requests
 * go.
 *
 * The client library writes to the console by itself, a tool's name among
 * what it writes. While a server is connected, what goes to the console is
 * printed as any stranger's text is: with nothing in it a terminal acts on.
 */

import { Client, ProtocolError, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { inspect } from "node:util";

import { printable, UsageError } from "@oip/local";

import type { Credentials } from "./credentials.ts";

/** Where an MCP server is. */
export type Target =
  | {
      readonly kind: "http";
      /** The URL of the server's MCP endpoint. */
      readonly url: string;
    }
  | {
      readonly kind: "stdio";
      /** The operator's name for the server: it is no secret, and is published. */
      readonly label: string;
      /** The command that is the server, and its arguments. They stay on this machine. */
      readonly command: string;
      readonly args: readonly string[];
    };

/** A server the gateway is connected to. */
export interface Server {
  /** What the server calls itself, if it says. Any text. */
  readonly name?: string;
  /** Every tool the server lists (`tools/list`), as it lists them. */
  tools(): Promise<unknown[]>;
  /**
   * Calls a tool (`tools/call`).
   *
   * @returns The result, as the server gave it.
   * @throws Refused if the server answered with an error and no result.
   *   Anything else if the call did not end as a call does: whether the
   *   tool ran is then not known.
   */
  call(tool: string, args: Readonly<Record<string, unknown>>): Promise<unknown>;
  close(): Promise<void>;
}

/** Thrown where a server refused a call: it answered, with an error and no result. */
export class Refused extends Error {
  override readonly name = "Refused";
}

/** Connects to a server. A test gives its own. */
export type Connect = (target: Target, credentials: Credentials) => Promise<Server>;

/**
 * The most pages of `tools/list` that are read, and the most tools. The
 * client library walks the pages itself, and gives up at this many: a
 * server that lists more cannot be bridged.
 */
export const MAX_PAGES = 32;
export const MAX_LISTED = 4096;
const LABEL = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * How a bridged mind's `oip.bridge` block names a server (Layer 0, 1.2):
 * its URL, or `stdio:` and the operator's name for a command.
 *
 * @throws UsageError for a target that is none: a URL that is not HTTPS
 *   (plain HTTP reaches this machine alone), or that carries a name and a
 *   password, a fragment or a query, or a label that is no label.
 */
export function endpointOf(target: Target): string {
  if (target.kind === "stdio") {
    if (!LABEL.test(target.label)) {
      throw new UsageError(
        "a server that is a command is named in lower-case letters, digits, dots, hyphens and underscores, 64 at most",
      );
    }
    if (target.command === "") throw new UsageError("a server that is a command has a command");
    return `stdio:${target.label}`;
  }
  if (!URL.canParse(target.url)) {
    // What was given is not said back: a URL that is none may still hold a key.
    throw new UsageError("that is no URL: a server is named as https://tools.example/mcp");
  }
  const url = new URL(target.url);
  const local = url.protocol === "http:" && LOOPBACK.has(url.hostname);
  if (url.protocol !== "https:" && !local) {
    throw new UsageError(
      "a server is reached over HTTPS: plain HTTP is for a server on this machine alone",
    );
  }
  if (url.username !== "" || url.password !== "" || url.hash !== "") {
    throw new UsageError(
      "the URL of a server carries no name, password or fragment: credentials go in the credentials file",
    );
  }
  if (url.search !== "") {
    // The URL is the `endpoint` of the mind's genesis and of its profile: published, for good.
    throw new UsageError(
      "the URL of a server carries no query: the whole URL is published in the mind's records, and cannot be taken back. What the server wants there goes in the credentials file, under `query`",
    );
  }
  return url.href;
}

/**
 * A `fetch` that reaches one origin, and follows nobody elsewhere.
 *
 * @param origin - The origin of the server.
 * @param inner - What makes the requests.
 */
export function pinned(origin: string, inner: typeof fetch): typeof fetch {
  return (input, init) => {
    const to = new URL(
      typeof input === "string" ? input : input instanceof URL ? input.href : input.url,
    );
    if (to.origin !== origin) {
      // A server names no other place for the gateway to go, with the operator's headers or without.
      return Promise.reject(
        new TypeError("the gateway sends a server's requests to the server's own origin alone"),
      );
    }
    return inner(to, { ...init, redirect: "error" });
  };
}

/** How many servers are connected now: while any is, the console is guarded. */
let connected = 0;
let unguarded: Pick<Console, "debug" | "error" | "info" | "log" | "warn"> | undefined;

/**
 * Has what is written to the console printed as a stranger's text: the
 * client library writes there, and what it writes holds a server's words.
 */
function guardConsole(): void {
  connected += 1;
  if (unguarded !== undefined) return;
  const { debug, error, info, log, warn } = console;
  unguarded = { debug, error, info, log, warn };
  const safe =
    (write: (...said: unknown[]) => void) =>
    (...said: unknown[]): void => {
      // An error, or an object, is written as the console would show it, and then made safe: a
      // server's words are in its message.
      write(...said.map((one) => printable(typeof one === "string" ? one : inspect(one))));
    };
  Object.assign(console, {
    debug: safe(debug),
    error: safe(error),
    info: safe(info),
    log: safe(log),
    warn: safe(warn),
  });
}

function unguardConsole(): void {
  connected -= 1;
  if (connected > 0 || unguarded === undefined) return;
  Object.assign(console, unguarded);
  unguarded = undefined;
}

/**
 * How the gateway connects where nobody says otherwise.
 *
 * @param options.version - The version the gateway gives as its own.
 * @param options.fetch - What requests over HTTP are made with. Default: the platform's.
 * @param options.stderr - Where what a command writes to its standard
 *   error goes. Default: to the gateway's own, as a log.
 */
export function connector(options: {
  readonly version: string;
  readonly fetch?: typeof fetch;
  readonly stderr?: "inherit" | "ignore";
}): Connect {
  return async (target, credentials) => {
    // Checked again here: what is written in the gateway's directory is not taken on trust.
    endpointOf(target);
    const client = new Client(
      { name: "oip-bridge-mcp", version: options.version },
      {
        // Nothing: no person to ask, no model to lend, no files to show.
        capabilities: {},
        versionNegotiation: { mode: "auto" },
        // A tool that asks for input is not answered: the call ends, and the requester is told.
        inputRequired: { autoFulfill: false },
        listMaxPages: MAX_PAGES,
      },
    );
    let transport: StreamableHTTPClientTransport | StdioClientTransport;
    if (target.kind === "http") {
      // What the server wants in its query is the operator's, and is in no record.
      const url = new URL(target.url);
      for (const [name, value] of Object.entries(credentials.query)) {
        url.searchParams.append(name, value);
      }
      transport = new StreamableHTTPClientTransport(url, {
        fetch: pinned(url.origin, options.fetch ?? fetch),
        requestInit: { headers: { ...credentials.headers } },
      });
    } else {
      transport = new StdioClientTransport({
        command: target.command,
        args: [...target.args],
        // What a command needs to start at all, and the operator's variables. Nothing else
        // of the gateway's environment: its passphrase is there.
        env: { ...getDefaultEnvironment(), ...credentials.env },
        stderr: options.stderr ?? "inherit",
      });
    }
    guardConsole();
    try {
      await client.connect(transport);
    } catch (error) {
      unguardConsole();
      throw error;
    }
    const name = client.getServerVersion()?.name;
    let closed = false;
    return {
      ...(typeof name === "string" && name !== "" ? { name } : {}),
      // The library reads every page, as far as `MAX_PAGES`, and leaves out a tool whose
      // declarations of headers it cannot follow.
      tools: async () => (await client.listTools()).tools.slice(0, MAX_LISTED),
      call: async (tool, args) => {
        try {
          return await client.callTool({ name: tool, arguments: { ...args } });
        } catch (error) {
          if (error instanceof ProtocolError) throw new Refused(error.message);
          throw error;
        }
      },
      close: async () => {
        if (closed) return;
        closed = true;
        try {
          await client.close();
        } finally {
          unguardConsole();
        }
      },
    };
  };
}
