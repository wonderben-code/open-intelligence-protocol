// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `oip-did-resolver`: the HTTP interface of the resolver on a port, as a
 * driver of the DIF Universal Resolver runs.
 *
 * It keeps nothing and holds no key. It asks the resolvers it is given,
 * and verifies what they serve.
 */

import { createServer } from "node:http";
import type { AddressInfo } from "node:net";

import { httpsOrigin, type LookupOptions } from "@oip/client";

import { handle } from "./http.ts";

/** What the program has of the process it runs in: `process` is one. */
export interface Host {
  /** The environment's variables. */
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly stdout: { write(text: string): unknown };
  readonly stderr: { write(text: string): unknown };
  /** Calls `heard` once, when the process is asked to stop. */
  once(signal: "SIGINT" | "SIGTERM", heard: () => void): unknown;
}

/** A program that serves: it ends when it is asked to stop. */
export interface Serving {
  /** The port it listens on. */
  readonly port: number;
  /** Ends once it has stopped listening. */
  readonly ended: Promise<void>;
}

const HELP = [
  "oip-did-resolver: resolves did:oip over HTTP, as a driver of the DIF Universal Resolver.",
  "",
  "  GET /1.0/identifiers/<did>   The result of resolving a did:oip DID, or its document for",
  "                               a caller that accepts application/did+json",
  "  GET /healthz                 200 while it serves",
  "",
  "It is set up by its environment:",
  "",
  "  OIP_DID_RESOLVERS   The resolvers it asks, as HTTPS origins with commas between them.",
  "                      Name two, run by different people",
  "  OIP_DID_HOST        The address to listen on. Default: 127.0.0.1",
  "  OIP_DID_PORT        The port to listen on. Default: 8080",
  "",
  "  --help              Show this",
  "",
].join("\n");

const DEFAULT_PORT = 8080;

/**
 * Runs the program.
 *
 * @param argv - Its arguments, without the program's own name.
 * @param more - What a test gives the lookups besides: a `fetch` of its own.
 * @returns What it exits with, or what serves.
 */
export async function main(
  argv: readonly string[],
  host: Host,
  more: Omit<LookupOptions, "resolvers"> = {},
): Promise<number | Serving> {
  const log = (line: string): void => {
    host.stderr.write(`${line}\n`);
  };
  if (argv.includes("--help")) {
    host.stdout.write(HELP);
    return 0;
  }
  if (argv.length > 0) {
    log("oip-did-resolver: it takes no arguments but --help: it is set up by its environment");
    return 2;
  }
  const resolvers = (host.env["OIP_DID_RESOLVERS"] ?? "")
    .split(",")
    .map((origin) => origin.trim())
    .filter((origin) => origin !== "");
  if (resolvers.length === 0 || resolvers.some((origin) => httpsOrigin(origin) !== origin)) {
    log(
      "oip-did-resolver: OIP_DID_RESOLVERS names the resolvers to ask, as HTTPS origins: https://resolver.example,https://other.example",
    );
    return 2;
  }
  const given = host.env["OIP_DID_PORT"];
  const port = given === undefined || given === "" ? DEFAULT_PORT : Number(given);
  if (!Number.isSafeInteger(port) || port < 0 || port > 65_535 || !/^\d*$/u.test(given ?? "")) {
    log("oip-did-resolver: OIP_DID_PORT is a port: a whole number from 0 to 65535");
    return 2;
  }
  const options: LookupOptions = { ...more, resolvers };
  const http = createServer((request, response) => {
    const { accept } = request.headers;
    void handle(
      {
        method: String(request.method),
        path: String(request.url),
        ...(accept === undefined ? {} : { accept }),
      },
      options,
    ).then(
      (answer) => {
        response.writeHead(answer.status, answer.headers);
        response.end(answer.body);
      },
      (error: unknown) => {
        // What is no fault of the caller's, and is none the resolution could name.
        log(`oip-did-resolver: ${error instanceof Error ? error.message : String(error)}`);
        response.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
        response.end("The resolver could not answer.\n");
      },
    );
  });
  try {
    await new Promise<void>((resolve, reject) => {
      http.once("error", reject);
      http.listen(port, host.env["OIP_DID_HOST"] ?? "127.0.0.1", () => {
        http.off("error", reject);
        resolve();
      });
    });
  } catch (error) {
    const { code, message } = error as NodeJS.ErrnoException;
    log(`oip-did-resolver: the port ${String(port)} cannot be listened on: ${code ?? message}`);
    return 2;
  }
  const listening = (http.address() as AddressInfo).port;
  log(
    `oip-did-resolver: resolving did:oip on port ${String(listening)}, by asking ${resolvers.join(" and ")}`,
  );
  const ended = new Promise<void>((resolve) => {
    const stop = (): void => {
      http.close(() => {
        resolve();
      });
      http.closeAllConnections();
    };
    host.once("SIGINT", stop);
    host.once("SIGTERM", stop);
  });
  return { port: listening, ended };
}
