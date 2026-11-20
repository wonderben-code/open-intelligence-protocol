// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { NETWORK_FILE, type NetworkFile } from "@oip/local";

import { type Command, one } from "../command.ts";
import { startNetwork } from "../network.ts";
import { networkDirectory } from "./init.ts";

export const demo: Command = {
  name: "demo",
  summary: "Runs a network on this machine: a resolver, a host and an indexer, until it is stopped",
  flags: {
    network: {
      type: "string",
      value: "path",
      describes: "Where the network keeps what it holds. Default: ~/.oip-demo",
    },
  },
  notes: [
    "It is for trying the protocol with nothing else to hand. What it holds is kept, and is",
    "there when it is started again. It listens on this machine only.",
  ],
  example: "oip demo",
  async run(context, given) {
    const { edges } = context;
    const directory = networkDirectory(edges.home, one(given, "network"));
    const network = await startNetwork({ directory });
    const file = join(directory, NETWORK_FILE);
    const said: NetworkFile = {
      resolver: network.resolver,
      host: network.host,
      indexer: network.indexer,
      routes: network.routes,
    };
    try {
      // A mind made with `--local` reads this each time, to know where the network is now.
      writeFileSync(file, `${JSON.stringify(said, undefined, 2)}\n`, { mode: 0o600 });
      const at = (origin: string): string => `${origin}  (${String(network.routes[origin])})`;
      context.say({
        lines: [
          "A network is running on this machine:",
          `  resolver  ${at(network.resolver)}`,
          `  host      ${at(network.host)}`,
          `  indexer   ${at(network.indexer)}`,
          "In another terminal, make a mind on it:",
          "  oip init --local",
          `What it holds is kept in ${directory}. Stop it with Ctrl-C.`,
        ],
        json: { ...said, directory },
      });
      await edges.stopped();
    } finally {
      rmSync(file, { force: true });
      await network.stop();
    }
    return { lines: ["The network has stopped."], json: { stopped: true } };
  },
};
