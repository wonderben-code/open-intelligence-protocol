// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { writeFileSync } from "node:fs";

import { Lookup } from "@oip/client";

import { counted, lookupOptions, servicesOf } from "@oip/local";

import { type Command, has, one, UsageError } from "../command.ts";
import { describe, described, lineageOf, row } from "./describe.ts";
import { networkDirectory } from "./init.ts";

export const resolve: Command = {
  name: "resolve",
  summary: "Resolves any mind by its address: fetches its log from the resolvers, and verifies it",
  positionals: "<address>",
  flags: {
    aliases: {
      type: "boolean",
      describes: "Check each other name the mind lists: it is the mind's only if it points back",
    },
    local: {
      type: "boolean",
      describes: "Ask the network `oip demo` runs on this machine, with no mind of your own",
    },
    network: {
      type: "string",
      value: "path",
      describes: "The directory of that network. Default: ~/.oip-demo",
    },
    out: {
      type: "string",
      value: "file",
      describes: "Write the mind's bundle to this file: its log, with its location and profile",
    },
  },
  notes: [
    "The resolvers asked are those of this directory's mind. What they serve is verified here,",
    "every event of it: a resolver is trusted for when it first saw an event, and for nothing else.",
  ],
  example: "oip resolve did:oip:bciqexample --aliases",
  async run(context, given) {
    const [address, ...more] = given.positionals;
    if (address === undefined || more.length > 0) {
      throw new UsageError("resolve takes one address: did:oip:…");
    }
    const config = servicesOf(
      context,
      has(given, "local") ? networkDirectory(context.edges.home, one(given, "network")) : undefined,
    );
    const lookup = new Lookup(lookupOptions(context, config));
    const resolved = await lookup.resolve(address);
    const parents = await lineageOf(lookup, resolved);
    const checks = has(given, "aliases") ? (await lookup.aliases(address)).checks : undefined;
    const out = one(given, "out");
    if (out !== undefined) {
      // What a resolver serves of the mind, as this command verified it: `oip verify` reads it.
      const bundle = {
        oip: "1",
        type: "Bundle",
        mind: resolved.mind,
        log: resolved.log.entries.map((entry) => entry.event),
        ...(resolved.location === undefined ? {} : { location: resolved.location.record }),
        ...(resolved.participant === undefined ? {} : { participant: resolved.participant.record }),
      };
      writeFileSync(out, `${JSON.stringify(bundle, undefined, 2)}\n`);
    }
    return {
      lines: [
        ...describe(resolved, parents),
        ...(checks ?? []).map((check) =>
          row(
            "name",
            `${check.alias}: ${check.verified ? "its own" : `not shown to be (${String(check.reason)})`}`,
          ),
        ),
        row(
          "resolvers",
          resolved.sources
            .map(
              ({ resolver, events }) =>
                `${resolver} (${events === undefined ? "no answer" : counted(events, "event")})`,
            )
            .join(", "),
        ),
      ],
      json: {
        ...described(resolved, parents),
        ...(checks === undefined ? {} : { aliases: checks }),
        did: resolved.did,
        sources: resolved.sources,
      },
    };
  },
};
