// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { Lookup } from "@oip/client";
import { Keystore } from "@oip/keystore";
import { fileStorage } from "@oip/keystore/node";

import { Home, lookupOptions } from "@oip/local";

import { type Command, UsageError } from "../command.ts";
import { describe, described, lineageOf, row } from "./describe.ts";

export const show: Command = {
  name: "show",
  summary: "Shows the mind of this directory, as its resolvers have it",
  flags: {},
  notes: ["It reads, and unlocks no key: no passphrase is asked for."],
  example: "oip show",
  async run(context) {
    const home = new Home(context.dir);
    const config = home.read();
    const keystore = await Keystore.open({ storage: fileStorage(home.keys) });
    const address = keystore.mind;
    if (address === undefined) {
      throw new UsageError(
        `the mind of ${home.dir} was never published: run \`oip init\` again to finish making it`,
      );
    }
    const lookup = new Lookup(lookupOptions(context, config));
    const resolved = await lookup.resolve(address);
    const parents = await lineageOf(lookup, resolved);
    const listed = (values: readonly string[]): string =>
      values.length === 0 ? "none" : values.join(", ");
    return {
      lines: [
        ...describe(resolved, parents),
        row("resolvers", listed(config.resolvers)),
        row("indexers", listed(config.indexers)),
      ],
      json: {
        ...described(resolved, parents),
        directory: home.dir,
        resolvers: [...config.resolvers],
        indexers: [...config.indexers],
      },
    };
  },
};
