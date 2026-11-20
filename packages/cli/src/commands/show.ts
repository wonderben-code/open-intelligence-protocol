// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { Lookup } from "@oip/client";
import { Keystore } from "@oip/keystore";
import { fileStorage } from "@oip/keystore/node";

import { type Command, UsageError } from "../command.ts";
import { Home } from "../home.ts";
import { lookupOptions } from "../mind.ts";

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
    const resolved = await new Lookup(lookupOptions(context, config)).resolve(address);
    const { state, location, participant } = resolved;
    const row = (name: string, value: string): string => `  ${name.padEnd(10)} ${value}`;
    const listed = (values: readonly string[]): string =>
      values.length === 0 ? "none" : values.join(", ");
    return {
      lines: [
        address,
        row("kind", state.kind),
        row("events", String(state.seq + 1) + (state.retired ? ", and retired" : "")),
        row(
          "keys",
          `${String(state.keys.length)} to sign with, ${String(state.agreement.length)} to be sealed to`,
        ),
        row("homes", listed(state.homes)),
        row("names", listed(state.alsoKnownAs)),
        row("resolvers", listed(config.resolvers)),
        row("indexers", listed(config.indexers)),
        row(
          "location",
          location === undefined
            ? "none published"
            : `${location.record.status}, ${String(location.record.endpoints.length)} endpoints${
                resolved.stale ? ", out of date" : ""
              }`,
        ),
        row(
          "profile",
          participant === undefined
            ? "none published"
            : `${participant.record.name}, ${String(participant.record.capabilities?.length ?? 0)} capabilities`,
        ),
      ],
      json: {
        mind: address,
        directory: home.dir,
        kind: state.kind,
        seq: state.seq,
        retired: state.retired,
        keys: [...state.keys],
        agreement: [...state.agreement],
        homes: [...state.homes],
        alsoKnownAs: [...state.alsoKnownAs],
        resolvers: [...config.resolvers],
        indexers: [...config.indexers],
        location: location?.record ?? null,
        participant: participant?.record ?? null,
      },
    };
  },
};
