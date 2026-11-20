// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { type Found, Lookup } from "@oip/client";
import { type Instant, proofDigest } from "@oip/core";
import type { CapabilityQuery } from "@oip/schema";

import { type Command, has, many, one, UsageError } from "../command.ts";
import { Home } from "../home.ts";
import { lookupOptions, servicesOf } from "../mind.ts";
import { KeptRecords } from "../records.ts";
import { row } from "./describe.ts";
import { networkDirectory } from "./init.ts";

const KINDS = { participant: "Participant", offer: "Offer", intent: "Intent" } as const;
const LABELS = { Participant: "profile", Offer: "offer", Intent: "intent" } as const;

/** What a record that was found says, in a line. They are a stranger's words. */
function saying(found: Found): string {
  const { record, capability } = found;
  if (record.type === "Participant") {
    return capability === undefined
      ? record.name
      : `${record.name}: ${capability.summary} (${capability.id})`;
  }
  if (record.type === "Intent") return record.want;
  const { price } = record.terms;
  return price === undefined
    ? record.provides
    : `${record.provides} (${price.amount} ${price.currency})`;
}

export const find: Command = {
  name: "find",
  summary: "Finds minds by what they can do: asks the indexers, and verifies what they name",
  flags: {
    want: { type: "string", value: "text", describes: "What is wanted, in words" },
    tag: {
      type: "string",
      multiple: true,
      value: "namespace:value",
      describes: "A tag a result must have, as domain:legal. oasf:nlp/* is any tag that begins so",
    },
    kind: {
      type: "string",
      multiple: true,
      value: "kind",
      describes: "What to find: participant, offer or intent. Default: participant",
    },
    limit: { type: "string", value: "count", describes: "The most results: 1 to 100. Default: 20" },
    local: {
      type: "boolean",
      describes: "Ask the network `oip demo` runs on this machine, with no mind of your own",
    },
    network: {
      type: "string",
      value: "path",
      describes: "The directory of that network. Default: ~/.oip-demo",
    },
  },
  notes: [
    "An indexer's answer is a claim. Every record it names is fetched from its author's hosts and",
    "verified here before it is shown, and what does not check out is told, with why.",
    "The ranking is the indexer's own, and so are its reasons.",
    "Asked from a mind's directory, what is found is kept there: `oip commit --offer` takes one up.",
  ],
  example: 'oip find --want "translate a lease into German" --tag domain:legal',
  async run(context, given) {
    if (given.positionals.length > 0) {
      throw new UsageError("find takes options alone: what is wanted is said with --want");
    }
    const want = one(given, "want");
    const tags = many(given, "tag");
    const kinds = many(given, "kind").map((kind) => {
      if (!Object.hasOwn(KINDS, kind)) {
        throw new UsageError(`${kind} is nothing to find: it is participant, offer or intent`);
      }
      return KINDS[kind as keyof typeof KINDS];
    });
    const limit = one(given, "limit");
    if (limit !== undefined && !/^([1-9][0-9]?|100)$/u.test(limit)) {
      throw new UsageError(`${limit} is no number of results from 1 to 100`);
    }
    const query: CapabilityQuery = {
      ...(want === undefined ? {} : { want }),
      ...(tags.length === 0 ? {} : { tags: [...tags] }),
      ...(kinds.length === 0 ? {} : { kinds }),
      ...(limit === undefined ? {} : { limit: Number(limit) }),
    };
    const config = servicesOf(
      context,
      has(given, "local") ? networkDirectory(context.edges.home, one(given, "network")) : undefined,
    );
    if (config.indexers.length === 0) {
      throw new UsageError(
        "the mind names no indexer to ask: `oip init --indexer` names one when a mind is made",
      );
    }
    const lookup = new Lookup(lookupOptions(context, config));
    const finding = await lookup.find(query);
    if (!has(given, "local")) {
      // What was found is kept for the commands that follow, as `oip commit --offer`: each
      // with when it was first obtained, which is now.
      const kept = new KeptRecords(new Home(context.dir).records);
      for (const { record } of finding.found) {
        const seen: Record<string, Instant> = {};
        for (const proof of record.proof) {
          const digest = proofDigest(proof);
          const first = lookup.seen.proofSeen(digest);
          if (first !== undefined) seen[digest] = first;
        }
        kept.add(record, seen);
      }
    }
    const answered = finding.sources.filter(({ results }) => results !== undefined).length;
    return {
      lines: [
        `${String(finding.found.length)} found. Indexers that answered: ${String(answered)} of ${String(finding.sources.length)}.`,
        ...finding.found.flatMap((found, index) => [
          `${String(index + 1)}. ${found.mind}`,
          row(
            LABELS[found.record.type],
            saying(found) + (found.current ? "" : " (replaced since)"),
          ),
          row("record", found.id),
          ...found.by.map(({ indexer, score, why }) =>
            row("ranked", `${score} by ${indexer}${why === undefined ? "" : `: ${why}`}`),
          ),
        ]),
        ...finding.refused.map(({ indexer, mind, record, failure }) =>
          row("refused", `${record} of ${mind}, named by ${indexer} (${failure})`),
        ),
        ...finding.sources
          .filter(({ results }) => results === undefined)
          .map(({ indexer, failure }) =>
            row("no answer", `${indexer} (${failure ?? "it did not say why"})`),
          ),
      ],
      json: { query, ...finding },
    };
  },
};
