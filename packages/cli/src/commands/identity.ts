// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The commands that add an event to the mind's identity log: `rotate`,
 * `add-key`, `revoke-key` and `fork`. Each is signed with the control keys,
 * which are unlocked for the one event and locked again.
 */

import { resolve } from "node:path";

import type { Mind } from "@oip/client";
import { parseTimestamp } from "@oip/core";

import { counted, Home, readObject, withMind } from "@oip/local";

import { type Command, many, one, type Result, UsageError } from "../command.ts";
import { makeMind, origins } from "./init.ts";

/** What every one of these commands says once its event is published. */
function changed(mind: Mind, first: string, more: Readonly<Record<string, unknown>>): Result {
  const resolvers = mind.publications.filter(({ service }) => service === "resolver");
  const took = resolvers.filter(({ taken }) => taken).length;
  return {
    lines: [
      first,
      `This mind's log has ${counted(mind.state.seq + 1, "event")}. Resolvers that have the new one: ${String(took)} of ${String(resolvers.length)}.`,
    ],
    json: { mind: mind.address, seq: mind.state.seq, published: took, ...more },
  };
}

const CONTROL_NOTE =
  "It is signed with the control keys, which the same lock opens as the keys of everyday work.";

export const rotate: Command = {
  name: "rotate",
  summary: "Rotates the mind's control keys: the next are revealed, and new ones committed to",
  flags: {},
  notes: [
    "Every event of a mind's log reveals the control keys the event before it committed to, and",
    "commits to new ones. This adds an event that does only that. The keys that signed are destroyed.",
    "A key of everyday work is replaced with `oip add-key`, and then `oip revoke-key`.",
  ],
  example: "oip rotate",
  run: (context) =>
    withMind(context, async ({ mind, lock }) => {
      await mind.update({}, { control: lock });
      return changed(mind, "The control keys are rotated.", {});
    }),
};

export const addKey: Command = {
  name: "add-key",
  summary: "Makes a new key of everyday work, and adds it to the mind's keys",
  flags: {
    label: {
      type: "string",
      value: "name",
      describes: "A name for the key, of at most 64 characters: where it is used, say",
    },
  },
  notes: [
    "The keys the mind has stay. The new key is sealed in the mind's directory.",
    CONTROL_NOTE,
  ],
  example: "oip add-key --label laptop",
  run: (context, given) =>
    withMind(context, async ({ mind, lock }) => {
      const label = one(given, "label");
      const key = await mind.addKey({ control: lock, ...(label === undefined ? {} : { label }) });
      return changed(mind, `The mind has a new key: ${key}`, { key });
    }),
};

export const revokeKey: Command = {
  name: "revoke-key",
  summary: "Takes a key of everyday work from the mind's keys for good, and destroys it here",
  positionals: "<key>",
  flags: {
    "compromised-since": {
      type: "string",
      value: "time",
      describes:
        "If the key was stolen: from when what it signed is withdrawn, as 2026-01-31T12:00:00Z",
    },
  },
  notes: [
    "What the key signed before stays valid, for a verifier with evidence of when it was signed.",
    "With --compromised-since, what it signed from that time on counts no longer, for everyone",
    "who learns of this event. That cannot be taken back.",
    "A mind keeps at least one key: add another first if this is the last. `oip show --json` lists them.",
  ],
  example: "oip revoke-key z6Mkexample --compromised-since 2026-01-31T12:00:00Z",
  run: (context, given) => {
    const [key, ...more] = given.positionals;
    if (key === undefined || more.length > 0) {
      throw new UsageError("revoke-key takes one key, as `oip show --json` lists it: z6Mk…");
    }
    const since = one(given, "compromised-since");
    if (since !== undefined && parseTimestamp(since) === undefined) {
      throw new UsageError(`${since} is no time: it is written as 2026-01-31T12:00:00Z`);
    }
    return withMind(context, async ({ mind, lock }) => {
      if (!mind.state.keys.includes(key)) {
        throw new UsageError(
          `${key} is not one of the mind's keys: \`oip show --json\` lists them`,
        );
      }
      await mind.revokeKey(key, {
        control: lock,
        ...(since === undefined ? {} : { compromisedSince: since }),
      });
      return changed(
        mind,
        since === undefined
          ? `The key is revoked: ${key}`
          : `The key is revoked, and what it signed from ${since} on is withdrawn: ${key}`,
        { revoked: key, ...(since === undefined ? {} : { compromisedSince: since }) },
      );
    });
  },
};

export const fork: Command = {
  name: "fork",
  summary: "Makes a child of this mind in a directory of its own, and acknowledges it",
  positionals: "[directory]",
  flags: {
    kind: {
      type: "string",
      value: "kind",
      describes: "What the child says it is. Default: what this mind is",
    },
    host: {
      type: "string",
      multiple: true,
      value: "origin",
      describes: "A host that serves the child. Default: the hosts of this mind",
    },
    terms: {
      type: "string",
      value: "file",
      describes: "What the child received, in the parent's words: a file with a JSON object",
    },
    acknowledge: {
      type: "string",
      value: "address",
      describes: "Make no mind: acknowledge one that is made already, by its address",
    },
  },
  notes: [
    "The child is a mind of its own: its own keys, in its own directory, with the same resolvers",
    "and the same kind of lock. Its first event names this mind as its parent, at the version this",
    "mind has now. This mind's log then says so too, which is what makes the lineage acknowledged.",
    "A child inherits none of its parent's keys, delegations or commitments.",
    "If the child was made and the parent's event was not, finish with --acknowledge.",
    CONTROL_NOTE,
  ],
  example: "oip fork ~/.oip-research --terms terms.json",
  run: (context, given) => {
    const [directory, ...more] = given.positionals;
    const named = one(given, "acknowledge");
    if (more.length > 0 || (directory === undefined) === (named === undefined)) {
      throw new UsageError(
        "fork takes a directory to make the child in, or --acknowledge and the address of one that is made",
      );
    }
    const file = one(given, "terms");
    const terms = file === undefined ? undefined : readObject(file, "what the child received");
    const acknowledged = { ...(terms === undefined ? {} : { terms }) };
    return withMind(context, async ({ mind, lock, config }) => {
      if (directory === undefined) {
        const child = named ?? "";
        await mind.fork(child, { control: lock, ...acknowledged });
        return changed(mind, `This mind's log acknowledges its child: ${child}`, { child });
      }
      const hosts = many(given, "host");
      const home = new Home(resolve(directory));
      const made = await makeMind({ ...context, dir: home.dir }, home, config, {
        kind: one(given, "kind") ?? mind.state.kind,
        homes: hosts.length > 0 ? origins(hosts, "a host") : mind.state.homes,
        parents: [{ mind: mind.address, at: mind.state.versionId }],
      });
      const child = made.mind.address;
      made.mind.close();
      await mind.fork(child, { control: lock, ...acknowledged });
      const said = changed(mind, "This mind's log acknowledges it.", {
        child,
        directory: home.dir,
      });
      return {
        lines: [`The child is ${child}`, `Its keys are in ${home.keys}.`, ...said.lines],
        json: said.json,
      };
    });
  },
};
