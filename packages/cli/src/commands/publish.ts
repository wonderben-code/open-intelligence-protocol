// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The commands that publish what a mind says of itself: its profile, where
 * it takes packets, and the records it puts on its public feed.
 */

import type { LocationFields, ProfileFields } from "@oip/client";
import { contentId, parseTimestamp } from "@oip/core";

import { counted, readObject, withMind } from "@oip/local";

import { type Command, many, one, UsageError } from "../command.ts";
import { taken } from "./describe.ts";

/** A capability as `--capability` names one: an ID, `=`, and what it is in a sentence. */
function capabilityOf(given: string, tags: readonly string[]) {
  const at = given.indexOf("=");
  const id = at < 0 ? "" : given.slice(0, at).trim();
  const summary = at < 0 ? "" : given.slice(at + 1).trim();
  if (id === "" || summary === "") {
    throw new UsageError(
      `${given} names no capability: one is written as translate="Translates legal texts"`,
    );
  }
  return { id, summary, ...(tags.length === 0 ? {} : { tags: [...tags] }) };
}

export const publishProfile: Command = {
  name: "publish profile",
  summary: "Publishes what the mind is and can do: its profile, which others find it by",
  flags: {
    name: {
      type: "string",
      value: "name",
      describes: "The mind's name. Anyone can take any name: it identifies nobody",
    },
    summary: { type: "string", value: "text", describes: "What the mind is, in a sentence or two" },
    capability: {
      type: "string",
      multiple: true,
      value: "id=summary",
      describes: "Something the mind can do: a short ID, and what it is in a sentence",
    },
    tag: {
      type: "string",
      multiple: true,
      value: "namespace:value",
      describes: "A tag of every capability named here, as domain:legal or lang:de",
    },
    file: {
      type: "string",
      value: "file",
      describes: "A JSON object with the whole profile, for what the options do not say",
    },
  },
  notes: [
    "The profile takes the place of the one before it: say all of it each time.",
    "A file may hold name, summary, capabilities, actsFor, interfaces, languages and attestations,",
    "as Layer 1, Section 16 has them. An option says its part in place of the file's.",
  ],
  example:
    'oip publish profile --name Ada --capability translate="Translates legal texts" --tag domain:legal --tag lang:de',
  run: (context, given) => {
    const file = one(given, "file");
    const from = file === undefined ? {} : readObject(file, "the profile");
    const name = one(given, "name") ?? from["name"];
    if (typeof name !== "string" || name === "") {
      throw new UsageError("a profile has a name: give one with --name");
    }
    const summary = one(given, "summary");
    const tags = many(given, "tag");
    const capabilities = many(given, "capability").map((named) => capabilityOf(named, tags));
    if (tags.length > 0 && capabilities.length === 0) {
      throw new UsageError("--tag is a tag of the capabilities named with --capability: name one");
    }
    // What the file says is no more trusted than this: the client validates the record it makes.
    const fields = {
      ...from,
      name,
      ...(summary === undefined ? {} : { summary }),
      ...(capabilities.length === 0 ? {} : { capabilities }),
    } as ProfileFields;
    return withMind(context, async ({ mind }) => {
      const profile = await mind.publishProfile(fields);
      const id = contentId(profile);
      return {
        lines: [
          `The mind's profile is published: ${id}`,
          `It is ${profile.name}, with ${counted(profile.capabilities?.length ?? 0, "capability", "capabilities")}.`,
          ...taken(mind.publications),
        ],
        json: { mind: mind.address, id, record: profile, publications: mind.publications },
      };
    });
  },
};

const STATUSES = ["active", "paused", "migrating"] as const;

export const publishLocation: Command = {
  name: "publish location",
  summary: "Publishes where the mind takes packets, and whether it takes them now",
  flags: {
    status: {
      type: "string",
      value: "status",
      describes: "active, paused or migrating. Default: as before, or else active",
    },
    "resume-after": {
      type: "string",
      value: "time",
      describes: "When a mind that is paused means to be back, as 2026-01-31T12:00:00Z",
    },
    ttl: {
      type: "string",
      value: "seconds",
      describes:
        "How long the record is good for: 60 to 86400. Default: as before, or else an hour",
    },
  },
  notes: [
    "The mind's endpoints are an inbox and a mailbox at each of its hosts, unless its record",
    "before said otherwise. A location record is good for a time: publish it again before then.",
  ],
  example: "oip publish location --status paused --resume-after 2026-01-31T12:00:00Z",
  run: (context, given) => {
    const status = one(given, "status");
    if (status !== undefined && !(STATUSES as readonly string[]).includes(status)) {
      throw new UsageError(`${status} is no status: it is active, paused or migrating`);
    }
    const resumeAfter = one(given, "resume-after");
    if (resumeAfter !== undefined && parseTimestamp(resumeAfter) === undefined) {
      throw new UsageError(`${resumeAfter} is no time: it is written as 2026-01-31T12:00:00Z`);
    }
    const seconds = one(given, "ttl");
    if (seconds !== undefined && !/^[1-9][0-9]{1,4}$/u.test(seconds)) {
      throw new UsageError(`${seconds} is no number of seconds from 60 to 86400`);
    }
    const fields: LocationFields = {
      ...(status === undefined ? {} : { status: status as (typeof STATUSES)[number] }),
      ...(resumeAfter === undefined ? {} : { resumeAfter }),
      ...(seconds === undefined ? {} : { ttl: Number(seconds) }),
    };
    return withMind(context, async ({ mind }) => {
      const location = await mind.publishLocation(fields);
      return {
        lines: [
          `The mind is ${location.status}, at ${counted(location.endpoints.length, "endpoint")}, for ${counted(location.ttl, "second")}.`,
          ...taken(mind.publications),
        ],
        json: { mind: mind.address, record: location, publications: mind.publications },
      };
    });
  },
};

export const publishRecord: Command = {
  name: "publish record",
  summary: "Puts a record on the mind's public feed, at its hosts",
  positionals: "<file>",
  flags: {},
  notes: [
    "The file holds the record, as JSON. It may be another mind's: a commitment this mind is a",
    "party to, say. The feed commits to the record and to the proofs it has now.",
    "An entry of a feed cannot be taken back. A mind with no host has no feed.",
  ],
  example: "oip publish record offer.json",
  run: (context, given) => {
    const [file, ...more] = given.positionals;
    if (file === undefined || more.length > 0) {
      throw new UsageError("publish record takes one file, with the record as JSON");
    }
    const record = readObject(file, "the record");
    return withMind(context, async ({ mind }) => {
      const entry = await mind.publishRecord(record);
      return {
        lines: [
          `The record is on the mind's feed, at position ${String(entry.seq)}: ${entry.object}`,
          ...taken(mind.publications),
        ],
        json: { mind: mind.address, entry, publications: mind.publications },
      };
    });
  },
};
