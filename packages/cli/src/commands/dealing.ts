// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What the commands that sign records share: how a record is named, for
 * whom it is signed, and where it goes once it is.
 */

import { type Acting, carried, type Mind } from "@oip/client";
import { contentId, formatRecordRef, type JsonObject, OipError, parseTimestamp } from "@oip/core";
import { validateRecordOfType } from "@oip/schema";

import { type Arguments, type Flag, has, many, one, type Result, UsageError } from "../command.ts";
import { readObject } from "../files.ts";
import type { Opened } from "../mind.ts";
import { row } from "./describe.ts";
import { deliveryLine } from "./packets.ts";

const CONTENT_ID = /^bciq[a-z2-7]{52}$/u;

/**
 * A record a command is told of: by the content ID of one the mind holds,
 * or by a file that holds it as JSON.
 *
 * @param what - What the record is to the command, for the message: "the offer".
 * @throws UsageError if the mind holds no such record, or there is no such file.
 */
export function recordOf(opened: Opened, named: string, what: string): JsonObject {
  if (!CONTENT_ID.test(named)) return readObject(named, what);
  const held = opened.mind.records().find((record) => contentId(record) === named);
  if (held === undefined) {
    throw new UsageError(
      `the mind holds no record ${named}: \`oip inbox\` reads what was sent to it, and a file names any other`,
    );
  }
  return held as unknown as JsonObject;
}

/** How a record is referred to by another: its author's address, and its content ID. */
export function refOf(record: JsonObject): string {
  const { author } = record;
  try {
    return formatRecordRef(typeof author === "string" ? author : "", contentId(record));
  } catch {
    throw new UsageError("that is no record another can refer to: it names no author");
  }
}

/** An address as a command is given one: `me` is the mind of the directory. */
export const who = (mind: Mind, named: string): string => (named === "me" ? mind.address : named);

/** A time as a command is given one, or what is wrong with it. */
export function timeOf(given: Arguments, flag: string): string | undefined {
  const time = one(given, flag);
  if (time !== undefined && parseTimestamp(time) === undefined) {
    throw new UsageError(`${time} is no time: --${flag} is written as 2026-01-31T12:00:00Z`);
  }
  return time;
}

/** The options of a command that signs for another mind. */
export const ACTING_FLAGS = {
  for: {
    type: "string",
    value: "address",
    describes:
      "The mind it is signed for, in place of this one: a collective this mind is a member of",
  },
  authority: {
    type: "string",
    multiple: true,
    value: "delegation",
    describes:
      "A delegation that lets this mind sign for another: an ID or a file. A chain, root first",
  },
  charter: {
    type: "string",
    value: "charter",
    describes: "The charter that gives this mind a role in the collective it signs for",
  },
} as const satisfies Readonly<Record<string, Flag>>;

/**
 * For whom a record is signed, and by what: the chain of delegations or the
 * charter the command was given, and the mind they are of.
 *
 * A record that says what one mind wants, offers or found is written in
 * the name of the mind it is signed for. A Commitment names in its parties
 * whom it binds, and its author is whoever wrote it: so there the author is
 * this mind, unless `--for` names another.
 *
 * @param own - Whether the author is this mind unless `--for` names another.
 */
export function actingOf(
  opened: Opened,
  given: Arguments,
  own = false,
): { author?: string; acting?: Acting } {
  const chain = many(given, "authority").map((named) => {
    const record = validateRecordOfType("Delegation", recordOf(opened, named, "the delegation"));
    if (!record.ok) throw new UsageError(`${named} is no delegation`);
    return record.value;
  });
  const named = one(given, "charter");
  const charter =
    named === undefined
      ? undefined
      : validateRecordOfType("Collective", recordOf(opened, named, "the charter"));
  if (charter !== undefined && !charter.ok) throw new UsageError(`${String(named)} is no charter`);
  if (chain.length > 0 && charter !== undefined) {
    throw new UsageError("a record is signed for another by --authority or by --charter, not both");
  }
  const [root] = chain;
  const principal = own ? undefined : (root?.subject ?? charter?.value.author);
  const author = one(given, "for") ?? principal;
  return {
    ...(author === undefined ? {} : { author }),
    ...(root === undefined ? {} : { acting: { chain } }),
    ...(charter === undefined ? {} : { acting: { charter: charter.value } }),
  };
}

/** The options of a command whose record may go somewhere once it is signed. */
export const SHARING_FLAGS = {
  publish: {
    type: "boolean",
    describes: "Put it on the mind's public feed, at its hosts, where anyone may read it",
  },
  "send-to": {
    type: "string",
    multiple: true,
    value: "address",
    describes: "Send it to this mind, sealed. It may be given several times",
  },
} as const satisfies Readonly<Record<string, Flag>>;

/**
 * Does what the sharing options ask with a record that is signed: puts it
 * on the mind's feed, and sends it.
 *
 * @param verb - The verb of the packet that carries it.
 * @returns What to say of it, and the same for a program.
 */
export async function share(
  opened: Opened,
  record: object,
  given: Arguments,
  verb: string,
): Promise<{ lines: string[]; json: Record<string, unknown> }> {
  const { mind } = opened;
  const lines: string[] = [];
  const json: Record<string, unknown> = {};
  if (has(given, "publish")) {
    const entry = await mind.publishRecord(record);
    lines.push(row("feed", `position ${String(entry.seq)}`));
    for (const { service, origin, taken, failure } of mind.publications) {
      if (!taken) lines.push(row("not", `the ${service} ${origin} (${failure ?? "no reason"})`));
    }
    json["entry"] = entry;
    json["publications"] = mind.publications;
  }
  const to = many(given, "send-to").map((named) => who(mind, named));
  if (to.length > 0) {
    const sent = await mind.send({ to, verb, content: carried(record) });
    lines.push(...sent.deliveries.map((delivery) => deliveryLine(delivery)));
    json["packet"] = sent.id;
    json["deliveries"] = sent.deliveries;
  }
  return { lines, json };
}

/** The status of a record, or `undefined` for a record of a type that has none. */
export async function statusOf(mind: Mind, record: object): Promise<string | undefined> {
  try {
    return await mind.statusOf(record);
  } catch (error) {
    if (error instanceof OipError && error.code === "invalid-record") return undefined;
    throw error;
  }
}

/**
 * What a command that signed a record says: its ID, its status, and where
 * it went.
 */
export async function signed(
  opened: Opened,
  record: object,
  given: Arguments,
  verb: string,
  more: readonly string[] = [],
): Promise<Result> {
  const { mind } = opened;
  const { type } = record as { type: string };
  const id = contentId(record);
  const status = await statusOf(mind, record);
  const shared = await share(opened, record, given, verb);
  return {
    lines: [
      `The ${type} is ${id}`,
      ...(status === undefined ? [] : [row("status", status)]),
      ...more,
      ...shared.lines,
    ],
    json: {
      mind: mind.address,
      id,
      record,
      ...(status === undefined ? {} : { status }),
      ...shared.json,
    },
  };
}
