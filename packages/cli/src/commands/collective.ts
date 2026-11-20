// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The commands of a collective (Layer 1, Section 9): a mind that its
 * members control together, each signing its identity events with a key of
 * its own.
 */

import { writeFileSync } from "node:fs";

import { contentId, type JsonObject, mindAddress } from "@oip/core";

import { type Command, has, many, one, UsageError } from "../command.ts";
import { withMind } from "../mind.ts";
import { counted } from "../text.ts";
import { recordOf, share, SHARING_FLAGS, who } from "./dealing.ts";
import { row } from "./describe.ts";
import { origins } from "./init.ts";

const OUT = {
  type: "string",
  value: "file",
  describes: "Write the event to this file too, with the proofs it has",
} as const;

/** The members an identity event names, and how many of them act for the collective. */
function controlOf(event: JsonObject): { members: string[]; threshold: number } | undefined {
  const { members, threshold } = (event["controller"] ?? {}) as {
    members?: unknown;
    threshold?: unknown;
  };
  if (!Array.isArray(members) || typeof threshold !== "number") return undefined;
  return { members: (members as readonly unknown[]).map((member) => String(member)), threshold };
}

/** The minds whose proofs an event has, as its proofs name them. */
function signers(event: JsonObject): Set<string> {
  const proofs = Array.isArray(event["proof"]) ? event["proof"] : [];
  const minds = new Set<string>();
  for (const proof of proofs) {
    const method = (proof as { verificationMethod?: unknown } | null)?.verificationMethod;
    const [address] = /^did:oip:[a-z2-7]+/u.exec(typeof method === "string" ? method : "") ?? [];
    if (address !== undefined) minds.add(address);
  }
  return minds;
}

/** The lines that say who has signed an event, of those who must. */
function signedBy(event: JsonObject): { lines: string[]; signed: string[]; waiting: string[] } {
  const control = controlOf(event);
  const have = signers(event);
  const members = control?.members ?? [];
  const waiting = members.filter((member) => !have.has(member));
  return {
    lines: [
      ...members.map((member) => row(have.has(member) ? "signed" : "waiting", member)),
      ...(control === undefined
        ? []
        : [row("acts by", `${String(control.threshold)} of ${counted(members.length, "member")}`)]),
    ],
    signed: members.filter((member) => have.has(member)),
    waiting,
  };
}

export const collectiveCreate: Command = {
  name: "collective create",
  summary: "Founds a collective with other minds: drafts its first event, and signs it as a member",
  flags: {
    member: {
      type: "string",
      multiple: true,
      value: "address",
      describes: "A founding member besides this mind. It may be given several times",
    },
    threshold: {
      type: "string",
      value: "count",
      describes: "How many members act for it: a majority of them",
    },
    host: {
      type: "string",
      multiple: true,
      value: "origin",
      describes: "A host that will serve the collective's records",
    },
    out: OUT,
    "send-to": SHARING_FLAGS["send-to"],
  },
  notes: [
    "The collective exists once every founder has signed its first event, and the event is",
    "published. Each founder signs with `oip collective sign`, and the last adds --publish.",
    "The event is held by this mind, under the ID this prints. Send it to the others: --send-to.",
    "It is signed with an invocation key, which the same lock opens as the keys of everyday work.",
  ],
  example:
    "oip collective create --member did:oip:bciqexample --member did:oip:bciqother --threshold 2 --send-to did:oip:bciqexample",
  run: (context, given) => {
    if (given.positionals.length > 0) throw new UsageError("collective create takes options alone");
    const others = many(given, "member");
    if (others.length === 0) {
      throw new UsageError("a collective has members besides this mind: name each with --member");
    }
    const threshold = one(given, "threshold");
    if (threshold === undefined || !/^[1-9][0-9]{0,2}$/u.test(threshold)) {
      throw new UsageError("a collective acts by a number of its members: --threshold 2");
    }
    const homes = origins(many(given, "host"), "a host");
    return withMind(context, async (opened) => {
      const { mind, lock } = opened;
      const members = [...new Set([mind.address, ...others.map((member) => who(mind, member))])];
      const event = await mind.foundCollective(
        { members, threshold: Number(threshold), ...(homes.length === 0 ? {} : { homes }) },
        { invocation: lock },
      );
      const id = mind.hold(event);
      const out = one(given, "out");
      if (out !== undefined) writeFileSync(out, `${JSON.stringify(event, undefined, 2)}\n`);
      const by = signedBy(event as unknown as JsonObject);
      const shared = await share(opened, event, given, "propose");
      return {
        lines: [
          `The collective will be ${mindAddress(id)}`,
          row("event", id),
          ...by.lines,
          ...shared.lines,
          "It exists once every member has signed: oip collective sign <event>",
        ],
        json: {
          mind: mind.address,
          collective: mindAddress(id),
          id,
          event,
          signed: by.signed,
          waiting: by.waiting,
          ...shared.json,
        },
      };
    });
  },
};

/** The types of the events of an identity log (Layer 1, Section 3). */
const EVENTS = new Set(["Genesis", "Update", "Fork", "Retire"]);

export const collectiveSign: Command = {
  name: "collective sign",
  summary: "Signs, as a member of a collective, one of its identity events or a record in its name",
  positionals: "<record>",
  flags: {
    publish: {
      type: "boolean",
      describes:
        "An event: publish the collective's log with it. A record: put it on this mind's feed",
    },
    out: OUT,
    "send-to": SHARING_FLAGS["send-to"],
  },
  notes: [
    "The record is named by the ID of one the mind holds, as `oip inbox` shows it, or by a file.",
    "Read what you sign. An event changes who the collective is, and a key signs one event for",
    "each position of a collective's log, and no other. A record is the collective's once the",
    "number of members it acts by have signed it.",
    "The proofs of every copy this mind has received are put together. Published, a log goes",
    "to the resolvers this mind trusts: anyone may publish a log, which stands by its signatures.",
  ],
  example: "oip collective sign bciqexample --publish",
  run: (context, given) => {
    const [named, ...more] = given.positionals;
    if (named === undefined || more.length > 0) {
      throw new UsageError("collective sign takes one event or record: an ID or a file");
    }
    return withMind(context, async (opened) => {
      const { mind, lock } = opened;
      const told = recordOf(opened, named, "the record");
      // With the proofs of every copy the mind holds: each member's came in a packet of its own.
      const id = mind.hold(told);
      const held = mind.records().find((record) => contentId(record) === id) ?? told;
      const { type, author } = held as { type: string; author?: unknown };
      const out = one(given, "out");
      const write = (signed: object): void => {
        if (out !== undefined) writeFileSync(out, `${JSON.stringify(signed, undefined, 2)}\n`);
      };
      if (!EVENTS.has(type)) {
        const record = await mind.cosign(held);
        write(record);
        const of = typeof author === "string" ? author : mind.address;
        const counts = await mind.countsFor(record, of);
        const shared = await share(opened, record, given, "inform");
        return {
          lines: [
            `The ${type} is ${id}`,
            row("in name of", of),
            row(
              "counts",
              counts
                ? "yes: enough of its members have signed"
                : "not yet: more of its members must sign",
            ),
            ...shared.lines,
          ],
          json: { mind: mind.address, id, record, author: of, counts, ...shared.json },
        };
      }
      const event = await mind.signEvent(held as never, { invocation: lock });
      mind.hold(event);
      write(event);
      const by = signedBy(event as unknown as JsonObject);
      const lines = [`The event is ${id}`, ...by.lines];
      const json: Record<string, unknown> = {
        mind: mind.address,
        id,
        event,
        signed: by.signed,
        waiting: by.waiting,
      };
      if (has(given, "publish")) {
        const { mind: of } = event as { mind?: string };
        // A first event is the whole log. Any other follows the log as the resolvers have it.
        const before =
          type === "Genesis" || of === undefined
            ? []
            : (await mind.lookup.resolve(of)).log.entries.map((entry) => entry.event);
        const resolved = await mind.publishLog([...before, event]);
        lines.push(
          `The collective is ${resolved.mind}`,
          row("log", counted(resolved.state.seq + 1, "event")),
        );
        json["collective"] = resolved.mind;
        json["publications"] = mind.publications;
      }
      // An event is published as a log, by the option above: it goes on no feed.
      const sending = { ...given, flags: { ...given.flags, publish: false } };
      const shared = await share(opened, event, sending, "inform");
      return { lines: [...lines, ...shared.lines], json: { ...json, ...shared.json } };
    });
  },
};
