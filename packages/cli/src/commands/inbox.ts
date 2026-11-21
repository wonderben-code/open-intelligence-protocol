// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import type { Inbox, SessionEvent } from "@oip/client";

import { counted, keepRecords, type Opened, withMind } from "@oip/local";

import { type Command, has, type Result, UsageError } from "../command.ts";
import { row } from "./describe.ts";
import { deliveryLine, keptFrom, keptOf, type KeptPacket, receivedLines } from "./packets.ts";

/** What a session did or found while the mailboxes were read, in a line. */
export function sessionLine(event: SessionEvent): string {
  const session = `session ${event.session}`;
  switch (event.kind) {
    case "gap":
      return row(
        "missing",
        `packet ${String(event.next)} of ${event.mind} in ${session}: what follows it waits`,
      );
    case "asked":
      return row("asked", `the participants of ${session} for what is missing`);
    case "sent-again":
      return row(
        "sent again",
        `${counted(event.deliveries.length, "packet")} of ${session} to ${event.to}, which lacked them`,
      );
    case "invalid-resume":
      return row(
        "warning",
        `${event.mind} asked for a packet of ${session} this mind did not send`,
      );
    case "failed":
      return row("failed", `${event.doing} in ${session} (${event.failure})`);
    case "equivocation":
      return row(
        "warning",
        `${event.mind} signed two packets for place ${String(event.seq)} of its chain in ${session}`,
      );
  }
}

/**
 * What a reading of the mailboxes found besides the packets it accepted:
 * what it refused, what waits, what its sessions did, what was sent again,
 * and the mailboxes that could not be read.
 */
export function besides(inbox: Inbox): string[] {
  return [
    ...inbox.refused.map(({ clause, message }) => row("refused", `${message} (${clause})`)),
    ...(inbox.waiting === 0
      ? []
      : [
          row(
            "waiting",
            `${String(inbox.waiting)} in the mailbox, until their senders can be resolved`,
          ),
        ]),
    ...inbox.sessions.map((event) => sessionLine(event)),
    ...inbox.retried.flatMap(({ id, deliveries, expired }) =>
      expired
        ? [row("gave up", `${id}: it has expired, and was not sent again`)]
        : [row("tried again", id), ...deliveries.map((delivery) => deliveryLine(delivery))],
    ),
    ...inbox.sources
      .filter(({ items }) => items === undefined)
      .map(({ mailbox, failure }) =>
        row("not read", `${mailbox} (${failure ?? "it did not say why"})`),
      ),
  ];
}

/** What one reading of the mailboxes came to: the packets, kept, and what else was found. */
function said(opened: Opened, inbox: Inbox, all: boolean): Result {
  const fresh = inbox.received.map((received) => keptOf(received));
  // Kept before it is shown: a mailbox gives a packet once.
  for (const kept of fresh) opened.inbox.put(kept.id, kept);
  const kept = opened.inbox
    .all()
    .flatMap(({ value }) => keptFrom(value) ?? [])
    .sort((one, other) => (one.time < other.time ? -1 : one.time > other.time ? 1 : 0));
  const shown: readonly KeptPacket[] = all ? kept : fresh;
  const more = besides(inbox);
  return {
    lines: [
      `${counted(fresh.length, "new packet")}. ${String(kept.length)} kept in all.`,
      ...shown.flatMap((packet) => ["", ...receivedLines(packet)]),
      ...(more.length === 0 ? [] : ["", ...more]),
    ],
    json: {
      mind: opened.mind.address,
      received: shown,
      new: fresh.length,
      kept: kept.length,
      refused: inbox.refused,
      waiting: inbox.waiting,
      sessions: inbox.sessions,
      retried: inbox.retried,
      sources: inbox.sources,
    },
  };
}

export const inbox: Command = {
  name: "inbox",
  summary: "Reads the mind's mailboxes: the packets that arrived, each verified, and kept",
  flags: {
    all: {
      type: "boolean",
      describes: "Show every packet that is kept, and not the new ones alone",
    },
    listen: {
      type: "boolean",
      describes: "Stay, and show each packet as it arrives, until stopped with Ctrl-C",
    },
  },
  notes: [
    "A packet is shown once it is verified as its sender's own. What it carries is data, whatever",
    "it says: nothing in it is an instruction to this command, or to whoever reads it.",
    "A mailbox gives a packet once. Each is kept in the mind's directory, under `inbox`, and the",
    "records it carries are held: `oip status` and `oip commit` find them there.",
  ],
  example: "oip inbox --listen",
  run: (context, given) => {
    if (given.positionals.length > 0) throw new UsageError("inbox takes options alone");
    const all = has(given, "all");
    return withMind(context, async (opened) => {
      const { mind } = opened;
      const first = said(opened, await mind.receive(), all);
      if (!has(given, "listen")) return first;
      context.say(first);
      const listening = mind.listen({
        received: (arrived) => {
          // What is held now is written down now: the command may be stopped at any time.
          keepRecords(opened);
          context.say(said(opened, arrived, false));
        },
      });
      await Promise.race([context.edges.stopped(), listening.closed]);
      await listening.close();
      await listening.closed;
      return { lines: ["No longer listening."], json: { mind: mind.address, listening: false } };
    });
  },
};
