// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { carried, type Message } from "@oip/client";

import { type Command, has, many, one, UsageError } from "../command.ts";
import { withMind } from "../mind.ts";
import { recordOf, who } from "./dealing.ts";
import { deliveryLine, packetLines } from "./packets.ts";

export const send: Command = {
  name: "send",
  summary: "Sends a packet to one mind or several: signed, and sealed to each",
  positionals: "<address>...",
  flags: {
    text: { type: "string", value: "text", describes: "What to say, as plain text" },
    record: {
      type: "string",
      multiple: true,
      value: "file",
      describes:
        "A record to carry: the ID of one the mind holds, or a file. It may be given several times",
    },
    verb: {
      type: "string",
      value: "verb",
      describes: "What kind of message it is: inform, request, propose, accept… Default: inform",
    },
    goal: { type: "string", value: "text", describes: "What it is for, in a line" },
    "reply-to": { type: "string", value: "id", describes: "The packet it answers, by its ID" },
    thread: { type: "string", value: "id", describes: "The thread it belongs to" },
    "expires-in": {
      type: "string",
      value: "seconds",
      describes: "How long it may be delivered: at most 604800, seven days. Default: an hour",
    },
    unsealed: {
      type: "boolean",
      describes: "Send it in the clear, signed but readable by the hosts that carry it",
    },
  },
  notes: [
    "A packet says something. It binds nobody, whatever its verb: what binds is a record it carries.",
    "A recipient that cannot be reached now is tried again, by `oip inbox` and by the next `oip send`,",
    "for as long as the packet may be delivered.",
  ],
  example:
    'oip send did:oip:bciqexample --verb request --text "Could you translate a lease by Friday?"',
  run: (context, given) => {
    const to = given.positionals;
    if (to.length === 0)
      throw new UsageError("send takes the address of each recipient: did:oip:…");
    const text = one(given, "text");
    const records = many(given, "record");
    if (text === undefined && records.length === 0) {
      throw new UsageError("a packet carries something: say it with --text, or carry a --record");
    }
    const seconds = one(given, "expires-in");
    if (seconds !== undefined && !/^[1-9][0-9]{0,5}$/u.test(seconds)) {
      throw new UsageError(`${seconds} is no number of seconds, of at most 604800`);
    }
    const goal = one(given, "goal");
    const replyTo = one(given, "reply-to");
    const thread = one(given, "thread");
    return withMind(context, async (opened) => {
      const { mind } = opened;
      const parts = [
        ...(text === undefined ? [] : [{ mediaType: "text/plain", body: text }]),
        ...records.map((named) => carried(recordOf(opened, named, "the record"))),
      ];
      const [first = { mediaType: "text/plain", body: "" }, ...more] = parts;
      const message: Message = {
        to: to.map((address) => who(mind, address)),
        verb: one(given, "verb") ?? "inform",
        content: more.length === 0 ? first : { parts },
        ...(goal === undefined ? {} : { goal }),
        ...(replyTo === undefined ? {} : { replyTo }),
        ...(thread === undefined ? {} : { thread }),
        ...(seconds === undefined ? {} : { expiresIn: Number(seconds) }),
        ...(has(given, "unsealed") ? { seal: false } : {}),
      };
      const sent = await mind.send(message);
      return {
        lines: [
          `The packet is ${sent.id}`,
          ...packetLines(sent.packet),
          ...sent.deliveries.map((delivery) => deliveryLine(delivery)),
        ],
        json: { mind: mind.address, ...sent },
      };
    });
  },
};
