// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The commands of delegation (Layer 1, Section 11): granting authority, and taking it back. */

import { formatTimestamp } from "@oip/core";
import { checkPolicy } from "@oip/delegation";
import { type Delegation, validateRecordOfType } from "@oip/schema";

import { readJson, withMind } from "@oip/local";

import { type Command, many, one, UsageError } from "../command.ts";
import { ACTING_FLAGS, recordOf, SHARING_FLAGS, signed, timeOf } from "./dealing.ts";
import { row } from "./describe.ts";

const DAY = 86_400_000_000_000n;
/** The longest a delegation is made for by a count of days: ten years. Longer is written as a time. */
const MOST_DAYS = 3650;

export const delegate: Command = {
  name: "delegate",
  summary: "Lets another mind sign for this one, within limits: signs a Delegation",
  positionals: "<delegate>",
  flags: {
    command: {
      type: "string",
      value: "command",
      describes: "What it may do: /oip/sign/Commitment, /oip/sign/Offer, /oip/send…",
    },
    days: { type: "string", value: "count", describes: "For how many days from now" },
    expires: { type: "string", value: "time", describes: "Or until when, as 2026-01-31T12:00:00Z" },
    "not-before": { type: "string", value: "time", describes: "From when. Default: from now" },
    policy: {
      type: "string",
      value: "file",
      describes:
        "What must hold of each record it signs so: a file with a JSON array of statements",
    },
    authority: ACTING_FLAGS.authority,
    "send-to": SHARING_FLAGS["send-to"],
    publish: SHARING_FLAGS.publish,
  },
  notes: [
    "What the delegate signs within the delegation binds this mind. A policy constrains only",
    "what it selects: constrain every term that matters, and exclude the delegate as a party.",
    "No longer than its purpose needs: expiry is what bounds a revocation that is missed.",
    "With --authority, the chain that lets this mind act, it passes part of that on.",
    "Give it to the delegate, who names it in what it signs: --send-to.",
  ],
  example:
    "oip delegate did:oip:bciqexample --command /oip/sign/Commitment --days 30 --policy policy.json --send-to did:oip:bciqexample",
  run: (context, given) => {
    const [to, ...more] = given.positionals;
    if (to === undefined || more.length > 0) {
      throw new UsageError("delegate takes the address of the one mind it grants: did:oip:…");
    }
    const command = one(given, "command");
    if (command === undefined) {
      throw new UsageError(
        "a delegation says what the delegate may do: --command /oip/sign/Commitment",
      );
    }
    const days = one(given, "days");
    const until = timeOf(given, "expires");
    if ((days === undefined) === (until === undefined)) {
      throw new UsageError("a delegation ends: say when with --days, or with --expires");
    }
    if (days !== undefined && (!/^[1-9][0-9]{0,3}$/u.test(days) || Number(days) > MOST_DAYS)) {
      throw new UsageError(`${days} is no number of days, of at most ${String(MOST_DAYS)}`);
    }
    const notBefore = timeOf(given, "not-before");
    const file = one(given, "policy");
    const policy = file === undefined ? undefined : readJson(file, "the policy");
    if (policy !== undefined && !Array.isArray(policy)) {
      throw new UsageError(`${String(file)} holds no JSON array: a policy is one, of statements`);
    }
    const checked = checkPolicy(policy);
    if (!checked.ok) {
      const [{ message, clause, path }] = checked.issues;
      throw new UsageError(
        `${String(file)} is no policy: ${message}, at ${path === "" ? "its top" : path} (${clause})`,
      );
    }
    return withMind(context, async (opened) => {
      const { mind } = opened;
      const now = context.edges.clock?.now() ?? BigInt(Date.now()) * 1_000_000n;
      const grant = {
        delegate: to,
        command,
        expires: until ?? formatTimestamp(now + BigInt(days ?? 0) * DAY),
        ...(notBefore === undefined ? {} : { notBefore }),
        ...(policy === undefined ? {} : { policy: policy as Delegation["policy"] }),
      };
      const chain = many(given, "authority").map((named) => {
        const held = validateRecordOfType("Delegation", recordOf(opened, named, "the delegation"));
        if (!held.ok) throw new UsageError(`${named} is no delegation`);
        return held.value;
      });
      const record =
        chain.length === 0 ? await mind.delegate(grant) : await mind.subDelegate(chain, grant);
      return signed(opened, record, given, "inform", [
        row("delegate", record.delegate),
        row("may", record.command),
        row("until", record.expires),
      ]);
    });
  },
};

export const revoke: Command = {
  name: "revoke",
  summary: "Takes a delegation back: signs a Revocation, and puts it on the mind's feed",
  positionals: "<delegation>",
  flags: { "send-to": SHARING_FLAGS["send-to"] },
  notes: [
    "The delegation is named by the ID of one the mind holds, or by a file.",
    "It takes effect for a verifier from when that verifier first sees it: what the delegate",
    "signed before stands. Send it to whoever relies on the delegate, as well as publishing it.",
  ],
  example: "oip revoke bciqexample --send-to did:oip:bciqexample",
  run: (context, given) => {
    const [named, ...more] = given.positionals;
    if (named === undefined || more.length > 0) {
      throw new UsageError("revoke takes one delegation: an ID or a file");
    }
    return withMind(context, async (opened) => {
      const held = validateRecordOfType("Delegation", recordOf(opened, named, "the delegation"));
      if (!held.ok) throw new UsageError(`${named} is no delegation`);
      const record = await opened.mind.revoke(held.value);
      return signed(opened, record, given, "inform", [
        row("revokes", record.revokes),
        row(
          "feed",
          opened.mind.state.homes.length === 0
            ? "the mind has no host: give the revocation out yourself"
            : "it is on the mind's feed",
        ),
      ]);
    });
  },
};
