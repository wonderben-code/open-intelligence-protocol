// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The parts of the command that are functions of what they are given: tested by themselves. */

import type { Delivery, Inbox, Received, Resolved } from "@oip/client";
import { clause } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import { many, one } from "../src/command.ts";
import { signedBy } from "../src/commands/collective.ts";
import { describe as lines, described, taken } from "../src/commands/describe.ts";
import { besides, sessionLine } from "../src/commands/inbox.ts";
import {
  deliveryLine,
  keptFrom,
  keptOf,
  packetLines,
  receivedLines,
} from "../src/commands/packets.ts";

const ID = `bciq${"a".repeat(52)}`;
const OTHER = `bciq${"b".repeat(52)}`;
const MIND = `did:oip:${ID}`;

describe("what a command was given", () => {
  it("is read as one value, or as several", () => {
    const given = { flags: { a: "x", b: ["y", "z"], c: true }, positionals: [] };
    expect([one(given, "a"), one(given, "b"), one(given, "c"), one(given, "d")]).toStrictEqual([
      "x",
      undefined,
      undefined,
      undefined,
    ]);
    expect([many(given, "a"), many(given, "b"), many(given, "c"), many(given, "d")]).toStrictEqual([
      ["x"],
      ["y", "z"],
      [],
      [],
    ]);
  });
});

describe("a packet, as it is shown and kept", () => {
  const packet = {
    oip: "1",
    type: "Packet",
    from: MIND,
    to: [MIND],
    created: "2026-01-31T12:00:00Z",
    nonce: "AAAAAAAAAAAAAAAAAAAAAA",
    purpose: { verb: "inform" },
    content: { mediaType: "text/plain", body: "Hello." },
    proof: [],
  } as never;

  it("shows each part of its content for what it is", () => {
    const shown = packetLines({
      ...(packet as object),
      purpose: { verb: "request", goal: "A translation" },
      replyTo: OTHER,
      thread: "lease-7",
      session: ID,
      seq: 3,
      content: {
        parts: [
          { mediaType: "text/markdown", body: "# A heading\nand a line" },
          { mediaType: "application/pdf", ref: "https://files.example/a.pdf", digest: "sha256:ab" },
          { mediaType: "application/oip+json", body: { type: "Offer" } },
          { mediaType: "application/json", body: { any: "thing" } },
          { mediaType: "text/plain", body: 5 },
        ],
      },
    } as never);
    expect(shown).toStrictEqual([
      "  verb       request: A translation",
      `  reply to   ${OTHER}`,
      "  thread     lease-7",
      `  session    ${ID}, packet 3 of its sender`,
      "  text       text/markdown",
      "    # A heading",
      "    and a line",
      "  reference  application/pdf at https://files.example/a.pdf (sha256:ab)",
      "  record     one that is no record",
      "  content    application/json: --json has it",
      "  content    text/plain: --json has it",
    ]);
    expect(packetLines({ ...(packet as object), session: ID } as never)).toContain(
      `  session    ${ID}, packet 0 of its sender`,
    );
  });

  it("says who sent it, for whom, through whom, and whether it was sealed", () => {
    const received = { id: ID, packet, from: MIND, sealed: true, time: 1_769_860_800_000_000_000n };
    expect(receivedLines(keptOf(received as Received))).toStrictEqual([
      ID,
      `  from       ${MIND}`,
      "  at         2026-01-31T12:00:00Z, sealed to this mind",
      "  verb       inform",
      "  text",
      "    Hello.",
    ]);
    const forAnother = keptOf({
      ...received,
      sealed: false,
      sentFor: `did:oip:${OTHER}`,
      broker: "https://indexer.example",
    });
    expect(receivedLines(forAnother).slice(1, 4)).toStrictEqual([
      `  from       ${MIND}, for did:oip:${OTHER}`,
      "  at         2026-01-31T12:00:00Z, not sealed",
      "  through    https://indexer.example",
    ]);
  });

  it("is read back from what was kept only if it is that packet", () => {
    for (const value of [
      {},
      {
        id: ID,
        from: MIND,
        sealed: true,
        time: "2026-01-31T12:00:00Z",
        packet: { type: "Packet" },
      },
      { id: ID, from: MIND, sealed: true, time: "2026-01-31T12:00:00Z", packet: { oip: "1" } },
    ]) {
      expect(keptFrom(value)).toBeUndefined();
    }
  });

  it("says what became of it for each recipient", () => {
    const to = MIND;
    const lines_ = [
      { to, sealed: true, stored: true },
      { to, sealed: false, stored: true, ack: {} },
      { to, sealed: true, stored: false, failure: "unreachable", queued: true },
      { to, sealed: true, stored: false, failure: "forbidden" },
      { to, sealed: true, stored: false },
    ].map((delivery) => deliveryLine(delivery as Delivery));
    expect(lines_).toStrictEqual([
      `  delivered  ${to}, sealed`,
      `  delivered  ${to}, not sealed, and acknowledged`,
      `  waiting    ${to} (unreachable): it is kept, and tried again`,
      `  not sent   ${to} (forbidden)`,
      `  not sent   ${to} (no endpoint took it)`,
    ]);
  });
});

describe(`${clause("L1 14.3")} what a reading of the mailboxes found besides its packets`, () => {
  const none: Inbox = {
    received: [],
    refused: [],
    waiting: 0,
    sessions: [],
    retried: [],
    sources: [],
  };

  it("is nothing, where there was nothing", () => {
    expect(besides(none)).toStrictEqual([]);
    expect(
      besides({ ...none, sources: [{ mailbox: "https://host.example/m", items: 2 }] }),
    ).toStrictEqual([]);
  });

  it("says what was refused, what waits, what was sent again, and what could not be read", () => {
    const delivery = { to: MIND, sealed: true, stored: true } as Delivery;
    expect(
      besides({
        ...none,
        refused: [{ clause: "L1 12.4", message: "the packet has expired" }],
        waiting: 2,
        retried: [
          { id: ID, deliveries: [delivery], waiting: 0, expired: false },
          { id: OTHER, deliveries: [], waiting: 0, expired: true },
        ],
        sources: [
          { mailbox: "https://host.example/a", items: undefined, failure: "unreachable" },
          { mailbox: "https://host.example/b", items: undefined },
        ],
      }),
    ).toStrictEqual([
      "  refused    the packet has expired (L1 12.4)",
      "  waiting    2 in the mailbox, until their senders can be resolved",
      `  tried again ${ID}`,
      `  delivered  ${MIND}, sealed`,
      `  gave up    ${OTHER}: it has expired, and was not sent again`,
      "  not read   https://host.example/a (unreachable)",
      "  not read   https://host.example/b (it did not say why)",
    ]);
  });

  it("says what each of its sessions did or found", () => {
    const session = ID;
    const said = [
      { kind: "gap", session, mind: MIND, next: 4 },
      { kind: "asked", session, sent: {} },
      { kind: "sent-again", session, to: MIND, from: 2, deliveries: [{}, {}] },
      { kind: "invalid-resume", session, mind: MIND, packet: OTHER },
      { kind: "failed", session, doing: "asked", failure: "unreachable" },
      { kind: "equivocation", session, mind: MIND, seq: 7, packets: [ID, OTHER] },
    ].map((event) => sessionLine(event as never));
    expect(said).toStrictEqual([
      `  missing    packet 4 of ${MIND} in session ${session}: what follows it waits`,
      `  asked      the participants of session ${session} for what is missing`,
      `  sent again 2 packets of session ${session} to ${MIND}, which lacked them`,
      `  warning    ${MIND} asked for a packet of session ${session} this mind did not send`,
      `  failed     asked in session ${session} (unreachable)`,
      `  warning    ${MIND} signed two packets for place 7 of its chain in session ${session}`,
    ]);
    expect(
      besides({ ...none, sessions: [{ kind: "gap", session, mind: MIND, next: 4 }] }),
    ).toHaveLength(1);
  });
});

describe("an event of a collective", () => {
  it("is signed by the members its proofs name, and waits for the others", () => {
    const key = (mind: string): string => `${mind}?versionId=0-${ID}#z6MkA`;
    const event = {
      controller: { members: [MIND, `did:oip:${OTHER}`], threshold: 2 },
      proof: [{ verificationMethod: key(MIND) }, { verificationMethod: 5 }, null, {}],
    };
    expect(signedBy(event as never)).toStrictEqual({
      lines: [
        `  signed     ${MIND}`,
        `  waiting    did:oip:${OTHER}`,
        "  acts by    2 of 2 members",
      ],
      signed: [MIND],
      waiting: [`did:oip:${OTHER}`],
    });
    // An event that changes no membership names none: nobody is listed.
    for (const other of [
      {},
      { controller: { members: "all", threshold: 2 } },
      { controller: [] },
    ]) {
      expect(signedBy(other as never)).toStrictEqual({ lines: [], signed: [], waiting: [] });
    }
  });
});

describe("a mind, as it is described", () => {
  /** A mind as it was resolved, with only what the description reads. */
  const resolved = (more: object = {}, state: object = {}): Resolved =>
    ({
      mind: MIND,
      state: {
        kind: "agent",
        seq: 0,
        retired: false,
        keys: ["z6MkA"],
        agreement: ["z6LSA"],
        homes: [],
        alsoKnownAs: [],
        ...state,
      },
      log: { children: [] },
      duplicitous: false,
      location: undefined,
      stale: false,
      participant: undefined,
      ...more,
    }) as never;

  it("says what it has not published, and what is wrong with it", () => {
    expect(lines(resolved(), [])).toStrictEqual([
      MIND,
      "  kind       agent",
      "  log        1 event",
      "  keys       1 to sign with, 1 to be sealed to",
      "  homes      none",
      "  names      none",
      "  location   none published",
      "  profile    none published",
    ]);
    const troubled = lines(
      resolved(
        {
          duplicitous: true,
          stale: true,
          location: { record: { status: "paused", endpoints: [{}] } },
          participant: { record: { name: "Ada" } },
          log: { children: [{ position: 1, child: `did:oip:${OTHER}` }] },
        },
        {
          seq: 4,
          retired: true,
          homes: ["https://a.example", "https://b.example"],
          alsoKnownAs: ["https://ada.example"],
        },
      ),
      [
        { mind: `did:oip:${OTHER}`, at: "0-x", status: "claimed" },
        { mind: MIND, at: "0-y", status: "acknowledged" },
      ],
    );
    expect(troubled).toStrictEqual([
      MIND,
      "  kind       agent",
      "  log        5 events, and retired",
      "  keys       1 to sign with, 1 to be sealed to",
      "  homes      https://a.example, https://b.example",
      "  names      https://ada.example",
      `  parent     did:oip:${OTHER} (by its own word alone)`,
      `  parent     ${MIND} (which says so too)`,
      `  child      did:oip:${OTHER}`,
      "  warning    its log has two events at one position",
      "  location   paused, 1 endpoint, out of date",
      "  profile    Ada, 0 capabilities",
    ]);
    expect(described(resolved(), [])).toMatchObject({
      location: null,
      participant: null,
      parents: [],
    });
  });

  it("says which services did not take what was published", () => {
    expect(
      taken([
        { service: "resolver", origin: "https://r.example", taken: true },
        { service: "home", origin: "https://h.example", taken: false, failure: "unreachable" },
        { service: "indexer", origin: "https://i.example", taken: false },
      ]),
    ).toStrictEqual([
      "Services that took it: 1 of 3.",
      "  not        the home https://h.example (unreachable)",
      "  not        the indexer https://i.example (it did not say why)",
    ]);
  });
});
