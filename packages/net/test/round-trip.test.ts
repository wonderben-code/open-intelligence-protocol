// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Every record type of the Mind Network, written and read back (BUILD.md, M4).
 *
 * A record goes out as its canonical form and comes back through the reader a
 * receiver uses. What comes back is the record that went out: the same
 * members, the same bytes when written again, the same content ID, and every
 * proof still verifying.
 */

import {
  canonicalBytes,
  contentId,
  encodeX25519Multikey,
  formatVersionId,
  parseRecord,
  proofDigest,
  sha256,
  utf8,
  verifyProofs,
  x25519PublicKey,
} from "@oip/core";
import { LogBook } from "@oip/identity";
import { clause, type JsonObject, readVectors } from "@oip/testkit";
import {
  at,
  intentBy,
  KeyMind,
  LATER,
  lineageBy,
  locationBy,
  T,
  witness,
} from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import { checkpointRoot, draftAck, receivePacket, sealPacket, Sessions } from "../src/index.ts";

type Signed = JsonObject & { proof: JsonObject[] };

const HOUR = 3_600_000_000_000n;

const ada = new KeyMind("ada");
/** Bob's agreement key is a real one, so that a packet can be sealed to him. */
const bob = new KeyMind("bob", 0, {
  agreement: [{ key: encodeX25519Multikey(x25519PublicKey(sha256(utf8("bob/agreement/secret")))) }],
});
/** A broker. */
const ian = new KeyMind("ian");
/** A fork of Ada, which her log names. */
const kid = new KeyMind("kid", 5, {
  parents: [{ mind: ada.address, at: ada.versionId(0) }],
});
ada.fork(6, { child: kid.address });

const minds = [ada, bob, ian, kid];
const seen = witness(minds.map((mind) => mind.events));
const book = new LogBook(seen);
for (const mind of minds) book.hold(mind.events, LATER);

const intent = ada.sign(intentBy(ada, 10)) as Signed;
const session = {
  oip: "1",
  type: "Session",
  participants: [ada.address, bob.address].sort(),
  nonce: "session-0001",
  created: T(0),
};
const carrying = (record: JsonObject) => ({ mediaType: "application/oip+json", body: record });

const entry = ada.sign({
  oip: "1",
  type: "Entry",
  author: ada.address,
  seq: 0,
  created: T(11),
  object: contentId(intent),
  objectType: "Intent",
  proofs: intent.proof.map((proof) => proofDigest(proof)),
}) as Signed;
const entry1 = ada.sign({
  oip: "1",
  type: "Entry",
  author: ada.address,
  seq: 1,
  prev: contentId(entry),
  created: T(12),
  object: contentId(session),
  objectType: "Session",
}) as Signed;
const packet = ada.sign({
  oip: "1",
  type: "Packet",
  from: ada.address,
  to: [bob.address],
  created: T(20),
  expires: T(3620),
  nonce: "nonce-0001",
  thread: "lease-17",
  purpose: { verb: "propose", goal: "A translation of the lease." },
  content: { parts: [carrying(intent), { mediaType: "text/plain", body: "See the Intent." }] },
  context: { summary: "The lease is in Swahili.", language: "en" },
  constraints: { retention: "P30D", prohibitedUses: ["train"], forwardOk: false },
}) as Signed;
const toQuery = ada.sign({
  oip: "1",
  type: "Packet",
  from: ada.address,
  to: {
    query: { want: "A translator of leases.", limit: 5 },
    brokers: [ian.address],
    maxFanout: 3,
  },
  created: T(20),
  expires: T(3620),
  nonce: "nonce-0002",
  purpose: { verb: "query" },
  content: {
    mediaType: "application/pdf",
    ref: "https://ada.example/lease.pdf",
    digest: `sha256:${"ab".repeat(32)}`,
  },
}) as Signed;
const opening = ada.sign({
  oip: "1",
  type: "Packet",
  from: ada.address,
  to: [bob.address],
  created: T(30),
  nonce: "nonce-0003",
  session: contentId(session),
  seq: 0,
  instance: "laptop",
  purpose: { verb: "open" },
  content: carrying(session),
}) as Signed;

/** The records, by what they are. Each is made as its author would make it. */
async function records(): Promise<[name: string, record: JsonObject][]> {
  const arrived = receivePacket(packet, receiverAt(25));
  if (!arrived.ok) throw new Error(JSON.stringify(arrived.issues));
  const sealed = await sealPacket({
    packet,
    to: bob.address,
    view: book,
    randomness: new Uint8Array(32).fill(7),
  });
  if (!sealed.ok) throw new Error(JSON.stringify(sealed.issues));
  const sessions = new Sessions(bob.address);
  const first = receivePacket(opening, receiverAt(35));
  if (!first.ok) throw new Error(JSON.stringify(first.issues));
  if (!sessions.take(first.value).ok) throw new Error("the opening packet was not taken");
  const resume = sessions.resume(contentId(session), undefined, T(40));
  if (resume === undefined) throw new Error("the session is not held");
  const branch = {
    oip: "1",
    type: "Branch",
    parentSession: contentId(session),
    fork: `${ada.address}?versionId=${formatVersionId(1, contentId(ada.events[1]))}`,
    created: T(45),
  };
  return [
    ["Entry", entry],
    ["Entry, after another", entry1],
    [
      "Checkpoint",
      ada.sign({
        oip: "1",
        type: "Checkpoint",
        author: ada.address,
        created: T(13),
        size: 2,
        head: contentId(entry1),
        root: checkpointRoot([contentId(entry), contentId(entry1)]),
      }),
    ],
    [
      "FeedPage",
      { oip: "1", type: "FeedPage", mind: ada.address, entries: [entry, entry1], next: 1 },
    ],
    [
      "Location",
      ada.sign({
        ...locationBy(ada, 14),
        homes: ["https://ada.example"],
        feed: { seq: 1, head: contentId(entry1) },
        endpoints: [
          { binding: "https", url: "https://ada.example/oip", instance: "laptop", priority: 10 },
          { binding: "mailbox", url: "https://mailbox.example/oip/mbox/ada", priority: 90 },
        ],
      }),
    ],
    [
      "Participant",
      ada.sign({
        oip: "1",
        type: "Participant",
        author: ada.address,
        created: T(15),
        name: "Ada",
        kind: "agent",
        summary: "Translates leases.",
        capabilities: [
          {
            id: "translate",
            summary: "Translate commercial leases between Swahili and English.",
            tags: ["lang:sw", "lang:en"],
            subject: "cap.nlp.translation.legal",
            inputs: ["text/plain"],
            outputs: ["text/markdown"],
          },
        ],
        languages: ["en", "sw"],
      }),
    ],
    ["Lineage", ada.sign(lineageBy(ada, kid.address, 16))],
    ["Packet, to a list", packet],
    ["Packet, to a query", toQuery],
    ["Packet, in a session", opening],
    [
      "Forwarded",
      ian.sign({
        oip: "1",
        type: "Forwarded",
        broker: ian.address,
        to: bob.address,
        packet: toQuery,
        created: T(21),
      }),
    ],
    ["Session", session],
    ["Resume", resume],
    ["Branch", branch],
    [
      "Ack",
      bob.sign(
        draftAck({ received: arrived.value, recipient: bob.address, at: T(25), created: T(26) }),
      ),
    ],
    [
      "Hello",
      bob.sign(
        { oip: "1", type: "Hello", author: bob.address, created: T(50) },
        { more: { challenge: "q8xG3kZ2pV7mT0wR5nY1aB", domain: "https://host.example" } },
      ),
    ],
    ["Sealed", sealed.value],
  ];
}

/** Bob as a receiver, at a time on his clock. */
function receiverAt(seconds: number) {
  return {
    address: bob.address,
    now: at(seconds),
    view: book,
    // His own first sight of what arrives: with no evidence for a proof, no packet counts.
    seen,
    accepted: () => false,
    window: HOUR,
  };
}

/** Writes a record, reads it back, and checks that nothing changed on the way. */
function roundTrip(name: string, record: JsonObject): void {
  const bytes = canonicalBytes(record);
  const read = parseRecord(bytes);
  if (!read.ok) throw new Error(`${name}: ${JSON.stringify(read.issues)}`);
  expect(read.value, name).toStrictEqual(record);
  expect(canonicalBytes(read.value), name).toStrictEqual(bytes);
  expect(contentId(read.value), name).toBe(contentId(record));
  // As text too, which is how most bindings carry it.
  const text = parseRecord(new TextDecoder().decode(bytes));
  expect(text.ok && text.value, name).toStrictEqual(record);
  const proofs = (record["proof"] as unknown[] | undefined) ?? [];
  const verdicts = verifyProofs(read.value);
  expect(verdicts.verified, name).toHaveLength(proofs.length);
  expect(verdicts.rejected, name).toStrictEqual([]);
}

describe(`${clause("core 2.1", "core 3.1")} every record type of the Mind Network, written and read back`, () => {
  it("is the record that was written: its members, its bytes, its content ID and its proofs", async () => {
    const all = await records();
    for (const [name, record] of all) roundTrip(name, record);
    // Every type the milestone builds is among them.
    expect([...new Set(all.map(([, record]) => record["type"]))].sort()).toStrictEqual([
      "Ack",
      "Branch",
      "Checkpoint",
      "Entry",
      "FeedPage",
      "Forwarded",
      "Hello",
      "Lineage",
      "Location",
      "Packet",
      "Participant",
      "Resume",
      "Sealed",
      "Session",
    ]);
  });

  it("is so for the network records of the golden vectors", () => {
    const { cases } = readVectors();
    const names = [
      "location",
      "participant",
      "feed_entry",
      "feed_entry_1",
      "checkpoint",
      "lineage",
      "session",
      "packet",
      "packet_on_behalf",
      "ack",
      "hello",
      "gateway_entry",
      "bridged_participant",
    ];
    for (const name of names) roundTrip(name, cases[name] as JsonObject);
  });
});
