// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The hot paths of the Mind Network: a packet that arrives, sealed or not,
 * and takes its place in its session; a feed read entry by entry; and an
 * authenticated HTTP request.
 *
 * BUILD.md 3.8 has one row for them, the delivery of a packet over a
 * WebSocket on one machine (p99 of 20 ms), which M5 measures with the
 * servers. The checks here are ratios against judging one record with one
 * proof, which is a signature and the reading around it: they hold on any
 * machine, and say what each rule of the network adds to the signature a
 * receiver must check in any case (ADR-0006).
 */

import {
  contentId,
  encodeX25519Multikey,
  forgetVerifiedSignatures,
  formatKeyRef,
  sha256,
  utf8,
  x25519PublicKey,
} from "@oip/core";
import { judgeRecord, LogBook } from "@oip/identity";
import type { JsonObject } from "@oip/testkit";
import { at, intentBy, KeyMind, LATER, T, witness } from "@oip/testkit/minds";
import { describe, expect, test } from "vitest";

import {
  type HttpRequest,
  receivePacket,
  type Receiver,
  receiveSealed,
  RequestNonces,
  sealPacket,
  Sessions,
  signRequest,
  verifyFeed,
  verifyRequest,
} from "../src/index.ts";

export const BUDGETS = {
  /**
   * A packet that arrives, with one proof, judged by the rules of Layer 1,
   * 12.4, against judging one record with one proof. It is that signature,
   * and the address, the dates and the receiver's memory. It measures at
   * about MEASURED_RECEIVE.
   */
  receive: 1.3,
  /**
   * The place of an accepted packet in its session's chain (14.3). No
   * signature: it measures at about MEASURED_TAKE.
   */
  take: 0.05,
  /**
   * A sealed packet opened and judged (12.6): the signature, and one
   * agreement under X25519 with the authenticated decryption. It measures
   * at about MEASURED_OPEN.
   */
  open: 2.6,
  /**
   * A feed of 50 entries verified, for each entry (Section 10): one
   * signature, and the entry's place. It measures at about MEASURED_FEED.
   */
  feedPerEntry: 1.3,
  /**
   * An authenticated HTTP request (13.3): one signature over the signature
   * base, the reading of two structured fields, and the key's standing. It
   * measures at about MEASURED_REQUEST.
   */
  request: 1.3,
} as const;

/** How many times each ratio is measured. Odd, so that one of them is the middle. */
const ROUNDS = 3;

/** The middle of an odd number of values. */
function middle(values: readonly number[]): number {
  const sorted = values.toSorted((a, b) => a - b);
  return sorted[(sorted.length - 1) / 2] ?? Number.NaN;
}

type Signed = JsonObject & { proof: JsonObject[] };

const HOUR = 3_600_000_000_000n;
const FEED = 50;

const ada = new KeyMind("ada");
const secret = sha256(utf8("bob/agreement/secret"));
/** Bob's agreement key is a real one, so that a packet can be sealed to him and opened. */
const bob = new KeyMind("bob", 0, {
  agreement: [{ key: encodeX25519Multikey(x25519PublicKey(secret)) }],
});
const agreement = encodeX25519Multikey(x25519PublicKey(secret));

const session = {
  oip: "1",
  type: "Session",
  participants: [ada.address, bob.address].sort(),
  nonce: "session-0001",
  created: T(0),
};

/** The `seq`th packet of Ada's chain in the session. The first carries the `Session` record. */
function packetAt(seq: number, prev: object | undefined): Signed {
  return ada.sign({
    oip: "1",
    type: "Packet",
    from: ada.address,
    to: [bob.address],
    created: T(100 + seq),
    nonce: "nonce-0001",
    session: contentId(session),
    seq,
    ...(prev === undefined ? {} : { prev: contentId(prev) }),
    purpose: { verb: "inform" },
    content:
      seq === 0
        ? { mediaType: "application/oip+json", body: session }
        : { mediaType: "text/plain", body: `Page ${seq} is translated.` },
  });
}

/** The entries of Ada's feed, each publishing an Intent of hers. */
function feedOf(length: number): Signed[] {
  const entries: Signed[] = [];
  for (let seq = 0; seq < length; seq++) {
    const published = ada.sign(intentBy(ada, 200 + seq, { want: `Thing ${seq}.` })) as Signed;
    entries.push(
      ada.sign({
        oip: "1",
        type: "Entry",
        author: ada.address,
        seq,
        ...(seq === 0 ? {} : { prev: contentId(entries[seq - 1]!) }),
        created: T(300 + seq),
        object: contentId(published),
        objectType: "Intent",
      }),
    );
  }
  return entries;
}

describe("the hot paths of the Mind Network", () => {
  const first = packetAt(0, undefined);
  const second = packetAt(1, first);
  const entries = feedOf(FEED);
  const seen = witness([ada.events, bob.events], [first, second, ...entries]);
  const book = new LogBook(seen);
  book.hold(ada.events, LATER);
  book.hold(bob.events, LATER);
  const receiver: Receiver = {
    address: bob.address,
    now: at(110),
    view: book,
    accepted: () => false,
    window: HOUR,
  };
  const drain: HttpRequest = {
    method: "GET",
    url: "https://mailbox.example/oip/mbox/abc?after=17",
    headers: [["Accept", "application/oip+json"]],
  };

  test("stay close to the signature each must check", async ({ bench }) => {
    const sealed = await sealPacket({
      packet: second,
      to: bob.address,
      view: book,
      randomness: new Uint8Array(32).fill(7),
    });
    if (!sealed.ok) throw new Error(JSON.stringify(sealed.issues));
    const sealedReceiver = {
      ...receiver,
      agreementKey: (key: string) => (key === agreement ? secret : undefined),
    };
    const added = await signRequest(
      drain,
      {
        keyRef: formatKeyRef(ada.address, ada.versionId(), ada.operational().publicKey),
        created: at(100),
        nonce: "nonce-0001",
      },
      ada.operational(),
    );
    const request: HttpRequest = { ...drain, headers: [...drain.headers, ...added] };
    const arrived = receivePacket(first, receiver);
    const next = receivePacket(second, receiver);
    if (!arrived.ok || !next.ok) throw new Error("the packets were not accepted");
    // What is measured gives the answer it should.
    expect((await receiveSealed(sealed.value, sealedReceiver)).ok).toBe(true);
    const whole = verifyFeed(entries, ada.address, book);
    expect(whole.ok && whole.value.entries).toHaveLength(FEED);
    expect(
      verifyRequest(request, { now: at(110), view: book, nonces: new RequestNonces() }).ok,
    ).toBe(true);
    const ratios = {
      receive: [] as number[],
      take: [] as number[],
      open: [] as number[],
      feed: [] as number[],
      request: [] as number[],
    };
    for (let round = 1; round <= ROUNDS; round++) {
      // What is timed is the checking of signatures: none is remembered from the call before.
      const measure = async (name: string, run: () => unknown): Promise<number> =>
        (
          await bench(`${name} (round ${round})`, () => {
            forgetVerifiedSignatures();
            return run();
          }).run()
        ).latency.p50;
      const one = await measure("judgeRecord: one packet, one proof", () => judgeRecord(first));
      ratios.receive.push(
        (await measure("receivePacket: one packet, one proof", () =>
          receivePacket(first, receiver),
        )) / one,
      );
      ratios.take.push(
        (await measure("Sessions.take: two packets of a chain, for each", () => {
          const sessions = new Sessions(bob.address);
          sessions.take(arrived.value);
          sessions.take(next.value);
        })) /
          2 /
          one,
      );
      ratios.open.push(
        (await measure("receiveSealed: open and judge one packet", () =>
          receiveSealed(sealed.value, sealedReceiver),
        )) / one,
      );
      ratios.feed.push(
        (await measure(`verifyFeed: ${FEED} entries, for each`, () =>
          verifyFeed(entries, ada.address, book),
        )) /
          FEED /
          one,
      );
      ratios.request.push(
        (await measure("verifyRequest: one signed request", () =>
          verifyRequest(request, { now: at(110), view: book, nonces: new RequestNonces() }),
        )) / one,
      );
    }
    expect(middle(ratios.receive)).toBeLessThan(BUDGETS.receive);
    expect(middle(ratios.take)).toBeLessThan(BUDGETS.take);
    expect(middle(ratios.open)).toBeLessThan(BUDGETS.open);
    expect(middle(ratios.feed)).toBeLessThan(BUDGETS.feedPerEntry);
    expect(middle(ratios.request)).toBeLessThan(BUDGETS.request);
  });
});
