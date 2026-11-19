// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  contentId,
  formatTimestamp,
  type JsonObject,
  mindId,
  OipError,
  type OipRecord,
  proofDigest,
} from "@oip/core";
import { judgeRecord, ownSignedTime } from "@oip/identity";
import type { Bundle, Proof } from "@oip/schema";
import { Database, HttpFailure, LogArchive } from "@oip/server";
import { clause } from "@oip/testkit";
import { at, intentBy, KeyMind, type Mind, T } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { Host, HOST_MIGRATIONS, type HostOptions } from "../src/index.ts";

let directory: string;
let db: Database;
let clock: { at: bigint; now: () => bigint };
let archive: LogArchive;

const ada = new KeyMind("ada");
const bob = new KeyMind("bob");
const eve = new KeyMind("eve");
const zed = new KeyMind("zed");

const open = (): Database =>
  Database.open({ path: join(directory, "host.db"), durable: false }, HOST_MIGRATIONS, clock);

/** A host that holds the logs of Ada, Bob and Eve, and serves Bob. */
function hosting(more: Partial<HostOptions> = {}): Host {
  archive = new LogArchive({ db, clock });
  for (const mind of [ada, bob, eve]) {
    archive.publish(mindId(mind.address) ?? "", {
      oip: "1",
      type: "Bundle",
      mind: mind.address,
      log: mind.events,
    } as unknown as Bundle);
  }
  const host = new Host({ db, archive, ...more });
  host.adopt(bob.address);
  return host;
}

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "oip-host-"));
  clock = { at: at(110), now: () => clock.at };
  db = open();
});
afterEach(() => {
  db.close();
  rmSync(directory, { recursive: true, force: true });
});

/** A packet from one mind to others, made at 100 and good for an hour. */
function packet(
  from: Mind,
  to: readonly Mind[],
  more: JsonObject = {},
  by: Mind = from,
): OipRecord {
  return by.sign({
    oip: "1",
    type: "Packet",
    from: from.address,
    to: to.map((mind) => mind.address),
    created: T(100),
    expires: T(3700),
    nonce: "nonce-0001",
    purpose: { verb: "inform" },
    content: { mediaType: "text/plain", body: "Hello." },
    ...more,
  }) as unknown as OipRecord;
}

/** A sealed record to a mind. The host cannot open it, so what it holds is of no matter here. */
const sealed = (to: Mind, enc = "AAAA"): OipRecord =>
  ({
    oip: "1",
    type: "Sealed",
    to: to.address,
    key: "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
    suite: "hpke-base-x25519-sha256-chacha20poly1305",
    enc,
    ciphertext: "AAAA",
  }) as unknown as OipRecord;

function refused(work: () => unknown): { code?: string; status?: number } {
  try {
    work();
  } catch (error) {
    if (error instanceof OipError) return { code: error.code };
    if (error instanceof HttpFailure) return { status: error.status };
    throw error;
  }
  throw new Error("it was taken");
}

const seenProofs = (): { digest: string; at: bigint }[] =>
  db.prepareWithTimes("SELECT digest, at FROM seen_proofs ORDER BY at").all() as never;

/**
 * The reading at which the host first saw anything. An archive's readings only go up, so
 * it is the clock's time or a few nanoseconds after it.
 */
function reading(): bigint {
  const [first] = seenProofs();
  if (first === undefined) throw new Error("nothing was seen");
  expect(first.at - clock.at).toBeGreaterThanOrEqual(0n);
  expect(first.at - clock.at).toBeLessThan(100n);
  return first.at;
}

const count = (table: string): number =>
  (db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get() as { n: number }).n;

describe(`${clause("L1 13.2", "L1 12.4")} a packet that arrives at a mind's inbox`, () => {
  it("is kept for the mind, and answered as stored by a host that does not sign for it", () => {
    const host = hosting();
    const sent = packet(ada, [bob]);
    expect(host.deliver(bob.address, sent)).toStrictEqual({ stored: true });
    expect(host.drain(bob.address, 0, 10)).toStrictEqual({ items: [{ cursor: 1, record: sent }] });
    // The proof on it was first seen now, and is recorded with it.
    const [proof] = (sent as unknown as { proof: Proof[] }).proof;
    expect(seenProofs()).toEqual([{ digest: proofDigest(proof!), at: reading() }]);
  });

  it("is answered the same when it arrives again, and is not kept twice", () => {
    const host = hosting();
    const sent = packet(ada, [bob]);
    const first = host.deliver(bob.address, sent);
    clock.at = at(500);
    expect(host.deliver(bob.address, sent)).toStrictEqual(first);
    expect(host.drain(bob.address, 0, 10).items).toHaveLength(1);
    // Even after the mind has taken it out of its mailbox.
    host.remove(bob.address, 1);
    expect(host.deliver(bob.address, sent)).toStrictEqual(first);
    expect(host.drain(bob.address, 0, 10).items).toHaveLength(0);
  });

  it("is acknowledged by a host that holds a key of the mind's, and the same again", () => {
    const host = hosting({
      signer: (mind) => (mind === bob.address ? bob.operational() : undefined),
    });
    const sent = packet(ada, [bob]);
    const ack = host.deliver(bob.address, sent);
    expect(ack).toMatchObject({
      oip: "1",
      type: "Ack",
      author: bob.address,
      packet: contentId(sent),
      received: formatTimestamp(reading()),
      created: formatTimestamp(reading()),
      proofs: [proofDigest((sent as unknown as { proof: Proof[] }).proof[0]!)],
    });
    // It is the recipient's own: a record its operational key signed. Whoever is sent it
    // sees its proof a moment later, and judges it then.
    const judged = judgeRecord(ack);
    if (!judged.ok) throw new Error(JSON.stringify(judged.issues));
    clock.at = at(120);
    archive.witnessing((seen, now) => {
      for (const proof of judged.value.proofs) seen.sawProof(proof.digest, now);
    });
    expect(ownSignedTime(judged.value, bob.address, archive.view(clock.now() + 1000n))).toBe(
      seenProofs()[1]?.at,
    );
    clock.at = at(900);
    expect(host.deliver(bob.address, sent)).toStrictEqual(ack);
  });

  it("is not acknowledged with a key that is not the mind's", () => {
    const host = hosting({ signer: () => eve.operational() });
    expect(host.deliver(bob.address, packet(ada, [bob]))).toStrictEqual({ stored: true });
  });

  it("is refused for what a recipient may not accept, and nothing is kept of it", () => {
    const host = hosting();
    const cases: [string, () => unknown, object][] = [
      [
        "a mind the host does not serve",
        () => host.deliver(ada.address, packet(bob, [ada])),
        { code: "not-found" },
      ],
      [
        "addressed to another",
        () => host.deliver(bob.address, packet(ada, [eve])),
        { code: "forbidden" },
      ],
      [
        "signed by another than its sender",
        () => host.deliver(bob.address, packet(ada, [bob], {}, eve)),
        { code: "invalid-proof" },
      ],
      [
        "from a mind the host holds no log of",
        () => host.deliver(bob.address, packet(zed, [bob])),
        { code: "stale-version" },
      ],
      [
        "no packet",
        () => host.deliver(bob.address, ada.sign(intentBy(ada, 100)) as unknown as OipRecord),
        { code: "invalid-record" },
      ],
      [
        "expired",
        () =>
          host.deliver(bob.address, packet(ada, [bob], { created: T(-9000), expires: T(-8000) })),
        { code: "expired" },
      ],
      [
        "dated ahead",
        () => host.deliver(bob.address, packet(ada, [bob], { created: T(900), expires: T(4500) })),
        { code: "expired" },
      ],
    ];
    for (const [name, work, problem] of cases) expect(refused(work), name).toStrictEqual(problem);
    expect(host.drain(bob.address, 0, 10).items).toStrictEqual([]);
    for (const table of ["mailbox", "accepted", "seen_proofs"]) expect(count(table), table).toBe(0);
  });

  it("takes a sealed record for the mind as it is, and none for another", () => {
    const host = hosting();
    expect(host.deliver(bob.address, sealed(bob))).toStrictEqual({ stored: true });
    expect(refused(() => host.deliver(bob.address, sealed(ada)))).toStrictEqual({
      code: "forbidden",
    });
    expect(host.drain(bob.address, 0, 10).items).toStrictEqual([
      { cursor: 1, record: sealed(bob) },
    ]);
  });
});

describe(`${clause("L1 13.5")} a mind's mailbox`, () => {
  it("keeps what is posted to it for the mind, judged or not", () => {
    const host = hosting();
    // A packet that an inbox would refuse: the mind judges it when it drains.
    const forged = packet(ada, [bob], {}, eve);
    expect(host.post(bob.address, forged)).toStrictEqual({ stored: true });
    expect(host.post(bob.address, sealed(bob))).toStrictEqual({ stored: true });
    // Posted again, it is there once.
    host.post(bob.address, forged);
    expect(host.drain(bob.address, 0, 10).items.map((item) => item.record)).toStrictEqual([
      forged,
      sealed(bob),
    ]);
    expect(
      refused(() => host.post(bob.address, ada.sign(intentBy(ada, 100)) as unknown as OipRecord)),
    ).toStrictEqual({
      code: "invalid-record",
    });
    expect(refused(() => host.post(bob.address, packet(ada, [eve])))).toStrictEqual({
      code: "forbidden",
    });
    expect(refused(() => host.post(ada.address, packet(bob, [ada])))).toStrictEqual({
      code: "not-found",
    });
  });

  it("is drained from a cursor on, a page at a time, and an item is removed once", () => {
    const host = hosting();
    for (let n = 1; n <= 5; n++) host.post(bob.address, sealed(bob, `AAA${String(n)}`));
    const first = host.drain(bob.address, 0, 2);
    expect(first.items.map((item) => item.cursor)).toStrictEqual([1, 2]);
    expect(first.next).toBe(2);
    const second = host.drain(bob.address, 2, 2);
    expect(second.items.map((item) => item.cursor)).toStrictEqual([3, 4]);
    expect(second.next).toBe(4);
    // The last page says there is no more.
    expect(host.drain(bob.address, 4, 2)).toStrictEqual({
      items: [{ cursor: 5, record: sealed(bob, "AAA5") }],
    });
    expect(host.drain(bob.address, 5, 2)).toStrictEqual({ items: [] });
    expect(host.remove(bob.address, 3)).toBe(true);
    expect(host.remove(bob.address, 3)).toBe(false);
    expect(host.drain(bob.address, 0, 10).items.map((item) => item.cursor)).toStrictEqual([
      1, 2, 4, 5,
    ]);
    // One mind's cursor removes nothing of another's.
    host.adopt(eve.address);
    expect(host.remove(eve.address, 1)).toBe(false);
    expect(host.drain(bob.address, 0, 1).items).toHaveLength(1);
  });

  it("holds a bounded number of items and of bytes for one mind", () => {
    const few = hosting({ limits: { mailboxItems: 2 } });
    few.post(bob.address, sealed(bob, "AAA1"));
    few.post(bob.address, sealed(bob, "AAA2"));
    expect(refused(() => few.post(bob.address, sealed(bob, "AAA3")))).toStrictEqual({
      status: 507,
    });
    expect(refused(() => few.deliver(bob.address, packet(ada, [bob])))).toStrictEqual({
      status: 507,
    });
    // A packet that found no room is not remembered as accepted: sent again, it is taken.
    expect(count("accepted")).toBe(0);
    expect(count("seen_proofs")).toBe(0);
    few.remove(bob.address, 1);
    expect(few.deliver(bob.address, packet(ada, [bob]))).toStrictEqual({ stored: true });
    // Another mind's mailbox has room of its own.
    few.adopt(eve.address);
    expect(few.post(eve.address, sealed(eve))).toStrictEqual({ stored: true });

    const bytes = JSON.stringify(sealed(bob, "AAA1")).length;
    const small = new Host({ db, archive, limits: { mailboxBytes: 3 * bytes - 1 } });
    expect(refused(() => small.post(bob.address, sealed(bob, "AAA9")))).toStrictEqual({
      status: 507,
    });
  });

  it("lets go of what has been there longer than the host keeps things", () => {
    const host = hosting({ limits: { retention: 1000n * 1_000_000_000n } });
    host.post(bob.address, sealed(bob, "AAA1"));
    host.deliver(bob.address, packet(ada, [bob]));
    clock.at = at(600);
    host.post(bob.address, sealed(bob, "AAA2"));
    expect(host.prune(at(1109))).toBe(0);
    // The first two were received at 110, and the packet may be accepted until 3700.
    expect(host.prune(at(1111))).toBe(2);
    expect(host.drain(bob.address, 0, 10).items.map((item) => item.cursor)).toStrictEqual([3]);
    expect(count("accepted")).toBe(1);
    expect(host.prune(at(5000))).toBe(2);
    expect(count("accepted")).toBe(0);
    expect(count("mailbox")).toBe(0);
  });

  it("tells whoever waits for a mind's mail when something new is kept", () => {
    const host = hosting();
    let told = 0;
    const stop = host.subscribe(bob.address, () => told++);
    host.subscribe(bob.address, () => {
      throw new Error("a listener of its own mind");
    });
    const sent = packet(ada, [bob]);
    host.deliver(bob.address, sent);
    host.deliver(bob.address, sent);
    host.post(bob.address, sealed(bob));
    host.post(bob.address, sealed(bob));
    expect(told).toBe(2);
    host.adopt(eve.address);
    host.post(eve.address, sealed(eve));
    expect(told).toBe(2);
    stop();
    host.post(bob.address, sealed(bob, "AAA2"));
    expect(told).toBe(2);
  });
});

describe("a host that has restarted", () => {
  it("serves the same minds, holds their mail, and answers a packet as it did", () => {
    let host = hosting({ signer: () => bob.operational() });
    const sent = packet(ada, [bob]);
    const ack = host.deliver(bob.address, sent);
    host.post(bob.address, sealed(bob));
    db.close();
    db = open();
    clock.at = at(700);
    archive = new LogArchive({ db, clock });
    host = new Host({ db, archive });
    expect(host.hosts(bob.address)).toBe(true);
    expect(host.hosts(ada.address)).toBe(false);
    expect(host.drain(bob.address, 0, 10).items.map((item) => item.record)).toStrictEqual([
      sent,
      sealed(bob),
    ]);
    expect(host.deliver(bob.address, sent)).toStrictEqual(ack);
  });

  it("takes on only a mind whose log it holds", () => {
    const host = hosting();
    expect(refused(() => host.adopt(zed.address))).toStrictEqual({ code: "not-found" });
    expect(host.hosts(zed.address)).toBe(false);
    host.adopt(bob.address);
    expect(count("hosted")).toBe(1);
  });
});
