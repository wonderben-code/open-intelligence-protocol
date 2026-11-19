// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { base64urlToBytes, contentId, type JsonObject, mindId, type OipRecord } from "@oip/core";
import { Challenges } from "@oip/net";
import { type Bundle, noteCutShort } from "@oip/schema";
import { Database, Log, LogArchive, Metrics, RateLimiter } from "@oip/server";
import { clause } from "@oip/testkit";
import { at, intentBy, KeyMind, type Mind, T } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  CLOSE,
  Host,
  HOST_MIGRATIONS,
  type HostOptions,
  Sockets,
  type SocketsOptions,
  SUBPROTOCOL,
} from "../src/index.ts";

const ORIGIN = "https://host.example";

let directory: string;
let db: Database;
let clock: { at: bigint; now: () => bigint };
let lines: Record<string, unknown>[];
let metrics: Metrics;
let host: Host;
let drawn = 0;

const ada = new KeyMind("ada");
const bob = new KeyMind("bob");
const eve = new KeyMind("eve");
const zed = new KeyMind("zed");

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "oip-host-sockets-"));
  clock = { at: at(110), now: () => clock.at };
  db = Database.open({ path: join(directory, "host.db"), durable: false }, HOST_MIGRATIONS, clock);
  lines = [];
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
  try {
    db.close();
  } catch {
    // A test closed it.
  }
  rmSync(directory, { recursive: true, force: true });
});

/** The binding of a host that holds the logs of Ada, Bob and Eve, and serves Bob. */
function binding(more: Partial<SocketsOptions> = {}, made: Partial<HostOptions> = {}): Sockets {
  const archive = new LogArchive({ db, clock });
  for (const mind of [ada, bob, eve]) {
    archive.publish(mindId(mind.address) ?? "", {
      oip: "1",
      type: "Bundle",
      mind: mind.address,
      log: mind.events,
    } as unknown as Bundle);
  }
  host = new Host({ db, archive, ...made });
  host.adopt(bob.address);
  metrics = new Metrics();
  return new Sockets({
    host,
    archive,
    clock,
    // Bytes nobody else has drawn, which is all a test needs of them.
    randomness: { bytes: (length) => new Uint8Array(length).fill(++drawn) },
    log: new Log({
      service: "host",
      clock,
      sink: (line) => lines.push(JSON.parse(line) as Record<string, unknown>),
    }),
    metrics,
    origin: ORIGIN,
    deliver: new RateLimiter({ burst: 1000, perMinute: 60_000 }, clock),
    ...more,
  });
}

/** A connection to a mind's socket, with what was sent over it and how it was closed. */
function connect(sockets: Sockets, mind: Mind = bob, address = "203.0.113.7") {
  const sent: JsonObject[] = [];
  const state = { closed: undefined as [number, string] | undefined, buffered: 0 };
  const connection = sockets.connect(
    mind.address,
    {
      send: (text) => {
        if (state.closed !== undefined) throw new Error("sent after the close");
        sent.push(JSON.parse(text) as JsonObject);
      },
      close: (code, reason) => {
        state.closed = [code, reason];
      },
      get buffered() {
        return state.buffered;
      },
    },
    address,
  );
  const nonce = sent[0]?.["nonce"] as string;
  return { connection, sent, state, nonce };
}

/** A Hello of a mind, signed over a challenge and the origin it connected to. */
const hello = (mind: Mind, challenge: string, domain = ORIGIN): string =>
  JSON.stringify(
    mind.sign(
      { oip: "1", type: "Hello", author: mind.address, created: T(110) },
      { more: { challenge, domain } },
    ),
  );

/** A connection on which a mind has authenticated. */
function welcomed(sockets: Sockets, as: Mind, to: Mind = bob, address?: string) {
  const opened = connect(sockets, to, address);
  opened.connection.message(hello(as, opened.nonce));
  expect(opened.sent[1]).toStrictEqual({ type: "Welcome", mind: as.address });
  return opened;
}

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

/** Bob's acknowledgement of a record he has. */
const ack = (by: Mind, record: OipRecord, more: JsonObject = {}): string =>
  JSON.stringify(
    by.sign({
      oip: "1",
      type: "Ack",
      author: by.address,
      packet: contentId(record),
      received: T(110),
      created: T(110),
      ...more,
    }),
  );

const mailbox = (): OipRecord[] =>
  host.drain(bob.address, 0, 100).items.map((item) => item.record as unknown as OipRecord);

describe(`${clause("L1 13.4", "L1 13.3")} a connection to a mind's socket`, () => {
  it("is challenged first, with random bytes of its own and the host's origin", () => {
    const sockets = binding();
    expect(SUBPROTOCOL).toBe("oip.v1");
    const first = connect(sockets);
    const second = connect(sockets);
    expect(first.sent).toStrictEqual([{ type: "Challenge", nonce: first.nonce, domain: ORIGIN }]);
    expect(base64urlToBytes(first.nonce)?.length).toBeGreaterThanOrEqual(16);
    expect(second.nonce).not.toBe(first.nonce);
    expect(sockets.open).toBe(2);
    expect(metrics.render()).toContain("oip_host_sockets_open 2");
  });

  it("welcomes the mind whose Hello answers the challenge, whichever mind it is", () => {
    const sockets = binding();
    const own = welcomed(sockets, bob);
    const other = welcomed(sockets, ada);
    expect(own.state.closed).toBeUndefined();
    expect(other.state.closed).toBeUndefined();
    expect(metrics.render()).toContain('oip_host_socket_messages_total{outcome="welcomed"} 2');
  });

  it("is closed with 4401 if what it says first authenticates no mind", () => {
    const sockets = binding();
    const used = connect(sockets);
    used.connection.message(hello(ada, used.nonce));
    const cases: [string, (nonce: string) => string][] = [
      ["no JSON", () => "{"],
      ["no Hello", () => JSON.stringify(ada.sign(intentBy(ada, 100)))],
      ["a Hello for another origin", (nonce) => hello(ada, nonce, "https://other.example")],
      [
        "a Hello for a challenge the host did not make",
        () => hello(ada, "bm90LWEtY2hhbGxlbmdlLW9mLW91cnM"),
      ],
      ["a Hello for a challenge that was used", () => hello(ada, used.nonce)],
      ["a Hello of a mind the host holds no log of", (nonce) => hello(zed, nonce)],
      [
        "a Hello another mind signed",
        (nonce) => JSON.stringify({ ...JSON.parse(hello(eve, nonce)), author: ada.address }),
      ],
    ];
    for (const [name, said] of cases) {
      const opened = connect(sockets);
      opened.connection.message(said(opened.nonce));
      expect(opened.state.closed?.[0], name).toBe(CLOSE.unauthenticated);
      expect(CLOSE.unauthenticated).toBe(4401);
      expect(opened.sent, name).toHaveLength(1);
      // Nothing more is heard on it.
      opened.connection.message(hello(ada, opened.nonce));
      expect(opened.sent, name).toHaveLength(1);
    }
    expect(sockets.open).toBe(1);
    // A challenge is one connection's: answered on another, it is still good once only.
    const [one, two] = [connect(sockets), connect(sockets)];
    two.connection.message(hello(ada, one.nonce));
    expect(two.sent[1]).toStrictEqual({ type: "Welcome", mind: ada.address });
    one.connection.message(hello(ada, one.nonce));
    expect(one.state.closed?.[0]).toBe(4401);
  });

  it("is closed with 4401 if no Hello comes in time, and not once one has", () => {
    vi.useFakeTimers();
    const sockets = binding({ helloMs: 5000 });
    const silent = connect(sockets);
    const prompt = connect(sockets);
    prompt.connection.message(hello(ada, prompt.nonce));
    vi.advanceTimersByTime(4999);
    expect(silent.state.closed).toBeUndefined();
    vi.advanceTimersByTime(1);
    expect(silent.state.closed).toStrictEqual([4401, "no Hello in time"]);
    vi.advanceTimersByTime(60_000);
    expect(prompt.state.closed).toBeUndefined();
    expect(sockets.open).toBe(1);
    // One that closed of itself is not closed again.
    const gone = connect(sockets);
    gone.connection.closed();
    vi.advanceTimersByTime(60_000);
    expect(gone.state.closed).toBeUndefined();
  });
});

describe(`${clause("L1 13.4", "L1 13.2")} a record sent over a socket`, () => {
  it("is delivered as at the inbox, and acknowledged if the host signs for the mind", () => {
    const sockets = binding();
    const { connection, sent, state } = welcomed(sockets, ada);
    const record = packet(ada, [bob]);
    connection.message(JSON.stringify(record));
    connection.message(JSON.stringify(sealed(bob)));
    expect(mailbox()).toStrictEqual([record, sealed(bob)]);
    // A host that holds no key of the mind's says nothing back: there is no record for that.
    expect(sent).toHaveLength(2);
    expect(state.closed).toBeUndefined();
    expect(metrics.render()).toContain('oip_host_socket_messages_total{outcome="delivered"} 2');

    db.close();
    rmSync(join(directory, "host.db"));
    db = Database.open(
      { path: join(directory, "host.db"), durable: false },
      HOST_MIGRATIONS,
      clock,
    );
    const custodial = welcomed(binding({}, { signer: () => bob.operational() }), ada);
    custodial.connection.message(JSON.stringify(record));
    expect(custodial.sent[2]).toMatchObject({
      type: "Ack",
      author: bob.address,
      packet: contentId(record),
    });
    // The same packet again is answered the same.
    custodial.connection.message(JSON.stringify(record));
    expect(custodial.sent[3]).toStrictEqual(custodial.sent[2]);
    expect(mailbox()).toHaveLength(1);
  });

  it("closes the connection if it is refused, with the code of its problem as the reason", () => {
    const sockets = binding({ maxRecordBytes: 4096 }, { limits: { mailboxItems: 1 } });
    const cases: [string, string, [number, string]][] = [
      ["no record", "{", [1008, "invalid-record"]],
      ["another record", JSON.stringify(ada.sign(intentBy(ada, 100))), [1008, "invalid-record"]],
      ["a packet for another", JSON.stringify(packet(ada, [eve])), [1008, "forbidden"]],
      [
        "a packet its sender did not sign",
        JSON.stringify(packet(ada, [bob], {}, eve)),
        [1008, "invalid-proof"],
      ],
      [
        "a packet from a mind the host cannot judge",
        JSON.stringify(packet(zed, [bob])),
        [1008, "stale-version"],
      ],
      [
        "too long a record",
        JSON.stringify(
          packet(ada, [bob], { content: { mediaType: "text/plain", body: "x".repeat(5000) } }),
        ),
        [1008, "too-large"],
      ],
      [
        "an Ack from a mind that is not the socket's",
        ack(bob, packet(ada, [bob])),
        [1008, "forbidden"],
      ],
    ];
    for (const [name, said, closed] of cases) {
      const { connection, state, sent } = welcomed(sockets, ada);
      connection.message(said);
      expect(state.closed, name).toStrictEqual(closed);
      expect(sent, name).toHaveLength(2);
    }
    expect(mailbox()).toStrictEqual([]);
    expect(sockets.open).toBe(0);
    // A mailbox that is full may have room later.
    host.post(bob.address, sealed(bob));
    const full = welcomed(sockets, ada);
    full.connection.message(JSON.stringify(packet(ada, [bob])));
    expect(full.state.closed).toStrictEqual([1013, "Insufficient Storage"]);
    expect(metrics.render()).toContain('oip_host_socket_messages_total{outcome="refused"} 8');
  });

  it("counts against what its address may deliver", () => {
    const sockets = binding({ deliver: new RateLimiter({ burst: 2, perMinute: 6 }, clock) });
    const { connection, state } = welcomed(sockets, ada);
    for (const enc of ["AAA1", "AAA2", "AAA3"])
      connection.message(JSON.stringify(sealed(bob, enc)));
    expect(state.closed).toStrictEqual([1013, "rate-limited"]);
    expect(mailbox()).toHaveLength(2);
    // Another address has an allowance of its own.
    const other = welcomed(sockets, ada, bob, "198.51.100.9");
    other.connection.message(JSON.stringify(sealed(bob, "AAA3")));
    expect(other.state.closed).toBeUndefined();
    expect(mailbox()).toHaveLength(3);
  });

  it("closes with 1011 on a failure nobody expected, and logs it without saying what", () => {
    const sockets = binding();
    const { connection, state } = welcomed(sockets, ada);
    db.close();
    connection.message(JSON.stringify(packet(ada, [bob])));
    expect(state.closed).toStrictEqual([1011, "internal error"]);
    expect(lines.at(-1)).toMatchObject({ level: "error", event: "socket failed" });
  });
});

describe(`${clause("L1 13.4", "L1 13.5")} the socket of a mind's own instance`, () => {
  it("is sent what waits in the mailbox, in order, and what arrives while it is open", () => {
    const sockets = binding();
    const first = packet(ada, [bob]);
    host.deliver(bob.address, first);
    host.post(bob.address, sealed(bob, "AAA1"));
    const { connection, sent, state } = welcomed(sockets, bob);
    expect(sent.slice(2)).toStrictEqual([first, sealed(bob, "AAA1")]);
    host.post(bob.address, sealed(bob, "AAA2"));
    expect(sent.slice(4)).toStrictEqual([sealed(bob, "AAA2")]);
    // Another mind's socket to the same mind is sent none of it.
    const other = welcomed(sockets, ada);
    host.post(bob.address, sealed(bob, "AAA3"));
    expect(other.sent).toHaveLength(2);
    expect(sent).toHaveLength(6);
    // What was sent stays in the mailbox until the mind says it has it.
    expect(mailbox()).toHaveLength(4);
    connection.message(ack(bob, first));
    connection.message(ack(bob, first));
    connection.message(
      ack(bob, packet(ada, [bob], { nonce: "nonce-0002" }), {
        sealed: contentId(sealed(bob, "AAA1")),
      }),
    );
    expect(mailbox()).toStrictEqual([sealed(bob, "AAA2"), sealed(bob, "AAA3")]);
    expect(state.closed).toBeUndefined();
    expect(metrics.render()).toContain('oip_host_socket_messages_total{outcome="acknowledged"} 3');
    // A socket that drops loses nothing: the next one is sent what is still there.
    connection.closed();
    host.post(bob.address, sealed(bob, "AAA4"));
    expect(sent).toHaveLength(6);
    const again = welcomed(sockets, bob);
    expect(again.sent.slice(2)).toStrictEqual([
      sealed(bob, "AAA2"),
      sealed(bob, "AAA3"),
      sealed(bob, "AAA4"),
    ]);
  });

  it("takes only the mind's own acknowledgement", () => {
    const sockets = binding();
    const record = packet(ada, [bob]);
    host.deliver(bob.address, record);
    const cases: [string, string, string][] = [
      [
        "an Ack another mind signed",
        JSON.stringify({ ...JSON.parse(ack(eve, record)), author: bob.address }),
        "invalid-proof",
      ],
      ["another mind's Ack", ack(ada, record), "forbidden"],
      [
        "an Ack that is not well formed",
        JSON.stringify({ ...JSON.parse(ack(bob, record)), packet: 7 }),
        "invalid-record",
      ],
    ];
    for (const [name, said, reason] of cases) {
      const { connection, state } = welcomed(sockets, bob);
      connection.message(said);
      expect(state.closed, name).toStrictEqual([1008, reason]);
    }
    expect(mailbox()).toStrictEqual([record]);
  });

  it("is sent no more than it takes, and the rest when it has taken that", () => {
    const sockets = binding({ maxBuffered: 100 });
    for (let n = 0; n < 40; n++)
      host.post(bob.address, sealed(bob, `AA${String(n).padStart(2, "0")}`));
    const opened = connect(sockets, bob);
    opened.state.buffered = 100;
    opened.connection.message(hello(bob, opened.nonce));
    // Nothing while the connection is full, whatever arrives.
    expect(opened.sent).toHaveLength(2);
    host.post(bob.address, sealed(bob, "AAA1"));
    opened.connection.drained();
    expect(opened.sent).toHaveLength(2);
    // With room, a batch at a time for as long as there is room.
    opened.state.buffered = 99;
    const send = opened.sent.push.bind(opened.sent);
    opened.sent.push = (...records) => {
      opened.state.buffered = 100;
      return send(...records);
    };
    opened.connection.drained();
    expect(opened.sent).toHaveLength(2 + 16);
    opened.state.buffered = 0;
    opened.sent.push = send;
    opened.connection.drained();
    expect(opened.sent).toHaveLength(2 + 41);
    // Before a Hello, and on another mind's socket, there is nothing to send.
    const early = connect(sockets, bob);
    early.connection.drained();
    expect(early.sent).toHaveLength(1);
    const other = welcomed(sockets, ada);
    other.connection.drained();
    expect(other.sent).toHaveLength(2);
  });
});

describe("a socket on which something fails", () => {
  it("is closed with 1011 when the mind's mail cannot be read or sent", () => {
    const sockets = binding();
    // Mail that arrives cannot be sent: the connection is broken.
    const broken = welcomed(sockets, bob);
    const send = broken.sent.push.bind(broken.sent);
    broken.sent.push = () => {
      throw new Error("the connection is gone");
    };
    host.post(bob.address, sealed(bob, "AAA1"));
    broken.sent.push = send;
    expect(broken.state.closed).toStrictEqual([1011, "internal error"]);
    expect(lines.at(-1)).toMatchObject({ level: "error", event: "socket failed" });
    // The mailbox cannot be read when the connection has room again.
    const waiting = welcomed(sockets, bob);
    db.close();
    waiting.connection.drained();
    expect(waiting.state.closed).toStrictEqual([1011, "internal error"]);
    expect(metrics.render()).toContain('oip_host_socket_messages_total{outcome="failed"} 2');
  });

  it("is told to ask again where a Hello or a record could not be judged (ADR-0010)", () => {
    const sockets = binding();
    // A check cut short while the Hello is judged: the challenge is left as it was.
    const opened = connect(sockets);
    const judged = vi.spyOn(Challenges.prototype, "issuedAt").mockImplementationOnce(function (
      this: Challenges,
      challenge: string,
    ) {
      noteCutShort(new RangeError("Maximum call stack size exceeded"));
      judged.mockRestore();
      return this.issuedAt(challenge);
    });
    opened.connection.message(hello(ada, opened.nonce));
    expect(opened.state.closed).toStrictEqual([1013, "ask again"]);
    const again = connect(sockets);
    again.connection.message(hello(ada, opened.nonce));
    expect(again.sent[1]).toStrictEqual({ type: "Welcome", mind: ada.address });
  });
});

describe("the sockets of a host", () => {
  it("are a bounded number, and all close when the host stops", () => {
    const sockets = binding({ maxSockets: 2 });
    expect(sockets.room).toBe(true);
    const one = welcomed(sockets, bob);
    expect(sockets.room).toBe(true);
    const two = connect(sockets);
    expect(sockets.room).toBe(false);
    two.connection.closed();
    expect(sockets.room).toBe(true);
    const three = connect(sockets);
    sockets.closeAll();
    expect(one.state.closed).toStrictEqual([1001, "the host is stopping"]);
    expect(three.state.closed).toStrictEqual([1001, "the host is stopping"]);
    expect(two.state.closed).toBeUndefined();
    expect(sockets.open).toBe(0);
    expect(metrics.render()).toContain("oip_host_sockets_open 0");
    // A mind's mail is not sent to a socket that has closed.
    host.post(bob.address, sealed(bob));
    expect(one.sent).toHaveLength(2);
  });
});
