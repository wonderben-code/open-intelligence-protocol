// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The host under load, as a process of its own, on sockets of this machine.
 * BUILD.md 3.8 gives it one budget: the delivery of a packet over a
 * WebSocket on the same machine, with a 99th percentile of 20 ms.
 *
 * A sender holds a socket to a mind's endpoint, and the mind's own instance
 * holds another. A packet is timed from the moment it was due to be sent to
 * the moment the instance has it: in between the host has read it, judged
 * it as its recipient would (Layer 1, 12.4), recorded when it first saw its
 * proof, kept it in the mailbox and sent it on.
 *
 * It is measured in three rounds, and the middle is compared. ADR-0015 has
 * what was measured.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { formatKeyRef, formatTimestamp, MEDIA_TYPE, mindId, utf8 } from "@oip/core";
import { signRequest } from "@oip/net";
import { repoRoot } from "@oip/testkit";
import {
  middle,
  recorded,
  type Round,
  roundOf,
  type StartedService,
  startService,
  steadyLoad,
  told,
} from "@oip/testkit/load";
import { KeyMind, type Mind } from "@oip/testkit/minds";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { WebSocket } from "ws";

/** The budget of BUILD.md 3.8, in milliseconds at the 99th percentile. */
export const BUDGETS = { delivery: 20 } as const;

const ORIGIN = "https://host.example";
const DELIVERY = { rate: 50, seconds: 6 } as const;
const ROUNDS = 3;

let directory: string;
let service: StartedService;
let nonce = 0;

const ada = new KeyMind("ada");
const bob = new KeyMind("bob");

/** The present, to the second: what a record made now is dated. */
const now = (seconds = 0): string =>
  formatTimestamp(BigInt(Math.floor(Date.now() / 1000) + seconds) * 1_000_000_000n);
const endpoint = (mind: Mind, rest = ""): string =>
  `/oip/v1/minds/${mindId(mind.address) ?? ""}${rest}`;

/** A mind on a socket to Bob's endpoint, authenticated, with each record it is sent given to `taken`. */
function connected(mind: Mind, taken: (record: { nonce?: string }) => void): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(`${service.ws}${endpoint(bob, "/ws")}`, ["oip.v1"]);
    socket.on("error", reject);
    socket.on("close", (code: number) => {
      reject(new Error(`the socket closed with ${code}`));
    });
    socket.on("message", (data: Buffer) => {
      const message = JSON.parse(data.toString("utf8")) as {
        type?: string;
        nonce?: string;
      };
      if (message.type === "Challenge") {
        socket.send(
          JSON.stringify(
            mind.sign(
              { oip: "1", type: "Hello", author: mind.address, created: now() },
              { more: { challenge: message.nonce ?? "", domain: ORIGIN } },
            ),
          ),
        );
      } else if (message.type === "Welcome") resolve(socket);
      else taken(message);
    });
  });
}

beforeAll(async () => {
  directory = mkdtempSync(join(tmpdir(), "oip-host-load-"));
  service = await startService(join(repoRoot, "packages", "host", "src", "bin.ts"), {
    OIP_HOST_ORIGIN: ORIGIN,
    OIP_HOST_HOST: "127.0.0.1",
    OIP_HOST_PORT: "0",
    OIP_HOST_DATABASE: join(directory, "host.db"),
    OIP_HOST_OPEN: "true",
    // The load comes from one address, and the mind acknowledges nothing: what is measured
    // is the work of a delivery, not the limits on it.
    OIP_HOST_DELIVER_BURST: "100000",
    OIP_HOST_DELIVER_PER_MINUTE: "1000000",
    OIP_HOST_MAILBOX_ITEMS: "100000",
    // `OIP_LOAD_ED25519=portable` measures the service without OpenSSL (ADR-0015, ADR-0016).
    ...(process.env["OIP_LOAD_ED25519"] === undefined
      ? {}
      : { OIP_HOST_ED25519: process.env["OIP_LOAD_ED25519"] }),
  });
  // The host takes both minds on: Bob to serve, Ada so that her packets can be judged.
  for (const mind of [ada, bob]) {
    const body = utf8(
      JSON.stringify({ oip: "1", type: "Bundle", mind: mind.address, log: mind.events }),
    );
    const headers: [string, string][] = [["content-type", MEDIA_TYPE]];
    const added = await signRequest(
      { method: "PUT", url: `${ORIGIN}${endpoint(mind)}`, headers, body },
      {
        keyRef: formatKeyRef(mind.address, mind.versionId(), mind.operational().publicKey),
        created: BigInt(Math.floor(Date.now() / 1000)) * 1_000_000_000n,
        nonce: `load-nonce-${++nonce}`,
      },
      mind.operational(),
    );
    const response = await fetch(`${service.http}${endpoint(mind)}`, {
      method: "PUT",
      headers: [...headers, ...added],
      body,
    });
    if (response.status >= 300) throw new Error(`a bundle was answered ${response.status}`);
  }
}, 120_000);
afterAll(async () => {
  await service.stop();
  rmSync(directory, { recursive: true, force: true });
});

describe("the host under load", () => {
  test("delivers a packet over a WebSocket within its budget", async () => {
    const count = DELIVERY.rate * DELIVERY.seconds;
    /** Who waits for each packet, by its nonce. */
    const waiting = new Map<string, () => void>();
    const instance = await connected(bob, (record) => {
      waiting.get(record.nonce ?? "")?.();
    });
    const sender = await connected(ada, () => undefined);
    const rounds: Round[] = [];
    try {
      for (let round = 0; round < ROUNDS; round++) {
        // Signed before the round: what is timed is the delivery, not the sender's signature.
        const packets = Array.from({ length: count }, (_, n) =>
          JSON.stringify(
            ada.sign({
              oip: "1",
              type: "Packet",
              from: ada.address,
              to: [bob.address],
              created: now(),
              expires: now(3600),
              nonce: `load-${round}-${String(n).padStart(4, "0")}`,
              purpose: { verb: "inform" },
              content: { mediaType: "text/plain", body: `Packet ${n} of round ${round}.` },
            }),
          ),
        );
        const latencies = await steadyLoad({
          rate: DELIVERY.rate,
          count,
          send: (n) =>
            new Promise<void>((resolve, reject) => {
              const name = `load-${round}-${String(n).padStart(4, "0")}`;
              const late = setTimeout(() => {
                reject(new Error(`packet ${name} was not delivered within 10 seconds`));
              }, 10_000);
              waiting.set(name, () => {
                clearTimeout(late);
                resolve();
              });
              sender.send(packets[n] ?? "");
            }),
        });
        rounds.push(roundOf(latencies));
      }
    } finally {
      instance.terminate();
      sender.terminate();
    }
    recorded("host: delivery of a packet over a WebSocket", rounds);
    expect(middle(rounds.map((round) => round.p99)), told(rounds)).toBeLessThan(BUDGETS.delivery);
  }, 300_000);
});
