// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Authenticating a mind to a server (Layer 1, 13.3): the `Hello` record.
 *
 * The server issues a challenge. The client answers with a `Hello` whose one
 * proof is over that challenge and over the origin the client connected to.
 * The server checks both, and that the key may sign for the mind now.
 *
 * The present, the server's origin and its memory of the challenges it has
 * issued are parameters: the package reads no clock and makes no nonce.
 */

import { CLOCK_SKEW, type Instant } from "@oip/core";
import {
  type FirstSeen,
  type IdentityView,
  type JudgeOptions,
  judgeRecord,
  ownSignedTime,
  witnessRecord,
} from "@oip/identity";
import type { Validation } from "@oip/schema";

import { no, ok } from "./result.ts";

/** A server's memory of the challenges it has issued and not yet seen answered. */
export interface IssuedChallenges {
  /** When the server issued this challenge, if it did and no `Hello` has used it. */
  issuedAt(challenge: string): Instant | undefined;
  /** Marks a challenge as used: it is never accepted again. */
  use(challenge: string): void;
}

/** A server that authenticates a mind. */
export interface HelloServer extends JudgeOptions {
  /**
   * The server's own origin, as its clients connect to it: `https://` and
   * the host, with the port if it is not 443, and nothing after.
   */
  readonly origin: string;
  /** The present: the server's own clock, read by the caller. */
  readonly now: Instant;
  /** The challenges the server has issued. `Challenges` is one such memory. */
  readonly challenges: IssuedChallenges;
  /** The identity logs the server holds, and its evidence of time. */
  readonly view: IdentityView;
  /**
   * The server's own record of when it first saw each proof (core 9.4),
   * which is written to: the proof of a `Hello` that answers a challenge of
   * this server is recorded as seen at `now`. It should be part of the
   * evidence of `view`.
   */
  readonly seen?: FirstSeen;
}

/** A mind that has authenticated. */
export interface Authenticated {
  /** The mind's address. */
  readonly mind: string;
  /** The challenge it answered, which is now used. */
  readonly challenge: string;
  /** The key that signed, as an Ed25519 Multikey. */
  readonly key: string;
}

/**
 * Layer 1, 13.3: judges a `Hello` that a client sent in answer to a
 * challenge.
 *
 * The record carries a single proof, with the purpose `authentication`. Its
 * `domain` is the server's own origin: the client set it from where it
 * connected, so a server that relays a challenge of another gets a proof it
 * cannot use there. Its `challenge` is one this server issued within the
 * last 300 seconds and that no `Hello` has used. The key is a valid
 * operational key of the mind under the current-state rule (Layer 1, 6.1):
 * it is among the keys of the latest state the server knows, and the mind
 * is not retired.
 *
 * A `Hello` that passes uses its challenge up. One that fails leaves the
 * challenge as it was: only the holder of the key can use it.
 *
 * It never throws on the value.
 *
 * @param value - What the client sent, as parsed.
 */
export function verifyHello(value: unknown, server: HelloServer): Validation<Authenticated> {
  if (typeof (server.now as unknown) !== "bigint") throw new TypeError("now is not a time");
  if (typeof (server.origin as unknown) !== "string") {
    throw new TypeError("a server's origin is a string");
  }
  const judged = judgeRecord(
    value,
    server.understood === undefined ? undefined : { understood: server.understood },
  );
  if (!judged.ok) return judged;
  const record = judged.value.record as {
    readonly type: string;
    readonly author?: unknown;
    readonly proof?: readonly unknown[];
  };
  if (record.type !== "Hello" || typeof record.author !== "string") {
    return no("the record is not a Hello", "L1 13.3", "/type");
  }
  if (record.proof?.length !== 1) {
    return no("a Hello carries a single proof", "L1 13.3", "/proof");
  }
  const [verified] = judged.value.proofs;
  if (verified === undefined) {
    return no(
      "the proof of the Hello does not verify as an authentication proof",
      "L1 13.3",
      "/proof/0",
    );
  }
  // That the purpose is `authentication` is part of what verified (core 5.6).
  const { challenge, domain } = verified.proof as {
    readonly challenge?: unknown;
    readonly domain?: unknown;
  };
  if (domain !== server.origin) {
    return no("`domain` is not this server's origin", "L1 13.3", "/proof/0/domain");
  }
  const issued = typeof challenge === "string" ? server.challenges.issuedAt(challenge) : undefined;
  if (
    typeof challenge !== "string" ||
    issued === undefined ||
    issued > server.now ||
    server.now - issued > CLOCK_SKEW
  ) {
    return no(
      "the challenge is not one this server issued within the last 300 seconds and has not seen used",
      "L1 13.3",
      "/proof/0/challenge",
    );
  }
  // The proof answers a challenge this server made: it cannot be older than that challenge.
  if (server.seen !== undefined) witnessRecord(judged.value, server.now, server.seen);
  if (ownSignedTime(judged.value, record.author, server.view) === undefined) {
    return no(
      "the proof is not by a valid operational key of the mind under the current-state rule",
      "L1 6.1",
      "/proof/0",
    );
  }
  server.challenges.use(challenge);
  return ok({ mind: record.author, challenge, key: verified.key });
}

/**
 * Layer 1, 13.3: the challenges a server has issued, each good for one
 * `Hello` within 300 seconds.
 *
 * The nonces are the caller's to make: at least 16 random bytes, in
 * base64url (13.4). It holds one entry for each challenge issued and not
 * yet used or forgotten, so call `forget` as the clock moves.
 */
export class Challenges implements IssuedChallenges {
  readonly #issued = new Map<string, Instant>();

  /** How many challenges are open. */
  get size(): number {
    return this.#issued.size;
  }

  /**
   * Remembers a challenge the server has just sent.
   *
   * @throws TypeError if the challenge is open already: a nonce is used once.
   */
  issue(challenge: string, now: Instant): void {
    if (typeof (challenge as unknown) !== "string" || challenge.length === 0) {
      throw new TypeError("a challenge is a string that is not empty");
    }
    if (typeof (now as unknown) !== "bigint") throw new TypeError("now is not a time");
    if (this.#issued.has(challenge)) throw new TypeError("the challenge was issued already");
    this.#issued.set(challenge, now);
  }

  issuedAt(challenge: string): Instant | undefined {
    return this.#issued.get(challenge);
  }

  use(challenge: string): void {
    this.#issued.delete(challenge);
  }

  /**
   * Forgets every challenge issued more than 300 seconds before `now`,
   * which no `Hello` can answer any more.
   *
   * @returns How many were forgotten.
   */
  forget(now: Instant): number {
    if (typeof (now as unknown) !== "bigint") throw new TypeError("now is not a time");
    let forgotten = 0;
    for (const [challenge, issued] of this.#issued) {
      if (now - issued > CLOCK_SKEW) {
        this.#issued.delete(challenge);
        forgotten++;
      }
    }
    return forgotten;
  }
}
