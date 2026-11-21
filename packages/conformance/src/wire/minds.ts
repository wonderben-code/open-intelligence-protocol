// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The minds the suite makes for a run. Each has keys of its own, drawn from
 * the randomness the suite is given, so a run leaves an implementation with
 * minds that nobody else can sign for and that no other run shares.
 */

import {
  contentId,
  createProofSync,
  encodeX25519Multikey,
  formatControlKeyRef,
  formatKeyRef,
  formatTimestamp,
  formatVersionId,
  type Instant,
  type JsonObject,
  keyHash,
  mindAddress,
  type SyncSigner,
  signerFromPrivateKey,
  withProofs,
  x25519PublicKey,
} from "@oip/core";
import {
  draftGenesis,
  draftUpdate,
  type GenesisFields,
  signEventSync,
  type UpdateFields,
} from "@oip/identity";
import type { IdentityEvent, Proof } from "@oip/schema";

import { present } from "./report.ts";

/** Where the suite's keys come from: `bytes` fresh random bytes. */
export type Randomness = (bytes: number) => Uint8Array;

/** An identity event with its proofs. */
export type SignedEvent = IdentityEvent & { proof: Proof[] };

/** A time as a timestamp of whole seconds: the second the instant falls in. */
export function second(instant: Instant): string {
  return formatTimestamp(
    instant - (((instant % 1_000_000_000n) + 1_000_000_000n) % 1_000_000_000n),
  );
}

/** Lower-case hex of fresh random bytes: a word no other run of the suite uses. */
export function word(random: Randomness, bytes = 8): string {
  return Array.from(random(bytes), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** What a mind of the suite is made of. A branch of it has the same keys. */
interface Parts {
  readonly random: Randomness;
  /** Control keys, made as they are needed and shared with the mind's branches. */
  readonly control: SyncSigner[];
  readonly operational: SyncSigner;
  readonly agreement: Uint8Array;
  readonly events: SignedEvent[];
}

/**
 * A key-controlled mind of the suite. Control key `n` signs event `n` and is
 * committed to by event `n - 1`. It has one operational key and one agreement
 * key, both in its genesis.
 */
export class WireMind {
  /** The log, genesis first. */
  readonly events: SignedEvent[];
  readonly #parts: Parts;

  private constructor(parts: Parts) {
    this.#parts = parts;
    this.events = parts.events;
  }

  /**
   * A new mind.
   *
   * @param random - Where its keys come from.
   * @param created - The `created` of its genesis.
   * @param fields - Members of the genesis besides its keys.
   */
  static create(
    random: Randomness,
    created: string,
    fields: Partial<GenesisFields> = {},
  ): WireMind {
    const mind = new WireMind({
      random,
      control: [],
      operational: signerFromPrivateKey(random(32)),
      agreement: random(32),
      events: [],
    });
    const genesis = draftGenesis(created, {
      kind: "agent",
      controller: mind.#controller(0),
      keys: [{ key: mind.signer.publicKey }],
      agreement: [{ key: mind.agreementKey }],
      ...fields,
    });
    mind.events.push(signEventSync(genesis, [{ control: mind.#controlKey(0) }]));
    return mind;
  }

  #controlKey(n: number): SyncSigner {
    const { control, random } = this.#parts;
    while (control.length <= n) control.push(signerFromPrivateKey(random(32)));
    return present(control[n]);
  }

  /** The controller of event `n`: it reveals control key `n` and commits to the next. */
  #controller(n: number) {
    return {
      keys: [this.#controlKey(n).publicKey],
      next: [keyHash(this.#controlKey(n + 1).publicKey)],
    };
  }

  /** The first event of the log. */
  get genesis(): SignedEvent {
    return present(this.events[0]);
  }

  /** The mind's address, `did:oip:<content ID of its genesis>`. */
  get address(): string {
    return mindAddress(this.id);
  }

  /** The content ID of the genesis: the `<mindId>` of the paths of Layer 1, 13.1 and 17.1. */
  get id(): string {
    return contentId(this.genesis);
  }

  /** The version identifier of the latest event. */
  get versionId(): string {
    const seq = this.events.length - 1;
    return formatVersionId(seq, contentId(this.events[seq]));
  }

  /** The mind's operational key, as a `key-ref` pinned to the latest version of its log. */
  get keyRef(): string {
    return formatKeyRef(this.address, this.versionId, this.signer.publicKey);
  }

  /** The signer of the mind's operational key. */
  get signer(): SyncSigner {
    return this.#parts.operational;
  }

  /** The mind's agreement key, as its genesis gives it. */
  get agreementKey(): string {
    return encodeX25519Multikey(x25519PublicKey(this.#parts.agreement));
  }

  /** The private part of the agreement key `key`, for opening what is sealed to it. */
  agreementSecret(key: string): Uint8Array | undefined {
    return key === this.agreementKey ? this.#parts.agreement : undefined;
  }

  /**
   * A record with a proof by the mind's operational key, pinned to the latest
   * version of its log, after any proofs the record has.
   *
   * @param more - A `created` other than the record's, and what a `Hello` adds (Layer 1, 13.3).
   */
  sign<T extends object>(
    record: T,
    more: { created?: string; challenge?: string; domain?: string } = {},
  ): T & { proof: Proof[] } {
    const { created = (record as { created: string }).created, ...rest } = more;
    const proof = createProofSync(
      record,
      { verificationMethod: this.keyRef, created, ...rest },
      this.signer,
    );
    return withProofs(record, [proof]) as T & { proof: Proof[] };
  }

  /**
   * A proof over an event by one of this mind's control keys that no event
   * has revealed. Its signature verifies, and it counts for nothing: the
   * event, whoever's it is, does not reveal the key (Layer 1, 3.4).
   */
  strayProof(event: SignedEvent): Proof {
    const key = this.#controlKey(this.events.length + 8);
    return createProofSync(
      event,
      { verificationMethod: formatControlKeyRef(key.publicKey), created: event.created },
      key,
    );
  }

  /** Appends an `Update` to the log, signed by the control key whose turn it is, and returns it. */
  update(created: string, fields: UpdateFields = {}): SignedEvent {
    const n = this.events.length;
    const head = { mind: this.address, seq: n - 1, head: contentId(this.events[n - 1]) };
    const event = draftUpdate(head, created, { controller: this.#controller(n), ...fields });
    const signed = signEventSync(event, [{ control: this.#controlKey(n) }]);
    this.events.push(signed);
    return signed;
  }

  /**
   * The same mind with only the first `events` events of its log, and the
   * same keys. What it appends is a second history of the mind from there:
   * what a duplicitous mind signs (Layer 1, Section 7).
   */
  branch(events: number): WireMind {
    return new WireMind({ ...this.#parts, events: this.events.slice(0, events) });
  }

  /** The mind's log as a `Bundle` (Layer 1, 13.1), with what else is given. */
  bundle(
    more: { location?: object; participant?: object; log?: readonly object[] } = {},
  ): JsonObject {
    return {
      oip: "1",
      type: "Bundle",
      mind: this.address,
      log: more.log ?? this.events,
      ...(more.location === undefined ? {} : { location: more.location }),
      ...(more.participant === undefined ? {} : { participant: more.participant }),
    } as unknown as JsonObject;
  }
}
