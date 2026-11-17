// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Minds for tests: logs written and signed with keys that are derived from names. */

import { createHash } from "node:crypto";

import {
  contentId,
  createProofSync,
  encodeX25519Multikey,
  formatControlKeyRef,
  formatKeyRef,
  formatTimestamp,
  formatVersionId,
  type Instant,
  keyHash,
  mindAddress,
  parseTimestamp,
  proofDigest,
  proofHashData,
  signerFromPrivateKey,
  type SyncSigner,
  withProofs,
} from "@oip/core";
import type { IdentityEvent, Proof } from "@oip/schema";
import type { JsonObject } from "@oip/testkit";

import {
  draftFork,
  draftGenesis,
  draftRetire,
  draftUpdate,
  type EventSigner,
  FirstSeen,
  type ForkFields,
  type GenesisFields,
  LogBook,
  type RetireFields,
  signEventSync,
  type UpdateFields,
} from "../src/index.ts";

const seed = (name: string): Uint8Array => createHash("sha256").update(name).digest();

/** A signer whose key is derived from a name. The same name gives the same key. */
export const signer = (name: string): SyncSigner => signerFromPrivateKey(seed(name));

/** An X25519 Multikey derived from a name. Any 32 bytes are a public key. */
export const agreementKey = (name: string): string => encodeX25519Multikey(seed(name));

const START = parseTimestamp("2026-01-01T00:00:00Z")!;

/** The instant `seconds` after the start of the tests' time. */
export const at = (seconds: number): Instant => START + BigInt(Math.round(seconds * 1e9));

/** The timestamp `seconds` after the start of the tests' time. */
export const T = (seconds: number): string => formatTimestamp(at(seconds));

/** A time by which every log of a test is known in full. */
export const LATER = at(10 ** 9);

type Event = IdentityEvent & { proof: Proof[] };

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58(bytes: Uint8Array): string {
  let number = 0n;
  for (const byte of bytes) number = number * 256n + BigInt(byte);
  let text = "";
  for (; number > 0n; number /= 58n) text = ALPHABET[Number(number % 58n)]! + text;
  for (const byte of bytes) {
    if (byte !== 0) break;
    text = `1${text}`;
  }
  return text;
}

/** The verification method an event signer uses (Layer 1, 3.11). */
export function methodOf(by: EventSigner<SyncSigner>): [SyncSigner, string] {
  return "control" in by
    ? [by.control, formatControlKeyRef(by.control.publicKey)]
    : [by.invocation, formatKeyRef(by.member, by.versionId, by.invocation.publicKey)];
}

/**
 * Signs anything that has a canonical form, well formed or not, as an
 * attacker with the keys could. `signEventSync` refuses a malformed event.
 */
export function rawSign<T extends object>(
  event: T,
  signers: readonly EventSigner<SyncSigner>[],
  options: { created?: string; purpose?: string } = {},
): T & { proof: Proof[] } {
  const { proof: _, ...subject } = event as T & { proof?: unknown };
  const proofs = signers.map((by) => {
    const [key, verificationMethod] = methodOf(by);
    const unsigned = {
      type: "DataIntegrityProof",
      cryptosuite: "eddsa-jcs-2022",
      verificationMethod,
      proofPurpose: options.purpose ?? "capabilityInvocation",
      created: options.created ?? (event as { created: string }).created,
    };
    return { ...unsigned, proofValue: `z${base58(key.sign(proofHashData(subject, unsigned)))}` };
  });
  return { ...subject, proof: proofs } as unknown as T & { proof: Proof[] };
}

/** What a test mind has in common, whoever controls it. */
export abstract class Mind {
  readonly name: string;
  readonly events: Event[] = [];

  constructor(name: string) {
    this.name = name;
  }

  get address(): string {
    return mindAddress(contentId(this.events[0]));
  }

  /** The version identifier of the event at a position; the latest by default. */
  versionId(position = this.events.length - 1): string {
    return formatVersionId(position, contentId(this.events[position]));
  }

  protected get head() {
    const seq = this.events.length - 1;
    return { mind: this.address, seq, head: contentId(this.events[seq]) };
  }

  /** The signer of an operational key. Key 0 is in the genesis. */
  operational(n = 0): SyncSigner {
    return signer(`${this.name}/operational/${n}`);
  }

  /** The signer of an invocation key. Key 0 is in the genesis. */
  invocation(n = 0): SyncSigner {
    return signer(`${this.name}/invocation/${n}`);
  }

  /** This mind as a member that signs another mind's identity event. */
  asMember(key = 0, position?: number): EventSigner<SyncSigner> {
    return {
      member: this.address,
      versionId: this.versionId(position),
      invocation: this.invocation(key),
    };
  }

  /** A record signed by one of this mind's operational keys, pinned to a version of its log. */
  sign<T extends object>(
    record: T,
    options: { key?: number; position?: number; created?: string } = {},
  ): T & { proof: Proof[] } {
    const by = this.operational(options.key);
    const proof = createProofSync(
      record,
      {
        verificationMethod: formatKeyRef(
          this.address,
          this.versionId(options.position),
          by.publicKey,
        ),
        created: options.created ?? (record as { created: string }).created,
      },
      by,
    );
    const earlier = (record as { proof?: Proof[] }).proof ?? [];
    return withProofs(record, [...earlier, proof]) as T & { proof: Proof[] };
  }
}

/** The keys of a genesis: operational key 0, invocation key 0 and one agreement key. */
function firstKeys(mind: Mind) {
  return {
    keys: [{ key: mind.operational().publicKey }],
    invocation: [{ key: mind.invocation().publicKey }],
    agreement: [{ key: agreementKey(`${mind.name}/agreement/0`) }],
  };
}

/**
 * A key-controlled mind. Control key `n` signs event `n` and is committed to
 * by event `n - 1`.
 */
export class KeyMind extends Mind {
  constructor(name: string, seconds = 0, fields: Partial<GenesisFields> = {}) {
    super(name);
    const genesis = draftGenesis(T(seconds), {
      kind: "agent",
      controller: this.controller(0),
      ...firstKeys(this),
      ...fields,
    });
    this.events.push(signEventSync(genesis, [{ control: this.control(0) }]));
  }

  control(n: number): SyncSigner {
    return signer(`${this.name}/control/${n}`);
  }

  /** The controller of event `n`: it reveals control key `n` and commits to the next. */
  controller(n: number, last = false) {
    return {
      keys: [this.control(n).publicKey],
      next: last ? [] : [keyHash(this.control(n + 1).publicKey)],
    };
  }

  update(seconds: number, fields: UpdateFields = {}): this {
    const n = this.events.length;
    const event = draftUpdate(this.head, T(seconds), { controller: this.controller(n), ...fields });
    this.events.push(signEventSync(event, [{ control: this.control(n) }]));
    return this;
  }

  fork(seconds: number, fields: ForkFields): this {
    const n = this.events.length;
    const event = draftFork(this.head, T(seconds), { controller: this.controller(n), ...fields });
    this.events.push(signEventSync(event, [{ control: this.control(n) }]));
    return this;
  }

  retire(seconds: number, fields: RetireFields = {}): this {
    const n = this.events.length;
    const event = draftRetire(this.head, T(seconds), {
      controller: this.controller(n, true),
      ...fields,
    });
    this.events.push(signEventSync(event, [{ control: this.control(n) }]));
    return this;
  }

  /**
   * Appends an event with any members at all, signed by the control key whose
   * turn it is: what the holder of the keys could publish, well formed or not.
   */
  raw(seconds: number, type: string, members: JsonObject = {}): this {
    const n = this.events.length;
    const { mind, seq, head } = this.head;
    const event = {
      oip: "1",
      type,
      mind,
      seq: seq + 1,
      prev: head,
      created: T(seconds),
      controller: this.controller(n),
      ...members,
    };
    // A member given as `undefined` is left out.
    const cleaned = Object.fromEntries(
      Object.entries(event).filter(([, value]) => value !== undefined),
    );
    this.events.push(rawSign(cleaned, [{ control: this.control(n) }]) as unknown as Event);
    return this;
  }
}

/**
 * The genesis of a key-controlled mind with some members changed, signed by
 * its control key whether or not it is well formed.
 */
export function rawGenesis(name: string, changes: JsonObject, seconds = 0): Event {
  const base = new KeyMind(name, seconds);
  return rawSign({ ...base.events[0], ...changes }, [
    { control: base.control(0) },
  ]) as unknown as Event;
}

/** A member-controlled mind. Its members sign its events with their invocation keys. */
export class Collective extends Mind {
  constructor(
    name: string,
    founders: readonly Mind[],
    threshold: number,
    seconds = 0,
    fields: Partial<GenesisFields> = {},
  ) {
    super(name);
    const genesis = draftGenesis(T(seconds), {
      kind: "collective",
      controller: { members: founders.map((founder) => founder.address), threshold },
      // Keys of its own, so that it can be a member of another collective (Layer 1, 9.4).
      ...firstKeys(this),
      ...fields,
    });
    this.events.push(
      signEventSync(
        genesis,
        founders.map((founder) => founder.asMember()),
      ),
    );
  }

  update(seconds: number, signers: readonly Mind[], fields: UpdateFields = {}): this {
    const event = draftUpdate(this.head, T(seconds), fields);
    this.events.push(
      signEventSync(
        event,
        signers.map((member) => member.asMember()),
      ),
    );
    return this;
  }

  retire(seconds: number, signers: readonly Mind[], fields: RetireFields = {}): this {
    const event = draftRetire(this.head, T(seconds), fields);
    this.events.push(
      signEventSync(
        event,
        signers.map((member) => member.asMember()),
      ),
    );
    return this;
  }
}

/**
 * A witness that saw each event of each log, and each proof of each record,
 * at its own `created`. `seen` gives other times, by content ID or digest.
 */
export function witness(
  logs: readonly (readonly JsonObject[] | readonly Event[])[],
  records: readonly object[] = [],
): FirstSeen {
  const seen = new FirstSeen();
  for (const events of logs) {
    for (const event of events as readonly JsonObject[]) {
      seen.sawEvent(contentId(event), parseTimestamp(event["created"])!);
    }
  }
  for (const record of records) {
    for (const proof of (record as { proof?: Proof[] }).proof ?? []) {
      seen.sawProof(proofDigest(proof), parseTimestamp(proof.created)!);
    }
  }
  return seen;
}

/** A book that holds the logs of some minds, known in full, with a witness that saw everything when it was made. */
export function bookOf(minds: readonly Mind[], records: readonly object[] = []): LogBook {
  const book = new LogBook(
    witness(
      minds.map((mind) => mind.events),
      records,
    ),
  );
  for (const mind of minds) book.hold(mind.events, LATER);
  return book;
}
