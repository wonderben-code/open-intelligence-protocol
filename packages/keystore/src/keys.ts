// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The keys of one role while they are unlocked. A handle signs, opens and
 * changes the keys of its role, and nothing leaves it but public keys,
 * signatures and what was sealed to the mind.
 *
 * Every change is written to storage before it is acted on. A control key is
 * marked with the event it is about to sign before it signs, so that a
 * process that stops in between cannot come back and sign another.
 */

import {
  contentId,
  hpkeOpen,
  type HpkeOpenInput,
  type JsonObject,
  signEd25519,
  type SyncSigner,
} from "@oip/core";
import { type EventSigner, signEvent, type Unsigned } from "@oip/identity";
import type { IdentityEvent, Proof } from "@oip/schema";

import {
  encodeContent,
  type HeldKey,
  isLabel,
  type KeyRole,
  MAX_KEYS,
  MAX_POSITIONS,
  newKey,
} from "./content.ts";
import { KeystoreError } from "./errors.ts";
import type { Randomness } from "./randomness.ts";
import { sealDocument, type SealedHeader } from "./seal.ts";
import type { KeyStorage } from "./storage.ts";

/** What a keystore says of a key: nothing that is secret. */
export interface KeyInfo {
  /** The Multikey of the public key: Ed25519, or X25519 for an agreement key. */
  readonly publicKey: string;
  /** What its owner called it. */
  readonly label?: string;
}

/** What a keystore says of a control key. */
export interface ControlKeyInfo extends KeyInfo {
  /**
   * The identity event this key was asked to sign, without its proofs, while
   * its publication is awaited. The key signs no other event.
   */
  readonly signing?: JsonObject;
}

/** What `generate` takes. */
export interface GenerateOptions {
  /** A name for the key, of at most 64 characters, as an identity event may carry (Layer 1, 3.5). */
  readonly label?: string;
}

/** What an unlocked role works with. Module-private: a handle is the only way to it. */
export interface Unlocked {
  readonly role: KeyRole;
  readonly storage: KeyStorage;
  readonly randomness: Randomness;
  header: SealedHeader;
  /** The version of the sealed document in storage that `keys` came from. */
  version: string;
  /** The key of the cipher. Zeroed when the role is locked. */
  readonly key: Uint8Array;
  keys: HeldKey[];
  locked: boolean;
  /** The last change asked for: changes happen one at a time, in the order they were asked. */
  last: Promise<unknown>;
  /** Tells the keystore that the role is locked again. */
  readonly release: () => void;
}

const STATES = new WeakMap<RoleKeys, Unlocked>();

/** How each kind of handle is made. Each class puts its own here, since none can be constructed from outside. */
const MAKERS: Partial<Record<KeyRole, (state: Unlocked) => RoleKeys>> = {};

/**
 * The handle over the unlocked keys of a role. For the keystore: it is not
 * part of the package's interface.
 */
export function handleOver(state: Unlocked): RoleKeys {
  const make = MAKERS[state.role];
  if (make === undefined) throw new KeystoreError("argument", "there is no such role");
  return make(state);
}

/**
 * The state of a handle that is still unlocked. For the keystore: it is not
 * part of the package's interface.
 *
 * @throws KeystoreError `locked` if the handle was locked.
 */
export function stateOf(handle: RoleKeys): Unlocked {
  const state = STATES.get(handle);
  if (state === undefined || state.locked) throw new KeystoreError("locked");
  return state;
}

/** Writes the keys as they now stand, replacing the version they were read as. */
async function write(state: Unlocked, keysChanged: boolean): Promise<void> {
  const header: SealedHeader = keysChanged
    ? { ...state.header, generation: state.header.generation + 1 }
    : state.header;
  const plaintext = encodeContent(state.keys);
  try {
    const document = sealDocument(header, state.key, plaintext, state.randomness);
    state.version = await state.storage.put(state.role, document, state.version);
    state.header = header;
  } finally {
    plaintext.fill(0);
  }
}

/**
 * Runs a change after the ones asked before it. If it fails, what was held
 * in memory is put back as it was: memory never says more than storage does.
 */
function changing<T>(handle: RoleKeys, change: (state: Unlocked) => Promise<T>): Promise<T> {
  const state = stateOf(handle);
  const run = async (): Promise<T> => {
    if (state.locked) throw new KeystoreError("locked");
    const before = state.keys.map((key) => ({
      key,
      label: key.label,
      signing: key.signing,
      signed: new Map(key.signed),
    }));
    try {
      return await change(state);
    } catch (error) {
      state.keys = before.map(({ key, label, signing, signed }) => {
        key.label = label;
        key.signing = signing;
        key.signed.clear();
        for (const [position, event] of signed) key.signed.set(position, event);
        return key;
      });
      throw error;
    }
  };
  const result = state.last.then(run, run);
  state.last = result.catch(() => undefined);
  return result;
}

function found(state: Unlocked, publicKey: string): HeldKey {
  const key = state.keys.find((held) => held.publicKey === publicKey);
  if (key === undefined) throw new KeystoreError("not-found", "no such key is held for this role");
  return key;
}

const infoOf = (key: HeldKey): KeyInfo => ({
  publicKey: key.publicKey,
  ...(key.label === undefined ? {} : { label: key.label }),
});

/** A signer over a key that is held, good until the role is locked or the key is destroyed. */
function signerOf(handle: RoleKeys, key: HeldKey): SyncSigner {
  return {
    publicKey: key.publicKey,
    sign: (message) => {
      const state = stateOf(handle);
      if (!state.keys.includes(key)) {
        throw new KeystoreError("not-found", "the key has been destroyed");
      }
      return signEd25519(message, key.privateKey);
    },
  };
}

/** Destroys keys: they are out of what is stored before their bytes are zeroed here. */
async function destroy(state: Unlocked, gone: readonly HeldKey[]): Promise<void> {
  state.keys = state.keys.filter((key) => !gone.includes(key));
  try {
    await write(state, true);
  } catch (error) {
    state.keys = [...state.keys, ...gone];
    throw error;
  }
  for (const key of gone) key.privateKey.fill(0);
}

/**
 * The keys of a role, unlocked. What every role has in common: its keys can
 * be listed, made and destroyed, and locked again.
 */
export abstract class RoleKeys {
  /** The role these keys have. */
  get role(): KeyRole {
    return stateOf(this).role;
  }

  /** Whether the keys were locked again. A locked handle does nothing more. */
  get locked(): boolean {
    return STATES.get(this)?.locked ?? true;
  }

  /** How many times the set of keys of this role has changed. */
  get generation(): number {
    return stateOf(this).header.generation;
  }

  /**
   * The keys held, in the order they were made.
   *
   * @throws KeystoreError `locked` once the keys are locked, as every method here does.
   */
  keys(): KeyInfo[] {
    return stateOf(this).keys.map(infoOf);
  }

  /** Whether a key is held. */
  has(publicKey: string): boolean {
    return stateOf(this).keys.some((key) => key.publicKey === publicKey);
  }

  /**
   * Makes a key and stores it. The key is in storage, sealed, before its
   * public key is returned.
   *
   * @throws KeystoreError `argument` if the label is too long or the role is
   *   full; `changed` if the stored keys were changed by another handle,
   *   after which this one is of no more use: lock it, and unlock afresh.
   */
  generate(options: GenerateOptions = {}): Promise<KeyInfo> {
    const { label } = options;
    if (label !== undefined && !isLabel(label)) {
      return Promise.reject(new KeystoreError("argument", "a label has at most 64 characters"));
    }
    return changing(this, async (state) => {
      if (state.keys.length >= MAX_KEYS) {
        throw new KeystoreError("argument", "the role holds as many keys as it can");
      }
      const key = newKey(state.role, state.randomness, label);
      state.keys = [...state.keys, key];
      try {
        await write(state, true);
      } catch (error) {
        state.keys = state.keys.filter((held) => held !== key);
        key.privateKey.fill(0);
        throw error;
      }
      return infoOf(key);
    });
  }

  /**
   * Destroys a key: it is taken out of what is stored, and its bytes here
   * are zeroed. A signer of it signs nothing more.
   *
   * @throws KeystoreError `not-found` if no such key is held.
   */
  remove(publicKey: string): Promise<void> {
    return changing(this, (state) => destroy(state, [found(state, publicKey)]));
  }

  /**
   * Locks the keys again: every private key and the key of the cipher is
   * zeroed, and this handle, its signers included, does nothing more.
   * Locking twice is locking once.
   */
  lock(): void {
    const state = STATES.get(this);
    if (state === undefined || state.locked) return;
    state.locked = true;
    for (const key of state.keys) key.privateKey.fill(0);
    state.keys = [];
    state.key.fill(0);
    state.release();
  }
}

/** The operational keys, unlocked: they sign the mind's everyday records (Layer 1, 3.5). */
export class OperationalKeys extends RoleKeys {
  static {
    MAKERS.operational = (state) => {
      const handle = new OperationalKeys();
      STATES.set(handle, state);
      return handle;
    };
  }

  private constructor() {
    super();
  }

  /**
   * A signer over one of the keys. It signs until the keys are locked or the
   * key is destroyed, and then throws `KeystoreError`.
   *
   * @throws KeystoreError `not-found` if no such key is held.
   */
  signer(publicKey: string): SyncSigner {
    return signerOf(this, found(stateOf(this), publicKey));
  }
}

/**
 * The control keys, unlocked. A control key signs one identity event, and is
 * destroyed once that event is published (Layer 1, 3.11 and 7.4).
 */
export class ControlKeys extends RoleKeys {
  static {
    MAKERS.control = (state) => {
      const handle = new ControlKeys();
      STATES.set(handle, state);
      return handle;
    };
  }

  private constructor() {
    super();
  }

  /** The keys held, in the order they were made, each with the event it is bound to, if any. */
  override keys(): ControlKeyInfo[] {
    return stateOf(this).keys.map((key) => ({
      ...infoOf(key),
      ...(key.signing === undefined ? {} : { signing: key.signing }),
    }));
  }

  /**
   * The identity events that keys here have signed and that are not yet
   * known to be published, without their proofs. After a process stopped
   * between signing and publishing, this is where the event is found again:
   * sign it once more, which gives the same event, and publish it.
   */
  pending(): JsonObject[] {
    const events = new Map<string, JsonObject>();
    for (const key of stateOf(this).keys) {
      if (key.signing !== undefined) events.set(contentId(key.signing), key.signing);
    }
    return [...events.values()];
  }

  /**
   * Signs an identity event with the control keys it reveals that are held
   * here (Layer 1, 3.11).
   *
   * Each key is first marked, in storage, as signing this event. A key so
   * marked signs this event again as often as it is asked, and never
   * another: a second event for one position of a log is duplicity (Layer 1,
   * Section 7).
   *
   * @param event - The event without its proofs, from `draftGenesis`,
   *   `draftUpdate`, `draftFork` or `draftRetire` of `@oip/identity`.
   * @param created - The `created` of the proofs. Default: the event's own.
   * @returns The event with one proof for each control key held.
   * @throws KeystoreError `argument` if the event names no control keys;
   *   `not-found` if none of them is held here; `already-signed` if one of
   *   them has signed another event.
   */
  sign<T extends Unsigned<IdentityEvent>>(
    event: T,
    created?: string,
  ): Promise<T & { proof: Proof[] }> {
    return changing(this, async (state) => {
      const named = revealed(event);
      const held = state.keys.filter((key) => named.includes(key.publicKey));
      if (held.length === 0) {
        throw new KeystoreError("not-found", "none of the control keys the event reveals is held");
      }
      const id = contentId(event);
      for (const key of held) {
        if (key.signing !== undefined && contentId(key.signing) !== id) {
          throw new KeystoreError("already-signed");
        }
      }
      if (held.some((key) => key.signing === undefined)) {
        // A copy: what is remembered must not change if the caller's object does.
        const kept = structuredClone(event) as unknown as JsonObject;
        for (const key of held) key.signing = kept;
        await write(state, false);
      }
      const signers: EventSigner[] = held.map((key) => ({ control: signerOf(this, key) }));
      return signEvent(event, signers, created);
    });
  }

  /**
   * Says that an event is published, and destroys the control keys that
   * signed it (Layer 1, 3.11 and 7.4): a used control key that still exists
   * can sign an alternative event.
   *
   * @param event - The event, with or without its proofs.
   * @returns How many keys were destroyed.
   * @throws KeystoreError `not-found` if no key here signed that event.
   */
  published(event: object): Promise<number> {
    return changing(this, async (state) => {
      const gone = signedBy(state, event);
      await destroy(state, gone);
      return gone.length;
    });
  }

  /**
   * Says that an event these keys signed was never sent to anyone, and lets
   * its keys sign another. This is for an event that turned out to be wrong
   * before it left the process. If any copy of it has left, another event
   * from these keys is duplicity, which no verifier forgives (Layer 1, 7.3).
   *
   * @throws KeystoreError `not-found` if no key here signed that event.
   */
  unsent(event: object): Promise<void> {
    return changing(this, async (state) => {
      for (const key of signedBy(state, event)) key.signing = undefined;
      await write(state, false);
    });
  }
}

/** The control keys an event reveals: the `keys` of its key controller. */
function revealed(event: object): readonly string[] {
  const controller: unknown = (event as { controller?: unknown }).controller;
  const keys: unknown =
    typeof controller === "object" && controller !== null
      ? (controller as { keys?: unknown }).keys
      : undefined;
  if (!Array.isArray(keys) || !keys.every((key) => typeof key === "string")) {
    throw new KeystoreError("argument", "the event reveals no control keys");
  }
  return keys;
}

/** The keys marked as signing an event. */
function signedBy(state: Unlocked, event: object): HeldKey[] {
  const { proof: _, ...unsigned } = event as { proof?: unknown };
  const id = contentId(unsigned);
  const keys = state.keys.filter(
    (key) => key.signing !== undefined && contentId(key.signing) === id,
  );
  if (keys.length === 0) {
    throw new KeystoreError("not-found", "no control key here signed that event");
  }
  return keys;
}

/** As whom an invocation key signs: the member, at a version of its own log (Layer 1, 6.4). */
export interface MemberSigning {
  /** The invocation key. */
  readonly publicKey: string;
  /** The member's address: the mind this keystore is of. */
  readonly member: string;
  /** A version of the member's log at which the key is an invocation key. */
  readonly versionId: string;
}

/**
 * The invocation keys, unlocked: with them the mind, as a member, signs
 * another mind's identity events (Layer 1, 3.5 and 9.4).
 */
export class InvocationKeys extends RoleKeys {
  static {
    MAKERS.invocation = (state) => {
      const handle = new InvocationKeys();
      STATES.set(handle, state);
      return handle;
    };
  }

  private constructor() {
    super();
  }

  /**
   * Signs an identity event of a collective as one of its members.
   *
   * The key remembers, in storage, which event it signed for each position
   * of each collective's log, and signs no other event for that position:
   * two valid events at one position are duplicity, and name the member that
   * signed both (Layer 1, 3.4 and Section 7). A genesis has no position: a
   * different genesis is a different mind.
   *
   * @param event - The event without proofs, or with the proofs of other members.
   * @param as - The key, and the member it signs for.
   * @param created - The `created` of the proof. Default: the event's own.
   * @returns The event with this member's proof, and no other.
   * @throws KeystoreError `not-found` if the key is not held;
   *   `already-signed` if it signed another event for that position.
   */
  sign<T extends Unsigned<IdentityEvent>>(
    event: T,
    as: MemberSigning,
    created?: string,
  ): Promise<T & { proof: Proof[] }> {
    return changing(this, async (state) => {
      const key = found(state, as.publicKey);
      const { proof: _, ...unsigned } = event as T & { proof?: unknown };
      const position = positionOf(unsigned);
      if (position !== undefined) {
        const id = contentId(unsigned);
        const before = key.signed.get(position);
        if (before !== undefined && before !== id) throw new KeystoreError("already-signed");
        if (before === undefined) {
          if (key.signed.size >= MAX_POSITIONS) {
            throw new KeystoreError(
              "argument",
              "the key has signed for as many positions as it remembers: replace it",
            );
          }
          key.signed.set(position, id);
          await write(state, false);
        }
      }
      const signer: EventSigner = {
        member: as.member,
        versionId: as.versionId,
        invocation: signerOf(this, key),
      };
      return signEvent(unsigned as unknown as T, [signer], created);
    });
  }
}

/** The position an event has in a log, as `<mind>#<seq>`, or `undefined` for a genesis. */
function positionOf(event: object): string | undefined {
  const { type, mind, seq } = event as { type?: unknown; mind?: unknown; seq?: unknown };
  if (type === "Genesis") return undefined;
  if (typeof mind !== "string" || typeof seq !== "number" || !Number.isSafeInteger(seq)) {
    throw new KeystoreError("argument", "the event has no position in a log");
  }
  return `${mind}#${String(seq)}`;
}

/** What was sealed to one of the mind's agreement keys (RFC 9180), without the key. */
export type SealedToKey = Omit<HpkeOpenInput, "recipientPrivateKey">;

/** The agreement keys, unlocked: records are sealed to them (Layer 1, 3.5 and 12.6). */
export class AgreementKeys extends RoleKeys {
  static {
    MAKERS.agreement = (state) => {
      const handle = new AgreementKeys();
      STATES.set(handle, state);
      return handle;
    };
  }

  private constructor() {
    super();
  }

  /**
   * Opens what was sealed to one of the keys.
   *
   * @returns The plaintext, or `undefined` if it does not open under that key.
   * @throws KeystoreError `not-found` if no such key is held.
   */
  open(publicKey: string, sealed: SealedToKey): Promise<Uint8Array | undefined> {
    const key = found(stateOf(this), publicKey);
    return hpkeOpen({ ...sealed, recipientPrivateKey: key.privateKey });
  }
}
