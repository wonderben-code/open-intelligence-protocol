// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A keystore: the private keys of one mind, kept apart by role (BUILD.md,
 * Section 3.4). Each role is one sealed document, under a lock of its own if
 * its owner wants one, and is unlocked by itself: a process that signs
 * everyday records never holds a control key.
 *
 * A private key leaves a keystore in one way only: sealed, in a backup.
 */

import {
  base64urlToBytes,
  bytesToBase64url,
  canonicalBytes,
  type JsonObject,
  type JsonValue,
  mindId,
  parseJsonBytes,
} from "@oip/core";

import {
  decodeContent,
  encodeContent,
  type HeldKey,
  KEY_ROLES,
  type KeyRole,
  keysOf,
  keyValue,
} from "./content.ts";
import { KeystoreError } from "./errors.ts";
import {
  type AgreementKeys,
  type ControlKeys,
  handleOver,
  type InvocationKeys,
  type OperationalKeys,
  type RoleKeys,
  stateOf,
  type Unlocked,
} from "./keys.ts";
import type { Lock } from "./lock.ts";
import { draw, type Randomness, systemRandomness } from "./randomness.ts";
import {
  FORMAT,
  KEYSTORE_ID_LENGTH,
  MAX_DOCUMENT_BYTES,
  members,
  openDocument,
  readSealed,
  type Sealed,
  sealDocument,
  type SealedHeader,
} from "./seal.ts";
import type { KeyStorage } from "./storage.ts";

/** The name of the document that says which keystore is stored, in the clear. */
const META = "meta";

/** Where a keystore is, and where its randomness comes from. */
export interface KeystoreOptions {
  /** Where the sealed documents are kept. */
  readonly storage: KeyStorage;
  /**
   * Where the control keys are kept, if not with the rest: somewhere that is
   * reached only when the mind's identity changes.
   */
  readonly controlStorage?: KeyStorage;
  /** Default: the platform's generator. */
  readonly randomness?: Randomness;
}

/** One lock for every role, or one for each. */
export type Locks = Lock | Readonly<Record<KeyRole, Lock>>;

/** What `Keystore.create` takes. */
export interface CreateOptions extends KeystoreOptions {
  /** What each role is sealed under. */
  readonly locks: Locks;
}

/** What `Keystore.restore` takes. */
export interface RestoreOptions extends CreateOptions {
  /** The backup, as `backup` gave it. */
  readonly backup: Uint8Array;
  /** The lock the backup was sealed under. */
  readonly backupLock: Lock;
}

/** The unlocked keys of every role, as a backup needs them. */
export interface AllKeys {
  /** The control keys. */
  readonly control: ControlKeys;
  /** The operational keys. */
  readonly operational: OperationalKeys;
  /** The invocation keys. */
  readonly invocation: InvocationKeys;
  /** The agreement keys. */
  readonly agreement: AgreementKeys;
}

/** A backup that was made, and the way to say that it was put somewhere safe. */
export interface Backup {
  /** The backup: one sealed document. Nothing in it can be read without its lock. */
  readonly bytes: Uint8Array;
  /**
   * Records that this backup is kept. Call it once the bytes are stored
   * where they will be found again, and not before: until then
   * `backupDue` goes on naming the roles that have keys no backup holds.
   */
  saved(): Promise<void>;
}

const isLock = (locks: Locks): locks is Lock =>
  typeof (locks as Partial<Lock>).fresh === "function";

const lockFor = (locks: Locks, role: KeyRole): Lock => (isLock(locks) ? locks : locks[role]);

/** The private keys of one mind, sealed in a storage. */
export class Keystore {
  readonly #storage: KeyStorage;
  readonly #control: KeyStorage;
  readonly #randomness: Randomness;
  readonly #id: string;
  readonly #unlocked = new Set<KeyRole>();
  #mind: string | undefined;
  #backedUp: Partial<Record<KeyRole, number>>;
  #metaVersion: string;

  private constructor(
    options: KeystoreOptions,
    meta: { id: string; mind: string | undefined; backedUp: Partial<Record<KeyRole, number>> },
    metaVersion: string,
  ) {
    this.#storage = options.storage;
    this.#control = options.controlStorage ?? options.storage;
    this.#randomness = options.randomness ?? systemRandomness;
    this.#id = meta.id;
    this.#mind = meta.mind;
    this.#backedUp = meta.backedUp;
    this.#metaVersion = metaVersion;
  }

  /**
   * Makes a keystore where there is none: four roles with no keys in them,
   * each sealed under its lock.
   *
   * @throws KeystoreError `exists` if anything of a keystore is stored
   *   there already; `weak-lock` if a lock is too weak to seal under.
   */
  static async create(options: CreateOptions): Promise<Keystore> {
    await mustBeEmpty(options);
    const randomness = options.randomness ?? systemRandomness;
    const id = bytesToBase64url(draw(randomness, KEYSTORE_ID_LENGTH));
    return Keystore.#write(options, { id, mind: undefined }, () => ({ generation: 0, keys: [] }));
  }

  /**
   * Opens the keystore that is stored. Nothing is unlocked by this, and no
   * lock is needed for it.
   *
   * @throws KeystoreError `not-found` if no keystore is stored there;
   *   `damaged` or `unsupported` if what is stored cannot be read.
   */
  static async open(options: KeystoreOptions): Promise<Keystore> {
    const stored = await options.storage.get(META);
    if (stored === undefined) throw new KeystoreError("not-found", "no keystore is stored here");
    return new Keystore(options, readMeta(stored.value), stored.version);
  }

  /**
   * Makes a keystore from a backup, where there is none. The keys are sealed
   * afresh under the locks given, which need not be the ones they had.
   *
   * A backup holds the keys as they were when it was made. A control key
   * that has signed and been destroyed since is in it still: before any
   * identity event is signed from a restored keystore, find out what the
   * mind has published, and destroy what was used (`ControlKeys.published`).
   *
   * @throws KeystoreError `not-opened` if the lock does not open the backup;
   *   `damaged` if it is not a backup; `exists` if a keystore is stored
   *   there already.
   */
  static async restore(options: RestoreOptions): Promise<Keystore> {
    await mustBeEmpty(options);
    const sealed = readSealed(options.backup);
    if (sealed.header.role !== "backup") throw new KeystoreError("damaged");
    const id = sealed.header.keystore;
    const key = await options.backupLock.key(sealed.header.lock, { keystore: id, role: "backup" });
    let plaintext: Uint8Array;
    try {
      plaintext = openDocument(sealed, key);
    } finally {
      key.fill(0);
    }
    try {
      const parsed = parseJsonBytes(plaintext, { maxLength: MAX_DOCUMENT_BYTES });
      const content = parsed.ok ? members(parsed.value, ["roles"], ["mind"]) : undefined;
      const roles = members(content?.["roles"], KEY_ROLES);
      const mind = content?.["mind"];
      if (roles === undefined || (mind !== undefined && mindId(mind) === undefined)) {
        throw new KeystoreError("damaged");
      }
      const held: [KeyRole, { generation: number; keys: HeldKey[] }][] = [];
      for (const role of KEY_ROLES) {
        const of = members(roles[role], ["generation", "keys"]);
        const generation = of?.["generation"];
        if (typeof generation !== "number" || !Number.isSafeInteger(generation) || generation < 0) {
          throw new KeystoreError("damaged");
        }
        held.push([role, { generation, keys: keysOf(role, { keys: of?.["keys"] as JsonValue }) }]);
      }
      const contents = Object.fromEntries(held) as Record<KeyRole, (typeof held)[number][1]>;
      const keystore = await Keystore.#write(
        options,
        { id, mind: mind as string | undefined },
        (role) => contents[role],
      );
      for (const [, { keys }] of held) for (const one of keys) one.privateKey.fill(0);
      // What was restored is what the backup holds: nothing is owed a backup yet.
      await keystore.#saveMeta(
        Object.fromEntries(held.map(([role, { generation }]) => [role, generation])),
      );
      return keystore;
    } finally {
      plaintext.fill(0);
    }
  }

  /** Seals each role and writes it, and then the document that says a keystore is here. */
  static async #write(
    options: CreateOptions,
    meta: { id: string; mind: string | undefined },
    content: (role: KeyRole) => { generation: number; keys: readonly HeldKey[] },
  ): Promise<Keystore> {
    const randomness = options.randomness ?? systemRandomness;
    for (const role of KEY_ROLES) {
      const { header: lock, key } = await lockFor(options.locks, role).fresh(
        { keystore: meta.id, role },
        randomness,
      );
      const { generation, keys } = content(role);
      const plaintext = encodeContent(keys);
      try {
        const header: SealedHeader = { format: FORMAT, keystore: meta.id, role, generation, lock };
        const storage =
          role === "control" ? (options.controlStorage ?? options.storage) : options.storage;
        await storage.put(role, sealDocument(header, key, plaintext, randomness), undefined);
      } finally {
        key.fill(0);
        plaintext.fill(0);
      }
    }
    // Last: a keystore is here once every role of it is.
    const whole = { id: meta.id, mind: meta.mind, backedUp: {} };
    const version = await options.storage.put(META, writeMeta(whole), undefined);
    return new Keystore(options, whole, version);
  }

  /** The keystore's identifier: 16 random bytes, in base64url. It names nothing but this keystore. */
  get id(): string {
    return this.#id;
  }

  /**
   * The address of the mind these keys are of, if the keystore was told. It
   * is kept in the clear and is not authenticated: a note for its owner, and
   * no evidence of anything. What a key may sign is decided by the mind's
   * identity log.
   */
  get mind(): string | undefined {
    return this.#mind;
  }

  /**
   * Notes which mind these keys are of.
   *
   * @throws KeystoreError `argument` if it is not a mind's address.
   */
  async setMind(address: string): Promise<void> {
    if (mindId(address) === undefined) {
      throw new KeystoreError("argument", "that is not the address of a mind");
    }
    const before = this.#mind;
    this.#mind = address;
    try {
      await this.#saveMeta(this.#backedUp);
    } catch (error) {
      this.#mind = before;
      throw error;
    }
  }

  /**
   * Unlocks the keys of a role. They stay in memory until the handle is
   * locked: lock it as soon as the work is done, and control keys above all.
   *
   * One handle at a time holds a role. Another keystore object over the same
   * storage, in this process or another, can unlock it too; the first of the
   * two to change the keys wins, and the other is told `changed`.
   *
   * @throws KeystoreError `in-use` if the role is unlocked already;
   *   `not-opened` if the lock does not open it; `damaged` or `unsupported`
   *   if what is stored cannot be read.
   */
  unlock(role: "control", lock: Lock): Promise<ControlKeys>;
  /** Unlocks the operational keys, as above. */
  unlock(role: "operational", lock: Lock): Promise<OperationalKeys>;
  /** Unlocks the invocation keys, as above. */
  unlock(role: "invocation", lock: Lock): Promise<InvocationKeys>;
  /** Unlocks the agreement keys, as above. */
  unlock(role: "agreement", lock: Lock): Promise<AgreementKeys>;
  /** Unlocks the keys of a role that is not known until the call, as above. */
  unlock(role: KeyRole, lock: Lock): Promise<RoleKeys>;
  async unlock(role: KeyRole, lock: Lock): Promise<RoleKeys> {
    if (!KEY_ROLES.includes(role)) throw new KeystoreError("argument", "there is no such role");
    if (this.#unlocked.has(role)) throw new KeystoreError("in-use");
    // Taken before the first wait, so that two calls cannot both go on.
    this.#unlocked.add(role);
    try {
      const { sealed, version } = await this.#read(role);
      const key = await lock.key(sealed.header.lock, { keystore: this.#id, role });
      let keys: HeldKey[];
      try {
        const plaintext = openDocument(sealed, key);
        try {
          keys = decodeContent(role, plaintext);
        } finally {
          plaintext.fill(0);
        }
      } catch (error) {
        key.fill(0);
        throw error;
      }
      const state: Unlocked = {
        role,
        storage: this.#storageOf(role),
        randomness: this.#randomness,
        header: sealed.header,
        version,
        key,
        keys,
        locked: false,
        last: Promise.resolve(),
        release: () => this.#unlocked.delete(role),
      };
      return handleOver(state);
    } catch (error) {
      this.#unlocked.delete(role);
      throw error;
    }
  }

  /**
   * Seals the keys of a role under another lock: a new passphrase, or the
   * keychain in place of one. What was sealed under the old lock is
   * replaced.
   *
   * @throws KeystoreError as `unlock` does, for the lock the role has now;
   *   `weak-lock` if the new lock is too weak to seal under.
   */
  async changeLock(role: KeyRole, from: Lock, to: Lock): Promise<void> {
    if (!KEY_ROLES.includes(role)) throw new KeystoreError("argument", "there is no such role");
    if (this.#unlocked.has(role)) throw new KeystoreError("in-use");
    this.#unlocked.add(role);
    try {
      const { sealed, version } = await this.#read(role);
      const old = await from.key(sealed.header.lock, { keystore: this.#id, role });
      let plaintext: Uint8Array;
      try {
        plaintext = openDocument(sealed, old);
      } finally {
        old.fill(0);
      }
      try {
        const fresh = await to.fresh({ keystore: this.#id, role }, this.#randomness);
        try {
          const header: SealedHeader = { ...sealed.header, lock: fresh.header };
          const document = sealDocument(header, fresh.key, plaintext, this.#randomness);
          await this.#storageOf(role).put(role, document, version);
        } finally {
          fresh.key.fill(0);
        }
      } finally {
        plaintext.fill(0);
      }
    } finally {
      this.#unlocked.delete(role);
    }
  }

  /**
   * The roles whose keys have changed since the last backup that was said to
   * be saved. No lock is needed to ask.
   *
   * A control key is made at every identity event, and the event commits to
   * it. If the keystore is lost before a backup holds that key, the mind's
   * identity can never change again: back up after every identity event.
   */
  async backupDue(): Promise<KeyRole[]> {
    const due: KeyRole[] = [];
    for (const role of KEY_ROLES) {
      const { sealed } = await this.#read(role);
      if (sealed.header.generation !== (this.#backedUp[role] ?? 0)) due.push(role);
    }
    return due;
  }

  /**
   * Makes a backup: the keys of every role in one document, sealed under a
   * lock of its own. It is the one form in which private keys leave a
   * keystore.
   *
   * @param keys - Every role, unlocked from this keystore.
   * @param lock - What the backup is sealed under. A passphrase kept apart
   *   from the keystore's own is what makes a backup worth having.
   * @throws KeystoreError `argument` if a role is missing or is of another
   *   keystore; `locked` if one was locked; `weak-lock` if the lock is too
   *   weak to seal under.
   */
  async backup(keys: AllKeys, lock: Lock): Promise<Backup> {
    const roles: Record<string, JsonObject> = {};
    const generations: Partial<Record<KeyRole, number>> = {};
    for (const role of KEY_ROLES) {
      const state = stateOf(keys[role]);
      if (state.role !== role || state.header.keystore !== this.#id) {
        throw new KeystoreError("argument", "those keys are not the keys of this keystore");
      }
      roles[role] = {
        generation: state.header.generation,
        keys: state.keys.map((key) => keyValue(key)),
      };
      generations[role] = state.header.generation;
    }
    const fresh = await lock.fresh({ keystore: this.#id, role: "backup" }, this.#randomness);
    const plaintext = canonicalBytes({
      ...(this.#mind === undefined ? {} : { mind: this.#mind }),
      roles,
    });
    try {
      const header: SealedHeader = {
        format: FORMAT,
        keystore: this.#id,
        role: "backup",
        generation: 0,
        lock: fresh.header,
      };
      const bytes = sealDocument(header, fresh.key, plaintext, this.#randomness);
      return { bytes, saved: () => this.#saveMeta(generations) };
    } finally {
      fresh.key.fill(0);
      plaintext.fill(0);
    }
  }

  #storageOf(role: KeyRole): KeyStorage {
    return role === "control" ? this.#control : this.#storage;
  }

  /** The sealed document of a role, checked to be this keystore's and that role's. */
  async #read(role: KeyRole): Promise<{ sealed: Sealed; version: string }> {
    const stored = await this.#storageOf(role).get(role);
    if (stored === undefined) {
      throw new KeystoreError("not-found", `the ${role} keys are not stored here`);
    }
    const sealed = readSealed(stored.value);
    // A document of another keystore, or of another role, put in this one's place.
    if (sealed.header.keystore !== this.#id || sealed.header.role !== role) {
      throw new KeystoreError("damaged");
    }
    return { sealed, version: stored.version };
  }

  async #saveMeta(backedUp: Partial<Record<KeyRole, number>>): Promise<void> {
    const meta = { id: this.#id, mind: this.#mind, backedUp };
    this.#metaVersion = await this.#storage.put(META, writeMeta(meta), this.#metaVersion);
    this.#backedUp = backedUp;
  }
}

/** @throws KeystoreError `exists` if anything of a keystore is stored there. */
async function mustBeEmpty(options: KeystoreOptions): Promise<void> {
  const names = new Set([
    ...(await options.storage.list()),
    ...(options.controlStorage === undefined ? [] : await options.controlStorage.list()),
  ]);
  if ([META, ...KEY_ROLES].some((name) => names.has(name))) throw new KeystoreError("exists");
}

function writeMeta(meta: {
  id: string;
  mind: string | undefined;
  backedUp: Partial<Record<KeyRole, number>>;
}): Uint8Array {
  return canonicalBytes({
    format: FORMAT,
    keystore: meta.id,
    ...(meta.mind === undefined ? {} : { mind: meta.mind }),
    backedUp: meta.backedUp as JsonObject,
  });
}

function readMeta(bytes: Uint8Array): {
  id: string;
  mind: string | undefined;
  backedUp: Partial<Record<KeyRole, number>>;
} {
  const parsed = parseJsonBytes(bytes, { maxLength: MAX_DOCUMENT_BYTES });
  const meta = parsed.ok
    ? members(parsed.value, ["format", "keystore", "backedUp"], ["mind"])
    : undefined;
  if (meta === undefined) throw new KeystoreError("damaged");
  const { format, keystore, mind } = meta;
  if (format !== FORMAT) {
    const later = typeof format === "string" && /^oip-keystore\/[1-9][0-9]{0,8}$/u.test(format);
    throw new KeystoreError(later ? "unsupported" : "damaged");
  }
  const noted = members(meta["backedUp"], [], KEY_ROLES);
  if (typeof keystore !== "string" || noted === undefined) throw new KeystoreError("damaged");
  // The identifier names secrets in a keychain: it is 16 bytes, as every sealed header says too.
  if (base64urlToBytes(keystore)?.length !== KEYSTORE_ID_LENGTH) throw new KeystoreError("damaged");
  if (mind !== undefined && mindId(mind) === undefined) throw new KeystoreError("damaged");
  const backedUp: Partial<Record<KeyRole, number>> = {};
  for (const role of KEY_ROLES) {
    const generation = noted[role];
    if (generation === undefined) continue;
    if (typeof generation !== "number" || !Number.isSafeInteger(generation) || generation < 0) {
      throw new KeystoreError("damaged");
    }
    backedUp[role] = generation;
  }
  return { id: keystore, mind: mind as string | undefined, backedUp };
}
