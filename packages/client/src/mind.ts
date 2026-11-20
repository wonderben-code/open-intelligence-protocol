// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A mind of one's own: its keys in a keystore, its identity log with the
 * resolvers it trusts.
 *
 * Changing a mind's identity is the one thing here that cannot be undone or
 * done twice. Each identity event is signed by control keys that sign
 * nothing else, and the order of the steps is what keeps that true when a
 * process stops in the middle:
 *
 * 1. the keystore binds the control keys to the event, in storage;
 * 2. the event is signed, and verified here as any verifier would;
 * 3. it is published, and read back from a resolver;
 * 4. only then are the control keys that signed it destroyed (Layer 1, 3.11).
 *
 * A process that stops after step 1 finds the event again in the keystore
 * and goes on from step 2 with the same event.
 */

import {
  contentId,
  createProof,
  formatKeyRef,
  formatTimestamp,
  type Instant,
  type JsonObject,
  keyHash,
  mindAddress,
  OipError,
  parseTimestamp,
} from "@oip/core";
import {
  draftFork,
  draftGenesis,
  draftRetire,
  draftUpdate,
  earliestEvidence,
  FirstSeen,
  type IdentityState,
  type Unsigned,
  verifyLog,
} from "@oip/identity";
import {
  type AgreementKeys,
  type ControlKeys,
  type InvocationKeys,
  type Keystore,
  KeystoreError,
  type Lock,
  type OperationalKeys,
} from "@oip/keystore";
import type { IdentityEvent, Proof } from "@oip/schema";

import { type Clock, Lookup, type LookupOptions, type Resolved, systemClock } from "./lookup.ts";
import { askJson, recordBody, TransportError } from "./transport.ts";

/** What a mind of one's own needs: where its keys are, and which resolvers it trusts. */
export interface MindOptions extends LookupOptions {
  /** The keystore that holds the mind's keys. */
  readonly keystore: Keystore;
  /**
   * What opens the keys of everyday work: the operational keys and the
   * agreement keys. They stay unlocked while the mind is open.
   */
  readonly lock: Lock;
}

/** What a new mind is made with. */
export interface NewMind {
  /** What the mind says it is: `human`, `agent`, `institution`, `service`, or another word (Layer 1, 3.6). */
  readonly kind: string;
  /** What opens the control keys, for this once. Default: `lock`. */
  readonly control?: Lock;
  /** What opens the invocation keys, for this once. Default: `lock`. */
  readonly invocation?: Lock;
  /** The HTTPS origins that will serve the mind's records (Layer 1, 3.13). */
  readonly homes?: readonly string[];
  /** Other names of the mind (Layer 1, 5.3). Each is verified by whoever reads it. */
  readonly alsoKnownAs?: readonly string[];
}

/** What changes with an identity event. What is left out stays as it is. */
export interface IdentityChanges {
  /** The operational keys from now on, in place of those the mind has (Layer 1, 3.7). */
  readonly keys?: readonly KeyEntry[];
  /** The invocation keys from now on. */
  readonly invocation?: readonly KeyEntry[];
  /** The agreement keys from now on. */
  readonly agreement?: readonly KeyEntry[];
  /** The mind's homes from now on. */
  readonly homes?: readonly string[];
  /** The mind's other names from now on. */
  readonly alsoKnownAs?: readonly string[];
  /**
   * Keys that are never to be the mind's again, each with the time from
   * which what it signed is withdrawn, if it was compromised (Layer 1, 3.7).
   */
  readonly revoked?: readonly { readonly key: string; readonly compromisedSince?: string }[];
}

/** A key as an identity event lists it (Layer 1, 3.5). */
export interface KeyEntry {
  /** The Multikey of the public key. */
  readonly key: string;
  /** A name for it, of at most 64 characters. */
  readonly label?: string;
}

/** What an identity change needs besides what changes. */
export interface ControlOptions {
  /** What opens the control keys. They are unlocked for this change and locked again. */
  readonly control: Lock;
}

/** What each resolver said when an identity event was published to it. */
export interface Publication {
  /** The resolver's origin. */
  readonly resolver: string;
  /** Whether it took the log. */
  readonly taken: boolean;
  /** Why it did not: the code of its problem, or the failure of the transport. */
  readonly failure?: string;
}

/** A mind of one's own. */
export class Mind {
  readonly #options: MindOptions;
  readonly #clock: Clock;
  readonly #lookup: Lookup;
  readonly #operational: OperationalKeys;
  readonly #agreement: AgreementKeys;
  #resolved: Resolved;
  #published: readonly Publication[] = [];

  private constructor(
    options: MindOptions,
    lookup: Lookup,
    keys: { operational: OperationalKeys; agreement: AgreementKeys },
    resolved: Resolved,
  ) {
    this.#options = options;
    this.#clock = options.clock ?? systemClock;
    this.#lookup = lookup;
    this.#operational = keys.operational;
    this.#agreement = keys.agreement;
    this.#resolved = resolved;
  }

  /**
   * Makes a mind: its keys in the keystore, and its genesis, published to
   * every resolver the client trusts.
   *
   * The keystore is one that holds no mind yet. If an earlier call stopped
   * before the genesis was published, this one goes on with the same
   * genesis, so the mind has the address it would have had.
   *
   * @throws OipError `forbidden` if the keystore is already a mind's;
   *   whatever `publish` throws if no resolver took the genesis. The keys
   *   are then in the keystore, and the next call goes on from there.
   */
  static async create(options: MindOptions, fields: NewMind): Promise<Mind> {
    const { keystore, lock } = options;
    if (keystore.mind !== undefined) {
      throw new OipError("forbidden", "the keystore holds the keys of a mind already: open it");
    }
    const clock = options.clock ?? systemClock;
    const lookup = new Lookup(options);
    const control = await keystore.unlock("control", fields.control ?? lock);
    try {
      let genesis = control.pending().find((event) => event["type"] === "Genesis") as
        Unsigned<IdentityEvent> | undefined;
      if (genesis === undefined) {
        // Each role that is unlocked is locked again, whichever of them fails to open.
        const unlocked: (OperationalKeys | AgreementKeys | InvocationKeys)[] = [];
        try {
          const invocation = await keystore.unlock("invocation", fields.invocation ?? lock);
          unlocked.push(invocation);
          const operational = await keystore.unlock("operational", lock);
          unlocked.push(operational);
          const agreement = await keystore.unlock("agreement", lock);
          unlocked.push(agreement);
          // Keys that an earlier call made, and stopped before it used, are the keys of this one.
          const [first = await control.generate(), next = await control.generate()] =
            control.keys();
          const held = async (keys: OperationalKeys | AgreementKeys | InvocationKeys) =>
            (keys.keys()[0] ?? (await keys.generate())).publicKey;
          genesis = draftGenesis(formatTimestamp(clock.now()), {
            kind: fields.kind,
            controller: { keys: [first.publicKey], next: [keyHash(next.publicKey)] },
            keys: [{ key: await held(operational) }],
            invocation: [{ key: await held(invocation) }],
            agreement: [{ key: await held(agreement) }],
            ...(fields.homes === undefined ? {} : { homes: [...fields.homes] }),
            ...(fields.alsoKnownAs === undefined ? {} : { alsoKnownAs: [...fields.alsoKnownAs] }),
          });
        } finally {
          for (const keys of unlocked) keys.lock();
        }
      }
      const signed = await proved(control, lookup, clock.now(), [], genesis);
      const mind = mindAddress(contentId(signed));
      const resolved = await publishAndConfirm(options, lookup, mind, [signed]);
      await control.published(signed);
      await keystore.setMind(mind);
      return await Mind.#opened(options, lookup, resolved.resolved, resolved.published);
    } finally {
      control.lock();
    }
  }

  /**
   * Opens a mind whose keys are in the keystore: resolves it, and unlocks
   * the keys of everyday work.
   *
   * @throws OipError `not-found` if the keystore holds no mind's keys, or no
   *   resolver holds the mind.
   */
  static async open(options: MindOptions): Promise<Mind> {
    const mind = options.keystore.mind;
    if (mind === undefined) {
      throw new OipError("not-found", "the keystore holds no mind's keys yet: create one");
    }
    const lookup = new Lookup(options);
    return Mind.#opened(options, lookup, await lookup.resolve(mind), []);
  }

  static async #opened(
    options: MindOptions,
    lookup: Lookup,
    resolved: Resolved,
    published: readonly Publication[],
  ): Promise<Mind> {
    const operational = await options.keystore.unlock("operational", options.lock);
    try {
      const agreement = await options.keystore.unlock("agreement", options.lock);
      const mind = new Mind(options, lookup, { operational, agreement }, resolved);
      mind.#published = published;
      return mind;
    } catch (error) {
      operational.lock();
      throw error;
    }
  }

  /** The mind's address. */
  get address(): string {
    return this.#resolved.mind;
  }

  /** The mind's identity state, as it was last resolved. */
  get state(): IdentityState {
    return this.#resolved.state;
  }

  /** The mind as it was last resolved: its log, its DID document, where it was read from. */
  get resolved(): Resolved {
    return this.#resolved;
  }

  /** What each resolver said when the mind last published an identity event. */
  get publications(): readonly Publication[] {
    return this.#published;
  }

  /**
   * What this mind knows of other minds, for resolving them and for the
   * judges that need the logs it holds.
   */
  get lookup(): Lookup {
    return this.#lookup;
  }

  /** The agreement keys, for opening what was sealed to the mind. */
  get agreement(): AgreementKeys {
    return this.#agreement;
  }

  /**
   * Locks the mind's keys. The mind signs nothing more: open it again for
   * that.
   */
  close(): void {
    this.#operational.lock();
    this.#agreement.lock();
  }

  /**
   * Resolves the mind afresh, as any other mind is resolved.
   *
   * @returns Its identity state now.
   */
  async refresh(): Promise<IdentityState> {
    this.#resolved = await this.#lookup.resolve(this.address);
    return this.#resolved.state;
  }

  /**
   * The operational key the mind signs with: the first of its current keys
   * that the keystore holds.
   *
   * @throws OipError `forbidden` if the keystore holds none of them.
   */
  signingKey(): string {
    if (this.state.retired) {
      throw new OipError("forbidden", "the mind is retired: its keys sign nothing", {
        clause: "L1 3.10",
      });
    }
    const key = this.state.keys.find((candidate) => this.#operational.has(candidate));
    if (key === undefined) {
      throw new OipError(
        "forbidden",
        "the keystore holds none of the mind's current operational keys",
        { clause: "L1 6.1" },
      );
    }
    return key;
  }

  /**
   * Signs a record as the mind, with an operational key, pinned to the
   * latest version of its identity that it has resolved (core 5; Layer 1, 6.1).
   *
   * @param record - The record without proofs, or with those of others.
   * @returns The record with the mind's proof after any it had.
   */
  async sign<T extends object>(record: T): Promise<T & { proof: Proof[] }> {
    const key = this.signingKey();
    const created = this.#clock.now();
    const said = parseTimestamp((record as { created?: unknown }).created);
    const proof = await createProof(
      record,
      {
        verificationMethod: formatKeyRef(this.address, this.state.versionId, key),
        // A proof is not dated before its record (core 5.7), whatever this clock says.
        created: formatTimestamp(said !== undefined && said > created ? said : created),
      },
      this.#operational.signer(key),
    );
    const before = (record as { proof?: Proof[] }).proof ?? [];
    return { ...record, proof: [...before, proof] };
  }

  /**
   * Changes the mind's identity with an `Update` (Layer 1, 3.7). Every
   * identity event of a key-controlled mind reveals the control keys the
   * event before committed to, and commits to new ones: so this also rotates
   * the control keys, and with no changes it does only that.
   *
   * @returns The mind's identity state after the event.
   * @throws OipError `forbidden` if the mind is retired, duplicitous, or the
   *   keystore holds no control key the log commits to.
   */
  update(changes: IdentityChanges, options: ControlOptions): Promise<IdentityState> {
    return this.#extend(options, (head, created, controller) =>
      draftUpdate(head, created, { controller, ...fieldsOf(changes) }),
    );
  }

  /**
   * Makes a new operational key in the keystore and adds it to the mind's
   * keys with an `Update`. The keys the mind has stay.
   *
   * @returns The new key, as a Multikey.
   */
  async addKey(options: ControlOptions & { readonly label?: string }): Promise<string> {
    const made = await this.#operational.generate(
      options.label === undefined ? {} : { label: options.label },
    );
    const entry = options.label === undefined ? {} : { label: options.label };
    await this.update(
      { keys: [...this.#entries("keys"), { key: made.publicKey, ...entry }] },
      options,
    );
    return made.publicKey;
  }

  /**
   * Takes an operational key from the mind's keys for good, with an `Update`
   * that lists it as revoked (Layer 1, 3.7), and destroys it in the keystore.
   *
   * @param key - The key, as a Multikey.
   * @param options.compromisedSince - If the key was stolen: the time from
   *   which what it signed is withdrawn. Everything it signed from then on
   *   stops counting, for every verifier that learns of this event.
   * @throws OipError `forbidden` if it is the mind's last operational key:
   *   add another first.
   */
  async revokeKey(
    key: string,
    options: ControlOptions & { readonly compromisedSince?: string },
  ): Promise<IdentityState> {
    const kept = this.#entries("keys").filter((entry) => entry.key !== key);
    if (kept.length === 0) {
      throw new OipError(
        "forbidden",
        "that is the mind's last operational key: add another before it is revoked",
        { clause: "L1 3.7" },
      );
    }
    const revoked =
      options.compromisedSince === undefined
        ? { key }
        : { key, compromisedSince: options.compromisedSince };
    const state = await this.update({ keys: kept, revoked: [revoked] }, options);
    if (this.#operational.has(key)) await this.#operational.remove(key);
    return state;
  }

  /** The entries of one of the mind's sets of keys: the keys of its state, with the labels its log gave them. */
  #entries(set: "keys" | "invocation" | "agreement"): KeyEntry[] {
    const labels = new Map<string, string>();
    for (const { event } of this.#resolved.log.entries) {
      for (const entry of ((event as Record<string, unknown>)[set] ?? []) as KeyEntry[]) {
        if (entry.label !== undefined) labels.set(entry.key, entry.label);
      }
    }
    return this.state[set].map((key) => {
      const label = labels.get(key);
      return label === undefined ? { key } : { key, label };
    });
  }

  /**
   * Acknowledges a child mind with a `Fork` (Layer 1, 3.8), which records
   * the lineage in this mind's own log.
   *
   * @param child - The child's address.
   * @param terms - What the child received, in the parent's words.
   */
  fork(
    child: string,
    options: ControlOptions & { readonly terms?: JsonObject; readonly changes?: IdentityChanges },
  ): Promise<IdentityState> {
    return this.#extend(options, (head, created, controller) =>
      draftFork(head, created, {
        child,
        controller,
        ...(options.terms === undefined ? {} : { terms: options.terms }),
        ...fieldsOf(options.changes ?? {}),
      }),
    );
  }

  /**
   * Ends the mind with a `Retire` (Layer 1, 3.10). No event follows it, and
   * the mind's keys sign nothing after it takes effect.
   */
  retire(
    options: ControlOptions & { readonly successor?: string; readonly reason?: string },
  ): Promise<IdentityState> {
    return this.#extend(
      options,
      (head, created, controller) =>
        draftRetire(head, created, {
          controller: { keys: controller.keys, next: [] },
          ...(options.successor === undefined ? {} : { successor: options.successor }),
          ...(options.reason === undefined ? {} : { reason: options.reason }),
        }),
      true,
    );
  }

  /** Signs, publishes and confirms the next event of the mind's log. */
  async #extend(
    options: ControlOptions,
    draft: (
      head: Pick<IdentityState, "mind" | "seq" | "head">,
      created: string,
      controller: { keys: string[]; next: string[] },
    ) => Unsigned<IdentityEvent>,
    last = false,
  ): Promise<IdentityState> {
    const control = await this.#options.keystore.unlock("control", options.control);
    try {
      let resolved = (this.#resolved = await this.#lookup.resolve(this.address));
      // An event that was signed and may not have been published comes first: its keys sign no other.
      for (const pending of control.pending()) {
        const id = contentId(pending);
        const held = resolved.log.entries[pending["seq"] as number]?.event;
        if (held !== undefined && contentId(held) !== id) {
          // The log has another event at that position, which the same control keys signed:
          // this one will never have it. Publishing it would add to the evidence of duplicity
          // and change nothing else. Its keys have signed, and are destroyed (Layer 1, 7.4).
          for (const key of control.keys()) {
            if (key.signing !== undefined && contentId(key.signing) === id) {
              await control.remove(key.publicKey);
            }
          }
        } else {
          resolved = await this.#publish(control, resolved, pending as Unsigned<IdentityEvent>);
        }
      }
      if (resolved.duplicitous) {
        throw new OipError(
          "forbidden",
          "the mind's log shows duplicity: it is extended no further",
          {
            clause: "L1 7.3",
          },
        );
      }
      const { state } = resolved;
      if (state.retired || state.controller.kind !== "key" || state.controller.next.length === 0) {
        throw new OipError("forbidden", "the mind's log can be extended no further", {
          clause: "L1 3.10",
        });
      }
      await destroyUseless(control, resolved);
      const committed = state.controller.next;
      const revealing = control
        .keys()
        .map((key) => key.publicKey)
        .filter((key) => committed.includes(keyHash(key)));
      if (revealing.length < state.controller.nextThreshold) {
        throw new OipError(
          "forbidden",
          "the keystore does not hold the control keys the mind's log commits to: restore a backup that does",
          { clause: "L1 3.4" },
        );
      }
      const made = last ? undefined : await control.generate();
      // Not earlier than the event before it (Layer 1, 3.2), whatever this clock says.
      const now = this.#clock.now();
      const created = formatTimestamp(now > state.created ? now : state.created);
      const event = draft(state, created, {
        keys: revealing,
        next: made === undefined ? [] : [keyHash(made.publicKey)],
      });
      const before = resolved.log.entries.map((entry) => entry.event);
      let signed: Unsigned<IdentityEvent>;
      try {
        signed = await proved(control, this.#lookup, now, before, event);
      } catch (error) {
        // Nothing of the event has left. The key it would have committed to is of no use.
        if (made !== undefined) await control.remove(made.publicKey);
        throw error;
      }
      resolved = await this.#publish(control, resolved, event, signed);
      return resolved.state;
    } finally {
      control.lock();
    }
  }

  /**
   * Publishes the log with an event at its end, and destroys the control
   * keys that signed the event once a resolver serves the log with it.
   */
  async #publish(
    control: ControlKeys,
    resolved: Resolved,
    event: Unsigned<IdentityEvent>,
    signed?: object,
  ): Promise<Resolved> {
    const before = resolved.log.entries.map((entry) => entry.event);
    const id = contentId(event);
    // Published already, by a call that stopped before it destroyed the keys.
    if (!before.some((held) => contentId(held) === id)) {
      const after = await publishAndConfirm(this.#options, this.#lookup, this.address, [
        ...before,
        signed ?? (await control.sign(event)),
      ]);
      this.#published = after.published;
      resolved = after.resolved;
    }
    await control.published(event);
    this.#resolved = resolved;
    return resolved;
  }
}

/** The members of an event that the changes fill in. */
function fieldsOf(changes: IdentityChanges): JsonObject {
  const entries = (list: readonly KeyEntry[]) =>
    list.map(({ key, label }) => (label === undefined ? { key } : { key, label }));
  return {
    ...(changes.keys === undefined ? {} : { keys: entries(changes.keys) }),
    ...(changes.invocation === undefined ? {} : { invocation: entries(changes.invocation) }),
    ...(changes.agreement === undefined ? {} : { agreement: entries(changes.agreement) }),
    ...(changes.homes === undefined ? {} : { homes: [...changes.homes] }),
    ...(changes.alsoKnownAs === undefined ? {} : { alsoKnownAs: [...changes.alsoKnownAs] }),
    ...(changes.revoked === undefined
      ? {}
      : {
          revoked: changes.revoked.map(({ key, compromisedSince }) =>
            compromisedSince === undefined ? { key } : { key, compromisedSince },
          ),
        }),
  };
}

/**
 * Signs an event and judges the log with it as any verifier would, before a
 * copy of it leaves: the events before it at the times the resolvers gave,
 * and this one as first seen now.
 *
 * If it cannot be signed, or does not verify, nothing of it has left, and
 * the control keys are free of it again.
 *
 * @returns The event, signed.
 * @throws OipError `invalid-record` if the event cannot be signed or does not verify.
 */
async function proved(
  control: ControlKeys,
  lookup: Lookup,
  now: Instant,
  before: readonly object[],
  event: Unsigned<IdentityEvent>,
): Promise<Unsigned<IdentityEvent>> {
  let signed: Unsigned<IdentityEvent>;
  try {
    signed = await control.sign(event);
  } catch (error) {
    // What cannot be signed is bound to no key (the keystore sees to that), and is the caller's mistake.
    if (error instanceof KeystoreError && error.code === "argument") {
      throw new OipError("invalid-record", error.message, { clause: "L1 3", cause: error });
    }
    throw error;
  }
  const seen = new FirstSeen();
  seen.sawEvent(contentId(signed), now);
  const own = verifyLog([...before, signed], {
    evidence: earliestEvidence(lookup.view.evidence, seen),
    asOf: now,
  });
  if (!own.ok) {
    await control.unsent(event);
    const [first] = own.issues;
    throw new OipError("invalid-record", `the event does not verify: ${first.message}`, {
      clause: first.clause,
      issues: own.issues,
    });
  }
  return signed;
}

/**
 * Destroys the control keys that are of no more use: those a published event
 * has revealed, which have signed, whatever the keystore remembers of it
 * (Layer 1, 7.4), and those that no published event commits to, which were
 * made for an event that was never published. A keystore restored from a
 * backup holds keys of the first kind.
 *
 * It is called once every event the keystore knows to be signed is
 * published, so a key that is bound to nothing and committed to by nothing
 * is waited for by nothing.
 */
async function destroyUseless(control: ControlKeys, resolved: Resolved): Promise<void> {
  const revealed = new Set<string>();
  for (const { event } of resolved.log.entries) {
    // Every event of a key-controlled mind's log names the control keys it reveals (Layer 1, 3.4).
    const { keys } = (event as unknown as { controller: { keys: readonly string[] } }).controller;
    for (const key of keys) revealed.add(key);
  }
  const { controller } = resolved.state;
  const committed = controller.kind === "key" ? controller.next : [];
  for (const { publicKey } of control.keys()) {
    if (revealed.has(publicKey) || !committed.includes(keyHash(publicKey))) {
      await control.remove(publicKey);
    }
  }
}

/**
 * Publishes a log to every resolver, and resolves the mind again to see the
 * whole log served and verified.
 *
 * @throws OipError `duplicity` if a resolver holds another event at a
 *   position of the log; the failure of the first resolver, if none took
 *   the log; `invalid-proof` if the log is not served back whole.
 */
async function publishAndConfirm(
  options: MindOptions,
  lookup: Lookup,
  mind: string,
  log: readonly object[],
): Promise<{ resolved: Resolved; published: Publication[] }> {
  const id = mind.slice("did:oip:".length);
  const body = recordBody({ oip: "1", type: "Bundle", mind, log });
  const failures: (OipError | TransportError)[] = [];
  const published = await Promise.all(
    options.resolvers.map(async (resolver): Promise<Publication> => {
      try {
        await askJson({ method: "PUT", url: `${resolver}/oip/v1/resolve/${id}`, body }, options);
        return { resolver, taken: true };
      } catch (error) {
        if (!(error instanceof OipError || error instanceof TransportError)) throw error;
        failures.push(error);
        return {
          resolver,
          taken: false,
          failure: error instanceof OipError ? error.code : error.failure,
        };
      }
    }),
  );
  // A resolver that holds another event at one of these positions: the mind's own duplicity.
  const duplicity = failures.find(
    (error) => error instanceof OipError && error.code === "duplicity",
  );
  const [first] = failures;
  if (duplicity !== undefined) throw duplicity;
  if (first !== undefined && failures.length === published.length) throw first;
  const resolved = await lookup.resolve(mind);
  if (resolved.log.entries.length < log.length) {
    throw new OipError(
      "invalid-proof",
      "the log was taken, and is not served back whole: its last event is not published yet",
      { clause: "L1 17.1" },
    );
  }
  return { resolved, published };
}
