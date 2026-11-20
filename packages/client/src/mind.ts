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
  formatVersionId,
  type Instant,
  type JsonObject,
  keyHash,
  mindAddress,
  mindId,
  OipError,
  type OipRecord,
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
  type KeyStorage,
  type Lock,
  memoryStorage,
  type OperationalKeys,
  type Randomness,
  systemRandomness,
} from "@oip/keystore";
import type {
  AuthorityItem,
  Collective as Charter,
  Commitment,
  Delegation,
  Entry,
  IdentityEvent,
  Intent,
  Location,
  Offer,
  Participant,
  Proof,
  Receipt,
  Revocation,
  Session,
} from "@oip/schema";
import type { Status } from "@oip/web";

import { type Clock, Lookup, type LookupOptions, type Resolved, systemClock } from "./lookup.ts";
import { Memory } from "./memory.ts";
import { type Acting, Dealings, type Fields, type Grant } from "./dealings.ts";
import { type Inbox, type Message, Messaging, type Retried, type Sent } from "./messages.ts";
import { Outbox, type Queued } from "./outbox.ts";
import { checkInstance, SessionBook, type SessionView } from "./sessions.ts";
import {
  listen,
  type Listening,
  type ListenOptions,
  type OpenSocket,
  platformSleep,
  platformSocket,
} from "./socket.ts";
import {
  homeEndpoints,
  type LocationFields,
  type Own,
  type ProfileFields,
  type Publication,
  Publishing,
} from "./publish.ts";
import { type RequestKey, signedAsking } from "./signed.ts";
import { type Asking, askJson, recordBody, TransportError } from "./transport.ts";

/** What a mind of one's own needs: where its keys are, and which resolvers it trusts. */
export interface MindOptions extends LookupOptions {
  /** The keystore that holds the mind's keys. */
  readonly keystore: Keystore;
  /**
   * What opens the keys of everyday work: the operational keys and the
   * agreement keys. They stay unlocked while the mind is open.
   */
  readonly lock: Lock;
  /**
   * Where the client remembers its own work between runs: where the mind's
   * feed stands, and the number of its last location record. None of it is
   * secret, and all of it keeps the mind from signing two things for one
   * position. Give it a storage that lasts, and one of its own: not the
   * keystore's. Default: memory that is gone when the process ends, after
   * which the client asks the mind's homes and resolvers where things stand
   * and goes by what they answer.
   */
  readonly memory?: KeyStorage;
  /** Where the nonces of signed requests come from. Default: the platform's generator. */
  readonly randomness?: Randomness;
  /**
   * A name for this client among the clients that run as the mind, in at
   * most 64 characters (Layer 1, 14.3). The packets it sends in a session
   * carry it, so that each client's packets are a chain of their own. A
   * mind that runs one client needs none. Clients that share one `memory`
   * are one instance.
   */
  readonly instance?: string;
  /**
   * Opens a WebSocket, for `listen`. Default: the platform's own
   * `WebSocket`, which a browser has, and Node.js from version 22.
   */
  readonly webSocket?: OpenSocket;
  /** Waits a number of milliseconds, between one connection and the next. Default: the platform's timer. */
  readonly sleep?: (ms: number) => Promise<void>;
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

/** What a collective is founded with (Layer 1, Section 9). */
export interface NewCollective {
  /** Its founding members, this mind among them: distinct addresses. Each of them signs the genesis. */
  readonly members: readonly string[];
  /** How many members act for it: a majority of them (Layer 1, 3.4). */
  readonly threshold: number;
  /** The HTTPS origins that will serve its records. */
  readonly homes?: readonly string[];
  /** Other names of the collective. */
  readonly alsoKnownAs?: readonly string[];
}

/** What changes with an identity event of a collective. What is left out stays as it is. */
export interface CollectiveChanges {
  /** Its members from now on. Every member that is new signs the event too (Layer 1, 9.3). */
  readonly members?: readonly string[];
  /** Its threshold from now on. */
  readonly threshold?: number;
  /** Its homes from now on. */
  readonly homes?: readonly string[];
  /** Its other names from now on. */
  readonly alsoKnownAs?: readonly string[];
}

/** What signing an identity event of a collective needs. */
export interface MemberOptions {
  /** What opens this mind's invocation keys. They are unlocked for the one signature and locked again. */
  readonly invocation: Lock;
}

/** The keys of everyday work, unlocked. */
interface Everyday {
  readonly operational: OperationalKeys;
  readonly agreement: AgreementKeys;
}

/** A mind of one's own. */
export class Mind {
  readonly #options: MindOptions;
  readonly #clock: Clock;
  readonly #randomness: Randomness;
  readonly #lookup: Lookup;
  readonly #operational: OperationalKeys;
  readonly #agreement: AgreementKeys;
  readonly #own: Own;
  readonly #publishing: Publishing;
  readonly #messaging: Messaging;
  readonly #sessions: SessionBook;
  readonly #outbox: Outbox;
  /** What the mind listens to, for as long as it does. */
  readonly #listening = new Set<Listening>();
  readonly #dealings: Dealings;
  #resolved: Resolved;
  #published: readonly Publication[] = [];

  private constructor(options: MindOptions, lookup: Lookup, keys: Everyday, resolved: Resolved) {
    this.#options = options;
    this.#clock = options.clock ?? systemClock;
    this.#randomness = options.randomness ?? systemRandomness;
    this.#lookup = lookup;
    this.#operational = keys.operational;
    this.#agreement = keys.agreement;
    this.#resolved = resolved;
    const own: Own = {
      address: resolved.mind,
      transport: options,
      resolvers: options.resolvers,
      indexers: options.indexers ?? [],
      clock: this.#clock,
      randomness: this.#randomness,
      lookup,
      memory: new Memory(options.memory ?? memoryStorage(), resolved.mind),
      opener: (key) =>
        this.#agreement.has(key) ? (sealed) => this.#agreement.open(key, sealed) : undefined,
      resolved: () => this.#resolved,
      refresh: async () => {
        await this.refresh();
        return this.#resolved;
      },
      sign: (record, authority) => this.sign(record, authority),
      signed: (asking) => this.#signed(asking),
      hello: (challenge, domain) => this.#hello(challenge, domain),
      signedForLog: (asking) => this.#signedForLog(asking),
      told: (publications) => {
        this.#published = publications;
      },
    };
    this.#own = own;
    this.#publishing = new Publishing(own);
    this.#outbox = new Outbox(own);
    this.#sessions = new SessionBook(own, options.instance, (packets) =>
      this.#outbox.forget(packets),
    );
    this.#messaging = new Messaging(own, this.#sessions, this.#outbox);
    this.#dealings = new Dealings(own);
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
    checkInstance(options.instance);
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
      const address = mindAddress(contentId(signed));
      const keys = await Mind.#everyday(options);
      try {
        const key = publisher(address, keys.operational, undefined, signed);
        const sign = (asking: Asking): Promise<Asking> =>
          key === undefined
            ? Promise.resolve(asking)
            : signedAsking(asking, key, clock.now(), options.randomness ?? systemRandomness);
        const { resolved, published } = await publishAndConfirm(
          options,
          lookup,
          address,
          [signed],
          sign,
        );
        await control.published(signed);
        await keystore.setMind(address);
        const mind = new Mind(options, lookup, keys, resolved);
        mind.#published = [...published, ...(await mind.#publishing.bring())];
        return mind;
      } catch (error) {
        keys.operational.lock();
        keys.agreement.lock();
        throw error;
      }
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
    checkInstance(options.instance);
    const lookup = new Lookup(options);
    const resolved = await lookup.resolve(mind);
    return new Mind(options, lookup, await Mind.#everyday(options), resolved);
  }

  /** Unlocks the keys of everyday work: both, or neither. */
  static async #everyday(options: MindOptions): Promise<Everyday> {
    const operational = await options.keystore.unlock("operational", options.lock);
    try {
      return { operational, agreement: await options.keystore.unlock("agreement", options.lock) };
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

  /**
   * What each service said when the mind last published: the resolvers the
   * client trusts, and the mind's homes. A method that publishes succeeds
   * when enough of them took what was published, and this tells which did
   * not.
   */
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
   * Locks the mind's keys, and stops what it listens to. The mind signs
   * nothing more: open it again for that.
   */
  close(): void {
    // A socket that stayed open would hear what it could not acknowledge: that takes a key.
    for (const listening of this.#listening) void listening.close();
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
   * @param authority - What lets the proof count for another mind besides
   *   this one (core 5.2): one chain of delegations, root first, or one
   *   charter. `cosign` and the makers of records take a chain and write
   *   this for you.
   * @returns The record with the mind's proof after any it had.
   */
  async sign<T extends object>(
    record: T,
    authority?: readonly AuthorityItem[],
  ): Promise<T & { proof: Proof[] }> {
    const key = this.signingKey();
    const created = this.#clock.now();
    const said = parseTimestamp((record as { created?: unknown }).created);
    const proof = await createProof(
      record,
      {
        verificationMethod: formatKeyRef(this.address, this.state.versionId, key),
        // A proof is not dated before its record (core 5.7), whatever this clock says.
        created: formatTimestamp(said !== undefined && said > created ? said : created),
        ...(authority === undefined ? {} : { authority }),
      },
      this.#operational.signer(key),
    );
    const before = (record as { proof?: Proof[] }).proof ?? [];
    return { ...record, proof: [...before, proof] };
  }

  /** A request signed by the mind, with the key it signs records with (Layer 1, 13.3). */
  /** Layer 1, 13.3: a `Hello` for a server's challenge, signed for the origin given. */
  async #hello(challenge: string, domain: string): Promise<object> {
    const key = this.signingKey();
    const created = formatTimestamp(this.#clock.now());
    const hello = { oip: "1", type: "Hello", author: this.address, created };
    const proof = await createProof(
      hello,
      {
        verificationMethod: formatKeyRef(this.address, this.state.versionId, key),
        created,
        challenge,
        domain,
      },
      this.#operational.signer(key),
    );
    return { ...hello, proof: [proof] };
  }

  #signed(asking: Asking): Promise<Asking> {
    const key = this.signingKey();
    return signedAsking(
      asking,
      {
        keyRef: formatKeyRef(this.address, this.state.versionId, key),
        signer: this.#operational.signer(key),
      },
      this.#clock.now(),
      this.#randomness,
    );
  }

  /**
   * A request that brings the mind's log, signed with a key that a service
   * can judge by the log it holds or by the one it is brought: `publisher`
   * says which.
   */
  #signedForLog(asking: Asking): Promise<Asking> {
    // For the last event of the log, with the state the event before it left.
    let before: IdentityState | undefined;
    let key: RequestKey | undefined;
    for (const { event, state } of this.#resolved.log.entries) {
      key = publisher(this.address, this.#operational, before, event);
      before = state;
    }
    return key === undefined
      ? Promise.resolve(asking)
      : signedAsking(asking, key, this.#clock.now(), this.#randomness);
  }

  /**
   * Publishes where the mind can be reached: its next location record
   * (Layer 1, Section 15), to every resolver the client trusts and to every
   * home of the mind. A home that does not serve the mind yet takes it on
   * with this, if it admits it.
   *
   * The record names the mind's current profile, and says where its feed
   * stands as this client remembers it.
   *
   * @param fields - What the record says. What is left out stays as the
   *   mind's current record has it.
   * @returns The record, signed.
   * @throws OipError `invalid-record` if the fields make no location record;
   *   the failure of the first resolver, if none took it. `publications`
   *   says what each service answered.
   */
  publishLocation(fields: LocationFields = {}): Promise<Location> {
    return this.#publishing.location(fields);
  }

  /**
   * Publishes what the mind is and can do: a profile (Layer 1, Section 16),
   * and a location record that names it, which is what makes it the mind's
   * current profile (16.4). The profile supersedes the one before it.
   *
   * @returns The profile, signed.
   * @throws As `publishLocation` does.
   */
  publishProfile(fields: ProfileFields): Promise<Participant> {
    return this.#publishing.profile(fields);
  }

  /**
   * Puts a record on the mind's public feed (Layer 1, Section 10): signs the
   * next entry, which names the record and the proofs it has now, and
   * brings the record and the entry to the mind's homes.
   *
   * A feed has one entry at each position, and two are equivocation, which
   * cannot be taken back (10.3). So the entry is remembered before it
   * leaves (`memory`), and a call that failed is finished by the next one
   * with the same entry. Calls are taken one after another.
   *
   * The record may be another mind's: a commitment the mind is a party to,
   * say (10.2).
   *
   * @returns The entry, signed.
   * @throws OipError `forbidden` if the mind names no home; `invalid-record`
   *   for what is no record; `duplicity` if a home holds another entry at
   *   the position; the failure of the first home, if none took the entry.
   */
  publishRecord(record: object): Promise<Entry> {
    return this.#publishing.record(record);
  }

  /**
   * Sends a packet (Layer 1, Section 12): signs it, seals it to each
   * recipient unless told not to (12.6), and posts it to the first endpoint
   * of each recipient's current location record that takes it (15.3), a
   * mailbox last.
   *
   * It does not throw for a recipient that could not be reached:
   * `deliveries` says what became of the packet for each.
   *
   * With `session`, the packet is one of a session (Section 14): it takes
   * the next place in this mind's chain there, and is written down in the
   * client's memory before it leaves, so that it can be sent again to a
   * participant that missed it.
   *
   * @returns The packet, and what became of it for each recipient.
   * @throws OipError `invalid-record` if the message makes no packet;
   *   `forbidden` if the mind has no key to sign with; `not-found` if it
   *   names a session the mind is not in.
   */
  send(message: Message): Promise<Sent> {
    return this.#messaging.send(message);
  }

  /**
   * Reads the mind's mailboxes (Layer 1, 13.5): the `mailbox` endpoints of
   * its current location record, or those of its homes if it has published
   * none. Each item is judged as a packet that has arrived (12.4), sealed
   * or not, on the evidence of the client's resolvers, and removed from the
   * mailbox once it is judged.
   *
   * A packet is returned once. The client remembers what it accepted
   * (`memory`), so a packet that is found again is a duplicate, and is not
   * returned again.
   *
   * The packets of a session are returned in the order of their sender's
   * chain (14.3). One that came ahead of a packet that is missing stays in
   * the mailbox, and a `Resume` is sent to ask for what is missing (14.4).
   * A participant's `Resume` is answered: what it lacks of this mind's
   * packets is sent to it again. `sessions` says what was found and done.
   *
   * @returns The packets accepted, what was refused, and what waits.
   */
  async receive(): Promise<Inbox> {
    const inbox = await this.#messaging.receive();
    const received = [];
    for (const arrived of inbox.received) {
      // The records the packets carry are held, to be judged when they are asked about.
      this.#dealings.holdCarried(arrived.packet.content);
      const sentFor = await this.#dealings.sentFor(arrived.packet);
      received.push(sentFor === undefined ? arrived : { ...arrived, sentFor });
    }
    return { ...inbox, received };
  }

  /**
   * The packets that wait in the outbox: each did not reach a recipient,
   * for a reason that may pass, and is kept in the client's memory to be
   * tried again. `send` says so in its `deliveries`, as `queued`.
   */
  outbox(): Promise<Queued[]> {
    return this.#outbox.list();
  }

  /**
   * Tries again every packet that waits in the outbox, now. `receive` and
   * `listen` try those that are due by themselves: after 30 seconds the
   * first time, then twice as long each time, up to an hour.
   *
   * A packet is given up for a recipient that now refuses it for what it
   * is, and dropped once it has expired: nobody would accept it then.
   *
   * @returns What came of each packet.
   */
  retry(): Promise<Retried[]> {
    return this.#messaging.retry(true);
  }

  /**
   * Gives up a packet that waits in the outbox: it is not tried again.
   *
   * @param packet - The packet's content ID.
   * @returns Whether it waited.
   */
  async abandon(packet: string): Promise<boolean> {
    return (await this.#outbox.forget([packet])) > 0;
  }

  /**
   * Holds a socket open to the mind's own host (Layer 1, 13.4), so that
   * packets arrive as they are sent. The host sends what the mind's
   * mailbox holds, and then what arrives. Each record is judged as
   * `receive` judges it, and `received` is called with what was found. The
   * mind tells its host that it has a record with an acknowledgement of
   * its own, and the host keeps the record until then: a connection that
   * drops loses nothing.
   *
   * A connection that ends is opened again after a wait, which doubles
   * from one second to a minute and starts again once the host has
   * welcomed the mind. The socket is the first the mind's location record
   * names, or that of its first home.
   *
   * Closing the mind stops it.
   *
   * @returns What stops the listening, and tells when it has ended.
   * @throws TypeError if the platform has no `WebSocket` and none is given.
   */
  listen(options: ListenOptions): Listening {
    const listening = listen(
      {
        own: this.#own,
        open: this.#options.webSocket ?? platformSocket,
        sleep: this.#options.sleep ?? platformSleep,
        take: (records) => this.#messaging.take(records),
        receive: () => this.receive(),
        retry: () => this.#messaging.retry(false),
      },
      options,
    );
    // Kept until it ends, however it ends, so that closing the mind ends it.
    this.#listening.add(listening);
    const ended = (): void => {
      this.#listening.delete(listening);
    };
    listening.closed.then(ended, ended);
    return listening;
  }

  /**
   * Makes a session with other minds (Layer 1, Section 14): an unsigned
   * `Session` record that names its participants, this mind among them.
   * Nothing is sent. The first packet this mind sends in it carries the
   * record, and the other participants follow the session from then on.
   *
   * A session another mind opened needs no call: the client follows it
   * from the first packet of it that arrives.
   *
   * @param others - The other participants: 1 to 255 addresses.
   * @returns The session's ID, to send in it by, and the record.
   * @throws OipError `invalid-record` if they make no session.
   */
  openSession(others: readonly string[]): Promise<{ id: string; session: Session }> {
    return this.#sessions.open(others);
  }

  /**
   * The sessions the mind is in, as the client's memory has them: how many
   * packets it sent in each, and where the chain of each other sender
   * stands.
   */
  sessions(): Promise<SessionView[]> {
    return this.#sessions.views();
  }

  /**
   * Sends a `Resume` to the participants of a session (Layer 1, 14.4): it
   * says where each chain stands for this mind, so that each participant
   * sends again what this mind lacks of its packets. `receive` sends one by
   * itself when it finds a gap, once. This asks again.
   *
   * @returns The packet that carries it, a packet of the session like any other.
   * @throws OipError `not-found` if the mind is in no such session.
   */
  resume(session: string): Promise<Sent> {
    return this.#messaging.resume(session);
  }

  /**
   * Forgets a session: where its chains stand, and the packets this mind
   * sent in it. A packet of it that arrives later is refused, unless it
   * carries the `Session` record: then the session is followed anew.
   *
   * @returns Whether the mind was in it.
   */
  leaveSession(session: string): Promise<boolean> {
    return this.#sessions.leave(session);
  }

  /**
   * Holds a record, for the client to judge others by: a delegation a
   * proof names, a Receipt about a Commitment, a record that supersedes
   * another. A record held in several copies is one record, with the
   * proofs of them all (Layer 2, Section 2).
   *
   * What the mind signs is held, and so are the records carried by the
   * packets it accepts. They are kept while the mind is open: keep what
   * matters yourself, and hold it again.
   *
   * @returns The record's content ID.
   * @throws OipError `invalid-record` for what is no record.
   */
  hold(record: unknown): string {
    return this.#dealings.hold(record);
  }

  /** The records the mind holds, each as the copy with every proof seen of it. */
  records(): OipRecord[] {
    return this.#dealings.held();
  }

  /**
   * Grants another mind part of this mind's authority (Layer 1, Section
   * 11): signs a `Delegation`. The delegate then signs records for this
   * mind by naming the delegation in its proof.
   *
   * Give it to the delegate, in a packet or by publishing it. Nothing
   * else needs it until a proof names it.
   *
   * @returns The delegation, signed.
   * @throws OipError `invalid-record` if the grant makes no delegation:
   *   a command that is reserved, a policy that is none, the mind itself
   *   as its delegate.
   */
  delegate(grant: Grant): Promise<Delegation> {
    return this.#dealings.delegate(grant);
  }

  /**
   * Passes on to another mind what this mind was delegated, or less
   * (Layer 1, 11.4): signs the next delegation of a chain.
   *
   * @param chain - The chain that ends with a delegation to this mind.
   * @throws OipError `forbidden` if the chain does not end so, or the
   *   grant asks for more than the chain gives: a command it does not
   *   cover, or a later expiry.
   */
  subDelegate(chain: readonly Delegation[], grant: Grant): Promise<Delegation> {
    return this.#dealings.subDelegate(chain, grant);
  }

  /**
   * Takes a delegation back (Layer 1, 11.5): signs a `Revocation`, and
   * puts it on the mind's feed if the mind has a home. It takes effect
   * from when a verifier first sees it: what the delegate signed before
   * stands.
   *
   * @returns The revocation, signed.
   * @throws OipError `forbidden` if the delegation is another mind's.
   */
  async revoke(delegation: Delegation): Promise<Revocation> {
    const revocation = await this.#dealings.revoke(delegation);
    if (this.state.homes.length > 0) await this.publishRecord(revocation);
    return revocation;
  }

  /**
   * States what the mind wants (Layer 2, 4.1): signs an `Intent`.
   *
   * @param acting - The chain of delegations by which this mind signs it
   *   for another, named in `fields.author`.
   */
  intent(fields: Fields<Intent>, acting?: Acting): Promise<Intent> {
    return this.#dealings.make<Intent>("Intent", fields, acting);
  }

  /** States what the mind offers (Layer 2, 4.2): signs an `Offer`. */
  offer(fields: Fields<Offer>, acting?: Acting): Promise<Offer> {
    return this.#dealings.make<Offer>("Offer", fields, acting);
  }

  /**
   * Writes a `Commitment` (Layer 2, Section 5) and signs it. It is
   * accepted once it counts for its author and for every party that is
   * required (7.3): the others add their proofs with `cosign`.
   *
   * The author is a party, or signs for one: a delegate that writes a
   * Commitment for its principal is its author, and need not be a party.
   */
  commitment(fields: Fields<Commitment>, acting?: Acting): Promise<Commitment> {
    return this.#dealings.make<Commitment>("Commitment", fields, acting);
  }

  /** Says what became of a record, usually a Commitment (Layer 2, 6.1): signs a `Receipt`. */
  receipt(fields: Fields<Receipt>, acting?: Acting): Promise<Receipt> {
    return this.#dealings.make<Receipt>("Receipt", fields, acting);
  }

  /**
   * Adds the mind's proof to a record another mind made: a Commitment it
   * is a party to. The record's content ID does not change (core 3.1).
   *
   * Read what you sign. A record binds whoever it counts for.
   *
   * @param acting - The chain of delegations by which this mind signs it for another.
   * @returns The record with the proofs it had and this mind's.
   */
  cosign<T extends object>(record: T, acting?: Acting): Promise<T> {
    return this.#dealings.cosign(record, acting);
  }

  /**
   * Founds a collective (Layer 1, Section 9): drafts its genesis, and signs
   * it as one of its founding members. The collective exists once every
   * founder has signed (9.2) and the genesis is published: give the event
   * to each of the others for `signEvent`, and then `publishLog`.
   *
   * @returns The genesis, with this mind's proof.
   * @throws OipError `invalid-record` if the fields make no genesis, such
   *   as a threshold that is no majority; `forbidden` if this mind is not
   *   among the members, or the keystore holds none of its invocation keys.
   */
  foundCollective(fields: NewCollective, options: MemberOptions): Promise<IdentityEvent> {
    if (!fields.members.includes(this.address)) {
      return Promise.reject(
        new OipError("forbidden", "a collective is founded by its members: name this mind", {
          clause: "L1 9.2",
        }),
      );
    }
    // What makes no genesis is found out when it is signed: a draft is checked by nothing.
    const genesis = draftGenesis(formatTimestamp(this.#clock.now()), {
      kind: "collective",
      controller: { members: [...fields.members], threshold: fields.threshold },
      ...(fields.homes === undefined ? {} : { homes: [...fields.homes] }),
      ...(fields.alsoKnownAs === undefined ? {} : { alsoKnownAs: [...fields.alsoKnownAs] }),
    });
    return this.signEvent(genesis, options);
  }

  /**
   * Drafts the next identity event of a collective this mind is a member
   * of, an `Update`, and signs it as a member (Layer 1, 9.3). It takes
   * effect once the threshold of the members has signed, and every member
   * that is new, and the log is published.
   *
   * @returns The event, with this mind's proof.
   * @throws OipError `forbidden` if the collective is retired, shows
   *   duplicity, or is no collective. What `resolve` throws.
   */
  async changeCollective(
    collective: string,
    changes: CollectiveChanges,
    options: MemberOptions,
  ): Promise<IdentityEvent> {
    const { state, duplicitous } = await this.#lookup.resolve(collective);
    const { controller } = state;
    if (state.retired || duplicitous || controller.kind !== "member") {
      throw new OipError("forbidden", "that mind's log is not a collective's to extend", {
        clause: "L1 9.3",
      });
    }
    const now = this.#clock.now();
    const membership = changes.members !== undefined || changes.threshold !== undefined;
    // Not earlier than the event before it (Layer 1, 3.2), whatever this clock says.
    const created = formatTimestamp(now > state.created ? now : state.created);
    const event = draftUpdate(state, created, {
      ...(membership
        ? {
            controller: {
              members: [...(changes.members ?? controller.members)],
              threshold: changes.threshold ?? controller.threshold,
            },
          }
        : {}),
      ...(changes.homes === undefined ? {} : { homes: [...changes.homes] }),
      ...(changes.alsoKnownAs === undefined ? {} : { alsoKnownAs: [...changes.alsoKnownAs] }),
    });
    return this.signEvent(event, options);
  }

  /**
   * Signs an identity event of a collective as one of its members, with
   * one of this mind's invocation keys (Layer 1, 9.4). The proofs the
   * event has stay.
   *
   * The keystore remembers which event the key signed for each position of
   * each collective's log, and signs no other for that position: two would
   * be duplicity, and would name this mind.
   *
   * Read what you sign: an event changes who the collective is.
   *
   * @returns The event with the proofs it had and this mind's.
   * @throws OipError `invalid-record` if it is no identity event that can
   *   be signed so; `forbidden` if the keystore holds none of the mind's
   *   invocation keys. KeystoreError `already-signed` if the key signed
   *   another event for the position.
   */
  async signEvent(
    event: IdentityEvent | Unsigned<IdentityEvent>,
    options: MemberOptions,
  ): Promise<IdentityEvent> {
    await this.refresh();
    const { proof: before = [], ...unsigned } = event as Unsigned<IdentityEvent> & {
      proof?: Proof[];
    };
    // One proof of a member is enough, and a second by the same key says nothing more.
    const mine = before.some((proof) => proof.verificationMethod.startsWith(`${this.address}?`));
    if (mine) return event as IdentityEvent;
    const invocation = await this.#options.keystore.unlock("invocation", options.invocation);
    try {
      const key = this.state.invocation.find((candidate) => invocation.has(candidate));
      if (key === undefined) {
        throw new OipError(
          "forbidden",
          "the keystore holds none of the mind's current invocation keys",
          { clause: "L1 6.4" },
        );
      }
      const now = this.#clock.now();
      const said = parseTimestamp((unsigned as { created?: unknown }).created);
      const signed = await invocation.sign(
        unsigned,
        { member: this.address, publicKey: key, versionId: this.state.versionId },
        // A proof is not dated before its event (core 5.7), whatever this clock says.
        formatTimestamp(said !== undefined && said > now ? said : now),
      );
      return { ...unsigned, proof: [...before, ...signed.proof] } as unknown as IdentityEvent;
    } catch (error) {
      if (error instanceof KeystoreError && error.code === "argument") throw asInvalid(error);
      throw error;
    } finally {
      invocation.lock();
    }
  }

  /**
   * Publishes an identity log this mind has a copy of, such as that of a
   * collective it is a member of, to every resolver the client trusts, and
   * resolves it. Anyone may publish a log: it is evidence, and stands by
   * its own signatures.
   *
   * The log is verified here first, as any verifier would, with the logs
   * of the members it names fetched afresh.
   *
   * @param events - The log, from its genesis.
   * @returns The mind the log is of, as the resolvers now serve it.
   * @throws OipError `invalid-record` if it is no log, or does not verify:
   *   a founder has not signed, or the threshold is not met. What
   *   publishing an identity event of one's own throws.
   */
  async publishLog(events: readonly object[]): Promise<Resolved> {
    // The logs of the members it names, afresh: its events are judged by them. A member is
    // named by an address, and what names anything else is found out below, by the judge.
    const members = new Set<string>();
    for (const event of events) {
      const named = (event as { controller?: { members?: unknown } }).controller?.members;
      for (const member of Array.isArray(named) ? (named as unknown[]) : []) {
        if (typeof member === "string" && mindId(member) !== undefined) members.add(member);
      }
    }
    // The log is seen now, and its members' logs are fetched after: a log held from before
    // an event was first seen does not judge the proofs on it (core 9.4).
    const now = this.#clock.now();
    for (const member of members) await this.#lookup.resolve(member);
    const own = verifyLog(events, {
      // Each event is seen now at the latest, unless a resolver saw it before.
      evidence: earliestEvidence(this.#lookup.view.evidence, {
        eventSeen: () => now,
        proofSeen: () => undefined,
      }),
      asOf: now,
      memberLog: (member) => this.#lookup.view.log(member),
    });
    if (!own.ok) {
      const [first] = own.issues;
      throw new OipError("invalid-record", `the log does not verify: ${first.message}`, {
        clause: first.clause,
        issues: own.issues,
      });
    }
    const address = own.value.mind;
    const { resolved, published } = await publishAndConfirm(
      this.#options,
      this.#lookup,
      address,
      events,
      (asking) => this.#signed(asking),
    );
    this.#published = published;
    return resolved;
  }

  /**
   * Writes a collective's charter (Layer 2, 6.2), and signs it as a member.
   * It is the collective's once the threshold of its members has signed
   * it, each with `cosign`, and it is in force from then.
   *
   * A charter names roles and what each may do. A member assigned to a
   * role signs records for the collective with `{ charter }` in place of a
   * chain of delegations. Give a charter an `expires`: it bounds when it
   * can still be signed.
   *
   * @param collective - The collective's address.
   */
  charter(collective: string, fields: Omit<Fields<Charter>, "author">): Promise<Charter> {
    return this.#dealings.make<Charter>("Collective", { ...fields, author: collective }, undefined);
  }

  /**
   * Whether a record counts for a mind (Layer 2, Section 7): by the mind's
   * own key, or by a delegate's proof whose chain of delegations covers
   * the record. The logs of the minds the record names are fetched afresh
   * first.
   *
   * @param mind - Default: this mind.
   */
  countsFor(record: unknown, mind: string = this.address): Promise<boolean> {
    return this.#dealings.countsFor(record, mind);
  }

  /**
   * The status of an Intent, an Offer, a Commitment or a charter (Layer 2,
   * Section 8), from the records the mind holds and the present time.
   * Another verifier, holding other records, may compute another.
   *
   * @throws OipError `invalid-record` for a record that has no status.
   */
  statusOf(record: unknown): Promise<Status> {
    return this.#dealings.status(record);
  }

  /**
   * Brings the mind's homes its identity log, with its current location
   * record and profile: what a home serves for it at
   * `/.well-known/oip/mind/m` (Layer 1, 13.1). Every identity change does
   * this by itself. Call it for a home that could not be reached then.
   *
   * A mind that has retired brings its log alone, signed as it was before
   * it retired. A home takes that for as long as it has not learned of the
   * retirement, and so learns of it.
   *
   * @returns What each home said.
   */
  async bringHomes(): Promise<readonly Publication[]> {
    await this.refresh();
    return (this.#published = await this.#publishing.bring());
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
   * Changes the hosts that serve the mind (Layer 1, 15.4).
   *
   * 1. Each host that is new is brought everything a home serves: the
   *    mind's identity log, its location record and profile, and its feed
   *    with every record the feed lists, read from the homes it has. A
   *    host that will not take the mind on stops the move here, before
   *    anything of the mind has changed.
   * 2. An `Update` names the new homes. If a host that is left held one of
   *    the mind's operational keys, name the key in `revoke`: the same
   *    event removes it, and a location record that host signs counts no
   *    longer. A mind MUST remove such a key when it moves away.
   * 3. A location record gives the mind's endpoints at its new homes.
   *
   * @param homes - The HTTPS origins that serve the mind from now on.
   * @param options.revoke - Operational keys to revoke with the move.
   * @returns The mind's identity state after the move.
   * @throws What `Lookup.feed` and `update` throw, and the failure of a
   *   new host that did not take the mind on or its feed. `forbidden` if
   *   `revoke` would leave the mind no operational key.
   */
  async moveHomes(
    homes: readonly string[],
    options: ControlOptions & { readonly revoke?: readonly string[] },
  ): Promise<IdentityState> {
    const revoke = options.revoke ?? [];
    const kept = this.#entries("keys").filter((entry) => !revoke.includes(entry.key));
    if (kept.length === 0) {
      throw new OipError(
        "forbidden",
        "that would leave the mind no operational key: add another before these are revoked",
        { clause: "L1 3.7" },
      );
    }
    await this.#publishing.prepare(homes);
    const state = await this.update(
      {
        homes,
        ...(revoke.length === 0 ? {} : { keys: kept, revoked: revoke.map((key) => ({ key })) }),
      },
      options,
    );
    for (const key of revoke) if (this.#operational.has(key)) await this.#operational.remove(key);
    await this.publishLocation({ endpoints: homeEndpoints(this.address, homes) });
    return state;
  }

  /**
   * Acknowledges a child mind with a `Fork` (Layer 1, 3.8), which records
   * the lineage in this mind's own log.
   *
   * @param child - The child's address.
   * @param options.terms - What the child received, in the parent's words.
   * @param options.changes - What else changes with the event, as for `update`.
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
      const committed = state.controller.next;
      await destroyUseless(control, resolved, committed);
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
    let published: readonly Publication[] | undefined;
    if (!before.some((held) => contentId(held) === id)) {
      const key = publisher(this.address, this.#operational, resolved.state, event);
      const after = await publishAndConfirm(
        this.#options,
        this.#lookup,
        this.address,
        [...before, signed ?? (await control.sign(event))],
        (asking) =>
          key === undefined
            ? Promise.resolve(asking)
            : signedAsking(asking, key, this.#clock.now(), this.#randomness),
      );
      ({ published, resolved } = after);
    }
    await control.published(event);
    this.#resolved = resolved;
    // The homes serve the log too, and judge the mind's requests by it.
    if (published !== undefined) {
      this.#published = [...published, ...(await this.#publishing.bring())];
    }
    return resolved;
  }
}

/**
 * The key that signs the request that publishes a log (Layer 1, 17.3): a
 * key the log's last event leaves the mind with, that the keystore holds,
 * at the version that event makes. A resolver judges the request against
 * the log it is given, and under the current-state rule (6.1).
 *
 * After a `Retire` no key of the mind signs. The request is then signed as
 * the mind was before it, which a resolver that holds the log so far can
 * still judge.
 *
 * @returns `undefined` if the keystore holds no such key: the request goes
 *   unsigned, which a resolver that asks for no authentication takes.
 */
function publisher(
  mind: string,
  operational: OperationalKeys,
  before: IdentityState | undefined,
  event: Unsigned<IdentityEvent>,
): RequestKey | undefined {
  const held = (keys: readonly string[]): string | undefined =>
    keys.find((candidate) => operational.has(candidate));
  const earlier = before?.keys ?? [];
  // The keys the event leaves the mind with: those it lists, or else those it had.
  const listed = (event as { keys?: readonly KeyEntry[] }).keys?.map((entry) => entry.key);
  const key = event.type === "Retire" ? undefined : held(listed ?? earlier);
  if (key !== undefined) {
    // A genesis has no `seq`: it is the event at 0.
    const version = formatVersionId((event as { seq?: number }).seq ?? 0, contentId(event));
    return { keyRef: formatKeyRef(mind, version, key), signer: operational.signer(key) };
  }
  const old = held(earlier);
  if (before === undefined || old === undefined) return undefined;
  return { keyRef: formatKeyRef(mind, before.versionId, old), signer: operational.signer(old) };
}

/** What a caller gave that makes no record: its mistake, as the protocol names it. */
function asInvalid(error: Error): OipError {
  return new OipError("invalid-record", error.message, { clause: "L1 3", cause: error });
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
async function destroyUseless(
  control: ControlKeys,
  resolved: Resolved,
  committed: readonly string[],
): Promise<void> {
  const revealed = new Set<string>();
  for (const { event } of resolved.log.entries) {
    // Every event of a key-controlled mind's log names the control keys it reveals (Layer 1, 3.4).
    const { keys } = (event as unknown as { controller: { keys: readonly string[] } }).controller;
    for (const key of keys) revealed.add(key);
  }
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
  sign: (asking: Asking) => Promise<Asking>,
): Promise<{ resolved: Resolved; published: Publication[] }> {
  const id = mind.slice("did:oip:".length);
  const body = recordBody({ oip: "1", type: "Bundle", mind, log });
  const failures: (OipError | TransportError)[] = [];
  const published = await Promise.all(
    options.resolvers.map(async (origin): Promise<Publication> => {
      try {
        const asking = await sign({ method: "PUT", url: `${origin}/oip/v1/resolve/${id}`, body });
        await askJson(asking, options);
        return { service: "resolver", origin, taken: true };
      } catch (error) {
        if (!(error instanceof OipError || error instanceof TransportError)) throw error;
        failures.push(error);
        return {
          service: "resolver",
          origin,
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
