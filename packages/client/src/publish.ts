// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What a mind publishes of itself: where it can be reached (Layer 1,
 * Section 15), what it is and can do (16), and the records it stands by in
 * public, on its feed (10).
 *
 * A location record and a profile go to every resolver the client trusts
 * and to every home of the mind. A feed lives at the homes.
 *
 * Layer 1 says what a host serves for a mind, and leaves open how the mind
 * brings it. The requests made of a home here are those of the reference
 * host, `@oip/host`.
 */

import {
  contentId,
  formatRecordRef,
  formatTimestamp,
  type JsonObject,
  mindId,
  OipError,
} from "@oip/core";
import { judgeRecord } from "@oip/identity";
import {
  type Entry,
  type JsonValue,
  type Location,
  type Participant,
  type Proof,
  validateRecordOfType,
} from "@oip/schema";

import { accepted, type Clock, type Lookup, type Resolved } from "./lookup.ts";
import type { Memory, Remembered } from "./memory.ts";
import {
  type Asking,
  askJson,
  recordBody,
  TransportError,
  type TransportOptions,
} from "./transport.ts";

/** An endpoint of a location record (Layer 1, 15.1). */
export type Endpoint = Location["endpoints"][number];

/**
 * What a location record says (Layer 1, 15.1). What is left out stays as
 * the mind's current record has it.
 */
export interface LocationFields {
  /**
   * Where the mind takes packets. Default: as its current record has them,
   * or else `homeEndpoints` of its homes.
   */
  readonly endpoints?: readonly Endpoint[];
  /** How long the record is good for, in seconds: 60 to 86 400. Default: as before, or else an hour. */
  readonly ttl?: number;
  /** Whether the mind takes packets now. Default: as before, or else `active`. */
  readonly status?: "active" | "paused" | "migrating";
  /** When a mind that is paused means to be back. It is not carried over from the record before. */
  readonly resumeAfter?: string;
}

/** What a profile says (Layer 1, 16.1). Its `kind` is the mind's own, and is not given. */
export interface ProfileFields {
  /** The mind's name, of at most 128 characters. Anyone can take any name: it identifies nobody. */
  readonly name: string;
  /** What the mind is, in at most 1024 characters. */
  readonly summary?: string;
  /** What the mind can do (16.2). */
  readonly capabilities?: Participant["capabilities"];
  /** The minds it acts for, each with the delegation that says so. */
  readonly actsFor?: Participant["actsFor"];
  /** Its other interfaces, by the name of their protocol: `a2a`, `mcp`, `openapi`. */
  readonly interfaces?: Readonly<Record<string, string>>;
  /** The languages it speaks, as BCP 47 tags. */
  readonly languages?: readonly string[];
  /** Credentials about the mind, as record references or URLs. */
  readonly attestations?: readonly string[];
}

/** What a service said when the mind published to it. */
export interface Publication {
  /** What the service is to the mind: a resolver the client trusts, or one of the mind's homes. */
  readonly service: "resolver" | "home";
  /** The service's origin. */
  readonly origin: string;
  /** Whether it took what was published. */
  readonly taken: boolean;
  /** Why it did not: the code of its problem, or the failure of the transport. */
  readonly failure?: string;
}

/** How long a location record is good for, unless the mind says otherwise: an hour. */
export const DEFAULT_TTL = 3600;

/**
 * The endpoints of a mind at the homes that serve it, as the reference host
 * lays them out: at each home an `https` endpoint, which has the inbox and
 * the WebSocket, and a `mailbox`. A home named earlier is tried earlier.
 *
 * @throws OipError `invalid-record` if the address is none.
 */
export function homeEndpoints(mind: string, homes: readonly string[]): Endpoint[] {
  const id = idOf(mind);
  return homes.flatMap((home, index) => [
    { binding: "https", url: `${home}/oip/v1/minds/${id}`, priority: index },
    { binding: "mailbox", url: `${home}/oip/v1/minds/${id}/mailbox`, priority: index },
  ]);
}

/** What the parts of a client need of the mind they work for. */
export interface Own {
  /** The mind's address. */
  readonly address: string;
  /** How services are talked to. */
  readonly transport: TransportOptions;
  /** The resolvers the client trusts. */
  readonly resolvers: readonly string[];
  readonly clock: Clock;
  readonly lookup: Lookup;
  readonly memory: Memory;
  /** The mind as it was last resolved. */
  resolved(): Resolved;
  /** Resolves the mind afresh. */
  refresh(): Promise<Resolved>;
  /** Signs a record as the mind. */
  sign<T extends object>(record: T): Promise<T & { proof: Proof[] }>;
  /** Signs a request as the mind (Layer 1, 13.3). */
  signed(asking: Asking): Promise<Asking>;
  /**
   * Signs a request that brings the mind's log, with a key a service can
   * judge by the log it holds or by the log it is brought (Layer 1, 17.3):
   * after a `Retire`, as the mind was before it.
   */
  signedForLog(asking: Asking): Promise<Asking>;
  /** Keeps what each service said, for `Mind.publications`. */
  told(publications: readonly Publication[]): void;
}

/** A failure of one service to take what was published. */
type Failure = OipError | TransportError;

/** What came of publishing to one service. */
interface Offered {
  readonly publication: Publication;
  readonly failure?: Failure;
}

/** Where a feed stands: its last entry. */
interface Head {
  readonly seq: number;
  readonly id: string;
}

/** What a client remembers of its feed. */
interface FeedState {
  /** The last entry a home took. None before the first. */
  readonly head?: Head;
  /** An entry that is signed and that no home is known to have taken, with the record it publishes. */
  readonly pending?: { readonly entry: Entry; readonly record: JsonObject };
}

/** The names of what is remembered. */
const FEED = "client-feed";
const LOCATION = "client-location";

/** A count as it is remembered, or `undefined` if what is stored is none. */
const count = (value: JsonValue | undefined): number | undefined =>
  typeof value === "number" && Number.isSafeInteger(value) ? value : undefined;

/** A value that is an object, or `undefined` if it is anything else. */
const objectOf = (value: JsonValue | undefined): JsonObject | undefined =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;

/** The head of a feed as it is remembered, or `undefined` if what is stored is none. */
function headOf(value: JsonValue | undefined): Head | undefined {
  const stored = objectOf(value);
  if (stored === undefined) return undefined;
  const seq = count(stored["seq"]);
  const id = stored["id"];
  return seq === undefined || seq < 0 || typeof id !== "string" ? undefined : { seq, id };
}

/** What is remembered of a feed, or `undefined` if what is stored is not that. */
function feedState(stored: JsonObject): FeedState | undefined {
  const head = stored["head"] === undefined ? undefined : headOf(stored["head"]);
  if (stored["head"] !== undefined && head === undefined) return undefined;
  if (stored["pending"] === undefined) return head === undefined ? {} : { head };
  const kept = objectOf(stored["pending"]);
  if (kept === undefined) return undefined;
  const entry = validateRecordOfType("Entry", kept["entry"]);
  const record = objectOf(kept["record"]);
  if (!entry.ok || record === undefined) return undefined;
  const pending = { entry: entry.value, record };
  return head === undefined ? { pending } : { head, pending };
}

/** The identifier of a mind: its address without `did:oip:`. */
function idOf(mind: string): string {
  const id = mindId(mind);
  if (id === undefined) {
    throw new OipError("invalid-record", "that is not the address of a mind", { clause: "L1 2" });
  }
  return id;
}

/** The code of a failure: of the service's problem, or of the transport. */
const codeOf = (failure: Failure): string =>
  failure instanceof OipError ? failure.code : failure.failure;

/** What a mind publishes of itself. */
export class Publishing {
  readonly #own: Own;
  /** The writes to the feed, one after another: a feed has a single writer (Layer 1, 10.3). */
  #writing: Promise<unknown> = Promise.resolve();

  constructor(own: Own) {
    this.#own = own;
  }

  /** Publishes a location record: see `Mind.publishLocation`. */
  async location(fields: LocationFields): Promise<Location> {
    return this.#location(await this.#own.refresh(), fields, undefined);
  }

  /** Publishes a profile, and a location record that names it: see `Mind.publishProfile`. */
  async profile(fields: ProfileFields): Promise<Participant> {
    const own = this.#own;
    const resolved = await own.refresh();
    const before = resolved.participant;
    const signed = await own.sign({
      oip: "1",
      type: "Participant",
      author: own.address,
      created: formatTimestamp(own.clock.now()),
      name: fields.name,
      kind: resolved.state.kind,
      ...(fields.summary === undefined ? {} : { summary: fields.summary }),
      ...(fields.capabilities === undefined ? {} : { capabilities: fields.capabilities }),
      ...(fields.actsFor === undefined ? {} : { actsFor: fields.actsFor }),
      ...(fields.interfaces === undefined ? {} : { interfaces: fields.interfaces }),
      ...(fields.languages === undefined ? {} : { languages: fields.languages }),
      ...(fields.attestations === undefined ? {} : { attestations: fields.attestations }),
      ...(before === undefined ? {} : { supersedes: formatRecordRef(own.address, before.id) }),
    });
    const profile = accepted(
      validateRecordOfType("Participant", signed),
      "invalid-record",
      "that is no profile",
    );
    await this.#location(resolved, {}, profile);
    return profile;
  }

  /**
   * Signs the mind's next location record and publishes it, with the
   * profile it names, to the resolvers and to the mind's homes.
   */
  async #location(
    resolved: Resolved,
    fields: LocationFields,
    profile: Participant | undefined,
  ): Promise<Location> {
    const own = this.#own;
    const before = resolved.location?.record;
    const remembered = await own.memory.get(LOCATION, (stored) => count(stored["seq"]));
    // Higher than every record of the mind's that counts, and than any this client signed (15.1).
    const seq = Math.max(remembered.value ?? -1, before?.seq ?? -1) + 1;
    const held = profile ?? resolved.participant?.record;
    const named = held === undefined ? before?.participant : contentId(held);
    const feed = (await own.memory.get(FEED, feedState)).value?.head;
    const pointer = feed === undefined ? before?.feed : { seq: feed.seq, head: feed.id };
    const signed = await own.sign({
      oip: "1",
      type: "Location",
      author: own.address,
      seq,
      created: formatTimestamp(own.clock.now()),
      ttl: fields.ttl ?? before?.ttl ?? DEFAULT_TTL,
      status: fields.status ?? before?.status ?? "active",
      ...(fields.resumeAfter === undefined ? {} : { resumeAfter: fields.resumeAfter }),
      endpoints: [
        ...(fields.endpoints ??
          before?.endpoints ??
          homeEndpoints(own.address, resolved.state.homes)),
      ],
      ...(named === undefined ? {} : { participant: named }),
      ...(pointer === undefined ? {} : { feed: pointer }),
    });
    const location = accepted(
      validateRecordOfType("Location", signed),
      "invalid-record",
      "that is no location record",
    );
    // Remembered before it leaves: no other record is signed with this number.
    await own.memory.put(LOCATION, { seq }, remembered.version);
    const offered = await this.#bundle(resolved, {
      location,
      ...(held === undefined ? {} : { participant: held }),
    });
    own.told(offered.map(({ publication }) => publication));
    const resolvers = offered.filter(({ publication }) => publication.service === "resolver");
    const [refused] = resolvers.flatMap(({ failure }) => (failure === undefined ? [] : [failure]));
    if (refused !== undefined && resolvers.every(({ publication }) => !publication.taken)) {
      throw refused;
    }
    await own.refresh();
    return location;
  }

  /**
   * Brings the mind's homes its identity log, with its current location
   * record and profile: what a home serves at `/.well-known/oip/mind/m`
   * (Layer 1, 13.1). A home that does not serve the mind yet takes it on, if
   * it admits it.
   *
   * A retired mind has no location record or profile that counts, and
   * brings its log alone, with a request signed as it was before it
   * retired: a home that holds its log so far can judge that.
   *
   * @returns What each home said.
   */
  async bring(): Promise<Publication[]> {
    const own = this.#own;
    const resolved = own.resolved();
    const others = resolved.state.retired
      ? {}
      : {
          ...(resolved.location === undefined ? {} : { location: resolved.location.record }),
          ...(resolved.participant === undefined
            ? {}
            : { participant: resolved.participant.record }),
        };
    const offered = await this.#bundle(resolved, others, false, (asking) =>
      own.signedForLog(asking),
    );
    return offered.map(({ publication }) => publication);
  }

  /** Offers a bundle of the mind's log and other records to the mind's homes, and to the resolvers. */
  #bundle(
    resolved: Resolved,
    others: { location?: Location; participant?: Participant },
    resolvers = true,
    sign: (asking: Asking) => Promise<Asking> = (asking) => this.#own.signed(asking),
  ): Promise<Offered[]> {
    const own = this.#own;
    const id = idOf(own.address);
    const body = recordBody({
      oip: "1",
      type: "Bundle",
      mind: own.address,
      log: resolved.log.entries.map((entry) => entry.event),
      ...others,
    });
    return Promise.all([
      ...(resolvers ? own.resolvers : []).map((origin) =>
        this.#offer(
          "resolver",
          origin,
          { method: "PUT", url: `${origin}/oip/v1/resolve/${id}`, body },
          sign,
        ),
      ),
      ...resolved.state.homes.map((origin) =>
        this.#offer(
          "home",
          origin,
          { method: "PUT", url: `${origin}/oip/v1/minds/${id}`, body },
          sign,
        ),
      ),
    ]);
  }

  /** Makes a signed request of a service, and says what came of it. */
  async #offer(
    service: Publication["service"],
    origin: string,
    asking: Asking,
    sign: (asking: Asking) => Promise<Asking> = (unsigned) => this.#own.signed(unsigned),
  ): Promise<Offered> {
    try {
      await askJson(await sign(asking), this.#own.transport);
      return { publication: { service, origin, taken: true } };
    } catch (error) {
      if (!(error instanceof OipError || error instanceof TransportError)) throw error;
      return {
        publication: { service, origin, taken: false, failure: codeOf(error) },
        failure: error,
      };
    }
  }

  /** Puts a record on the mind's feed: see `Mind.publishRecord`. */
  record(record: object): Promise<Entry> {
    const next = this.#writing.then(() => this.#append(record));
    this.#writing = next.catch(() => undefined);
    return next;
  }

  /** Signs the next entry of the feed for a record, and brings both to the mind's homes. */
  async #append(record: object): Promise<Entry> {
    const own = this.#own;
    const resolved = await own.refresh();
    if (resolved.state.homes.length === 0) {
      throw new OipError(
        "forbidden",
        "the mind names no home that could serve its feed: give it one with `update`",
        { clause: "L1 13.1" },
      );
    }
    const judged = accepted(judgeRecord(record), "invalid-record", "that is no record");
    let state = await this.#feed(resolved);
    // An entry that was signed and may not have been taken comes first: its position has no other.
    if (state.value.pending !== undefined) {
      state = await this.#finish(state.value.pending, state.version, resolved);
    }
    const { head } = state.value;
    const signed = await own.sign({
      oip: "1",
      type: "Entry",
      author: own.address,
      seq: head === undefined ? 0 : head.seq + 1,
      ...(head === undefined ? {} : { prev: head.id }),
      created: formatTimestamp(own.clock.now()),
      object: contentId(judged.record),
      objectType: judged.record.type,
      // The proofs the record has now, so that evidence for the entry is evidence for them (10.1).
      ...(judged.proofs.length === 0 ? {} : { proofs: judged.proofs.map((proof) => proof.digest) }),
    });
    const entry = accepted(
      validateRecordOfType("Entry", signed),
      "invalid-record",
      "that is no entry",
    );
    const pending = { entry, record: record as JsonObject };
    // Remembered before it leaves: after a stop this entry is brought again, and no other is
    // signed for its position (10.3).
    const version = await own.memory.put(
      FEED,
      { ...(head === undefined ? {} : { head: { ...head } }), pending },
      state.version,
    );
    await this.#finish(pending, version, resolved);
    return entry;
  }

  /**
   * Where the feed stands: as the client remembers it, or else as the
   * mind's homes serve it.
   */
  async #feed(resolved: Resolved): Promise<Remembered<FeedState> & { value: FeedState }> {
    const own = this.#own;
    const remembered = await own.memory.get(FEED, feedState);
    if (remembered.value !== undefined) return { ...remembered, value: remembered.value };
    // Nothing is remembered: a first entry, or a new device. The homes are asked.
    let last: Head | undefined;
    try {
      const { feed } = await own.lookup.feed(own.address);
      if (feed.equivocation.length > 0) {
        throw new OipError(
          "duplicity",
          "the mind's feed holds two valid entries at one position: it is verified no further, and goes no further",
          { clause: "L1 10.3" },
        );
      }
      const end = feed.entries.at(-1);
      last = end === undefined ? undefined : { seq: end.entry.seq, id: end.id };
    } catch (error) {
      // No home serves the mind yet: it has no feed.
      if (!(error instanceof OipError && error.code === "not-found")) throw error;
    }
    // What the mind's own location record says of its feed is a floor: homes that serve less
    // are withholding, or have lost, entries this mind signed.
    const said = resolved.location?.record.feed;
    if (said !== undefined && (last === undefined || last.seq < said.seq)) {
      throw new OipError(
        "not-found",
        "the homes serve less of the feed than the mind's location record says there is: the next entry cannot be placed",
        { clause: "L1 10.3" },
      );
    }
    return { value: last === undefined ? {} : { head: last }, version: undefined };
  }

  /**
   * Brings an entry that is pending, and its record, to the mind's homes.
   * Once a home has taken it, it is the head of the feed.
   *
   * @param remembered - The version of what is remembered, which holds the entry as pending.
   * @throws OipError `duplicity` if a home holds another entry at its
   *   position; the failure of the first home, if none took it. The entry
   *   stays pending, and the next call brings it again.
   */
  async #finish(
    pending: NonNullable<FeedState["pending"]>,
    remembered: string | undefined,
    resolved: Resolved,
  ): Promise<Remembered<FeedState> & { value: FeedState }> {
    const own = this.#own;
    const { entry, record } = pending;
    const id = idOf(own.address);
    const bring = async (home: string): Promise<Offered> => {
      const kept = await this.#offer("home", home, {
        method: "PUT",
        url: `${home}/oip/v1/minds/${id}/obj/${entry.object}`,
        body: recordBody(record),
      });
      if (!kept.publication.taken) return kept;
      return this.#offer("home", home, {
        method: "POST",
        url: `${home}/oip/v1/minds/${id}/feed`,
        body: recordBody({ oip: "1", type: "FeedPage", mind: own.address, entries: [entry] }),
      });
    };
    const offered = await Promise.all(
      resolved.state.homes.map(async (home) => {
        const first = await bring(home);
        if (first.publication.failure !== "not-found") return first;
        // The home does not serve the mind yet. It is brought the mind's bundle, and asked again.
        await this.bring();
        return bring(home);
      }),
    );
    own.told(offered.map(({ publication }) => publication));
    const taken = offered.some(({ publication }) => publication.taken);
    const failures = offered.flatMap(({ failure }) => (failure === undefined ? [] : [failure]));
    const parted = failures.find(
      (failure) => failure instanceof OipError && failure.code === "duplicity",
    );
    if (parted !== undefined) {
      // A home holds another entry there, which this mind signed: what this client remembers of
      // the feed was behind. If no home took this entry, it is let go, and the feed is read
      // afresh by the next call.
      if (!taken) await own.memory.forget(FEED, remembered);
      throw parted;
    }
    const [first] = failures;
    if (!taken && first !== undefined) throw first;
    const head = { seq: entry.seq, id: contentId(entry) };
    const version = await own.memory.put(FEED, { head }, remembered);
    return { value: { head }, version };
  }
}
