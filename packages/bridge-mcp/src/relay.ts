// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Between a bridged mind and its MCP server (Layer 0, 2.1).
 *
 * A packet with verb `request` whose content is
 * `{ "mediaType": "application/json", "body": { "tool", "arguments" } }`
 * is a call of a tool. The gateway makes the call if its operator's
 * policy covers the requester, and answers with the result in a packet
 * with verb `deliver`, or `error` where the tool or the call failed, or
 * `decline` where the policy does not cover the requester.
 *
 * A tool may do something in the world, so a call is made **at most
 * once**. The gateway writes down that it is about to call before it
 * calls, and what came of the call before it answers. A pass that stops
 * in between is not made good by calling again: the requester is told
 * that the gateway does not know whether the tool ran. One pass at a time
 * relays for a bridged mind: the gateway holds the mind's directory while
 * it does (`Gateway.relay`).
 *
 * A requester's authority is judged when the gateway acts. Where a tool is
 * open to the mind a packet was sent for, and not to its sender, the
 * gateway reads what the authors of the delegations have revoked before it
 * calls (Layer 1, 11.5), and calls only if the delegations stand now.
 *
 * Everything the bridged mind signs here is the gateway's word about the
 * server (Layer 0, 1.4). A Receipt says what the gateway saw the server
 * return, with outcome `progress`: whether a result keeps a promise is not
 * the gateway's to say. It is signed only about a Commitment that the mind
 * has entered into and that the request names.
 *
 * Nothing of the operator's credentials is said to anyone. A server may
 * say them back, in an error or in a result: what it said is searched for
 * them before any of it goes into a packet.
 */

import { join } from "node:path";

import { carried, type Clock, type Message, type Mind } from "@oip/client";
import {
  CLOCK_SKEW,
  contentId,
  formatRecordRef,
  type JsonObject,
  type JsonValue,
  MEDIA_TYPE,
  parseRecordRef,
  parseTimestamp,
} from "@oip/core";
import {
  Arrivals,
  asciiJson,
  keepRecords,
  type KeptPacket,
  type Opened,
  recordText,
  Store,
} from "@oip/local";

import { type Connect, Refused, type Server } from "./connect.ts";
import { readCredentials, repeatsSecret, secretsOf, withoutSecrets } from "./credentials.ts";
import type { Bridged } from "./gateway.ts";
import { carriedJson, digestOf, readJsonText, sizeOf, Unsayable } from "./json.ts";
import { allows, type Policy, readPolicy } from "./policy.ts";

/** What a relay reaches outside itself with. */
export interface RelayEdges {
  /** Connects to the server. It is connected to once in a pass, and only if a tool is to be called. */
  readonly connect: Connect;
  /** The clock a waiting request's age is read on. */
  readonly clock: Clock;
  /**
   * Whether the pass has had the time it may take. Asked before each
   * packet, and once more before a tool is called: once it says so, what
   * is left waits for the next pass. Default: a pass has all the time it
   * needs.
   */
  readonly spent?: () => boolean;
}

/** What one pass of the relay did. */
export interface Relayed {
  /** Requests for which a tool was called, by the content ID of their packet. */
  readonly called: readonly string[];
  /** Requests the operator's policy does not cover. No tool was called for them. */
  readonly declined: readonly string[];
  /** Packets that were read and are no request: any verb but `request`. */
  readonly ignored: readonly string[];
  /** Receipts signed, by content ID, each with the Commitment it is about. */
  readonly receipts: readonly { readonly id: string; readonly about: string }[];
  /** Packets the bridged mind sent back, by content ID, with their verb. */
  readonly sent: readonly { readonly id: string; readonly verb: string; readonly to: string }[];
  /**
   * Answers that no endpoint of their requester took, and that are not kept
   * to be tried again: the requester is not reached, and will not be. Each
   * is in `sent` too. With why, as the client says it.
   */
  readonly lost: readonly { readonly id: string; readonly to: string; readonly why: string }[];
  /** Packets that could not be dealt with in this pass, with why. Each is tried again by the next. */
  readonly failed: readonly { readonly packet: string; readonly message: string }[];
}

/** One part of what the bridged mind sends. */
interface Part {
  readonly mediaType: string;
  readonly body: JsonValue;
}

/** What the gateway has written down of a request. */
type Call =
  | {
      /** The tool is about to be called, or was being called when a pass stopped. */
      readonly state: "calling";
    }
  | {
      /** The request has its answer. It is sent, and sent again by a pass that finds it here. */
      readonly state: "answered";
      readonly verb: "deliver" | "error" | "decline";
      readonly content: readonly Part[];
      /** The Receipt that was signed about the call, if one was. */
      readonly receipt?: JsonObject;
      /** Whether the Receipt is on the mind's feed: it is put there once. */
      readonly published?: boolean;
    };

/**
 * The largest result a packet of the gateway carries, in bytes of the
 * packet's canonical form: with a Receipt beside it, the packet stays one
 * that every implementation accepts (core 1.6: 256 KiB at least).
 */
export const MAX_RESULT_BYTES = 196_608;
/** The longest of a stranger's words quoted to a requester. */
const MAX_QUOTED = 1024;
/** How many of a request's references are looked at for a Commitment it is made under: the first so many of `context.refs`. */
export const MAX_REFS = 8;
/**
 * How long a request that names no time of its own waits, in seconds: a
 * day. A request waits where the server cannot be reached, or a feed the
 * gateway reads before it acts. After that no tool is called for it, and
 * its requester is told so.
 */
export const MAX_WAITING_SECONDS = 86_400;
const SECOND = 1_000_000_000n;

const isObject = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const text = (body: string): Part => ({ mediaType: "text/plain", body });

/**
 * A stranger's words, quoted so that nothing in them reads as the
 * gateway's: as a string of JSON in ASCII, which no text ends early, turns
 * round or dresses up, and which any record holds.
 */
const quoted = (words: string): string => asciiJson(recordText(words, MAX_QUOTED));

/**
 * Reads a request as a call of a tool.
 *
 * @returns The tool and its arguments, or why the content is no call.
 */
export function readCall(
  content: unknown,
):
  | { readonly tool: string; readonly args: Readonly<Record<string, unknown>> }
  | { readonly why: string } {
  const form =
    'A call of a tool is content with media type application/json whose body is { "tool": <name>, "arguments": { … } }, or the JSON text of that.';
  // A packet may carry records beside the call: the `Session` record of a session's first packet
  // (Layer 1, 14.1), or a Commitment the request is made under. They are no part of the call.
  const parts =
    isObject(content) && Array.isArray(content["parts"])
      ? (content["parts"] as readonly unknown[]).filter(
          (part) => !isObject(part) || part["mediaType"] !== MEDIA_TYPE,
        )
      : [content];
  const [one, ...more] = parts;
  if (
    more.length > 0 ||
    !isObject(one) ||
    one["mediaType"] !== "application/json" ||
    !("body" in one)
  ) {
    return { why: `This is no call of a tool. ${form}` };
  }
  let body = one["body"];
  if (typeof body === "string") {
    // Layer 0, 2.1: arguments a record cannot hold come as their JSON text.
    const read = readJsonText(body);
    if (read === undefined) {
      // Text that two readers would read as two calls is no call (`readJsonText`).
      return {
        why: `The body is text that is no JSON the gateway acts on: it does not parse, nests too deep, names a member twice in one object, or holds a number that is not finite. ${form}`,
      };
    }
    body = read.value;
  }
  if (!isObject(body)) return { why: `This is no call of a tool. ${form}` };
  const tool = body["tool"];
  const args = body["arguments"] ?? {};
  if (typeof tool !== "string" || tool === "") {
    return { why: `The call names no tool. ${form}` };
  }
  if (!isObject(args)) return { why: `The arguments of a call are an object. ${form}` };
  return { tool, args };
}

/** One pass of relaying for one bridged mind. */
export class Relay {
  readonly #opened: Opened;
  readonly #mind: Mind;
  readonly #dir: string;
  readonly #bridged: Bridged;
  readonly #edges: RelayEdges;
  readonly #arrivals: Arrivals;
  readonly #calls: Store<Call>;
  #server: Server | undefined;
  /** Whether the server could not be connected to in this pass: it is not tried again in it. */
  #down = false;
  /** Every text of the operator's credentials, once they were read: none of them is said. */
  #secrets: readonly string[] = [];
  /** The records the mind holds, by content ID: made once in a pass, when a request names one. */
  #held: Map<string, JsonObject> | undefined;
  readonly #did = {
    called: [] as string[],
    declined: [] as string[],
    ignored: [] as string[],
    receipts: [] as { id: string; about: string }[],
    sent: [] as { id: string; verb: string; to: string }[],
    lost: [] as { id: string; to: string; why: string }[],
    failed: [] as { packet: string; message: string }[],
  };

  /**
   * @param opened - The bridged mind, open. The caller closes it.
   * @param bridged - What the gateway's directory records of the server.
   */
  constructor(opened: Opened, bridged: Bridged, edges: RelayEdges) {
    this.#opened = opened;
    this.#mind = opened.mind;
    this.#dir = opened.home.dir;
    this.#bridged = bridged;
    this.#edges = edges;
    this.#arrivals = new Arrivals(opened, this.#dir);
    this.#calls = new Store(join(this.#dir, "calls"));
  }

  /**
   * Reads the mailbox and answers what is asked of the server.
   *
   * @throws UsageError if the operator's policy cannot be read: the
   *   packets wait, and no tool is called on a guess.
   */
  async pass(): Promise<Relayed> {
    const waiting = await this.#arrivals.waiting();
    // What is written down of a request that waits no more is of no use to anyone. A request
    // whose file is there and could not be read just now waits still: what is written of it
    // says that its tool was called, and is kept.
    const still = new Set(waiting.map(({ id }) => id));
    for (const { key } of this.#calls.all()) {
      if (!still.has(key) && !this.#arrivals.has(key)) this.#calls.delete(key);
    }
    const policy = readPolicy(this.#dir);
    try {
      for (const kept of waiting) {
        if (this.#edges.spent?.() === true) break;
        try {
          await this.#handle(kept, policy);
        } catch (error) {
          // What stops one packet is noted, and the pass goes on: the next tries it again.
          // What went wrong may hold what a server said: nothing of the credentials is noted.
          const said = error instanceof Error ? error.message : String(error);
          this.#did.failed.push({ packet: kept.id, message: withoutSecrets(said, this.#secrets) });
        }
      }
    } finally {
      await this.#server?.close().catch(() => undefined);
    }
    return this.#did;
  }

  /** The server, connected to when the first call of the pass needs it. */
  async #connected(): Promise<Server> {
    if (this.#server !== undefined) return this.#server;
    const credentials = readCredentials(this.#dir);
    this.#secrets = secretsOf(credentials);
    try {
      this.#server = await this.#edges.connect(this.#bridged.target, credentials);
    } catch (error) {
      // A server that is away is away for every request of this pass: each would wait as long.
      this.#down = true;
      throw error;
    }
    return this.#server;
  }

  /**
   * The minds a request has the authority of, as the gateway judges it at
   * the moment it acts: the sender, and the mind the packet was sent for,
   * where the delegations that say so stand now.
   *
   * @throws What `Mind.holdRevocations` throws, where the feed of a
   *   delegation's author cannot be read: nothing was shown either way, and
   *   the request waits.
   */
  async #authority(kept: KeptPacket): Promise<string[]> {
    const { from, sentFor, packet } = kept;
    if (sentFor === undefined) return [from];
    // Layer 1, 11.5: an author publishes its revocations in its feed. Read before the gateway
    // acts on the delegate's word, and not only when somebody sends them.
    await this.#mind.holdRevocations(packet);
    const stands =
      (await this.#mind.delegationsStand(packet)) && (await this.#mind.sentFor(packet)) === sentFor;
    return stands ? [from, sentFor] : [from];
  }

  /** Deals with one packet that reached the bridged mind. */
  async #handle(kept: KeptPacket, policy: Policy): Promise<void> {
    const { packet, id } = kept;
    // Layer 0, 2.1: a `request` is a call. Nothing else is, and nothing else is answered.
    if (packet.purpose.verb !== "request") {
      this.#did.ignored.push(id);
      this.#arrivals.done(id);
      return;
    }
    const before = this.#calls.get(id);
    if (before?.state === "answered") {
      await this.#finish(kept, before, false);
      return;
    }
    if (before?.state === "calling") {
      // A pass stopped while the tool was being called. It is not called again.
      await this.#answer(kept, {
        state: "answered",
        verb: "error",
        content: [
          text(
            "The gateway stopped while it was calling the tool. It does not know whether the tool ran, and does not call it a second time. Ask again if a second call does no harm.",
          ),
        ],
      });
      return;
    }
    const asked = readCall(packet.content);
    if ("why" in asked) {
      await this.#answer(kept, { state: "answered", verb: "error", content: [text(asked.why)] });
      return;
    }
    if (this.#expired(kept)) {
      // Asked for by a time that has passed, or a day ago: a tool is not called for what its
      // requester has stopped waiting for. Asked first, so that nothing is waited for without end.
      await this.#answer(kept, {
        state: "answered",
        verb: "error",
        content: [
          text(
            "The request waited until it was too old to act on: the MCP server, or a feed the gateway reads before it acts, could not be reached in time. The tool was not called.",
          ),
        ],
      });
      return;
    }
    // The requester's authority: its own, and that of the mind it was sent for, where a chain
    // of delegations that covers sending says so (Layer 1, 11.2) and stands now.
    const minds = await this.#authority(kept);
    if (!allows(policy, asked.tool, minds)) {
      this.#did.declined.push(id);
      await this.#answer(kept, {
        state: "answered",
        verb: "decline",
        content: [
          text(
            `The operator of this gateway has not opened the tool ${quoted(asked.tool)} to you.`,
          ),
        ],
      });
      return;
    }
    // The server did not answer a moment ago: this request waits for the next pass.
    if (this.#down) return;
    // Looked for before the call: afterwards the mind's own Receipt would change how it stands.
    const commitment = await this.#commitment(packet.context?.refs, minds);
    const server = await this.#connected();
    // Asked once more, now that the server is there: a pass that lost its hold on the mind's
    // directory while it waited, or that is to end, calls nothing.
    if (this.#edges.spent?.() === true) return;
    // Written down, and on the disk, before the call: from here on, the tool is not called for
    // this packet again, whatever stops the pass.
    this.#calls.put(id, { state: "calling" });
    this.#did.called.push(id);
    let result: unknown;
    try {
      result = await server.call(asked.tool, asked.args);
    } catch (error) {
      await this.#answer(kept, {
        state: "answered",
        verb: "error",
        content: [
          text(
            error instanceof Refused
              ? // The server's words are its own, and may repeat what it was sent.
                `The MCP server answered the call with an error, and gave no result. It said: ${quoted(withoutSecrets(error.message, this.#secrets))} The gateway does not know whether the tool ran, and does not call it a second time.`
              : // What a transport says of a failure may be the server's whole answer. None of it is passed on.
                "The call did not end as a call does: the server could not be heard to the end. The gateway does not know whether the tool ran, and does not call it a second time.",
          ),
        ],
      });
      return;
    }
    // The tool ran. Whatever goes wrong from here, the requester is told so, and no pass
    // finds `calling` and says that the gateway stopped.
    let answered: Extract<Call, { state: "answered" }>;
    try {
      answered = await this.#answerOf(kept, asked.tool, result, commitment);
    } catch (error) {
      answered = {
        state: "answered",
        verb: "error",
        content: [
          text(
            error instanceof Unsayable
              ? "The tool ran, and returned a result that JSON cannot carry: a number that is not finite, say. The result is not here."
              : "The tool ran, and the gateway could not make a packet of its result. The result is not here.",
          ),
        ],
      };
    }
    await this.#answer(kept, answered);
  }

  /** Whether a request that waits has waited as long as it may. */
  #expired({ packet, time }: KeptPacket): boolean {
    const now = this.#edges.clock.now();
    const expires = packet.expires === undefined ? undefined : parseTimestamp(packet.expires);
    // The time its sender gave it, with the allowance a receiver makes for two clocks (12.4).
    if (expires !== undefined) return now > expires + CLOCK_SKEW;
    const since = parseTimestamp(time);
    return since !== undefined && now - since > BigInt(MAX_WAITING_SECONDS) * SECOND;
  }

  /** What a request is answered with, of the result its tool returned. */
  async #answerOf(
    kept: KeptPacket,
    tool: string,
    result: unknown,
    commitment: string | undefined,
  ): Promise<Extract<Call, { state: "answered" }>> {
    const body = carriedJson(result);
    if (repeatsSecret(result, this.#secrets)) {
      return {
        state: "answered",
        verb: "error",
        content: [
          text(
            "The tool ran. Its result repeats a credential of the gateway's operator, and is not passed on.",
          ),
        ],
      };
    }
    const size = sizeOf(body);
    if (size > MAX_RESULT_BYTES) {
      return {
        state: "answered",
        verb: "error",
        content: [
          text(
            `The tool ran, and returned a result of ${String(size)} bytes. A packet of this gateway carries ${String(MAX_RESULT_BYTES)} at most, so the result is not here.`,
          ),
        ],
      };
    }
    // Layer 0, 2.1: a result the server marks as an error is returned as one, and says so.
    const failed = isObject(result) && result["isError"] === true;
    let receipt: JsonObject | undefined;
    if (!failed && commitment !== undefined) {
      // Layer 0, 1.4: what the gateway observed, and no more. It saw a result. Whether the
      // result keeps the promise is not the gateway's to say, so the outcome is `progress`,
      // which changes how no Commitment stands (Layer 2, 8.3). The tool's name is the
      // requester's text: it is quoted.
      receipt = (await this.#mind.receipt({
        about: commitment,
        outcome: "progress",
        statement:
          `The gateway observed the MCP server at ${this.#bridged.endpoint} return a result ` +
          `for the tool ${quoted(tool)}, called for the request ${kept.id}.`,
        evidence: [
          {
            kind: "hash",
            // The request the result answers. The digest is of the result's body.
            ref: formatRecordRef(kept.from, kept.id),
            digest: digestOf(body),
            mediaType: "application/json",
          },
        ],
      })) as unknown as JsonObject;
      // What the mind signed, it signed: written down now, and not at the end of the pass.
      keepRecords(this.#opened);
    }
    return {
      state: "answered",
      verb: failed ? "error" : "deliver",
      content: [{ mediaType: "application/json", body }],
      ...(receipt === undefined ? {} : { receipt }),
    };
  }

  /**
   * The Commitment a request is made under, if the mind has entered into
   * one that the request names: one it holds, in which it owes and the
   * requester is owed, and which stands open. Of several that qualify, the
   * first the request names.
   *
   * @returns The reference a Receipt gives as what it is about.
   */
  async #commitment(refs: unknown, minds: readonly string[]): Promise<string | undefined> {
    if (!Array.isArray(refs)) return undefined;
    // A request names what it likes, and as much of it as a packet holds. The first few of its
    // references are looked at, and each is looked up, not looked for.
    const named = (refs as readonly unknown[]).slice(0, MAX_REFS).flatMap((ref) => {
      const parsed = parseRecordRef(ref);
      return parsed === undefined ? [] : [parsed];
    });
    if (named.length === 0) return undefined;
    this.#held ??= new Map(
      this.#mind.records().map((record) => [contentId(record), record as unknown as JsonObject]),
    );
    for (const { contentId: id } of named) {
      const record = this.#held.get(id) as
        (JsonObject & { parties?: readonly { mind?: unknown; role?: unknown }[] }) | undefined;
      if (record?.["type"] !== "Commitment" || typeof record["author"] !== "string") continue;
      const parties = record.parties ?? [];
      const owes = parties.some((p) => p.mind === this.#mind.address && p.role === "debtor");
      const owed = parties.some((p) => p.role === "creditor" && minds.includes(p.mind as string));
      if (!owes || !owed) continue;
      // Accepted by every party that must sign, and not yet settled (Layer 2, 8.3).
      const status = await this.#mind.statusOf(record);
      if (status !== "accepted" && status !== "overdue") continue;
      return formatRecordRef(record["author"], id);
    }
    return undefined;
  }

  /** Writes down what a request is answered with, and answers it. */
  async #answer(kept: KeptPacket, answered: Extract<Call, { state: "answered" }>): Promise<void> {
    // Written down before it leaves: a request has one answer, whatever stops the pass.
    this.#calls.put(kept.id, answered);
    await this.#finish(kept, answered, true);
  }

  /** Whether a Receipt of the mind's is on its feed already. A feed too long to read does not say. */
  async #onFeed(id: string): Promise<boolean> {
    const { feed } = await this.#mind.lookup.feed(this.#mind.address);
    return feed.entries.some(({ entry }) => entry.object === id);
  }

  /** Publishes the Receipt of a call, if it has one, brings the answer to the requester, and is done with the request. */
  async #finish(
    kept: KeptPacket,
    answered: Extract<Call, { state: "answered" }>,
    fresh: boolean,
  ): Promise<void> {
    const { receipt } = answered;
    if (receipt !== undefined) {
      const id = contentId(receipt);
      if (answered.published !== true) {
        // After a stop the mind holds its Receipt again, and the feed says whether it reached
        // it: a record has one entry there.
        if (!fresh) this.#mind.hold(receipt);
        // Layer 2, 10.2: a mind publishes the Receipts it authors. This one is about a
        // Commitment, which its requester named.
        if (fresh || !(await this.#onFeed(id))) await this.#mind.publishRecord(receipt);
        this.#calls.put(kept.id, { ...answered, published: true });
      }
      const { about } = receipt;
      this.#did.receipts.push({ id, about: typeof about === "string" ? about : "" });
    }
    const parts = [...answered.content, ...(receipt === undefined ? [] : [carried(receipt)])];
    const [first = text(""), ...more] = parts;
    const { session } = kept.packet;
    let message: Message = {
      to: [kept.from],
      verb: answered.verb,
      content: more.length === 0 ? first : { parts: [first, ...more] },
      replyTo: kept.id,
    };
    if (session !== undefined) {
      // What is said of a request of a session is said in it, to everyone in it (Layer 1,
      // 14.3), if the mind holds the session still.
      const held = (await this.#mind.sessions()).find((view) => view.id === session);
      if (held !== undefined) {
        const others = held.session.participants.filter((mind) => mind !== this.#mind.address);
        message = { ...message, to: others, session };
      }
    }
    const sent = await this.#mind.send(message);
    this.#did.sent.push({ id: sent.id, verb: answered.verb, to: kept.from });
    for (const { to, stored, queued, failure } of sent.deliveries) {
      // What no endpoint took and the outbox does not keep will not arrive: sending it again
      // would end the same way. It is said, and not counted as if it had arrived.
      if (!stored && queued !== true) {
        this.#did.lost.push({ id: sent.id, to, why: failure ?? "no endpoint took it" });
      }
    }
    // The request waits no more. Only then is what was written down of it let go.
    this.#arrivals.done(kept.id);
    this.#calls.delete(kept.id);
  }
}
