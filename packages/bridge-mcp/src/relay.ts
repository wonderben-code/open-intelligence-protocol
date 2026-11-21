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
 * that the gateway does not know whether the tool ran.
 *
 * Everything the bridged mind signs here is the gateway's word about the
 * server (Layer 0, 1.4). A Receipt says what the gateway saw the server
 * return, and is signed only about a Commitment that the mind has entered
 * into and that the request names.
 */

import { join } from "node:path";

import { carried, type Message, type Mind } from "@oip/client";
import {
  contentId,
  formatRecordRef,
  type JsonObject,
  type JsonValue,
  MEDIA_TYPE,
  parseRecordRef,
} from "@oip/core";
import { Arrivals, type KeptPacket, type Opened, printableJson, Store } from "@oip/local";

import { type Connect, Refused, type Server } from "./connect.ts";
import { readCredentials } from "./credentials.ts";
import type { Bridged } from "./gateway.ts";
import { carriedJson, digestOf, readJsonText, sizeOf } from "./json.ts";
import { allows, type Policy, readPolicy } from "./policy.ts";

/** What a relay reaches outside itself with. */
export interface RelayEdges {
  /** Connects to the server. It is connected to once in a pass, and only if a tool is to be called. */
  readonly connect: Connect;
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
    };

/** The largest result a packet of the gateway carries, in bytes: the packet stays one that anyone accepts (core 1.6). */
export const MAX_RESULT_BYTES = 196_608;
/** The longest of a server's words quoted to a requester. */
const MAX_QUOTED = 1024;

const isObject = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const text = (body: string): Part => ({ mediaType: "text/plain", body });

/** A stranger's words, quoted so that nothing in them reads as the gateway's. */
const quoted = (words: string): string => printableJson(words.slice(0, MAX_QUOTED));

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
    if (read === undefined) return { why: `The body is text that is no JSON. ${form}` };
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
  readonly #mind: Mind;
  readonly #dir: string;
  readonly #bridged: Bridged;
  readonly #edges: RelayEdges;
  readonly #arrivals: Arrivals;
  readonly #calls: Store<Call>;
  #server: Server | undefined;
  readonly #did = {
    called: [] as string[],
    declined: [] as string[],
    ignored: [] as string[],
    receipts: [] as { id: string; about: string }[],
    sent: [] as { id: string; verb: string; to: string }[],
    failed: [] as { packet: string; message: string }[],
  };

  /**
   * @param opened - The bridged mind, open. The caller closes it.
   * @param bridged - What the gateway's directory records of the server.
   */
  constructor(opened: Opened, bridged: Bridged, edges: RelayEdges) {
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
    // What is written down of a request that waits no more is of no use to anyone.
    const still = new Set(waiting.map(({ id }) => id));
    for (const { key } of this.#calls.all()) if (!still.has(key)) this.#calls.delete(key);
    const policy = readPolicy(this.#dir);
    try {
      for (const kept of waiting) {
        try {
          await this.#handle(kept, policy);
        } catch (error) {
          // What stops one packet is noted, and the pass goes on: the next tries it again.
          this.#did.failed.push({
            packet: kept.id,
            message: error instanceof Error ? error.message : String(error),
          });
        }
      }
    } finally {
      await this.#server?.close().catch(() => undefined);
    }
    return this.#did;
  }

  /** The server, connected to when the first call of the pass needs it. */
  async #connected(): Promise<Server> {
    this.#server ??= await this.#edges.connect(this.#bridged.target, readCredentials(this.#dir));
    return this.#server;
  }

  /** Deals with one packet that reached the bridged mind. */
  async #handle(kept: KeptPacket, policy: Policy): Promise<void> {
    const { packet, id, from } = kept;
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
    // The requester's authority: its own, and that of the mind it was sent for, where a chain
    // of delegations that covers sending says so (Layer 1, 11.2).
    const minds = [from, ...(kept.sentFor === undefined ? [] : [kept.sentFor])];
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
    // Looked for before the call: afterwards the mind's own Receipt would change how it stands.
    const commitment = await this.#commitment(packet.context?.refs, minds);
    const server = await this.#connected();
    // Written down before the call: from here on, the tool is not called for this packet again.
    this.#calls.put(id, { state: "calling" });
    this.#did.called.push(id);
    let result: unknown;
    try {
      result = await server.call(asked.tool, asked.args);
    } catch (error) {
      const words = error instanceof Error ? error.message : String(error);
      await this.#answer(kept, {
        state: "answered",
        verb: "error",
        content: [
          text(
            error instanceof Refused
              ? `The MCP server refused the call. It said: ${quoted(words)}`
              : `The call did not end as a call does: ${quoted(words)} The gateway does not know whether the tool ran, and does not call it a second time.`,
          ),
        ],
      });
      return;
    }
    const body = carriedJson(result);
    const size = sizeOf(body);
    if (size > MAX_RESULT_BYTES) {
      await this.#answer(kept, {
        state: "answered",
        verb: "error",
        content: [
          text(
            `The tool ran, and returned a result of ${String(size)} bytes. A packet of this gateway carries ${String(MAX_RESULT_BYTES)} at most, so the result is not here.`,
          ),
        ],
      });
      return;
    }
    // Layer 0, 2.1: a result the server marks as an error is returned as one, and says so.
    const failed = isObject(result) && result["isError"] === true;
    let receipt: JsonObject | undefined;
    if (!failed && commitment !== undefined) {
      // Layer 0, 1.4: what the gateway observed, and no more. The tool's name is the requester's
      // text: it is quoted.
      receipt = (await this.#mind.receipt({
        about: commitment,
        outcome: "fulfilled",
        statement:
          `The gateway observed the MCP server at ${this.#bridged.endpoint} return a result ` +
          `for the tool ${quoted(asked.tool)}, called for the request ${id}.`,
        evidence: [
          {
            kind: "hash",
            ref: formatRecordRef(from, id),
            digest: digestOf(body),
            mediaType: "application/json",
          },
        ],
      })) as unknown as JsonObject;
    }
    await this.#answer(kept, {
      state: "answered",
      verb: failed ? "error" : "deliver",
      content: [{ mediaType: "application/json", body }],
      ...(receipt === undefined ? {} : { receipt }),
    });
  }

  /**
   * The Commitment a request is made under, if the mind has entered into
   * one that the request names: one it holds, in which it owes and the
   * requester is owed, and which stands open.
   *
   * @returns The reference a Receipt gives as what it is about.
   */
  async #commitment(refs: unknown, minds: readonly string[]): Promise<string | undefined> {
    if (!Array.isArray(refs)) return undefined;
    const held = this.#mind.records();
    for (const ref of refs as readonly unknown[]) {
      const named = parseRecordRef(ref);
      if (named === undefined) continue;
      const record = held.find((one) => contentId(one) === named.contentId) as
        (JsonObject & { parties?: readonly { mind?: unknown; role?: unknown }[] }) | undefined;
      if (record?.["type"] !== "Commitment" || typeof record["author"] !== "string") continue;
      const parties = record.parties ?? [];
      const owes = parties.some((p) => p.mind === this.#mind.address && p.role === "debtor");
      const owed = parties.some((p) => p.role === "creditor" && minds.includes(p.mind as string));
      if (!owes || !owed) continue;
      // Accepted by every party that must sign, and not yet settled (Layer 2, 8.3).
      const status = await this.#mind.statusOf(record);
      if (status !== "accepted" && status !== "overdue") continue;
      return formatRecordRef(record["author"], named.contentId);
    }
    return undefined;
  }

  /** Writes down what a request is answered with, and answers it. */
  async #answer(kept: KeptPacket, answered: Extract<Call, { state: "answered" }>): Promise<void> {
    // Written down before it leaves: a request has one answer, whatever stops the pass.
    this.#calls.put(kept.id, answered);
    await this.#finish(kept, answered, true);
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
      let published = false;
      if (!fresh) {
        // After a stop the feed says whether the Receipt reached it: a record has one entry there.
        this.#mind.hold(receipt);
        const { feed } = await this.#mind.lookup.feed(this.#mind.address);
        published = feed.entries.some(({ entry }) => entry.object === id);
      }
      // Layer 2, 10.2: a mind publishes the Receipts it authors.
      if (!published) await this.#mind.publishRecord(receipt);
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
    // The request waits no more. Only then is what was written down of it let go.
    this.#arrivals.done(kept.id);
    this.#calls.delete(kept.id);
  }
}
