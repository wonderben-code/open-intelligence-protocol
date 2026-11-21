// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Minds as A2A agents (Layer 0, 3.2): what an A2A client asks of a mind,
 * said to the mind in packets, and what the mind answers, kept as tasks.
 *
 * An A2A client has no mind. The gateway's own mind speaks for it: each
 * message of a client is a packet of the gateway's with verb `request`, in
 * a session the gateway opens with the mind for each A2A context, and the
 * mind's answers are read as the table of Layer 0, 3.1 says, the other way
 * round:
 *
 * | The mind answers with          | The task                                |
 * |--------------------------------|-----------------------------------------|
 * | a packet with verb `deliver`   | is completed, and the content delivered |
 * | a packet with verb `decline`   | is rejected                             |
 * | a packet with verb `request`   | needs input                             |
 * | a packet with verb `error`     | has failed                              |
 * | a packet with verb `ack`       | is at work                              |
 * | a packet with verb `inform`    | is answered: with a message, and no     |
 * |                                | task, where no client was told of one   |
 * | a Receipt about the request    | is completed, failed or cancelled, as   |
 * |                                | the outcome says                        |
 *
 * A mind is served only if it asks to be: its current profile lists the
 * URL of the card this gateway serves for it, under `interfaces.a2a`.
 */

import { randomUUID } from "node:crypto";
import { join } from "node:path";

import { carried, type Clock, type Message } from "@oip/client";
import { formatRecordRef, isMindAddress, OipError } from "@oip/core";
import { Arrivals, asciiJson, type KeptPacket, type Opened, recordText } from "@oip/local";
import { receivePacket } from "@oip/net";
import { type Participant, validateRecordOfType } from "@oip/schema";

import type { A2aMessage, Part } from "./a2a.ts";
import { type Asked, Book, type Held, type Page } from "./book.ts";
import { CARD_PATH } from "./card.ts";
import { type Content, gather, mediaTypeOf, partsOf } from "./content.ts";
import {
  contentTypeNotSupported,
  internal,
  invalidParams,
  taskNotCancelable,
  taskNotFound,
  unsupported,
} from "./fault.ts";
import { cardFor, isTerminal, OIP_MEDIA_TYPE, type TaskState } from "./mapping.ts";

/** What a front needs. */
export interface FrontOptions {
  /** The gateway's own mind, open: it speaks for the A2A clients. The caller closes it. */
  readonly opened: Opened;
  /**
   * The URL the minds are served under, with no slash at its end:
   * `https://gateway.example/a2a`. The interface of a mind is at
   * `<base>/<the mind's ID>`, and its card under that at
   * `/.well-known/agent-card.json`.
   */
  readonly base: string;
  /** The version the cards carry: the gateway's own (Layer 0, 3.2). */
  readonly version: string;
  readonly clock: Clock;
  /**
   * How long a client that waits for a task is kept waiting for the mind,
   * in milliseconds. Default: a minute. After that it is given the task as
   * it stands, and asks again with `GetTask`.
   */
  readonly waitMs?: number;
}

/** A mind this gateway serves as an A2A agent. */
export interface ServedMind {
  /** The mind's address. */
  readonly address: string;
  /** The URL of its A2A interface. */
  readonly url: string;
  /** Its Agent Card, made of its profile (Layer 0, 3.2), as the JSON that is served. */
  readonly card: Readonly<Record<string, unknown>>;
  /** When the profile the card is made of was signed: a timestamp. */
  readonly modified: string;
}

/** How a client wants its message taken (A2A, `SendMessageConfiguration`). */
export interface Taking {
  /** Whether the client is answered at once, with the task as it stands. Default: it waits. */
  readonly returnImmediately?: boolean;
}

/** How long what was found out about a mind is gone by: a minute, in nanoseconds. */
const SERVED_FOR = 60_000_000_000n;
/** How often what is kept no longer is looked for: an hour, in nanoseconds. */
const SWEEP_EVERY = 3_600_000_000_000n;
const DEFAULT_WAIT_MS = 60_000;
/** The media types of bytes that are a text, and are carried as the text they are. */
const TEXTUAL = /^(?:text\/[a-z0-9!#$&^_.+-]+|application\/(?:[a-z0-9!#$&^_.-]+\+)?json)$/u;
/** The states in which a task waits for its client (A2A, 3.2.2). */
const INTERRUPTED: readonly TaskState[] = ["TASK_STATE_INPUT_REQUIRED", "TASK_STATE_AUTH_REQUIRED"];
/** What an outcome of a Receipt makes of a task (Layer 0, 3.1). */
const ENDED: Readonly<Record<string, TaskState>> = {
  fulfilled: "TASK_STATE_COMPLETED",
  broken: "TASK_STATE_FAILED",
  cancelled: "TASK_STATE_CANCELED",
};

/** A thing without some of its members. */
function without<T extends object, K extends keyof T>(value: T, ...keys: K[]): Omit<T, K> {
  const names: readonly PropertyKey[] = keys;
  return Object.fromEntries(Object.entries(value).filter(([key]) => !names.includes(key))) as Omit<
    T,
    K
  >;
}

/**
 * A time as A2A writes one (A2A, 5.6.1): in UTC, and always with its
 * milliseconds, so that two of them are in order as texts are.
 */
const written = (instant: bigint): string => new Date(Number(instant / 1_000_000n)).toISOString();

/** What a client that handed over a packet is told. */
const PASSED =
  "The packet was brought to the mind it is for. What the mind answers, it answers to the packet's sender, as a packet.";

/** The fault of a message or a packet that the mind could not be given, with why where that is known. */
const notGiven = (what: string, failure: string | undefined): Error =>
  internal(
    `The mind could not be given the ${what}: ${failure ?? "none of its endpoints took it"}.`,
  );

/** Whether a client that waits for a task is answered now. */
const settled = (task: Held): boolean =>
  isTerminal(task.state) || INTERRUPTED.includes(task.state) || task.answer !== undefined;

/** The gateway's side of the minds it serves as A2A agents. */
export class Front {
  readonly #opened: Opened;
  readonly #options: FrontOptions;
  readonly #book: Book;
  readonly #arrivals: Arrivals;
  /** What was found out about a mind, and when. */
  readonly #served = new Map<string, { at: bigint; mind: ServedMind | undefined }>();
  /** Who waits for a task to change. */
  readonly #waiting = new Map<string, Set<() => void>>();
  #swept: bigint;

  constructor(options: FrontOptions) {
    this.#opened = options.opened;
    this.#options = options;
    const dir = join(options.opened.home.dir, "front");
    this.#book = new Book(dir);
    this.#arrivals = new Arrivals(options.opened, dir);
    this.#swept = options.clock.now();
  }

  #now(): string {
    return written(this.#options.clock.now());
  }

  /** The URL of the A2A interface of a mind, by the mind's ID: its address without `did:oip:`. */
  urlOf(id: string): string {
    return `${this.#options.base}/${id}`;
  }

  /**
   * The mind of an ID, if this gateway serves it: if its current profile
   * lists the URL of the card this gateway serves for it (Layer 0, 3.2).
   *
   * @throws What keeps the mind's records from being had, other than that there are none.
   */
  async served(id: string): Promise<ServedMind | undefined> {
    const address = `did:oip:${id}`;
    if (!isMindAddress(address)) return undefined;
    const now = this.#options.clock.now();
    const known = this.#served.get(id);
    if (known !== undefined && now - known.at < SERVED_FOR) return known.mind;
    let profile: Participant | undefined;
    try {
      const resolved = await this.#opened.mind.lookup.resolve(address);
      // A mind that is retired asks nothing more of anyone.
      profile = resolved.state.retired ? undefined : resolved.participant?.record;
    } catch (error) {
      if (!(error instanceof OipError && error.code === "not-found")) throw error;
    }
    const url = this.urlOf(id);
    const mind =
      profile?.interfaces?.["a2a"] === `${url}${CARD_PATH}`
        ? {
            address,
            url,
            card: cardFor(profile, { url, version: this.#options.version }),
            modified: profile.created,
          }
        : undefined;
    this.#served.set(id, { at: now, mind });
    return mind;
  }

  /** A task of a mind's that a client was told of. @throws Fault if there is none. */
  get(mind: ServedMind, id: string): Held {
    const task = this.#book.get(id);
    // Another mind's task is no task to who asks this one (A2A, 3.3.2).
    if (task?.mind !== mind.address || !task.announced) throw taskNotFound();
    return task;
  }

  /** The tasks of a mind, a page at a time. @throws Fault if the page token is none of this gateway's. */
  list(mind: ServedMind, asked: Omit<Asked, "mind">): Page {
    const page = this.#book.list({ ...asked, mind: mind.address });
    if (page === undefined) throw invalidParams("pageToken is no token this agent gave.");
    return page;
  }

  /**
   * Takes a message of an A2A client for a mind (A2A, `SendMessage`): says
   * it to the mind in a packet, and waits for what the mind makes of it,
   * unless the client does not wait.
   *
   * @returns The task, or the mind's answer where it answered with a
   *   message and no task was told of.
   * @throws Fault if the message names a task that is none or has ended,
   *   a context that is not the task's, or holds what a packet cannot carry.
   */
  async send(
    mind: ServedMind,
    message: A2aMessage,
    taking: Taking = {},
  ): Promise<{ readonly task: Held } | { readonly message: A2aMessage }> {
    // Layer 0, 3.3: a message may carry a whole packet. Then the packet is the message.
    const packets = message.parts.filter(
      (part) => "data" in part && part.mediaType === OIP_MEDIA_TYPE,
    );
    if (packets.length > 0) return { message: await this.#passed(mind, message, packets) };
    const before = message.taskId === undefined ? undefined : this.get(mind, message.taskId);
    if (before !== undefined) {
      if (isTerminal(before.state)) {
        throw unsupported("The task has ended: a message begins a new one.");
      }
      if (message.contextId !== undefined && message.contextId !== before.contextId) {
        throw invalidParams("contextId is not the context of the task the message names.");
      }
    }
    const content = await this.#content(message.parts);
    const contextId = before?.contextId ?? message.contextId ?? randomUUID();
    const id = before?.id ?? randomUUID();
    const session = before?.session ?? (await this.#sessionOf(mind.address, contextId));
    const sent = await this.#opened.mind.send({
      to: [mind.address],
      verb: "request",
      // Layer 0, 1.4: the gateway says whose words these are. They are not its own.
      goal: "A message of an A2A client, passed on by the gateway.",
      content: content.length === 1 && content[0] !== undefined ? content[0] : { parts: content },
      session,
      thread: id,
      // What the mind asked is what this answers.
      ...(before?.question === undefined ? {} : { replyTo: before.question }),
      context: { refs: [`a2a:message/${encodeURIComponent(recordText(message.messageId))}`] },
    });
    const [delivery] = sent.deliveries;
    // What did not arrive and is kept to be tried again will arrive, or its task will say not.
    if (delivery?.stored !== true && delivery?.queued !== true) {
      throw notGiven("message", delivery?.failure);
    }
    const said: A2aMessage = {
      messageId: message.messageId,
      role: "ROLE_USER",
      parts: message.parts,
      contextId,
      taskId: id,
    };
    const at = this.#now();
    let task: Held =
      before === undefined
        ? {
            id,
            mind: mind.address,
            contextId,
            // The mind has the message, and has said nothing of it yet.
            state: "TASK_STATE_SUBMITTED",
            at,
            artifacts: [],
            history: [said],
            session,
            request: sent.id,
            announced: false,
          }
        : {
            // What the mind asked has its answer now: the task is at work again.
            ...without(before, "question"),
            state: "TASK_STATE_WORKING",
            at,
            history: [...before.history, said],
          };
    this.#book.put(task);
    this.#book.sent(sent.id, id);
    if (taking.returnImmediately !== true) {
      task = await this.#awaited(task, this.#options.waitMs ?? DEFAULT_WAIT_MS);
      if (task.answer !== undefined && !task.announced) {
        // The mind answered with a message, and nobody was told of a task: there is none.
        this.#book.drop(task.id);
        const { messageId, role, parts } = task.answer;
        return { message: { messageId, role, parts, contextId } };
      }
    }
    if (!task.announced) {
      task = { ...task, announced: true };
      this.#book.put(task);
    }
    return { task };
  }

  /**
   * Brings a packet that a message carries to the mind it is for (Layer 0,
   * 3.3). The packet is another mind's own, signed by it. It is verified
   * here as the mind it is for will verify it (Layer 1, 12.4), and passed
   * on as it is: the gateway is its courier, and nothing of it is the
   * gateway's. No task comes of it. The mind answers its sender, as a packet.
   *
   * @returns What the client is told: that the packet was brought.
   * @throws Fault if what is carried is no packet, does not verify, is not
   *   for this mind, or could not be brought.
   */
  async #passed(
    mind: ServedMind,
    message: A2aMessage,
    packets: readonly Part[],
  ): Promise<A2aMessage> {
    const [part, ...more] = packets;
    if (part === undefined || !("data" in part) || more.length > 0) {
      throw invalidParams("A message carries one packet at most.");
    }
    if (message.taskId !== undefined) {
      throw invalidParams(
        "A packet is its sender's own message: it goes on with no task of this agent's.",
      );
    }
    const shaped = validateRecordOfType("Packet", part.data);
    if (!shaped.ok) {
      throw invalidParams(`What the message carries is no packet: ${shaped.issues[0].message}.`);
    }
    if (shaped.value.session !== undefined) {
      throw invalidParams(
        "A packet of a session is brought by its sender: its place in the session is the sender's to keep.",
      );
    }
    const own = this.#opened.mind;
    const judge = (): ReturnType<typeof receivePacket> =>
      receivePacket(part.data, {
        address: mind.address,
        now: this.#options.clock.now(),
        view: own.lookup.view,
        seen: own.lookup.seen,
        accepted: (id) => this.#book.wasPassed(id),
        window: 0n,
      });
    // A first reading notes when the packet's proofs were first seen. Its sender's log is asked
    // for after that: a log is evidence for a proof as it stands no earlier (core 9.4).
    judge();
    try {
      await own.lookup.resolve(shaped.value.from);
    } catch (error) {
      // A sender that cannot be resolved has no key that counts: the judge says so.
      if (!(error instanceof OipError)) throw error;
    }
    const judged = judge();
    if (!judged.ok) {
      const [{ message: why, clause }] = judged.issues;
      throw invalidParams(`The packet the message carries is not taken: ${why} (${clause}).`);
    }
    const { id, packet, duplicate, forgetAfter } = judged.value;
    const parts: Part[] = [{ text: PASSED }];
    // Layer 1, 12.4: a packet that was brought before is not brought again. Its sender is told the same.
    if (!duplicate) {
      const delivery = await own.pass(packet, mind.address);
      if (!delivery.stored) throw notGiven("packet", delivery.failure);
      this.#book.pass(id, written(forgetAfter));
      // The mind's own acknowledgement, where its endpoint gave one: it is a record, and says so itself.
      if (delivery.ack !== undefined) parts.push({ data: delivery.ack, mediaType: OIP_MEDIA_TYPE });
    }
    return {
      messageId: randomUUID(),
      role: "ROLE_AGENT",
      parts,
      contextId: message.contextId ?? randomUUID(),
    };
  }

  /**
   * Cancels a task for an A2A client (A2A, `CancelTask`). The mind is told
   * with a Receipt of the gateway's, with outcome `cancelled`, about the
   * request that began the task.
   *
   * @throws Fault if there is no such task, or it has ended.
   */
  async cancel(mind: ServedMind, id: string): Promise<Held> {
    const task = this.get(mind, id);
    if (isTerminal(task.state)) throw taskNotCancelable();
    const own = this.#opened.mind;
    // Layer 0, 1.4: what the gateway observed, and no more.
    const receipt = await own.receipt({
      about: formatRecordRef(own.address, task.request),
      outcome: "cancelled",
      statement: `The gateway observed an A2A client cancel task ${asciiJson(task.id)}.`,
    });
    await this.#say(task, { verb: "inform", content: carried(receipt) });
    const cancelled: Held = {
      ...without(task, "question"),
      state: "TASK_STATE_CANCELED",
      at: this.#now(),
    };
    this.#book.put(cancelled);
    this.#wake(id);
    return cancelled;
  }

  /**
   * Reads the gateway's mailbox once, and brings each answer of a mind to
   * its task.
   *
   * @returns How many tasks an answer changed.
   */
  async pump(): Promise<number> {
    let changed = 0;
    for (const kept of await this.#arrivals.waiting()) {
      if (this.#apply(kept)) changed += 1;
      this.#arrivals.done(kept.id);
    }
    const now = this.#options.clock.now();
    if (now - this.#swept > SWEEP_EVERY) {
      this.#swept = now;
      this.#book.sweep((seconds) => written(now - BigInt(seconds) * 1_000_000_000n));
    }
    return changed;
  }

  /** The session of a mind's context: the one it has, if the gateway holds it still, or a new one. */
  async #sessionOf(mind: string, contextId: string): Promise<string> {
    const own = this.#opened.mind;
    const known = this.#book.session(mind, contextId);
    if (known !== undefined && (await own.sessions()).some(({ id }) => id === known)) return known;
    const { id } = await own.openSession([mind]);
    this.#book.context(mind, contextId, id);
    return id;
  }

  /** Says something to the mind of a task, in the task's session if the gateway holds it still. */
  async #say(task: Held, message: Pick<Message, "verb" | "content">): Promise<void> {
    const own = this.#opened.mind;
    const held = (await own.sessions()).some(({ id }) => id === task.session);
    await own.send({
      ...message,
      to: [task.mind],
      thread: task.id,
      ...(held ? { session: task.session } : {}),
    });
  }

  /** Content for a packet, of the parts of a client's message. @throws Fault for what a packet cannot carry. */
  async #content(parts: readonly Part[]): Promise<Content[]> {
    if (parts.length === 0) throw invalidParams("A message has one part at least.");
    const fit = parts.map((part): Part => {
      if (!("raw" in part)) return part;
      // A packet has no place for bytes. Bytes that are a text are carried as that text.
      const mediaType = mediaTypeOf(part, "application/octet-stream");
      const refused = contentTypeNotSupported(
        `A part of media type ${mediaType} cannot be given to this agent: it takes texts, JSON and files by their URLs.`,
      );
      if (!TEXTUAL.test(mediaType)) throw refused;
      try {
        const text = new TextDecoder("utf-8", { fatal: true }).decode(
          Buffer.from(part.raw, "base64"),
        );
        return { text, mediaType };
      } catch {
        throw refused;
      }
    });
    const { content, left } = await gather(fit.map((part) => ({ part, ref: "" })));
    if (left > 0) {
      throw invalidParams(
        "The message holds more than a packet carries, or a URL that is none of the web.",
      );
    }
    return content;
  }

  /** The task, once the mind has answered or the wait is over: whichever is first. */
  async #awaited(task: Held, ms: number): Promise<Held> {
    const until = Date.now() + ms;
    let now = this.#book.get(task.id) ?? task;
    while (!settled(now) && Date.now() < until) {
      await new Promise<void>((resolve) => {
        const waiting = this.#waiting.get(task.id) ?? new Set();
        this.#waiting.set(task.id, waiting);
        const done = (): void => {
          clearTimeout(timer);
          waiting.delete(done);
          if (waiting.size === 0) this.#waiting.delete(task.id);
          resolve();
        };
        const timer = setTimeout(done, Math.max(0, until - Date.now()));
        waiting.add(done);
      });
      now = this.#book.get(task.id) ?? now;
    }
    return now;
  }

  #wake(id: string): void {
    for (const done of [...(this.#waiting.get(id) ?? [])]) done();
  }

  /** Brings a packet that reached the gateway to the task it answers. Whether a task changed. */
  #apply(kept: KeptPacket): boolean {
    const { packet, id, from } = kept;
    const named =
      (packet.replyTo === undefined ? undefined : this.#book.taskOf(packet.replyTo)) ??
      packet.thread;
    const task = named === undefined ? undefined : this.#book.get(named);
    // Only the mind a task is asked of answers in it, and a task that has ended has its answer.
    if (task?.mind !== from || isTerminal(task.state)) return false;
    const parts = partsOf(packet.content);
    const words: A2aMessage = {
      messageId: id,
      role: "ROLE_AGENT",
      parts,
      contextId: task.contextId,
      taskId: task.id,
    };
    const rest = without(task, "question", "said");
    const at = this.#now();
    const told = { ...rest, at, said: words, history: [...task.history, words] };
    const delivered = { ...rest, at, artifacts: [...task.artifacts, { artifactId: id, parts }] };
    let next: Held;
    const ended = this.#ended(packet, task);
    if (ended !== undefined) {
      // A Receipt says how the request went (Layer 0, 3.1), whatever the packet's verb.
      next =
        ended === "TASK_STATE_COMPLETED"
          ? { ...delivered, state: ended }
          : { ...told, state: ended };
    } else {
      switch (packet.purpose.verb) {
        case "deliver":
          next = { ...delivered, state: "TASK_STATE_COMPLETED" };
          break;
        case "decline":
          next = { ...told, state: "TASK_STATE_REJECTED" };
          break;
        case "request":
          next = { ...told, state: "TASK_STATE_INPUT_REQUIRED", question: id };
          break;
        case "error":
          next = { ...told, state: "TASK_STATE_FAILED" };
          break;
        case "ack":
          next = { ...task, state: "TASK_STATE_WORKING", at };
          break;
        case "inform":
          // An answer. No task was told of: then the answer is a message, and there is no task.
          next = task.announced
            ? { ...told, state: "TASK_STATE_COMPLETED" }
            : { ...task, answer: words };
          break;
        default:
          return false;
      }
    }
    this.#book.put(next);
    this.#wake(task.id);
    return true;
  }

  /** What a Receipt in a packet says became of a task's request, if the packet carries such a Receipt of the mind's. */
  #ended(packet: KeptPacket["packet"], task: Held): TaskState | undefined {
    const about = formatRecordRef(this.#opened.mind.address, task.request);
    const pieces = "parts" in packet.content ? packet.content.parts : [packet.content];
    for (const piece of pieces) {
      if (piece.mediaType !== OIP_MEDIA_TYPE || !("body" in piece)) continue;
      const receipt = validateRecordOfType("Receipt", piece.body);
      if (!receipt.ok) continue;
      const { author, about: of, outcome } = receipt.value;
      // The packet is the mind's, signed: a Receipt of the mind's in it is the mind's word.
      if (author === task.mind && of === about && ENDED[outcome] !== undefined)
        return ENDED[outcome];
    }
    return undefined;
  }
}
