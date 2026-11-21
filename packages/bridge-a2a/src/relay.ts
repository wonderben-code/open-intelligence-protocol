// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Relaying between a bridged mind and its agent (Layer 0, 3.1).
 *
 * A packet with verb `request` that reaches the bridged mind is sent to
 * the agent as an A2A message. What the agent answers comes back in OIP,
 * as the table of 3.1 says: a message as a packet, a task that is done as
 * a Receipt, one that is refused as a packet with verb `decline`, and one
 * that needs more as a packet with verb `request` to the requester.
 *
 * Everything the bridged mind signs here is a statement by the gateway
 * about the agent (Layer 0, 1.4). A Receipt says what the gateway saw the
 * agent report, and no more. Whatever of it is the agent's own (the name
 * of a task, the agent's words) is quoted, so that it cannot be read as
 * the gateway's.
 *
 * What a pass does, it does once:
 *
 * - a packet is written down before anything is done with it, and is not
 *   dealt with again once the agent has answered it. If a pass stops
 *   before that, the next sends the message again under the same ID, which
 *   is the packet's own, so that the agent can tell;
 * - a Receipt is written down as soon as it is signed. A pass that stops
 *   after that is finished by the next with the same Receipt: no second
 *   one is signed for a task.
 */

import { join } from "node:path";

import { carried, type Clock, type Message, type Mind } from "@oip/client";
import {
  contentId,
  formatRecordRef,
  formatTimestamp,
  type JsonObject,
  parseTimestamp,
} from "@oip/core";
import { Arrivals, type KeptPacket, type Opened, printableJson, Store } from "@oip/local";

import {
  A2aError,
  type A2aMessage,
  type Agent,
  type Answered,
  type Ask,
  type Get,
  getTask,
  sendMessage,
  type Task,
} from "./a2a.ts";
import { type Content, gather, leftOut, partsOf, wellFormed } from "./content.ts";
import type { Bridged } from "./gateway.ts";
import { OIP_EXTENSION, OIP_MEDIA_TYPE, saidOf } from "./mapping.ts";

/** What a relay reaches outside itself with, and its clock. */
export interface RelayEdges {
  /** Makes a request of the agent. */
  readonly ask: Ask;
  /** Gets a file an agent names by its URL, to say which bytes were there. */
  readonly get: Get;
  readonly clock: Clock;
}

/** What was signed for the end of a task, until it is published and sent. */
interface Settled {
  readonly receipt: JsonObject;
  readonly outcome: string;
  readonly verb: "deliver" | "inform";
  /** What the agent delivered, as the packet carries it. */
  readonly content: readonly Content[];
}

/** A task the gateway follows for a requester. */
interface Followed {
  /** The mind that asked. */
  readonly requester: string;
  /** The content ID of the packet that asked. */
  readonly request: string;
  /** When the gateway began to follow it. */
  readonly since: string;
  /** The session the request is a packet of, if it is one of a session. */
  readonly session?: string;
  /** The state the gateway last acted on, so that it acts on each once. */
  readonly acted?: string;
  /** The packet with which the requester was last asked for more, by its content ID. */
  readonly question?: string;
  readonly settled?: Settled;
}

/** A question the gateway passed on to a requester: the requester's reply to it goes on with the task. */
interface Question {
  readonly taskId: string;
  readonly requester: string;
  readonly contextId?: string;
}

/** What one pass did, for a caller to log or to show. */
export interface Relayed {
  /** Requests passed on to the agent, by the content ID of their packet. */
  readonly passed: readonly string[];
  /** Packets that were read and are nothing the agent is asked: any verb but `request`, unless it answers a question. */
  readonly ignored: readonly string[];
  /** Receipts signed for tasks that ended, by content ID, with their outcome. */
  readonly receipts: readonly {
    readonly id: string;
    readonly outcome: string;
    readonly about: string;
  }[];
  /** Packets the bridged mind sent back, by content ID, with their verb. */
  readonly sent: readonly { readonly id: string; readonly verb: string; readonly to: string }[];
  /**
   * What could not be done in this pass, with why: a packet (by content
   * ID) or a task (by the agent's name for it, which is any text). A task
   * is tried again by the next pass, and so is a packet the agent has not
   * answered.
   */
  readonly failed: readonly {
    readonly packet?: string;
    readonly task?: string;
    readonly message: string;
  }[];
  /** Tasks that are still open after the pass. */
  readonly open: number;
}

/** The media types of answers the gateway can pass on. */
const ACCEPTED = ["text/plain", "application/json", OIP_MEDIA_TYPE];
/** The longest of an agent's words quoted in a Receipt or said for it. */
const MAX_QUOTED = 1024;
/** The longest statement of a Receipt (Layer 2, 6.1). */
const MAX_STATEMENT = 8192;
/** The most tasks of one agent the gateway follows at a time. */
export const MAX_OPEN_TASKS = 256;
/** How long the gateway follows a task that does not end: thirty days. */
export const MAX_FOLLOWED_SECONDS = 2_592_000;
/** What an agent's parts are of, in a word to a requester about those that are left out. */
const ANSWER = "the agent's answer";
/** A2A, Section 5.4: the agent has no such task. */
const TASK_NOT_FOUND = -32001;

/** The agent's own words in a message, as one text, cut short. */
function wordsOf(message: A2aMessage | undefined): string {
  const said = (message?.parts ?? []).flatMap((part) => ("text" in part ? [part.text] : []));
  const text = wellFormed(said.join("\n").trim());
  return text.length > MAX_QUOTED ? `${text.slice(0, MAX_QUOTED - 1)}…` : text;
}

/** One pass of relaying for one bridged mind. */
export class Relay {
  readonly #mind: Mind;
  readonly #bridged: Bridged;
  readonly #edges: RelayEdges;
  readonly #agent: Agent;
  readonly #arrivals: Arrivals;
  readonly #tasks: Store<Followed>;
  readonly #questions: Store<Question>;
  readonly #contexts: Store<string>;
  /** The tasks this pass was told of by the agent: they are not asked about again in it. */
  readonly #told = new Set<string>();
  readonly #did = {
    passed: [] as string[],
    ignored: [] as string[],
    receipts: [] as { id: string; outcome: string; about: string }[],
    sent: [] as { id: string; verb: string; to: string }[],
    failed: [] as { packet?: string; task?: string; message: string }[],
  };

  /**
   * @param opened - The bridged mind, open. The caller closes it.
   * @param bridged - What the gateway's directory records of the agent.
   */
  constructor(opened: Opened, bridged: Bridged, edges: RelayEdges) {
    this.#mind = opened.mind;
    this.#bridged = bridged;
    this.#edges = edges;
    this.#agent = {
      ask: edges.ask,
      interface: bridged.interface,
      ...(bridged.extension ? { extensions: [OIP_EXTENSION] } : {}),
    };
    const dir = opened.home.dir;
    this.#arrivals = new Arrivals(opened, dir);
    this.#tasks = new Store(join(dir, "tasks"));
    this.#questions = new Store(join(dir, "questions"));
    this.#contexts = new Store(join(dir, "contexts"));
  }

  /** Reads the mailbox, passes on what is asked of the agent, and follows the tasks that are open. */
  async pass(): Promise<Relayed> {
    const waiting = await this.#arrivals.waiting();
    for (const kept of waiting) {
      await this.#attempt({ packet: kept.id }, () => this.#handle(kept));
    }
    for (const { key, value } of this.#tasks.all()) {
      if (this.#told.has(key)) continue;
      await this.#attempt({ task: key }, () => this.#follow(key, value));
    }
    return { ...this.#did, open: this.#tasks.all().length };
  }

  /** Does one piece of a pass. What stops it is noted, and the pass goes on: the next tries it again. */
  async #attempt(about: { packet?: string; task?: string }, piece: () => Promise<void>) {
    try {
      await piece();
    } catch (error) {
      this.#did.failed.push({
        ...about,
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }

  /** Sends a packet from the bridged mind about a request, and notes it. */
  async #send(
    about: Pick<Followed, "requester" | "request" | "session">,
    verb: string,
    content: readonly Content[],
  ): Promise<string> {
    const { requester, request, session } = about;
    const [first = { mediaType: "text/plain", body: "" }, ...more] = content;
    let message: Message = {
      to: [requester],
      verb,
      content: more.length === 0 ? first : { parts: [first, ...more] },
      replyTo: request,
    };
    if (session !== undefined) {
      // Layer 0, 3.1: a context is a session. What is said of a request of a session is said in it,
      // to everyone in it (Layer 1, 14.3), if the mind holds the session still.
      const held = (await this.#mind.sessions()).find((view) => view.id === session);
      if (held !== undefined) {
        const others = held.session.participants.filter((mind) => mind !== this.#mind.address);
        message = { ...message, to: others, session };
      }
    }
    const sent = await this.#mind.send(message);
    this.#did.sent.push({ id: sent.id, verb, to: requester });
    return sent.id;
  }

  /** Tells a requester, in the gateway's own words, what the agent cannot be asked or will not say. */
  async #tell(
    about: Pick<Followed, "requester" | "request" | "session">,
    words: string,
  ): Promise<void> {
    await this.#send(about, "error", [{ mediaType: "text/plain", body: words }]);
  }

  /** Deals with one packet that reached the bridged mind. */
  async #handle(kept: KeptPacket): Promise<void> {
    const { packet, id, from } = kept;
    const { session } = packet;
    const about = { requester: from, request: id, ...(session === undefined ? {} : { session }) };
    const asked = packet.replyTo === undefined ? undefined : this.#questions.get(packet.replyTo);
    // An answer goes on with a task only if it is from the mind that the task is for.
    const question = asked?.requester === from ? asked : undefined;
    // Layer 0, 3.1: a `request` is a message to the agent. So is the answer to what the agent asked.
    if (packet.purpose.verb !== "request" && question === undefined) {
      this.#did.ignored.push(id);
      this.#arrivals.done(id);
      return;
    }
    if (question === undefined && this.#tasks.all().length >= MAX_OPEN_TASKS) {
      await this.#tell(
        about,
        "The gateway follows as many tasks of this agent as it can. Ask again later.",
      );
      this.#arrivals.done(id);
      return;
    }
    // A context is one requester's: two minds that name one session do not share what the agent keeps.
    const context = session === undefined ? undefined : JSON.stringify([from, session]);
    const contextId =
      question?.contextId ?? (context === undefined ? undefined : this.#contexts.get(context));
    const message: A2aMessage = {
      // The packet's own ID: an agent that is sent it twice can tell.
      messageId: id,
      role: "ROLE_USER",
      parts: [
        ...partsOf(packet.content),
        // Layer 0, 3.3: the whole packet, signed, for an agent that declares the extension.
        ...(this.#bridged.extension
          ? [{ data: packet as unknown, mediaType: OIP_MEDIA_TYPE }]
          : []),
      ],
      ...(contextId === undefined ? {} : { contextId }),
      ...(question === undefined ? {} : { taskId: question.taskId }),
    };
    let answered: Answered;
    try {
      answered = await sendMessage(this.#agent, message, ACCEPTED);
    } catch (error) {
      if (!(error instanceof A2aError)) throw error;
      // The requester is told that the agent did not take it, in the gateway's own words.
      await this.#tell(about, `The gateway could not pass this on: ${error.message}.`);
      this.#arrivals.done(id);
      return;
    }
    const answer = "task" in answered ? answered.task : answered.message;
    if (context !== undefined && answer.contextId !== undefined) {
      // What the agent calls this session's context is kept for the next packet of it.
      this.#contexts.put(context, answer.contextId);
    }
    if ("message" in answered) {
      // The agent has answered: from here on the packet is not sent to it again.
      this.#arrivals.done(id);
      this.#finishQuestion(packet.replyTo, question);
      this.#did.passed.push(id);
      const { content, left } = await gather(
        answered.message.parts.map((part) => ({ part, ref: "" })),
      );
      await this.#send(about, "inform", [...content, ...leftOut(left, ANSWER, false)]);
      return;
    }
    const { task } = answered;
    const before = this.#tasks.get(task.id);
    const followed: Followed =
      before === undefined
        ? { ...about, since: formatTimestamp(this.#edges.clock.now()) }
        : // The agent was told more: what it says now is new, the state it had before too.
          {
            requester: before.requester,
            request: before.request,
            since: before.since,
            ...(before.session === undefined ? {} : { session: before.session }),
          };
    // The task is followed, and the packet done with, before anything is said of it: what is
    // said is said again by the next pass if this one stops, and the agent is not asked twice.
    this.#tasks.put(task.id, followed);
    this.#told.add(task.id);
    this.#arrivals.done(id);
    this.#finishQuestion(packet.replyTo, question);
    this.#did.passed.push(id);
    await this.#attempt({ task: task.id }, () => this.#settle(task, followed));
  }

  /** A question that was answered is no question any more. */
  #finishQuestion(replyTo: string | undefined, question: Question | undefined): void {
    if (question !== undefined && replyTo !== undefined) this.#questions.delete(replyTo);
  }

  /** Asks the agent where a task stands, and says what became of it. */
  async #follow(taskId: string, followed: Followed): Promise<void> {
    if (followed.settled !== undefined) {
      // A Receipt was signed and the pass stopped: it is finished with that Receipt.
      await this.#finish(taskId, followed, followed.settled, false);
      return;
    }
    const named = printableJson(taskId);
    const since = parseTimestamp(followed.since);
    const age = since === undefined ? 0n : this.#edges.clock.now() - since;
    if (age > BigInt(MAX_FOLLOWED_SECONDS) * 1_000_000_000n) {
      await this.#tell(
        followed,
        `The gateway no longer follows task ${named} of the agent at ${this.#bridged.origin}: ` +
          "the agent reported no end of it in thirty days. The gateway does not know what became of it.",
      );
      this.#drop(taskId, followed);
      return;
    }
    let task: Task;
    try {
      task = await getTask(this.#agent, taskId);
    } catch (error) {
      if (error instanceof A2aError && error.code === TASK_NOT_FOUND) {
        await this.#tell(
          followed,
          `The agent at ${this.#bridged.origin} no longer knows task ${named}. ` +
            "The gateway does not know what became of it.",
        );
        this.#drop(taskId, followed);
        return;
      }
      throw error;
    }
    await this.#settle(task, followed);
  }

  /** Says in OIP what a task's state maps to, once for each state, and follows the task while it is open. */
  async #settle(task: Task, followed: Followed): Promise<void> {
    const said = saidOf(task.state);
    const state = task.state ?? "";
    // Nothing is said of a task that is at work, or in a state the gateway does not know, and
    // nothing twice of one that waits for its requester. It is followed on.
    if (said.as === "nothing" || followed.acted === state) return;
    const words = wordsOf(task.said);
    if (said.as === "packet") {
      const body =
        words !== ""
          ? words
          : said.verb === "decline"
            ? "The agent declined the request."
            : "The agent needs more before it can go on.";
      const sent = await this.#send(followed, said.verb, [{ mediaType: "text/plain", body }]);
      if (said.verb === "request") {
        // The requester's reply to this packet goes on with the task. What was asked before is
        // asked no more.
        if (followed.question !== undefined) this.#questions.delete(followed.question);
        this.#questions.put(sent, {
          taskId: task.id,
          requester: followed.requester,
          ...(task.contextId === undefined ? {} : { contextId: task.contextId }),
        });
        this.#tasks.put(task.id, { ...followed, acted: state, question: sent });
      } else {
        this.#drop(task.id, followed);
      }
      return;
    }
    // A Receipt: what the gateway observed, and no more (Layer 0, 1.4).
    const name = encodeURIComponent(wellFormed(task.id));
    const { content, evidence, left } = await gather(
      task.artifacts.flatMap((artifact) =>
        artifact.parts.map((part, index) => ({
          part,
          ref: `a2a:task/${name}/artifact/${encodeURIComponent(wellFormed(artifact.artifactId))}/part/${String(index)}`,
        })),
      ),
      this.#edges.get,
    );
    const reported = { fulfilled: "completed", broken: "failed", cancelled: "canceled" }[
      said.outcome
    ];
    // The name of the task and the agent's words are the agent's: each is quoted as a string of
    // JSON, which no text can end early, so that neither reads as words of the gateway.
    const statement =
      `The gateway observed the A2A agent at ${this.#bridged.origin} report task ` +
      `${printableJson(task.id)} as ${reported}.` +
      (words === "" ? "" : ` The agent said: ${printableJson(words)}`);
    const receipt = (await this.#mind.receipt({
      about: formatRecordRef(followed.requester, followed.request),
      outcome: said.outcome,
      statement: statement.slice(0, MAX_STATEMENT),
      ...(evidence.length === 0 ? {} : { evidence }),
    } as Parameters<Mind["receipt"]>[0])) as unknown as JsonObject;
    const settled: Settled = {
      receipt,
      outcome: said.outcome,
      verb: said.outcome === "fulfilled" ? "deliver" : "inform",
      content: [...content, ...leftOut(left, ANSWER, true)],
    };
    // Written down before it leaves: a task has one Receipt, whatever stops the pass.
    this.#tasks.put(task.id, { ...followed, settled });
    await this.#finish(task.id, followed, settled, true);
  }

  /** Publishes the Receipt of a task that ended and brings it to the requester, and is done with the task. */
  async #finish(
    taskId: string,
    followed: Followed,
    settled: Settled,
    fresh: boolean,
  ): Promise<void> {
    const { receipt } = settled;
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
    this.#did.receipts.push({ id, outcome: settled.outcome, about: followed.request });
    await this.#send(followed, settled.verb, [...settled.content, carried(receipt)]);
    this.#drop(taskId, followed);
  }

  /** Is done with a task: it is followed no more, and what it asked is no question any more. */
  #drop(taskId: string, followed: Followed): void {
    if (followed.question !== undefined) this.#questions.delete(followed.question);
    this.#tasks.delete(taskId);
  }
}
