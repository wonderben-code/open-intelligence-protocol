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
 * agent report, and no more. The one thing in its statement that is the
 * agent's own, the name of the task, is quoted as a string of JSON in
 * ASCII, so that nothing in it can be read as the gateway's.
 *
 * A Receipt is brought to the requester, in the packet that carries what
 * the agent delivered, and is not published: the request came to the
 * bridged mind alone, and a feed would tell everybody who asked, the
 * agent's name for the task, and where its files are (ADR-0034).
 *
 * What a pass does, it does once:
 *
 * - a packet is written down before the client notes that it arrived, and
 *   is not sent to the agent again once the agent has answered it. If a
 *   pass stops before that, the next sends the message again under the
 *   same ID, which is the packet's own, so that the agent can tell;
 * - what the agent answered is written down before the packet is done
 *   with, and what a task ended with before a Receipt is signed for it: a
 *   pass that stops after that is finished by the next from what was
 *   written, with the same Receipt. No second one is signed for a task,
 *   and an agent's files are fetched once.
 *
 * And nothing is tried for ever. A request that could not be passed on
 * before it expired is answered with an `error`. An agent that cannot be
 * reached is asked once in a pass, and not again in it. Whatever an agent
 * sends, the requester is told something: text that no record holds is
 * mended before it is carried (`recordText`), and where a packet still
 * cannot be made, the gateway says so in words of its own.
 */

import { join } from "node:path";

import { carried, type Clock, type Message, type Mind } from "@oip/client";
import {
  CLOCK_SKEW,
  contentId,
  formatRecordRef,
  formatTimestamp,
  type JsonObject,
  OipError,
  parseTimestamp,
} from "@oip/core";
import { Arrivals, asciiJson, type KeptPacket, type Opened, recordText, Store } from "@oip/local";

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
import { type Content, gather, leftOut, partsOf } from "./content.ts";
import type { Bridged } from "./gateway.ts";
import { OIP_EXTENSION, OIP_MEDIA_TYPE, saidOf } from "./mapping.ts";

/** What a relay reaches outside itself with, and its clock. */
export interface RelayEdges {
  /** Makes a request of the agent. */
  readonly ask: Ask;
  /** Gets a file an agent names by its URL, to say which bytes were there. */
  readonly get: Get;
  readonly clock: Clock;
  /**
   * Whether the pass has had the time it may take. Asked before each piece
   * of work: once it says so, what is left waits for the next pass. Default:
   * a pass has all the time it needs.
   */
  readonly spent?: () => boolean;
}

/** What an agent answered a request with at once, until the requester has it. */
interface Answer {
  readonly requester: string;
  readonly request: string;
  readonly session?: string;
  /** When the agent answered. */
  readonly since: string;
  readonly content: readonly Content[];
}

/** What a task ended with, as the gateway first saw it: gathered once, with the agent's files fetched once. */
interface Ended {
  readonly outcome: "fulfilled" | "broken" | "cancelled";
  /** The state the agent reported, in A2A's word. */
  readonly reported: string;
  /** What the agent said and delivered, as the packet carries it. */
  readonly content: readonly Content[];
  /** Evidence of what the gateway was shown (Layer 2, Section 9). */
  readonly evidence: readonly JsonObject[];
}

/** What was signed for the end of a task, until the requester has it. */
interface Settled {
  readonly receipt: JsonObject;
  readonly outcome: string;
  readonly verb: "deliver" | "inform";
  /** What the agent said and delivered, as the packet carries it. */
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
  /** What the task ended with, from when the gateway saw that it had ended. */
  readonly ended?: Ended;
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
  /** Receipts brought to the requesters of tasks that ended, by content ID, with their outcome. */
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
   * answered, until it expires.
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
/** The most tasks of one agent the gateway follows at a time. */
export const MAX_OPEN_TASKS = 256;
/** How long the gateway follows a task that does not end, or keeps what it could not bring: thirty days. */
export const MAX_FOLLOWED_SECONDS = 2_592_000;
/**
 * How long a request that names no time of its own waits to be passed on:
 * a day. A packet of a session carries no `expires` (Layer 1, 12.1).
 */
export const MAX_WAITING_SECONDS = 86_400;
/** What an agent's parts are of, in a word to a requester about those that are left out. */
const ANSWER = "the agent's answer";
/** A2A, Section 5.4: the agent has no such task. */
const TASK_NOT_FOUND = -32001;

const SECOND = 1_000_000_000n;

/** A place in the agent's own naming, for an evidence item's `ref`: ASCII, whatever the agent wrote. */
const named = (id: string): string => encodeURIComponent(recordText(id));

/** Whether what a mind was to sign could not be made a record: nothing that trying again mends. */
const unsignable = (error: unknown): boolean =>
  error instanceof OipError && error.code === "invalid-record";

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
  readonly #answers: Store<Answer>;
  /** The tasks this pass was told of by the agent: they are not asked about again in it. */
  readonly #told = new Set<string>();
  /** Whether the agent could not be reached in this pass: it is not asked again in it. */
  #silent = false;
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
    this.#answers = new Store(join(dir, "answers"));
  }

  /**
   * Brings what an earlier pass could not, reads the mailbox, passes on
   * what is asked of the agent, and follows the tasks that are open.
   */
  async pass(): Promise<Relayed> {
    const spent = (): boolean => this.#edges.spent?.() === true;
    for (const { key, value } of this.#answers.all()) {
      if (spent()) break;
      await this.#attempt({ packet: key }, () => this.#bring(key, value));
    }
    const waiting = await this.#arrivals.waiting();
    for (const kept of waiting) {
      if (spent()) break;
      await this.#attempt({ packet: kept.id }, () => this.#handle(kept));
    }
    for (const { key, value } of this.#tasks.all()) {
      if (spent()) break;
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

  /** How long ago a moment was, as the relay's clock has it. What is no moment was never. */
  #since(moment: string): bigint {
    const then = parseTimestamp(moment);
    return then === undefined ? 0n : this.#edges.clock.now() - then;
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

  /**
   * Sends what is the agent's. Where no packet can be made of it, the
   * requester is told so in the gateway's own words, with whatever of the
   * gateway's own was to go with it: trying again would not mend it.
   *
   * @param own - What of the content is the gateway's own: a Receipt, say.
   */
  async #carry(
    about: Pick<Followed, "requester" | "request" | "session">,
    verb: string,
    content: readonly Content[],
    own: readonly Content[] = [],
  ): Promise<string> {
    try {
      return await this.#send(about, verb, [...content, ...own]);
    } catch (error) {
      if (!unsignable(error)) throw error;
      const words =
        `The agent at ${this.#bridged.origin} answered, and the gateway cannot carry its answer: ` +
        "it is nothing a packet holds.";
      return this.#send(about, own.length === 0 ? "error" : verb, [
        { mediaType: "text/plain", body: words },
        ...own,
      ]);
    }
  }

  /** Whether a request that waits has waited as long as it may. */
  #expired({ packet, time }: KeptPacket): boolean {
    const expires = packet.expires === undefined ? undefined : parseTimestamp(packet.expires);
    // The time its sender gave it, with the allowance a receiver makes for two clocks (12.4).
    if (expires !== undefined) return this.#edges.clock.now() > expires + CLOCK_SKEW;
    return this.#since(time) > BigInt(MAX_WAITING_SECONDS) * SECOND;
  }

  /** Brings a requester what the agent answered its request with, and is done with it. */
  async #bring(request: string, answer: Answer): Promise<void> {
    // The agent has answered: the packet is not sent to it again, whatever stopped an earlier pass.
    this.#arrivals.done(request);
    if (this.#since(answer.since) <= BigInt(MAX_FOLLOWED_SECONDS) * SECOND) {
      await this.#carry(answer, "inform", answer.content);
    }
    // What could not be brought in thirty days is brought no more.
    this.#answers.delete(request);
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
    if (this.#expired(kept)) {
      // Its sender has stopped waiting, and the agent is not asked for what nobody waits for.
      await this.#tell(
        about,
        `The gateway could not pass this request on to the agent at ${this.#bridged.origin} ` +
          "before it expired. The agent was not asked.",
      );
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
    // The agent did not answer a moment ago: this packet waits for the next pass.
    if (this.#silent) return;
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
      if (!(error instanceof A2aError)) {
        // The agent could not be reached. It is not asked again in this pass, for this packet
        // or for any other: each would wait as long for nothing.
        this.#silent = true;
        throw error;
      }
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
      const { content, left } = await gather(
        answered.message.parts.map((part) => ({ part, ref: "" })),
      );
      const said: Answer = {
        ...about,
        since: formatTimestamp(this.#edges.clock.now()),
        content: [...content, ...leftOut(left, ANSWER, false)],
      };
      // The agent has answered. What it said is written down before the packet is done with:
      // from here on the packet is not sent to the agent again, and its answer is not lost.
      this.#answers.put(id, said);
      this.#arrivals.done(id);
      this.#finishQuestion(packet.replyTo, question);
      this.#did.passed.push(id);
      await this.#bring(id, said);
      return;
    }
    const { task } = answered;
    const before = this.#tasks.get(task.id);
    if (before !== undefined && question === undefined && before.request !== id) {
      // The agent answered with a task that the gateway follows for another request. What
      // becomes of that task is said to whoever asked for it, and nothing here would ever be
      // said of this request: its sender is told now.
      await this.#tell(
        about,
        `The agent at ${this.#bridged.origin} answered this request with a task it took on for ` +
          "another. The gateway does not follow it for this one.",
      );
      this.#arrivals.done(id);
      this.#did.passed.push(id);
      return;
    }
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
    const old = this.#since(followed.since) > BigInt(MAX_FOLLOWED_SECONDS) * SECOND;
    if (followed.settled !== undefined) {
      // A Receipt was signed and the pass stopped: it is finished with that Receipt. One that
      // could not be brought in thirty days is brought no more.
      if (old) this.#drop(taskId, followed);
      else await this.#finish(taskId, followed, followed.settled);
      return;
    }
    if (followed.ended !== undefined) {
      // The task had ended and the pass stopped before a Receipt was signed: it is signed now,
      // for what the gateway saw then. The agent is not asked again, and its files not fetched again.
      await this.#sign(taskId, followed, followed.ended);
      return;
    }
    // The agent's name for the task, as a string of JSON in ASCII: whatever is in it, it is
    // text a record holds and nothing that reads as the gateway's words.
    const name = asciiJson(taskId);
    if (old) {
      await this.#tell(
        followed,
        `The gateway no longer follows task ${name} of the agent at ${this.#bridged.origin}: ` +
          "the agent reported no end of it in thirty days. The gateway does not know what became of it.",
      );
      this.#drop(taskId, followed);
      return;
    }
    // The agent did not answer a moment ago: the task waits for the next pass.
    if (this.#silent) return;
    let task: Task;
    try {
      task = await getTask(this.#agent, taskId);
    } catch (error) {
      if (error instanceof A2aError && error.code === TASK_NOT_FOUND) {
        await this.#tell(
          followed,
          `The agent at ${this.#bridged.origin} no longer knows task ${name}. ` +
            "The gateway does not know what became of it.",
        );
        this.#drop(taskId, followed);
        return;
      }
      if (!(error instanceof A2aError)) this.#silent = true;
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
    // What the agent says with the state: its words, and whatever else it gives. A sign-in is a URL.
    const words = (task.said?.parts ?? []).map((part, index) => ({
      part,
      ref: `a2a:task/${named(task.id)}/status/part/${String(index)}`,
    }));
    if (said.as === "packet") {
      const { content, left } = await gather(words);
      const body =
        said.verb === "decline"
          ? "The agent declined the request."
          : "The agent needs more before it can go on.";
      const sent = await this.#carry(
        followed,
        said.verb,
        content.length === 0
          ? [{ mediaType: "text/plain", body }]
          : [...content, ...leftOut(left, ANSWER, false)],
      );
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
    // The task has ended. What the agent said and delivered is gathered once, with its files
    // fetched once, and written down before anything is signed.
    const { content, evidence, left } = await gather(
      [
        ...words,
        ...task.artifacts.flatMap((artifact) =>
          artifact.parts.map((part, index) => ({
            part,
            ref: `a2a:task/${named(task.id)}/artifact/${named(artifact.artifactId)}/part/${String(index)}`,
          })),
        ),
      ],
      this.#edges.get,
    );
    const ended: Ended = {
      outcome: said.outcome,
      reported: { fulfilled: "completed", broken: "failed", cancelled: "canceled" }[said.outcome],
      content: [...content, ...leftOut(left, ANSWER, true)],
      evidence,
    };
    const known = { ...followed, ended };
    this.#tasks.put(task.id, known);
    await this.#sign(task.id, known, ended);
  }

  /** Signs the Receipt of a task that ended: what the gateway observed, and no more (Layer 0, 1.4). */
  async #sign(taskId: string, followed: Followed, ended: Ended): Promise<void> {
    // The name of the task is the agent's. It is quoted as a string of JSON in ASCII, which no
    // text can end early or dress up, so that it does not read as words of the gateway. The
    // agent's own words are not in the statement at all: they are in the packet.
    const statement =
      `The gateway observed the A2A agent at ${this.#bridged.origin} report task ` +
      `${asciiJson(taskId)} as ${ended.reported}.`;
    let receipt: JsonObject;
    try {
      receipt = (await this.#mind.receipt({
        about: formatRecordRef(followed.requester, followed.request),
        outcome: ended.outcome,
        statement,
        ...(ended.evidence.length === 0 ? {} : { evidence: ended.evidence }),
      } as Parameters<Mind["receipt"]>[0])) as unknown as JsonObject;
    } catch (error) {
      if (!unsignable(error)) throw error;
      // Nothing of an agent's should be able to keep a Receipt from being made. If something
      // does, the requester is told, and the task is not asked about for ever.
      await this.#tell(
        followed,
        `The agent at ${this.#bridged.origin} reported task ${asciiJson(taskId)} as ${ended.reported}, ` +
          "and the gateway could not make a Receipt of what it was shown.",
      );
      this.#drop(taskId, followed);
      return;
    }
    const settled: Settled = {
      receipt,
      outcome: ended.outcome,
      verb: ended.outcome === "fulfilled" ? "deliver" : "inform",
      content: ended.content,
    };
    // Written down before it leaves: a task has one Receipt, whatever stops the pass.
    this.#tasks.put(taskId, { ...followed, settled });
    await this.#finish(taskId, followed, settled);
  }

  /** Brings the Receipt of a task that ended to the requester, with what was delivered, and is done with the task. */
  async #finish(taskId: string, followed: Followed, settled: Settled): Promise<void> {
    const { receipt } = settled;
    // After a stop the mind holds its Receipt again, to judge by.
    this.#mind.hold(receipt);
    await this.#carry(followed, settled.verb, settled.content, [carried(receipt)]);
    this.#did.receipts.push({
      id: contentId(receipt),
      outcome: settled.outcome,
      about: followed.request,
    });
    this.#drop(taskId, followed);
  }

  /** Is done with a task: it is followed no more, and what it asked is no question any more. */
  #drop(taskId: string, followed: Followed): void {
    if (followed.question !== undefined) this.#questions.delete(followed.question);
    this.#tasks.delete(taskId);
  }
}
