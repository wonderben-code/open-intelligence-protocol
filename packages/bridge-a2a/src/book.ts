// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The tasks a gateway holds for the minds it serves as A2A agents (Layer 0,
 * 3.2).
 *
 * To an A2A client a mind is an agent with tasks. A mind has none: it has
 * packets. So the gateway keeps each task itself: the state the mind's
 * answers have brought it to, what was delivered, and what was said, with
 * the packets and the session that carry it on the mind's side.
 */

import { join } from "node:path";

import { Store } from "@oip/local";

import type { A2aMessage, Artifact } from "./a2a.ts";
import { isTerminal, type TaskState } from "./mapping.ts";

/** A task, as the gateway holds it. */
export interface Held {
  readonly id: string;
  /** The mind the task is asked of, by its address. */
  readonly mind: string;
  readonly contextId: string;
  readonly state: TaskState;
  /** What was said with the state: the mind's words, as an A2A message. */
  readonly said?: A2aMessage;
  /**
   * When the state was set: a time in UTC, always written with its
   * milliseconds, so that two of them are in order as texts are.
   */
  readonly at: string;
  /** What the mind delivered. */
  readonly artifacts: readonly Artifact[];
  /** What was said in the task, by the client and by the mind, oldest first. */
  readonly history: readonly A2aMessage[];
  /** The session the task's packets are of (Layer 0, 3.1: a context is a session). */
  readonly session: string;
  /** The gateway's packet that began the task, by content ID. */
  readonly request: string;
  /** The mind's packet that asked for more, by content ID, while the task waits for the answer. */
  readonly question?: string;
  /**
   * Whether an A2A client was told of the task. One that was not is not
   * listed, and ends as a message if the mind answers with one.
   */
  readonly announced: boolean;
  /** The mind's answer where it answered with a message, and no client was told of a task. */
  readonly answer?: A2aMessage;
}

/** Which tasks of a mind are asked for (A2A, 3.1.4). */
export interface Asked {
  readonly mind: string;
  readonly contextId?: string;
  readonly state?: TaskState;
  /** Only tasks whose state was set at this time or later. */
  readonly since?: string;
  readonly pageSize: number;
  /** Where the page begins: what the page before gave as `next`. */
  readonly pageToken?: string;
}

/** One page of tasks. */
export interface Page {
  readonly tasks: readonly Held[];
  /** Where the next page begins, or the empty text after the last. */
  readonly next: string;
  /** How many tasks there are, on all pages. */
  readonly total: number;
}

/** How long a task that has ended is kept: thirty days. */
export const MAX_KEPT_SECONDS = 2_592_000;
/** How long a task is kept that no client was told of: a day. */
export const MAX_UNANNOUNCED_SECONDS = 86_400;

/** Where a task stands among the tasks of a listing: the newest state first, and one order for equal times. */
const place = ({ at, id }: Held): string => `${at} ${id}`;

const encoded = (text: string): string => Buffer.from(text, "utf8").toString("base64url");

/** The tasks, the packets that began or went on with them, and the sessions of their contexts. */
export class Book {
  readonly #tasks: Store<Held>;
  readonly #packets: Store<string>;
  readonly #contexts: Store<string>;
  readonly #passed: Store<string>;

  /** @param dir - The directory the book is kept in. */
  constructor(dir: string) {
    this.#tasks = new Store(join(dir, "tasks"));
    this.#packets = new Store(join(dir, "packets"));
    this.#contexts = new Store(join(dir, "contexts"));
    this.#passed = new Store(join(dir, "passed"));
  }

  /**
   * Notes that a packet of another mind's was brought to the mind it is
   * for (Layer 0, 3.3), until a time: after it the packet can be accepted
   * by nobody, and need not be remembered (Layer 1, 12.4).
   */
  pass(packet: string, until: string): void {
    this.#passed.put(packet, until);
  }

  /** Whether a packet of another mind's was brought before. */
  wasPassed(packet: string): boolean {
    return this.#passed.get(packet) !== undefined;
  }

  /** A task, by the name the gateway gave it. */
  get(id: string): Held | undefined {
    return this.#tasks.get(id);
  }

  /** Keeps a task as it is now. */
  put(task: Held): void {
    this.#tasks.put(task.id, task);
  }

  /** Forgets a task that no client was told of. */
  drop(id: string): void {
    this.#tasks.delete(id);
  }

  /** Notes that a packet the gateway sent is of a task: an answer to it is an answer in that task. */
  sent(packet: string, task: string): void {
    this.#packets.put(packet, task);
  }

  /** The task a packet of the gateway's is of, if it is of one. */
  taskOf(packet: string): string | undefined {
    return this.#packets.get(packet);
  }

  /** The session of a mind's context, if the context has one. */
  session(mind: string, contextId: string): string | undefined {
    return this.#contexts.get(JSON.stringify([mind, contextId]));
  }

  /** Notes the session of a mind's context. */
  context(mind: string, contextId: string, session: string): void {
    this.#contexts.put(JSON.stringify([mind, contextId]), session);
  }

  /**
   * The tasks of a mind that a client was told of, the one whose state is
   * newest first (A2A, 3.1.4), a page at a time.
   *
   * @returns `undefined` if the page token is none this book gave.
   */
  list(asked: Asked): Page | undefined {
    const all = this.#tasks
      .all()
      .map(({ value }) => value)
      .filter(
        (task) =>
          task.announced &&
          task.mind === asked.mind &&
          (asked.contextId === undefined || task.contextId === asked.contextId) &&
          (asked.state === undefined || task.state === asked.state) &&
          (asked.since === undefined || task.at >= asked.since),
      )
      .sort((one, other) => (place(one) > place(other) ? -1 : 1));
    let from = 0;
    if (asked.pageToken !== undefined && asked.pageToken !== "") {
      // A token names the last task of the page before. Tasks whose state has changed since have
      // moved to the front, and are not given twice for it.
      const before = Buffer.from(asked.pageToken, "base64url").toString("utf8");
      if (encoded(before) !== asked.pageToken || !/^\S+ \S+$/u.test(before)) return undefined;
      from = all.findIndex((task) => place(task) < before);
      if (from === -1) from = all.length;
    }
    const tasks = all.slice(from, from + asked.pageSize);
    const last = tasks.at(-1);
    const more = from + tasks.length < all.length;
    return {
      tasks,
      next: more && last !== undefined ? encoded(place(last)) : "",
      total: all.length,
    };
  }

  /**
   * Forgets what is kept no longer: tasks that ended thirty days ago, tasks
   * no client was told of that are a day old, the packets of both, and the
   * packets that were brought for others and can be accepted no more.
   *
   * @param ago - The timestamp a number of seconds before now.
   * @returns How many tasks were forgotten.
   */
  sweep(ago: (seconds: number) => string): number {
    const ended = ago(MAX_KEPT_SECONDS);
    const untold = ago(MAX_UNANNOUNCED_SECONDS);
    const kept = new Set<string>();
    let forgotten = 0;
    for (const { key, value } of this.#tasks.all()) {
      const old = value.announced ? isTerminal(value.state) && value.at < ended : value.at < untold;
      if (old) {
        this.#tasks.delete(key);
        forgotten += 1;
      } else {
        kept.add(key);
      }
    }
    for (const { key, value } of this.#packets.all()) {
      if (!kept.has(value)) this.#packets.delete(key);
    }
    const now = ago(0);
    for (const { key, value } of this.#passed.all()) {
      if (value < now) this.#passed.delete(key);
    }
    return forgotten;
  }
}
