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

import { readdirSync } from "node:fs";
import { join } from "node:path";

import { fileNameOf, Store } from "@oip/local";

import type { A2aMessage, Artifact } from "./a2a.ts";
import type { TaskState } from "./mapping.ts";

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
  /**
   * The gateway's Receipt of a client's cancelling, from when it is signed
   * until the mind has been told: a cancelling that is asked for again is
   * told with the same Receipt.
   */
  readonly cancelling?: Readonly<Record<string, unknown>>;
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

/**
 * How long a task is kept after its state last changed: thirty days. One
 * that has ended is history by then, and one that has not is a task whose
 * mind never answered.
 */
export const MAX_KEPT_SECONDS = 2_592_000;
/** The most tasks of one mind that are kept. */
export const MAX_TASKS = 4096;
/** How long the session of a context is kept after the context was last used, where no task of it is kept: a day. */
export const MAX_IDLE_CONTEXT_SECONDS = 86_400;
/** How long a task is kept that no client was told of: a day. */
export const MAX_UNANNOUNCED_SECONDS = 86_400;

/** Where a task stands among the tasks of a listing: the newest state first, and one order for equal times. */
const place = ({ at, id }: Held): string => `${at} ${id}`;

const encoded = (text: string): string => Buffer.from(text, "utf8").toString("base64url");

/** The session of a mind's context, and when the context was last used. */
interface Context {
  readonly mind: string;
  readonly contextId: string;
  readonly session: string;
  readonly at: string;
}

/** The tasks, the packets that began or went on with them, and the sessions of their contexts. */
export class Book {
  readonly #dir: string;
  /** The tasks of each mind, in a directory of the mind's own: a listing reads one mind's tasks. */
  readonly #tasks = new Map<string, Store<Held>>();
  readonly #packets: Store<string>;
  readonly #contexts: Store<Context>;
  readonly #passed: Store<string>;

  /** @param dir - The directory the book is kept in. */
  constructor(dir: string) {
    this.#dir = join(dir, "tasks");
    this.#packets = new Store(join(dir, "packets"));
    this.#contexts = new Store(join(dir, "contexts"));
    this.#passed = new Store(join(dir, "passed"));
  }

  /** The tasks of a mind. */
  #of(mind: string): Store<Held> {
    const known = this.#tasks.get(mind);
    if (known !== undefined) return known;
    const made = new Store<Held>(join(this.#dir, fileNameOf(mind)));
    this.#tasks.set(mind, made);
    return made;
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

  /** A task of a mind, by the name the gateway gave it. Another mind's task is none of this mind's. */
  get(mind: string, id: string): Held | undefined {
    const task = this.#of(mind).get(id);
    return task?.mind === mind && task.id === id ? task : undefined;
  }

  /** Keeps a task as it is now. */
  put(task: Held): void {
    this.#of(task.mind).put(task.id, task);
  }

  /** Forgets a task that no client was told of. */
  drop(mind: string, id: string): void {
    this.#of(mind).delete(id);
  }

  /** How many tasks of a mind are kept. */
  count(mind: string): number {
    return this.#of(mind).all().length;
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
    return this.#contexts.get(JSON.stringify([mind, contextId]))?.session;
  }

  /**
   * Notes the session of a mind's context, and that the context is in use.
   *
   * @param at - The time now, as `Held.at` has one.
   */
  context(mind: string, contextId: string, session: string, at: string): void {
    this.#contexts.put(JSON.stringify([mind, contextId]), { mind, contextId, session, at });
  }

  /**
   * The tasks of a mind that a client was told of, the one whose state is
   * newest first (A2A, 3.1.4), a page at a time.
   *
   * @returns `undefined` if the page token is none this book gave.
   */
  list(asked: Asked): Page | undefined {
    const all = this.#of(asked.mind)
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
   * Forgets what is kept no longer: tasks whose state last changed thirty
   * days ago, tasks no client was told of that are a day old, the packets
   * of both, the packets that were brought for others and can be accepted
   * no more, and the contexts that have no task and were last used a day ago.
   *
   * @param ago - The timestamp a number of seconds before now.
   * @returns How many tasks were forgotten, and the sessions of the
   *   contexts that were: nothing more is said in them.
   */
  sweep(ago: (seconds: number) => string): { forgotten: number; sessions: string[] } {
    const changed = ago(MAX_KEPT_SECONDS);
    const untold = ago(MAX_UNANNOUNCED_SECONDS);
    const kept = new Set<string>();
    const used = new Set<string>();
    let forgotten = 0;
    let minds: string[];
    try {
      minds = readdirSync(this.#dir);
    } catch {
      // No task was ever kept.
      minds = [];
    }
    for (const name of minds) {
      const tasks = new Store<Held>(join(this.#dir, name));
      for (const { key, value } of tasks.all()) {
        // A task that has not ended and has not changed in thirty days is one whose mind never
        // answered: it is kept no longer than one that ended.
        const old = value.announced ? value.at < changed : value.at < untold;
        if (old) {
          tasks.delete(key);
          forgotten += 1;
        } else {
          kept.add(key);
          used.add(JSON.stringify([value.mind, value.contextId]));
        }
      }
    }
    for (const { key, value } of this.#packets.all()) {
      if (!kept.has(value)) this.#packets.delete(key);
    }
    const now = ago(0);
    for (const { key, value } of this.#passed.all()) {
      if (value < now) this.#passed.delete(key);
    }
    const idle = ago(MAX_IDLE_CONTEXT_SECONDS);
    const sessions: string[] = [];
    for (const { key, value } of this.#contexts.all()) {
      if (used.has(key) || value.at >= idle) continue;
      this.#contexts.delete(key);
      sessions.push(value.session);
    }
    return { forgotten, sessions: sessions.sort() };
  }
}
