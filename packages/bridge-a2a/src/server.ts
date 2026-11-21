// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The A2A interface of the minds a gateway serves (Layer 0, 3.2): the
 * JSON-RPC binding of A2A 1.0 (Section 9), and each mind's Agent Card.
 *
 * Whoever asks is a stranger. A request is read within limits and member
 * by member, and is answered with an error of A2A if it is not what A2A
 * says it is. What goes wrong inside the gateway is answered with an
 * internal error that says nothing of the inside.
 *
 * This is the protocol alone: a request is a method, a path, headers and a
 * body, and so is the answer. How requests arrive is the caller's.
 */

import { sha256 } from "@oip/core";

import { type A2aMessage, Malformed, MAX_ID, readMessage } from "./a2a.ts";
import type { Held } from "./book.ts";
import { A2A_VERSION, CARD_PATH } from "./card.ts";
import {
  Fault,
  internal,
  invalidParams,
  invalidRequest,
  methodNotFound,
  parseError,
  pushNotSupported,
  unsupported,
  versionNotSupported,
} from "./fault.ts";
import type { Front, ServedMind } from "./front.ts";
import { TASK_STATES, type TaskState } from "./mapping.ts";

/** A request, as it arrived. */
export interface Asking {
  /** The HTTP method. */
  readonly method: string;
  /** The path of the URL, with its query if it has one. */
  readonly path: string;
  /** The headers, by their names in lower case. */
  readonly headers: Readonly<Record<string, string | undefined>>;
  readonly body: Uint8Array;
}

/** What is answered. */
export interface Answer {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Uint8Array;
}

/** The longest request that is read, in bytes: a packet is a megabyte at most. */
export const MAX_REQUEST_BYTES = 1_048_576;
/** How many tasks a page of a listing holds where the client names no size, and at most (A2A, 3.1.4). */
const DEFAULT_PAGE = 50;
const MAX_PAGE = 100;
/** How long a card may be kept by who fetched it, in seconds (A2A, 8.6.1). */
const CARD_MAX_AGE = 300;
/** What an `ErrorInfo` names as the domain of the errors of A2A (A2A, 9.5). */
const ERROR_DOMAIN = "a2a-protocol.org";

/** A time with its date and its zone, as A2A writes one (A2A, 5.6.1). */
const ISO_TIME = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)$/u;

const JSON_TYPE = "application/json";
const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

const isObject = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

const json = (status: number, value: unknown, more: Record<string, string> = {}): Answer => ({
  status,
  headers: { "content-type": JSON_TYPE, ...more },
  body: utf8(JSON.stringify(value)),
});

const plain = (status: number, text: string): Answer => ({
  status,
  headers: { "content-type": "text/plain; charset=utf-8" },
  body: utf8(text),
});

/** A whole number of a request that is zero or more, or `undefined` where none is given. */
function count(value: unknown, name: string): number | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw invalidParams(`${name} is a whole number, zero or more.`);
  }
  return value;
}

/** The name of a task in a request. */
function taskId(params: Readonly<Record<string, unknown>>): string {
  const { id } = params;
  if (typeof id !== "string" || id === "" || id.length > MAX_ID) {
    throw invalidParams("id names the task: a text.");
  }
  return id;
}

/** The version of A2A this server speaks, as a client may name it: with a patch number, or without. */
const SPOKEN = new RegExp(`^${A2A_VERSION.replace(".", "\\.")}(?:\\.\\d+)?$`, "u");

/** A task as A2A writes one (A2A, 4.1.1), with as much of its history as was asked for. */
function taskJson(
  task: Held,
  show: { readonly history: number | undefined; readonly artifacts: boolean },
): Record<string, unknown> {
  // A2A, 3.2.4: the most recent messages, as many as were asked for. None asked for: none given.
  const history =
    show.history === undefined
      ? task.history
      : show.history === 0
        ? []
        : task.history.slice(-show.history);
  return {
    id: task.id,
    contextId: task.contextId,
    status: {
      state: task.state,
      ...(task.said === undefined ? {} : { message: task.said }),
      timestamp: task.at,
    },
    ...(show.artifacts && task.artifacts.length > 0 ? { artifacts: task.artifacts } : {}),
    ...(history.length === 0 ? {} : { history }),
  };
}

/** The A2A interface of every mind a front serves. */
export class A2aServer {
  readonly #front: Front;
  readonly #prefix: string;
  readonly #failed: (error: unknown) => void;

  /**
   * @param prefix - The path the minds are served under, as the front's
   *   `base` has it: `/a2a` for `https://gateway.example/a2a`.
   * @param failed - Told of what went wrong inside the gateway, to log it.
   *   The client is told only that something did.
   */
  constructor(front: Front, prefix: string, failed: (error: unknown) => void = () => undefined) {
    this.#front = front;
    this.#prefix = prefix.replace(/\/+$/u, "");
    this.#failed = failed;
  }

  /** Answers one request. It does not throw. */
  async handle(asked: Asking): Promise<Answer> {
    try {
      return await this.#route(asked);
    } catch (error) {
      this.#failed(error);
      return plain(500, "The gateway could not answer.\n");
    }
  }

  async #route(asked: Asking): Promise<Answer> {
    const url = new URL(asked.path, "http://gateway.invalid");
    if (!url.pathname.startsWith(`${this.#prefix}/`)) return plain(404, "Not found.\n");
    const [id = "", ...rest] = url.pathname.slice(this.#prefix.length + 1).split("/");
    const under = rest.length === 0 ? "" : `/${rest.join("/")}`;
    if (under !== "" && under !== CARD_PATH) return plain(404, "Not found.\n");
    const mind = await this.#front.served(id);
    // A mind that did not ask to be served here is none this gateway speaks for.
    if (mind === undefined) return plain(404, "Not found.\n");
    if (under === CARD_PATH) {
      return asked.method === "GET" ? this.#card(mind, asked) : plain(405, "Method not allowed.\n");
    }
    if (asked.method !== "POST") return plain(405, "Method not allowed.\n");
    // A2A, 9.1: a request is JSON, and says so. A page in a browser cannot send what says so
    // to another origin without the browser asking first, and this server does not answer that.
    const [type = ""] = (asked.headers["content-type"] ?? "").split(";");
    if (type.trim().toLowerCase() !== "application/json") {
      return plain(415, "A request is JSON, and says so: Content-Type: application/json.\n");
    }
    if (asked.body.length > MAX_REQUEST_BYTES) return plain(413, "The request is too large.\n");
    const version = asked.headers["a2a-version"] ?? url.searchParams.get("A2A-Version") ?? "";
    return json(200, await this.#rpc(mind, asked.body, version));
  }

  /** The card of a mind (A2A, 8.2), with what lets a cache keep it (8.6.1). */
  #card(mind: ServedMind, asked: Asking): Answer {
    const body = utf8(JSON.stringify(mind.card));
    const etag = `"${hex(sha256(body)).slice(0, 32)}"`;
    const headers = {
      "cache-control": `public, max-age=${String(CARD_MAX_AGE)}`,
      etag,
      "last-modified": new Date(mind.modified).toUTCString(),
    };
    if (asked.headers["if-none-match"] === etag) {
      return { status: 304, headers, body: new Uint8Array() };
    }
    return { status: 200, headers: { "content-type": JSON_TYPE, ...headers }, body };
  }

  /** Answers a JSON-RPC request (A2A, 9.1): with a result, or with an error. */
  async #rpc(mind: ServedMind, body: Uint8Array, version: string): Promise<unknown> {
    let id: string | number | null = null;
    try {
      let request: unknown;
      try {
        request = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
      } catch {
        throw parseError();
      }
      if (!isObject(request) || request["jsonrpc"] !== "2.0") {
        throw invalidRequest("The request is no JSON-RPC 2.0 request.");
      }
      const { method, params = {} } = request;
      if (typeof request["id"] !== "string" && typeof request["id"] !== "number") {
        throw invalidRequest("The request has no id: every method of A2A is answered.");
      }
      id = request["id"];
      if (typeof method !== "string") throw invalidRequest("The request names no method.");
      if (!isObject(params)) throw invalidParams("params is an object.");
      // A2A, 3.6.2: no version given is 0.3, and a patch number decides nothing.
      const asked = version.trim() === "" ? "0.3" : version.trim();
      // 1.0, and 1.0 with a patch number. What begins the same is another version: 1.01, 1.0x.
      if (!SPOKEN.test(asked)) {
        throw versionNotSupported(asked.replace(/[^\x20-\x7e]/gu, " ").slice(0, 32));
      }
      return { jsonrpc: "2.0", id, result: await this.#call(mind, method, params) };
    } catch (error) {
      let fault: Fault;
      if (error instanceof Fault) {
        fault = error;
      } else {
        this.#failed(error);
        fault = internal("The agent could not do that.");
      }
      return {
        jsonrpc: "2.0",
        id,
        error: {
          code: fault.code,
          message: fault.message,
          // A2A, 9.5: an error of A2A says which it is in an ErrorInfo.
          ...(fault.reason === undefined
            ? {}
            : {
                data: [
                  {
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    reason: fault.reason,
                    domain: ERROR_DOMAIN,
                  },
                ],
              }),
        },
      };
    }
  }

  /** Does what a method asks, and gives its result. @throws Fault */
  async #call(
    mind: ServedMind,
    method: string,
    params: Readonly<Record<string, unknown>>,
  ): Promise<unknown> {
    switch (method) {
      case "SendMessage":
        return this.#send(mind, params);
      case "GetTask": {
        const history = count(params["historyLength"], "historyLength");
        return taskJson(this.#front.get(mind, taskId(params)), { history, artifacts: true });
      }
      case "ListTasks":
        return this.#list(mind, params);
      case "CancelTask":
        return taskJson(await this.#front.cancel(mind, taskId(params)), {
          history: undefined,
          artifacts: true,
        });
      case "SendStreamingMessage":
      case "SubscribeToTask":
        // A2A, 3.3.4: the card says that this agent does not stream.
        throw unsupported(
          "This agent does not stream: send with SendMessage, and ask for the task with GetTask.",
        );
      case "GetExtendedAgentCard":
        throw unsupported("This agent has no extended card.");
      case "CreateTaskPushNotificationConfig":
      case "GetTaskPushNotificationConfig":
      case "ListTaskPushNotificationConfigs":
      case "DeleteTaskPushNotificationConfig":
        throw pushNotSupported();
      default:
        throw methodNotFound(method.replace(/[^\x20-\x7e]/gu, " ").slice(0, 64));
    }
  }

  async #send(mind: ServedMind, params: Readonly<Record<string, unknown>>): Promise<unknown> {
    let message: A2aMessage;
    try {
      message = readMessage(params["message"]);
    } catch (error) {
      if (!(error instanceof Malformed)) throw error;
      throw invalidParams(`message is no message of A2A: ${error.message}.`);
    }
    if (message.role !== "ROLE_USER")
      throw invalidParams("A client's message has the role of a user.");
    const { configuration = {} } = params;
    if (!isObject(configuration)) throw invalidParams("configuration is an object.");
    if (isObject(configuration["taskPushNotificationConfig"])) throw pushNotSupported();
    const history = count(configuration["historyLength"], "historyLength");
    const answered = await this.#front.send(mind, message, {
      returnImmediately: configuration["returnImmediately"] === true,
    });
    return "task" in answered
      ? { task: taskJson(answered.task, { history, artifacts: true }) }
      : { message: answered.message };
  }

  #list(mind: ServedMind, params: Readonly<Record<string, unknown>>): unknown {
    const { contextId, status, pageToken, statusTimestampAfter, includeArtifacts } = params;
    if (contextId !== undefined && (typeof contextId !== "string" || contextId.length > MAX_ID)) {
      throw invalidParams("contextId is a text.");
    }
    const state = TASK_STATES.find((known) => known === status);
    // The state that says "any" is how a client that names none is written.
    if (status !== undefined && status !== "TASK_STATE_UNSPECIFIED" && state === undefined) {
      throw invalidParams("status is no state of a task.");
    }
    if (pageToken !== undefined && (typeof pageToken !== "string" || pageToken.length > 1024)) {
      throw invalidParams("pageToken is a text.");
    }
    let since: number | undefined;
    if (statusTimestampAfter !== undefined) {
      // A time as ISO 8601 writes one, and nothing else that some parser of dates would take.
      since =
        typeof statusTimestampAfter === "string" && ISO_TIME.test(statusTimestampAfter)
          ? Date.parse(statusTimestampAfter)
          : Number.NaN;
      if (Number.isNaN(since)) {
        throw invalidParams("statusTimestampAfter is a time, as ISO 8601 writes one.");
      }
    }
    const pageSize = count(params["pageSize"], "pageSize") ?? DEFAULT_PAGE;
    if (pageSize < 1 || pageSize > MAX_PAGE) {
      throw invalidParams(`pageSize is from 1 to ${String(MAX_PAGE)}.`);
    }
    const history = count(params["historyLength"], "historyLength");
    // Nobody says who a client is: a name of a task or of a context is all that it shows. So the
    // tasks a client is shown are those of a context it can name (A2A, 3.1.4), and no others.
    if (typeof contextId !== "string" || contextId === "") {
      return { tasks: [], nextPageToken: "", pageSize, totalSize: 0 };
    }
    const page = this.#front.list(mind, {
      contextId,
      ...(state === undefined ? {} : { state: state satisfies TaskState }),
      ...(since === undefined ? {} : { since: new Date(since).toISOString() }),
      pageSize,
      ...(typeof pageToken === "string" && pageToken !== "" ? { pageToken } : {}),
    });
    return {
      // A2A, 3.1.4: artifacts are left out unless they are asked for.
      tasks: page.tasks.map((task) =>
        taskJson(task, { history, artifacts: includeArtifacts === true }),
      ),
      nextPageToken: page.next,
      pageSize,
      totalSize: page.total,
    };
  }
}
