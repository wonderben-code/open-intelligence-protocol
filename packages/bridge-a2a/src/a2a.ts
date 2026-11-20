// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Speaking A2A to an agent: the JSON-RPC binding of A2A 1.0 (Section 9),
 * as far as a gateway uses it.
 *
 * An agent is a stranger, and so is whatever answers at the URL its card
 * names. A response is read within limits and member by member, and what
 * is not what A2A says it is, is refused: nothing of it is passed on.
 * How a request leaves this process is the caller's (`Ask`): a gateway
 * gives the guarded fetcher, and a test gives an agent of its own.
 */

import { A2A_VERSION, type AgentInterface } from "./card.ts";
import { TASK_STATES, type TaskState } from "./mapping.ts";

/** One part of a message or of an artifact (A2A, `Part`): a text, bytes, a URL, or structured data. */
export type Part = (
  | { readonly text: string }
  /** Bytes, as base64. */
  | { readonly raw: string }
  | { readonly url: string }
  | { readonly data: unknown }
) & {
  readonly mediaType?: string;
  readonly filename?: string;
};

/** A message (A2A, `Message`), as far as a gateway reads one. */
export interface A2aMessage {
  readonly messageId: string;
  readonly role: "ROLE_USER" | "ROLE_AGENT";
  readonly parts: readonly Part[];
  readonly contextId?: string;
  readonly taskId?: string;
}

/** Something a task produced (A2A, `Artifact`). */
export interface Artifact {
  readonly artifactId: string;
  readonly name?: string;
  readonly parts: readonly Part[];
}

/** A task (A2A, `Task`), as far as a gateway reads one. */
export interface Task {
  readonly id: string;
  readonly contextId?: string;
  /** Its state, or `undefined` for one this gateway does not know. */
  readonly state: TaskState | undefined;
  /** What the agent says with the state, if anything. */
  readonly said?: A2aMessage;
  readonly artifacts: readonly Artifact[];
}

/** What an agent answers a message with: a task it took on, or a message at once. */
export type Answered = { readonly task: Task } | { readonly message: A2aMessage };

/** A request as it leaves, and what came back. */
export type Ask = (asked: {
  readonly url: string;
  readonly body: Uint8Array;
  readonly headers: Readonly<Record<string, string>>;
}) => Promise<{ readonly status: number; readonly body: Uint8Array }>;

/** Gets a URL. The answer is given whatever its status. */
export type Get = (url: string) => Promise<{ readonly status: number; readonly body: Uint8Array }>;

/** Thrown when an agent answers with an error of A2A or of JSON-RPC, or with what is no answer. */
export class A2aError extends Error {
  override readonly name = "A2aError";
  /**
   * The JSON-RPC error code the agent gave (A2A, Section 5.4), or
   * `undefined` where the answer was not one A2A defines.
   */
  readonly code: number | undefined;

  constructor(code: number | undefined, message: string) {
    super(message);
    this.code = code;
  }
}

/** The most parts of a message or an artifact that are read, and the most artifacts of a task. */
export const MAX_PARTS = 32;
export const MAX_ARTIFACTS = 64;
/** The longest identifier an agent gives that is kept. */
export const MAX_ID = 256;
/** The longest error message of an agent that is kept. */
const MAX_ERROR_TEXT = 256;

const isObject = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const invalid = (what: string): A2aError =>
  new A2aError(undefined, `the agent's answer is not what A2A says it is: ${what}`);

function id(value: unknown, what: string): string {
  if (typeof value !== "string" || value === "" || value.length > MAX_ID) throw invalid(what);
  return value;
}

function optionalId(value: unknown, what: string): string | undefined {
  return value === undefined || value === "" ? undefined : id(value, what);
}

function partOf(value: unknown): Part {
  if (!isObject(value)) throw invalid("a part is no object");
  const { text, raw, url, data, mediaType, filename } = value;
  const more = {
    ...(typeof mediaType === "string" && mediaType !== "" ? { mediaType } : {}),
    ...(typeof filename === "string" && filename !== "" ? { filename } : {}),
  };
  const given = [text, raw, url, data].filter((one) => one !== undefined).length;
  if (given !== 1) throw invalid("a part holds one of a text, bytes, a URL or data");
  if (text !== undefined) {
    if (typeof text !== "string") throw invalid("the text of a part is no text");
    return { text, ...more };
  }
  if (raw !== undefined) {
    if (typeof raw !== "string" || !/^[A-Za-z0-9+/_-]*={0,2}$/u.test(raw)) {
      throw invalid("the bytes of a part are not base64");
    }
    return { raw, ...more };
  }
  if (url !== undefined) {
    if (typeof url !== "string" || url === "") throw invalid("the URL of a part is no text");
    return { url, ...more };
  }
  return { data, ...more };
}

function partsOf(value: unknown, what: string): Part[] {
  if (!Array.isArray(value) || value.length > MAX_PARTS) {
    throw invalid(`${what} has no list of at most ${String(MAX_PARTS)} parts`);
  }
  return (value as readonly unknown[]).map((part) => partOf(part));
}

function messageOf(value: unknown): A2aMessage {
  if (!isObject(value)) throw invalid("a message is no object");
  const { role } = value;
  if (role !== "ROLE_USER" && role !== "ROLE_AGENT") throw invalid("a message has no role");
  const contextId = optionalId(value["contextId"], "a context ID is no identifier");
  const taskId = optionalId(value["taskId"], "a task ID is no identifier");
  return {
    messageId: id(value["messageId"], "a message has no ID"),
    role,
    parts: partsOf(value["parts"], "a message"),
    ...(contextId === undefined ? {} : { contextId }),
    ...(taskId === undefined ? {} : { taskId }),
  };
}

function taskOf(value: unknown): Task {
  if (!isObject(value)) throw invalid("a task is no object");
  const { status, artifacts } = value;
  if (!isObject(status)) throw invalid("a task has no status");
  const state = TASK_STATES.find((known) => known === status["state"]);
  if (typeof status["state"] !== "string") throw invalid("a task's status has no state");
  if (artifacts !== undefined && (!Array.isArray(artifacts) || artifacts.length > MAX_ARTIFACTS)) {
    throw invalid(`a task has no list of at most ${String(MAX_ARTIFACTS)} artifacts`);
  }
  const contextId = optionalId(value["contextId"], "a context ID is no identifier");
  return {
    id: id(value["id"], "a task has no ID"),
    ...(contextId === undefined ? {} : { contextId }),
    state,
    ...(status["message"] === undefined ? {} : { said: messageOf(status["message"]) }),
    artifacts: ((artifacts ?? []) as readonly unknown[]).map((artifact) => {
      if (!isObject(artifact)) throw invalid("an artifact is no object");
      const { name } = artifact;
      return {
        artifactId: id(artifact["artifactId"], "an artifact has no ID"),
        ...(typeof name === "string" && name !== "" ? { name: name.slice(0, MAX_ID) } : {}),
        parts: partsOf(artifact["parts"], "an artifact"),
      };
    }),
  };
}

/** What a gateway asks an agent with: how requests leave, and the interface they go to. */
export interface Agent {
  readonly ask: Ask;
  /** The interface of the agent's card that is spoken to: see `interfaceOf`. */
  readonly interface: AgentInterface;
  /** The extensions the gateway asks to use, by their URIs (A2A, Section 4.6). */
  readonly extensions?: readonly string[];
}

let asked = 0;

/** Makes one JSON-RPC call, and gives its result. */
async function call(
  agent: Agent,
  method: string,
  params: Record<string, unknown>,
): Promise<Readonly<Record<string, unknown>>> {
  const { url, tenant } = agent.interface;
  const callId = `oip-${String(++asked)}`;
  const body = new TextEncoder().encode(
    JSON.stringify({
      jsonrpc: "2.0",
      id: callId,
      method,
      // A client sets `tenant` to what the interface declares, in every request (A2A, 8.3.2).
      params: { ...(tenant === undefined ? {} : { tenant }), ...params },
    }),
  );
  const { extensions = [] } = agent;
  const response = await agent.ask({
    url,
    body,
    headers: {
      "content-type": "application/json",
      // A2A, 3.6.1: a client says which version it speaks with every request.
      "a2a-version": A2A_VERSION,
      ...(extensions.length === 0 ? {} : { "a2a-extensions": extensions.join(",") }),
    },
  });
  let answer: unknown;
  try {
    answer = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(response.body));
  } catch {
    throw invalid(`a response of status ${String(response.status)} that is not JSON`);
  }
  if (!isObject(answer) || answer["jsonrpc"] !== "2.0") throw invalid("it is no JSON-RPC response");
  const { error, result } = answer;
  if (isObject(error)) {
    const { code, message } = error;
    // The agent's own words, cut short and with nothing in them that is not printable.
    const said = typeof message === "string" ? message.replace(/[^\x20-\x7e]/gu, " ") : "";
    throw new A2aError(
      typeof code === "number" && Number.isSafeInteger(code) ? code : undefined,
      `the agent refused ${method}${said === "" ? "" : `: ${said.slice(0, MAX_ERROR_TEXT)}`}`,
    );
  }
  if (answer["id"] !== callId) throw invalid("it answers another request");
  if (!isObject(result)) throw invalid("it has neither a result nor an error");
  return result;
}

/**
 * Sends a message to an agent (A2A, `SendMessage`).
 *
 * @param accepted - The media types the gateway can pass on.
 * @returns The task the agent took on, or the message it answered with.
 * @throws A2aError if the agent refuses, or answers with what is no answer.
 */
export async function sendMessage(
  agent: Agent,
  message: A2aMessage,
  accepted: readonly string[] = [],
): Promise<Answered> {
  const { extensions = [] } = agent;
  const result = await call(agent, "SendMessage", {
    message: { ...message, ...(extensions.length === 0 ? {} : { extensions: [...extensions] }) },
    ...(accepted.length === 0 ? {} : { configuration: { acceptedOutputModes: [...accepted] } }),
  });
  if (result["task"] !== undefined && result["message"] === undefined) {
    return { task: taskOf(result["task"]) };
  }
  if (result["message"] !== undefined && result["task"] === undefined) {
    return { message: messageOf(result["message"]) };
  }
  throw invalid("it holds one of a task or a message");
}

/** Asks an agent where a task stands (A2A, `GetTask`). */
export async function getTask(agent: Agent, taskId: string): Promise<Task> {
  const task = taskOf(await call(agent, "GetTask", { id: taskId }));
  // A task that is not the one asked about says nothing of it.
  if (task.id !== taskId) throw invalid("it is another task than was asked about");
  return task;
}

/** Asks an agent to cancel a task (A2A, `CancelTask`). */
export async function cancelTask(agent: Agent, taskId: string): Promise<Task> {
  const task = taskOf(await call(agent, "CancelTask", { id: taskId }));
  if (task.id !== taskId) throw invalid("it is another task than was asked about");
  return task;
}
