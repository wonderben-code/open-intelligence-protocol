// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Speaking A2A to an agent, and reading what a stranger answers. */

import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  A2aError,
  type A2aMessage,
  type Agent,
  cancelTask,
  getTask,
  MAX_ARTIFACTS,
  MAX_PARTS,
  sendMessage,
} from "../src/index.ts";

interface Sent {
  url: string;
  headers: Readonly<Record<string, string>>;
  body: { jsonrpc: string; id: string; method: string; params: Record<string, unknown> };
}

/**
 * An agent that answers each request with what the test says: a result, or
 * a whole response if `whole` is set, or the very text of one if `raw` is,
 * with the request's own ID unless the answer names another.
 */
function agent(
  answer: unknown,
  options: { whole?: boolean; raw?: boolean; more?: Partial<Agent>; tenant?: string } = {},
): Agent & { sent: Sent[] } {
  const sent: Sent[] = [];
  return {
    sent,
    interface: {
      url: "https://agent.example/a2a",
      protocolBinding: "JSONRPC",
      protocolVersion: "1.0",
      ...(options.tenant === undefined ? {} : { tenant: options.tenant }),
    },
    ask: ({ url, body, headers }) => {
      const request = JSON.parse(new TextDecoder().decode(body)) as Sent["body"];
      sent.push({ url, headers, body: request });
      const response =
        typeof answer === "string" && options.raw === true
          ? answer
          : JSON.stringify(
              options.whole === true ? answer : { jsonrpc: "2.0", id: request.id, result: answer },
            );
      return Promise.resolve({ status: 200, body: new TextEncoder().encode(response) });
    },
    ...options.more,
  };
}

const HELLO: A2aMessage = {
  messageId: "m-1",
  role: "ROLE_USER",
  parts: [{ text: "Translate this lease.", mediaType: "text/plain" }],
};

const TASK = {
  id: "task-1",
  contextId: "ctx-1",
  status: { state: "TASK_STATE_WORKING" },
};

/** What an agent's answer is refused with. */
async function refusal(work: Promise<unknown>): Promise<string> {
  try {
    await work;
  } catch (error) {
    if (error instanceof A2aError) return error.message;
    throw error;
  }
  throw new Error("the answer was taken");
}

describe("a message sent to an A2A agent", () => {
  it("is a JSON-RPC call of SendMessage, with the version of A2A that is spoken", async () => {
    const to = agent({ task: TASK });
    await sendMessage(to, HELLO, ["text/plain"]);
    expect(to.sent).toHaveLength(1);
    const [{ url, headers, body } = {} as Sent] = to.sent;
    expect(url).toBe("https://agent.example/a2a");
    expect(headers).toStrictEqual({ "content-type": "application/json", "a2a-version": "1.0" });
    expect(body).toMatchObject({
      jsonrpc: "2.0",
      method: "SendMessage",
      params: { message: HELLO, configuration: { acceptedOutputModes: ["text/plain"] } },
    });
    expect(body.id).toMatch(/^oip-\d+$/u);
    expect(body.params).not.toHaveProperty("tenant");
  });

  it("names the tenant its interface declares, and the extensions it asks to use", async () => {
    const to = agent(
      { task: TASK },
      {
        tenant: "acme",
        more: { extensions: ["https://example.com/ext/a", "https://example.com/ext/b"] },
      },
    );
    await sendMessage(to, HELLO);
    const [{ headers, body } = {} as Sent] = to.sent;
    expect(headers["a2a-extensions"]).toBe("https://example.com/ext/a,https://example.com/ext/b");
    expect(body.params).toMatchObject({
      tenant: "acme",
      message: { extensions: ["https://example.com/ext/a", "https://example.com/ext/b"] },
    });
    expect(body.params).not.toHaveProperty("configuration");
  });

  it("is answered with a task the agent took on, or with a message at once", async () => {
    expect(await sendMessage(agent({ task: TASK }), HELLO)).toStrictEqual({
      task: { id: "task-1", contextId: "ctx-1", state: "TASK_STATE_WORKING", artifacts: [] },
    });
    const reply = { messageId: "m-2", role: "ROLE_AGENT", parts: [{ text: "Hello." }] };
    expect(await sendMessage(agent({ message: reply }), HELLO)).toStrictEqual({ message: reply });
  });

  it("is answered with a task whose artifacts and words are read part by part", async () => {
    const done = {
      id: "task-1",
      contextId: "",
      status: {
        state: "TASK_STATE_COMPLETED",
        message: {
          messageId: "m-3",
          role: "ROLE_AGENT",
          taskId: "task-1",
          parts: [{ text: "Done." }],
        },
      },
      artifacts: [
        {
          artifactId: "a-1",
          name: "The translation",
          description: "ignored",
          parts: [
            { text: "A lease.", mediaType: "text/plain", metadata: { ignored: true } },
            { raw: "aGVsbG8=", filename: "lease.txt", mediaType: "" },
            { url: "https://files.example/lease.pdf", mediaType: "application/pdf" },
            { data: { pages: 12, ratio: 0.5 } },
          ],
        },
      ],
      history: [{ anything: "at all" }],
    };
    expect(await sendMessage(agent({ task: done }), HELLO)).toStrictEqual({
      task: {
        id: "task-1",
        state: "TASK_STATE_COMPLETED",
        said: {
          messageId: "m-3",
          role: "ROLE_AGENT",
          taskId: "task-1",
          parts: [{ text: "Done." }],
        },
        artifacts: [
          {
            artifactId: "a-1",
            name: "The translation",
            parts: [
              { text: "A lease.", mediaType: "text/plain" },
              { raw: "aGVsbG8=", filename: "lease.txt" },
              { url: "https://files.example/lease.pdf", mediaType: "application/pdf" },
              { data: { pages: 12, ratio: 0.5 } },
            ],
          },
        ],
      },
    });
  });

  it("is answered with a task in a state this gateway does not know, which it then knows nothing of", async () => {
    const odd = { ...TASK, status: { state: "TASK_STATE_ASLEEP" } };
    const answered = await sendMessage(agent({ task: odd }), HELLO);
    expect(answered).toMatchObject({ task: { id: "task-1", state: undefined } });
  });
});

describe("what an agent answers", () => {
  it("is an error where the agent says so, with its code and its words made safe", async () => {
    const refusing = agent(
      {
        jsonrpc: "2.0",
        id: 1,
        error: { code: -32009, message: `Version not supported\u001b[2J ${"x".repeat(500)}` },
      },
      { whole: true },
    );
    try {
      await sendMessage(refusing, HELLO);
      throw new Error("the error was taken for an answer");
    } catch (error) {
      expect(error).toBeInstanceOf(A2aError);
      const { code, message } = error as A2aError;
      expect(code).toBe(-32009);
      expect(message).toMatch(/^the agent refused SendMessage: Version not supported \[2J x+$/u);
      expect(message.length).toBeLessThan(300);
    }
    const wordless = agent(
      { jsonrpc: "2.0", id: 1, error: { code: "no", message: 7 } },
      { whole: true },
    );
    await expect(sendMessage(wordless, HELLO)).rejects.toMatchObject({
      code: undefined,
      message: "the agent refused SendMessage",
    });
  });

  it("is refused where it is not a response to the request that was made", async () => {
    for (const [answer, why] of [
      [[1, 2], "it is no JSON-RPC response"],
      [{ id: "x", result: {} }, "it is no JSON-RPC response"],
      [{ jsonrpc: "1.0", id: "x", result: {} }, "it is no JSON-RPC response"],
      [{ jsonrpc: "2.0", id: "another", result: { task: TASK } }, "it answers another request"],
      [{ jsonrpc: "2.0", result: { task: TASK } }, "it answers another request"],
    ] as const) {
      const said = await refusal(sendMessage(agent(answer, { whole: true }), HELLO));
      expect(said, JSON.stringify(answer)).toBe(
        `the agent's answer is not what A2A says it is: ${why}`,
      );
    }
    expect(await refusal(sendMessage(agent("null", { raw: true }), HELLO))).toContain(
      "no JSON-RPC response",
    );
    expect(
      await refusal(sendMessage(agent("<html>502 Bad Gateway</html>", { raw: true }), HELLO)),
    ).toContain("a response of status 200 that is not JSON");
  });

  it("is refused where its result is neither a task nor a message, or is both", async () => {
    const reply = { messageId: "m-2", role: "ROLE_AGENT", parts: [] };
    for (const result of [{}, { task: TASK, message: reply }, { something: "else" }]) {
      expect(await refusal(sendMessage(agent(result), HELLO))).toContain(
        "it holds one of a task or a message",
      );
    }
    for (const result of ["a task", 7, null, [TASK]]) {
      expect(await refusal(sendMessage(agent(result), HELLO))).toContain(
        "it has neither a result nor an error",
      );
    }
  });

  it("is refused where a task, a message or a part is not what A2A says it is", async () => {
    const part = { text: "x" };
    const message = { messageId: "m", role: "ROLE_AGENT", parts: [part] };
    const cases: [unknown, string][] = [
      [{ task: "task-1" }, "a task is no object"],
      [{ task: { ...TASK, id: "" } }, "a task has no ID"],
      [{ task: { ...TASK, id: 7 } }, "a task has no ID"],
      [{ task: { ...TASK, id: "x".repeat(257) } }, "a task has no ID"],
      [{ task: { id: "t" } }, "a task has no status"],
      [{ task: { id: "t", status: {} } }, "a task's status has no state"],
      [{ task: { id: "t", status: { state: 3 } } }, "a task's status has no state"],
      [{ task: { ...TASK, contextId: 7 } }, "a context ID is no identifier"],
      [{ task: { ...TASK, artifacts: "none" } }, "a task has no list of at most 64 artifacts"],
      [
        {
          task: {
            ...TASK,
            artifacts: Array.from({ length: MAX_ARTIFACTS + 1 }, () => ({
              artifactId: "a",
              parts: [],
            })),
          },
        },
        "a task has no list",
      ],
      [{ task: { ...TASK, artifacts: ["a"] } }, "an artifact is no object"],
      [{ task: { ...TASK, artifacts: [{ parts: [] }] } }, "an artifact has no ID"],
      [
        { task: { ...TASK, artifacts: [{ artifactId: "a" }] } },
        "an artifact has no list of at most 32 parts",
      ],
      [
        { task: { ...TASK, status: { state: "TASK_STATE_WORKING", message: "soon" } } },
        "a message is no object",
      ],
      [{ message: "hello" }, "a message is no object"],
      [{ message: { ...message, role: "ROLE_SYSTEM" } }, "a message has no role"],
      [{ message: { ...message, messageId: undefined } }, "a message has no ID"],
      [{ message: { ...message, taskId: {} } }, "a task ID is no identifier"],
      [{ message: { ...message, parts: undefined } }, "a message has no list of at most 32 parts"],
      [
        { message: { ...message, parts: Array.from({ length: MAX_PARTS + 1 }, () => part) } },
        "a message has no list",
      ],
      [{ message: { ...message, parts: ["text"] } }, "a part is no object"],
      [{ message: { ...message, parts: [{}] } }, "a part holds one of"],
      [
        { message: { ...message, parts: [{ text: "x", url: "https://x.example" }] } },
        "a part holds one of",
      ],
      [{ message: { ...message, parts: [{ text: 7 }] } }, "the text of a part is no text"],
      [
        { message: { ...message, parts: [{ raw: "not base64!" }] } },
        "the bytes of a part are not base64",
      ],
      [{ message: { ...message, parts: [{ raw: 7 }] } }, "the bytes of a part are not base64"],
      [{ message: { ...message, parts: [{ url: "" }] } }, "the URL of a part is no text"],
    ];
    for (const [result, why] of cases) {
      expect(await refusal(sendMessage(agent(result), HELLO)), why).toContain(why);
    }
  });

  it("is an A2A error or an answer, whatever it is: nothing else is thrown", async () => {
    await fc.assert(
      fc.asyncProperty(fc.jsonValue(), fc.boolean(), async (answer, whole) => {
        try {
          await sendMessage(agent(answer, { whole }), HELLO);
        } catch (error) {
          expect(error).toBeInstanceOf(A2aError);
        }
      }),
      { numRuns: 500 },
    );
  });
});

describe("a task asked about, or cancelled", () => {
  it("is asked for by its ID, and is the task that was asked about", async () => {
    const to = agent({ ...TASK, status: { state: "TASK_STATE_COMPLETED" } }, { tenant: "acme" });
    expect(await getTask(to, "task-1")).toMatchObject({
      id: "task-1",
      state: "TASK_STATE_COMPLETED",
    });
    expect(to.sent[0]?.body).toMatchObject({
      method: "GetTask",
      params: { id: "task-1", tenant: "acme" },
    });
    expect(await refusal(getTask(to, "task-2"))).toContain(
      "it is another task than was asked about",
    );
  });

  it("is cancelled by its ID", async () => {
    const to = agent({ ...TASK, status: { state: "TASK_STATE_CANCELED" } });
    expect(await cancelTask(to, "task-1")).toMatchObject({ state: "TASK_STATE_CANCELED" });
    expect(to.sent[0]?.body).toMatchObject({ method: "CancelTask", params: { id: "task-1" } });
    expect(await refusal(cancelTask(to, "task-9"))).toContain("another task");
    const unable = agent(
      { jsonrpc: "2.0", id: 1, error: { code: -32002, message: "Task cannot be canceled" } },
      { whole: true },
    );
    await expect(cancelTask(unable, "task-1")).rejects.toMatchObject({ code: -32002 });
  });
});
