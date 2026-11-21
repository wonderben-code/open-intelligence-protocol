// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The person's answer, bound to the question it was given to.
 *
 * A tool that must ask comes back with a question. The host puts it to the
 * person and makes the call again, with their answer. Everything in that
 * second call comes from outside this server: the arguments, the answer,
 * and the state the server handed out with the question. So an answer
 * counts only if all of this holds:
 *
 * - The state is this server's own, unaltered and not too old. It is
 *   sealed with a key that this process made and that never leaves it.
 * - The state names the digest of exactly what the call would sign now.
 *   A yes to one Commitment is not a yes to another.
 * - The state has not been used. A yes signs once: a call that is made
 *   again with the same answer is asked again.
 *
 * A call that brings an answer nobody asked for is a call without one.
 */

import {
  createRequestStateCodec,
  type InputRequest,
  inputRequired,
  inputResponse,
  type ServerContext,
} from "@modelcontextprotocol/server";

import type { Question } from "./tool.ts";

/** How long an answer may take, in seconds. A person is not hurried. */
export const ANSWER_SECONDS = 600;

/** The name the question goes under in a call's input requests. */
export const CONFIRM = "confirm";

/** What the server hands out with a question, to get back with the answer. */
interface Asked {
  /** The digest of what the question is about. */
  readonly digest: string;
  /** What tells this asking from every other. */
  readonly nonce: string;
}

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

/** The questions a server has put, and the answers it has taken. */
export class Confirmations {
  // The key is made here, of the platform's randomness, and is in no file and no result.
  readonly #codec = createRequestStateCodec<Asked>({
    key: globalThis.crypto.getRandomValues(new Uint8Array(32)),
    ttlSeconds: ANSWER_SECONDS,
  });
  /** The askings that were answered, each with when its state stops being accepted anyway. */
  readonly #spent = new Map<string, number>();

  /**
   * Checks the state a call brought back. It goes into the server's
   * options: a call whose state is not this server's own never reaches a tool.
   */
  readonly verify = (state: string, context: ServerContext): Promise<unknown> =>
    this.#codec.verify(state, context);

  /** What a tool's question goes to the host as: the question, and the state to bring back. */
  async asking(
    question: Question,
  ): Promise<{ inputRequests: Record<string, InputRequest>; requestState: string }> {
    const nonce = hex(globalThis.crypto.getRandomValues(new Uint8Array(16)));
    return {
      inputRequests: {
        [CONFIRM]: inputRequired.elicit({
          message: question.text,
          requestedSchema: {
            type: "object",
            properties: {
              sign: {
                type: "boolean",
                title: question.action,
                description: "Yes signs it in your name. It cannot be taken back.",
              },
            },
            required: ["sign"],
          },
        }),
      },
      requestState: await this.#codec.mint({ digest: question.digest, nonce }),
    };
  }

  /**
   * What the person answered to the question with this digest, as this
   * call brought it: `yes`, `no`, or `undefined` if the call brings no
   * answer to that question. An answer is taken once.
   */
  answer(context: ServerContext, digest: string): "yes" | "no" | undefined {
    const asked = context.mcpReq.requestState<Partial<Asked>>();
    if (typeof asked !== "object" || asked.digest !== digest || typeof asked.nonce !== "string") {
      return undefined;
    }
    const view = inputResponse(context.mcpReq.inputResponses, CONFIRM);
    if (view.kind !== "elicit") return undefined;
    const now = Date.now();
    for (const [nonce, until] of this.#spent) if (until < now) this.#spent.delete(nonce);
    if (this.#spent.has(asked.nonce)) return undefined;
    // The state is refused after this long whatever it says: it need be remembered no longer.
    this.#spent.set(asked.nonce, now + (ANSWER_SECONDS + 60) * 1000);
    return view.action === "accept" && view.content?.["sign"] === true ? "yes" : "no";
  }
}
