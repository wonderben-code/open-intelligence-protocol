// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `@oip/mcp-server`: an MCP server that gives an assistant a mind.
 *
 * A host starts the program `oip-mcp`, and its model is given nine tools
 * (Layer 0, 2.2): it can say who it is, find other minds, send and read
 * packets, publish what its user wants, make offers, sign Commitments,
 * write Receipts and ask where a record stands.
 *
 * Three things hold whatever the model is told by whom:
 *
 * - The keys stay in the server. No tool returns one, or takes one.
 * - What other minds wrote reaches the model as data, under `untrusted`.
 * - A Commitment is signed only once the person has confirmed the very
 *   terms that are signed, or a policy of theirs permits them.
 *
 * This module is the same server for a program that wants to host it
 * itself: `serverFactory` makes servers of the official MCP library.
 *
 * @packageDocumentation
 */

export { ANSWER_SECONDS } from "./confirm.ts";
export type { Given } from "./given.ts";
export { type Host, main, type Serve } from "./main.ts";
export { permits, type Policy, POLICY_FILE, readPolicy } from "./policy.ts";
export { commitmentQuestion, receiptQuestion } from "./question.ts";
export { INSTRUCTIONS, NAME, serverFactory, type ServerOptions, VERSION } from "./server.ts";
export type { Confirming, Question, Said, Tool } from "./tool.ts";
export { TOOLS } from "./tools/index.ts";
export {
  MAX_DEPTH,
  MAX_NAME,
  MAX_TEXT,
  MAX_VALUES,
  NOTICE,
  safe,
  type Untrusted,
  untrusted,
} from "./untrusted.ts";
export { type Reading, Work } from "./work.ts";
