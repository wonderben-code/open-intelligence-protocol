// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The tools of an OIP MCP server (Layer 0, 2.2), in the order a host lists them. */

import type { Tool } from "../tool.ts";
import { inbox, send } from "./packets.ts";
import { find, status, whoami } from "./reading.ts";
import { commit, makeOffer, publishIntent, receipt } from "./web.ts";

/**
 * The nine tools. No tool signs a Delegation: an assistant is given the
 * use of a mind, and no way to hand that use on.
 */
export const TOOLS: readonly Tool[] = [
  whoami,
  find,
  send,
  inbox,
  publishIntent,
  makeOffer,
  commit,
  receipt,
  status,
];
