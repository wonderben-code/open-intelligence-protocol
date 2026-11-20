// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `@oip/cli`: the `oip` command. A mind of the Open Intelligence Protocol,
 * from a terminal: made, published, found, written to, and bound by what it
 * signs.
 *
 * The package is a program first. What it exports is for running the same
 * command inside another process, as its tests do, and for starting the
 * network `oip demo` runs.
 *
 * @packageDocumentation
 */

export {
  type Arguments,
  type Command,
  type Context,
  type Flag,
  type Result,
  UsageError,
} from "./command.ts";
export { COMMANDS } from "./commands/index.ts";
export type { Edges } from "./edges.ts";
export { type Config, type NetworkFile } from "./home.ts";
export {
  LOCAL,
  type Network,
  type NetworkOptions,
  routed,
  routedSocket,
  startNetwork,
} from "./network.ts";
export { type ExitCode, GLOBAL_FLAGS, helpOf, overview, run, VERSION } from "./run.ts";
export { type Process, systemEdges } from "./system.ts";
