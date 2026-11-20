// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What the command reaches outside itself, behind one interface: the
 * environment, the terminal, the network, the clock and the machine's
 * keychain. A test gives its own, and runs a command in its own process.
 */

import type { Machine } from "@oip/local";

/** The edges of a run of the command: the machine it runs on, and its terminal. */
export interface Edges extends Machine {
  /** Writes to standard output. */
  readonly out: (text: string) => void;
  /** Writes to standard error. */
  readonly err: (text: string) => void;
  /** Settles when the command is asked to stop: for what runs until then. */
  readonly stopped: () => Promise<void>;
}
