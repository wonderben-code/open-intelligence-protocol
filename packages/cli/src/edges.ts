// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What the command reaches outside itself, behind one interface: the
 * environment, the terminal, the network, the clock and the machine's
 * keychain. A test gives its own, and runs a command in its own process.
 */

import type { Clock, Fetch, OpenSocket } from "@oip/client";
import type { Keychain } from "@oip/keystore";

/** The edges of a run of the command. */
export interface Edges {
  /** The environment's variables. */
  readonly env: Readonly<Record<string, string | undefined>>;
  /** The user's home directory. A mind's directory is under it unless another is named. */
  readonly home: string;
  /** Writes to standard output. */
  readonly out: (text: string) => void;
  /** Writes to standard error. */
  readonly err: (text: string) => void;
  /**
   * Asks for a secret where a person can type one, without showing what is
   * typed. Absent where there is no terminal.
   */
  readonly secret?: (question: string) => Promise<string>;
  /** The keychain of the machine. It is asked for only where a mind's keys are kept under it. */
  readonly keychain: () => Promise<Keychain>;
  /** Settles when the command is asked to stop: for what runs until then. */
  readonly stopped: () => Promise<void>;
  /** How services are asked. Default: the platform's `fetch`. */
  readonly fetch?: Fetch;
  /** The present. Default: the system's clock. */
  readonly clock?: Clock;
  /** Opens a WebSocket. Default: the platform's. */
  readonly webSocket?: OpenSocket;
  /**
   * The work factor of scrypt for a passphrase that seals keys afresh.
   * Default: the keystore's own. A test gives the least that is accepted.
   */
  readonly scryptN?: number;
}
