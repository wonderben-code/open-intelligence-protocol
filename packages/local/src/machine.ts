// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What a program on this machine reaches outside itself to work for a
 * mind: the environment, the keychain, the network and the clock. A test
 * gives its own.
 */

import type { Clock, Fetch, OpenSocket } from "@oip/client";
import type { Keychain } from "@oip/keystore";

/** The machine a mind's directory is on, as a program sees it. */
export interface Machine {
  /** The environment's variables. */
  readonly env: Readonly<Record<string, string | undefined>>;
  /** The user's home directory. A mind's directory is under it unless another is named. */
  readonly home: string;
  /**
   * Asks for a secret where a person can type one, without showing what is
   * typed. Absent where there is no terminal.
   */
  readonly secret?: (question: string) => Promise<string>;
  /** The keychain of the machine. It is asked for only where a mind's keys are kept under it. */
  readonly keychain: () => Promise<Keychain>;
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

/** Where a program works: on a machine, for the mind of a directory. */
export interface Where {
  /** The machine. */
  readonly edges: Machine;
  /** The directory of the mind the program works for. */
  readonly dir: string;
}
