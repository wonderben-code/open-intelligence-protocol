// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `@oip/local`: a mind on this machine.
 *
 * A client holds a mind while its process lives. A program that runs for a
 * moment and stops, a command or a server that a host starts, needs the
 * mind to be somewhere between its runs: a directory with the sealed keys,
 * the client's memory, the records the mind holds with when each proof
 * first came, and the packets it has received. This package is that
 * directory, the lock of its keys, and the way to a network that runs on
 * the same machine.
 *
 * @packageDocumentation
 */

export { Arrivals } from "./arrivals.ts";
export { type BridgeBlock, type BridgedSystem, type Custody, withBridged } from "./bridged.ts";
export { UsageError } from "./errors.ts";
export { MAX_FILE_BYTES, readJson, readObject } from "./files.ts";
export { recordOf, refOf, statusOf } from "./held.ts";
export {
  type Config,
  directoryOf,
  Home,
  isLocal,
  NETWORK_FILE,
  type NetworkFile,
  readNetwork,
} from "./home.ts";
export type { Machine, Where } from "./machine.ts";
export {
  backupLockOf,
  fetchOf,
  keepRecords,
  lockOf,
  lookupOptions,
  type Opened,
  openMind,
  optionsOf,
  passphraseOf,
  servicesOf,
  withMind,
} from "./mind.ts";
export { keptFrom, keptOf, type KeptPacket } from "./packets.ts";
export { Kept, type KeptRecord, KeptRecords } from "./records.ts";
export { routed, routedSocket } from "./routes.ts";
export { fileNameOf, Store } from "./store.ts";
export { counted, printable, printableJson, quoted } from "./text.ts";
