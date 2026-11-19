// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The host (Layer 1, Section 13): a mind's well-known resources, its inbox,
 * its WebSocket and its mailbox.
 *
 * @packageDocumentation
 */

export {
  type Answer,
  DEFAULT_HOST_LIMITS,
  Host,
  type HostLimits,
  type HostOptions,
} from "./host.ts";
export { HOST_MIGRATIONS, HostStore, type MailboxItem } from "./store.ts";
