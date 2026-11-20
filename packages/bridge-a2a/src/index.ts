// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `@oip/bridge-a2a`: a gateway between the Open Intelligence Protocol and
 * A2A (Layer 0, Sections 1 and 3).
 *
 * In one direction an A2A agent becomes a participant of the network: the
 * gateway reads its Agent Card, makes a bridged mind for it, and attests
 * that mind in its own feed. In the other an OIP mind is given an Agent
 * Card, and an A2A interface that the gateway translates into packets.
 *
 * @packageDocumentation
 */

export {
  A2A_VERSION,
  type AgentCard,
  type AgentExtension,
  type AgentInterface,
  type AgentSkill,
  CARD_PATH,
  type CardSignature,
  interfaceOf,
  MAX_CARD_BYTES,
  MAX_CARD_ITEMS,
  MAX_CARD_TEXT,
  readCard,
  type ReadCard,
  supports,
} from "./card.ts";
export {
  capabilitiesOf,
  cardFor,
  isTerminal,
  OIP_EXTENSION,
  OIP_MEDIA_TYPE,
  type Said,
  saidOf,
  type Served,
  TAG_NAMESPACE,
  TASK_STATES,
  type TaskState,
} from "./mapping.ts";
