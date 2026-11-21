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
  A2aError,
  type A2aMessage,
  type Agent,
  type Answered,
  type Artifact,
  type Ask,
  cancelTask,
  type Get,
  getTask,
  Malformed,
  MAX_ARTIFACTS,
  MAX_ID,
  MAX_PARTS,
  type Part,
  readMessage,
  sendMessage,
  type Task,
} from "./a2a.ts";
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
export {
  type CardSignatures,
  type KeySource,
  type PublicJwk,
  verifySignatures,
} from "./signature.ts";
export { BridgeError, type Bridged, Gateway, type GatewayEdges, PROTOCOL } from "./gateway.ts";
export {
  type Asked,
  type Held,
  MAX_IDLE_CONTEXT_SECONDS,
  MAX_KEPT_SECONDS,
  MAX_TASKS,
  MAX_UNANNOUNCED_SECONDS,
  type Page,
} from "./book.ts";
export { Fault } from "./fault.ts";
export { Front, type FrontOptions, type ServedMind, type Taking } from "./front.ts";
export { A2aServer, type Answer, type Asking, MAX_REQUEST_BYTES } from "./server.ts";
export { listen, type Listening, type Served as ServedInterface } from "./listen.ts";
export { type Host, main, type Reach, type Serving, VERSION } from "./main.ts";
export { MAX_CARRIED_BYTES, MAX_FETCHED } from "./content.ts";
export { MAX_FOLLOWED_SECONDS, MAX_OPEN_TASKS, type Relayed } from "./relay.ts";
