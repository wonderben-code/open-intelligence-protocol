// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `@oip/bridge-mcp`: MCP servers as participants (Layer 0, 2.1).
 *
 * A gateway makes a mind for an MCP server and holds that mind's keys.
 * Each tool of the server is a capability of the mind. A request packet
 * that names a tool is a call of it, made for the minds the gateway's
 * operator allows, and answered with the result.
 *
 * @packageDocumentation
 */

export {
  type Connect,
  connector,
  endpointOf,
  Refused,
  type Server,
  type Target,
} from "./connect.ts";
export {
  type Credentials,
  CREDENTIALS_FILE,
  credentialsIn,
  NONE,
  readCredentials,
} from "./credentials.ts";
export {
  type Bridged,
  type BridgedNow,
  BridgeError,
  Gateway,
  type GatewayEdges,
  PROTOCOL,
} from "./gateway.ts";
export { carriedJson, digestOf, holds, jsonText, readJsonText } from "./json.ts";
export { type Host, main, type Reach, type Serving, VERSION } from "./main.ts";
export {
  allows,
  ANYONE,
  EVERY_TOOL,
  NOBODY,
  type Policy,
  POLICY_FILE,
  readPolicy,
} from "./policy.ts";
export { MAX_RESULT_BYTES, readCall, Relay, type Relayed, type RelayEdges } from "./relay.ts";
export {
  capabilitiesOf,
  type Mapped,
  MAX_CAPABILITIES,
  MAX_NAME,
  MAX_SCHEMA_BYTES,
  MAX_SCHEMAS_BYTES,
  MAX_SUMMARY,
  MCP_NAMESPACE,
  type ToolCapability,
} from "./tools.ts";
