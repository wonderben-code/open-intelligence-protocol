// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `@oip/did-resolver`: resolves `did:oip` for the tools of the DID
 * ecosystem (Layer 1, Section 5).
 *
 * `getResolver` is a driver for the DIF `did-resolver` library, `handle`
 * is the HTTP interface a driver of the DIF Universal Resolver has, and
 * `main` is the program that serves it.
 *
 * @packageDocumentation
 */

export {
  DID_JSON,
  type DidResolutionError,
  type DidResolutionMetadata,
  type DidResolutionResult,
  type DidResolver,
  getResolver,
  type ParsedDid,
  resolveDid,
  type Writable,
} from "./driver.ts";
export { type Answer, type Asking, handle, RESOLUTION_RESULT } from "./http.ts";
export { type Host, main, type Serving } from "./main.ts";
