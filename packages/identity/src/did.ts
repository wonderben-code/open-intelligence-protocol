// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** DID documents for `did:oip` addresses (Layer 1, Section 5). */

import type { Validation } from "@oip/schema";

import { no, ok } from "./result.ts";
import {
  entryAt,
  type IdentityState,
  latestState,
  type Parent,
  type VerifiedLog,
} from "./state.ts";

/** One key of a DID document (Layer 1, 5.2). */
export interface DidVerificationMethod {
  /** The address, `#` and the key. In a versioned document, the address with its `versionId`. */
  readonly id: string;
  /** Every key is given as a Multikey (core 4.1). */
  readonly type: "Multikey";
  /** The mind's address. */
  readonly controller: string;
  /** The key, as a Multikey string. */
  readonly publicKeyMultibase: string;
}

/** A home or an endpoint of a mind (Layer 1, 5.2). */
export interface DidService {
  /** The address and `#home-<n>` or `#endpoint-<n>`, counting from 0. */
  readonly id: string;
  /** A home serves the mind's records; an endpoint receives its packets. */
  readonly type: "OIPHome" | "OIPEndpoint";
  /** The origin of a home, or the URL of an endpoint. */
  readonly serviceEndpoint: string;
}

/** The DID Core document of a mind (Layer 1, 5.2). */
export interface DidDocument {
  /** The mind's address. */
  readonly id: string;
  /** One entry for each operational, invocation and agreement key, in that order. Control keys are not listed. */
  readonly verificationMethod: readonly DidVerificationMethod[];
  /** The ids of the operational keys. */
  readonly authentication: readonly string[];
  /** The ids of the operational keys. */
  readonly assertionMethod: readonly string[];
  /** The ids of the operational keys. */
  readonly capabilityDelegation: readonly string[];
  /** The ids of the invocation keys. */
  readonly capabilityInvocation: readonly string[];
  /** The ids of the agreement keys. */
  readonly keyAgreement: readonly string[];
  /** The homes, and then the endpoints of a location record if one was given. Absent when there are none. */
  readonly service?: readonly DidService[];
  /** The aliases the caller has verified. Absent when there are none. */
  readonly alsoKnownAs?: readonly string[];
}

/** What a document does not hold about the log it came from (Layer 1, 5.2). */
export interface DidDocumentMetadata {
  /** The version identifier of the event the document was produced up to. */
  readonly versionId: string;
  /** True when the mind is retired. */
  readonly deactivated: boolean;
  /** The parents the genesis names (Layer 1, 8.1). */
  readonly parents: readonly Parent[];
  /** The children the log acknowledges with `Fork` events. */
  readonly children: readonly string[];
  /** For a key-controlled mind: the commitments to the keys that sign the next event. */
  readonly nextKeyHashes?: readonly string[];
  /** For a key-controlled mind that can still be extended: how many of them must sign. */
  readonly nextThreshold?: number;
  /** For a member-controlled mind: the addresses of its members. */
  readonly members?: readonly string[];
  /** For a member-controlled mind: how many members must sign. */
  readonly threshold?: number;
}

/** The result of resolving an address. */
export interface DidResolution {
  /** The DID Core document. */
  readonly didDocument: DidDocument;
  /** What the log holds and the document does not. */
  readonly didDocumentMetadata: DidDocumentMetadata;
}

/** What the log alone does not say. */
export interface DidDocumentOptions {
  /**
   * Layer 1, 2.4: produce the document from the log up to and including this
   * event. Each key's `id` is then the versioned form, so that a key
   * reference in a proof matches it exactly.
   */
  readonly versionId?: string;
  /** The endpoints of the mind's current location record, in its order, if one is known. */
  readonly endpoints?: readonly string[];
  /**
   * The aliases that have been verified in both directions (Layer 1, 5.3).
   * Only those the state lists are presented.
   */
  readonly verifiedAliases?: readonly string[];
}

function metadata(state: IdentityState): DidDocumentMetadata {
  const base = {
    versionId: state.versionId,
    deactivated: state.retired,
    parents: state.parents,
    children: state.children,
  };
  const controller = state.controller;
  if (controller.kind === "member") {
    return { ...base, members: controller.members, threshold: controller.threshold };
  }
  return {
    ...base,
    nextKeyHashes: controller.next,
    ...(controller.next.length === 0 ? {} : { nextThreshold: controller.nextThreshold }),
  };
}

/**
 * Layer 1, 5.2: the DID document of a mind, from its verified log. Control
 * keys are not listed. An alias is listed only if the caller has verified
 * it; none is verified here.
 */
export function didDocument(
  log: VerifiedLog,
  options: DidDocumentOptions = {},
): Validation<DidResolution> {
  const { versionId, endpoints, verifiedAliases } = options;
  let state = latestState(log);
  if (versionId !== undefined) {
    const pinned = entryAt(log, versionId);
    if (pinned === undefined) {
      return no("versionId names no event of the mind's log", "L1 2.4");
    }
    state = pinned.entry.state;
  }
  const mind = state.mind;
  const id = (key: string): string =>
    versionId === undefined ? `${mind}#${key}` : `${mind}?versionId=${state.versionId}#${key}`;
  const service: DidService[] = [
    ...state.homes.map((home, n): DidService => ({
      id: `${mind}#home-${n}`,
      type: "OIPHome",
      serviceEndpoint: home,
    })),
    ...(endpoints ?? []).map((url, n): DidService => ({
      id: `${mind}#endpoint-${n}`,
      type: "OIPEndpoint",
      serviceEndpoint: url,
    })),
  ];
  const aliases = state.alsoKnownAs.filter((alias) => verifiedAliases?.includes(alias) === true);
  return ok({
    didDocument: {
      id: mind,
      verificationMethod: [...state.keys, ...state.invocation, ...state.agreement].map((key) => ({
        id: id(key),
        type: "Multikey",
        controller: mind,
        publicKeyMultibase: key,
      })),
      authentication: state.keys.map(id),
      assertionMethod: state.keys.map(id),
      capabilityDelegation: state.keys.map(id),
      capabilityInvocation: state.invocation.map(id),
      keyAgreement: state.agreement.map(id),
      ...(service.length === 0 ? {} : { service }),
      ...(aliases.length === 0 ? {} : { alsoKnownAs: aliases }),
    },
    didDocumentMetadata: metadata(state),
  });
}
