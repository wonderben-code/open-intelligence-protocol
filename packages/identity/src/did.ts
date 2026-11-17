// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** DID documents for `did:oip` addresses (Layer 1, Section 5). */

import type { Validation } from "@oip/schema";

import { no, ok } from "./result.ts";
import { type IdentityState, latestState, type Parent, positionOf, type VerifiedLog } from "./state.ts";

/** One key of a DID document (Layer 1, 5.2). */
export interface DidVerificationMethod {
  readonly id: string;
  readonly type: "Multikey";
  readonly controller: string;
  readonly publicKeyMultibase: string;
}

/** A home or an endpoint of a mind (Layer 1, 5.2). */
export interface DidService {
  readonly id: string;
  readonly type: "OIPHome" | "OIPEndpoint";
  readonly serviceEndpoint: string;
}

/** The DID Core document of a mind (Layer 1, 5.2). */
export interface DidDocument {
  readonly id: string;
  readonly verificationMethod: readonly DidVerificationMethod[];
  readonly authentication: readonly string[];
  readonly assertionMethod: readonly string[];
  readonly capabilityDelegation: readonly string[];
  readonly capabilityInvocation: readonly string[];
  readonly keyAgreement: readonly string[];
  readonly service?: readonly DidService[];
  readonly alsoKnownAs?: readonly string[];
}

/** What a document does not hold about the log it came from (Layer 1, 5.2). */
export interface DidDocumentMetadata {
  readonly versionId: string;
  /** True when the mind is retired. */
  readonly deactivated: boolean;
  readonly parents: readonly Parent[];
  readonly children: readonly string[];
  readonly nextKeyHashes?: readonly string[];
  readonly nextThreshold?: number;
  readonly members?: readonly string[];
  readonly threshold?: number;
}

/** The result of resolving an address. */
export interface DidResolution {
  readonly didDocument: DidDocument;
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
    const position = positionOf(log, versionId);
    if (position === undefined) {
      return no("versionId names no event of the mind's log", "L1 2.4");
    }
    state = log.states[position] as IdentityState;
  }
  const mind = state.mind;
  const id = (key: string): string =>
    versionId === undefined ? `${mind}#${key}` : `${mind}?versionId=${state.versionId}#${key}`;
  const service: DidService[] = [
    ...state.homes.map(
      (home, n): DidService => ({ id: `${mind}#home-${n}`, type: "OIPHome", serviceEndpoint: home }),
    ),
    ...(endpoints ?? []).map(
      (url, n): DidService => ({
        id: `${mind}#endpoint-${n}`,
        type: "OIPEndpoint",
        serviceEndpoint: url,
      }),
    ),
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
