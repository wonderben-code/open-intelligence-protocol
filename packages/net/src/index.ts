// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The Mind Network of the Open Intelligence Protocol (Layer 1, Sections 10
 * and 12 to 16): feeds and checkpoints, locations and profiles, packets,
 * sessions and sealing.
 *
 * The package is pure: it does no I/O and never reads the clock.
 *
 * @packageDocumentation
 */

export {
  type AckContext,
  type AckDraft,
  type AckEvidence,
  ackEvidence,
  acknowledges,
  draftAck,
  verifyAck,
  type VerifiedAck,
} from "./ack.ts";
export { type ProposedBranch, verifyBranch } from "./branch.ts";
export { isStale, type PacketClock, packetDates } from "./dates.ts";
export {
  committedProofs,
  type CoveredFeed,
  type FeedEntry,
  type VerifiedFeed,
  verifyCheckpoint,
  verifyFeed,
} from "./feed.ts";
export {
  type Authenticated,
  Challenges,
  type HelloServer,
  type IssuedChallenges,
  verifyHello,
} from "./hello.ts";
export {
  type AuthenticatedRequest,
  contentDigest,
  type HttpRequest,
  RequestNonces,
  type RequestSignature,
  type RequestVerifier,
  type SeenNonces,
  signatureBase,
  signRequest,
  verifyRequest,
} from "./http-signature.ts";
export {
  type Binding,
  currentLocation,
  endpointsToTry,
  type HeldLocation,
  type KnownEndpoint,
  postUrl,
  webSocketUrl,
} from "./location.ts";
export { checkpointRoot, merkleTreeHash } from "./merkle.ts";
export {
  AcceptedPackets,
  type ReceivedPacket,
  receivePacket,
  type Receiver,
  type SendingChain,
} from "./packet.ts";
export {
  type ReceivedSealed,
  receiveSealed,
  type SealDraft,
  type SealedOpener,
  type SealedReceiver,
  sealPacket,
} from "./sealed.ts";
export {
  type Bare,
  type InnerList,
  type Item,
  type Parameters,
  parseDictionary,
  writeInnerList,
  writeItem,
} from "./structured.ts";
export {
  type ChainEquivocation,
  DEFAULT_SESSION_LIMITS,
  lacking,
  type OwnChain,
  type Placed,
  recordsCarried,
  sessionCarried,
  type SessionLimits,
  Sessions,
} from "./session.ts";
export {
  currentParticipant,
  type HeldParticipant,
  type ProfileSources,
  verifyParticipant,
} from "./participant.ts";
