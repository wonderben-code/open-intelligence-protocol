// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A fork's proposal to go on from one of its parent's sessions (Layer 1,
 * 14.5).
 *
 * A fork is a new mind with an address of its own, so it is no participant
 * of its parent's sessions and cannot send in them (8.4). It may send a
 * `Branch` record instead: a proposal that names the session and the
 * parent's `Fork` event for it. The counterpart may accept by opening a new
 * session with the fork. Whether it does is its own decision: nothing here
 * opens anything.
 */

import { parseVersionedMind } from "@oip/core";
import { entryAt, type IdentityView, lineage } from "@oip/identity";
import type { Branch, Session, Validation } from "@oip/schema";

import type { ReceivedPacket } from "./packet.ts";
import { judging, no, ok } from "./result.ts";
import { recordsCarried } from "./session.ts";

/** A branch that a fork proposes, with what it rests on. */
export interface ProposedBranch {
  /** The `Branch` record. */
  readonly branch: Branch;
  /** The fork that proposes it: the sender of the packet. */
  readonly child: string;
  /** Its parent, a participant of the session. */
  readonly parent: string;
  /** The parent's session it proposes to go on from. */
  readonly parentSession: Session;
}

/**
 * Layer 1, 14.5: judges the `Branch` record a packet carries.
 *
 * The proposal stands if:
 *
 * - the packet carries one `Branch` record, and is not itself a packet of
 *   the session it names: a fork does not send in its parent's sessions;
 * - the receiver holds that session;
 * - `fork` names an event of a participant of that session, which is a
 *   `Fork` event whose `child` is the packet's sender;
 * - the sender's own genesis names that participant as a parent, and the
 *   lineage is acknowledged (8.2).
 *
 * @param received - The packet, from `receivePacket`: its sender's
 *   signature has counted.
 * @param session - The `Session` record of a session the receiver holds,
 *   by its ID: `Sessions.session` is one such lookup.
 */
export function verifyBranch(
  received: ReceivedPacket,
  session: (id: string) => Session | undefined,
  view: IdentityView,
): Validation<ProposedBranch> {
  return judging(() => proposed(received, session, view));
}

function proposed(
  received: ReceivedPacket,
  session: (id: string) => Session | undefined,
  view: IdentityView,
): Validation<ProposedBranch> {
  const { packet } = received;
  const carried = recordsCarried(packet, "Branch");
  const [branch] = carried;
  if (branch === undefined || carried.length > 1) {
    return no("the packet carries one Branch record", "L1 14.5", "/content");
  }
  if (packet.session === branch.parentSession) {
    return no("a fork does not send packets in its parent's sessions", "L1 14.5", "/session");
  }
  const parentSession = session(branch.parentSession);
  if (parentSession === undefined) {
    return no("the receiver does not hold the session the branch names", "L1 14.5", "/content");
  }
  const named = parseVersionedMind(branch.fork);
  if (named === undefined || !parentSession.participants.includes(named.mind)) {
    return no(
      "`fork` does not name an event of a participant of that session",
      "L1 14.5",
      "/content",
    );
  }
  const parent = view.log(named.mind);
  if (!parent.ok) return parent;
  const event = entryAt(parent.value, named.versionId)?.entry.event as
    { readonly type: string; readonly child?: unknown } | undefined;
  if (event?.type !== "Fork" || event.child !== packet.from) {
    return no("`fork` does not name a Fork event for the sender", "L1 14.5", "/content");
  }
  const child = view.log(packet.from);
  if (!child.ok) return child;
  const acknowledged = lineage(child.value, view).some(
    (from) => from.mind === named.mind && from.status === "acknowledged",
  );
  if (!acknowledged) {
    return no("the sender's lineage from that participant is not acknowledged", "L1 8.2", "/from");
  }
  return ok({ branch, child: packet.from, parent: named.mind, parentSession });
}
