// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Location records (Layer 1, Section 15): where a mind can be reached now,
 * and in what order a sender tries its endpoints.
 */

import { contentId, type Instant } from "@oip/core";
import { type IdentityView, type JudgedRecord, ownSignedTime } from "@oip/identity";
import type { Endpoint, Location } from "@oip/schema";

import { finding } from "./result.ts";

/** A location record that counts for its mind. */
export interface HeldLocation {
  /** The record's content ID. */
  readonly id: string;
  /** The record. */
  readonly record: Location;
  /** The evaluation time of its author's signature. */
  readonly time: Instant;
}

/**
 * Layer 1, 15.2: the current location record of a mind, among those held.
 *
 * It is the one with the highest `seq` among the mind's location records
 * that are signed by its own authority under the current-state rule (6.1,
 * item 6; for a collective 9.5), and of two with that `seq`, the one with
 * the lower content ID. A record signed with a key the mind has since
 * removed counts no longer, however high its `seq`, so nobody who held a
 * key can lock the mind out.
 *
 * @param records - The records held, from `judgeRecord`. Those that are no
 *   location record of this mind are passed over.
 * @returns `undefined` if no record held counts.
 */
export function currentLocation(
  records: Iterable<JudgedRecord>,
  mind: string,
  view: IdentityView,
): HeldLocation | undefined {
  return finding(() => locationAmong(records, mind, view));
}

/** The current location record, as `currentLocation` answers when no check is cut short. */
function locationAmong(
  records: Iterable<JudgedRecord>,
  mind: string,
  view: IdentityView,
): HeldLocation | undefined {
  let current: HeldLocation | undefined;
  for (const judged of records) {
    const { type, author } = judged.record as { type: string; author?: unknown };
    if (type !== "Location" || author !== mind) continue;
    const record = judged.record as Location;
    // A record that cannot win is not judged: its signature is the costly part.
    if (current !== undefined && record.seq < current.record.seq) continue;
    const id = contentId(record);
    if (record.seq === current?.record.seq && id >= current.id) continue;
    const time = ownSignedTime(judged, mind, view);
    if (time !== undefined) current = { id, record, time };
  }
  return current;
}

/** The bindings of Layer 1, 15.1 that this revision gives a meaning to. */
export type Binding = "https" | "wss" | "mailbox";

const BINDINGS: readonly string[] = ["https", "wss", "mailbox"];

/** An endpoint whose binding this revision gives a meaning to. */
export type KnownEndpoint = Endpoint & { readonly binding: Binding };

/** Lower `priority` first; an endpoint without one after those with one; otherwise as listed. */
function byPriority(endpoints: readonly KnownEndpoint[]): KnownEndpoint[] {
  return endpoints
    .map((endpoint, listed) => ({ endpoint, listed }))
    .toSorted((a, b) => {
      const [first, second] = [a.endpoint.priority, b.endpoint.priority];
      if (first !== undefined && second !== undefined && first !== second) return first - second;
      if ((first === undefined) !== (second === undefined)) return first === undefined ? 1 : -1;
      return a.listed - b.listed;
    })
    .map(({ endpoint }) => endpoint);
}

/**
 * Layer 1, 15.1 and 15.3: the endpoints of a location record in the order a
 * sender tries them.
 *
 * Endpoints with a binding this revision gives no meaning to are ignored
 * (15.1). The others come in priority order, lower first, with the
 * `mailbox` endpoints after the rest: a mailbox is for when no other
 * endpoint accepts the packet. While the mind's `status` is `paused`, only
 * its mailboxes are tried.
 */
export function endpointsToTry(record: Location): KnownEndpoint[] {
  const known = record.endpoints.filter((endpoint): endpoint is KnownEndpoint =>
    BINDINGS.includes(endpoint.binding),
  );
  const mailboxes = byPriority(known.filter((endpoint) => endpoint.binding === "mailbox"));
  if (record.status === "paused") return mailboxes;
  return [...byPriority(known.filter((endpoint) => endpoint.binding !== "mailbox")), ...mailboxes];
}

/** An `https` URL with no query and no fragment, which a path can be added to. */
const BASE_URL = /^https:\/\/[^\s?#]+$/;

/** A base URL with a path added, whether or not the base ends with a slash. */
function under(base: string, path: string): string | undefined {
  return BASE_URL.test(base) ? `${base.replace(/\/+$/, "")}/${path}` : undefined;
}

/**
 * Layer 1, 15.1 and 13.2: the URL a packet is posted to at an endpoint. For
 * the `https` binding it is `{url}/inbox`, and for `mailbox` the URL
 * itself.
 *
 * @returns `undefined` for a `wss` endpoint, which takes no posts, and for
 *   an `https` endpoint whose `url` is no base URL: not `https`, or with a
 *   query or a fragment.
 */
export function postUrl(endpoint: KnownEndpoint): string | undefined {
  if (endpoint.binding === "https") return under(endpoint.url, "inbox");
  return endpoint.binding === "mailbox" ? endpoint.url : undefined;
}

/**
 * Layer 1, 15.1 and 13.4: the WebSocket URL of an endpoint. For the `wss`
 * binding it is the URL itself, and for `https` it is `{url}/ws` with the
 * `wss` scheme.
 *
 * @returns `undefined` for a `mailbox` endpoint, and for an `https`
 *   endpoint whose `url` is no base URL.
 */
export function webSocketUrl(endpoint: KnownEndpoint): string | undefined {
  if (endpoint.binding === "wss") return endpoint.url;
  if (endpoint.binding !== "https") return undefined;
  const url = under(endpoint.url, "ws");
  return url === undefined ? undefined : `wss${url.slice("https".length)}`;
}
