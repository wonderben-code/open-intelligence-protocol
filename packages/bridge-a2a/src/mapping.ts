// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What a thing of A2A is in OIP, and the other way round (Layer 0, 3.1 and
 * 3.2). Nothing here fetches, signs or reads a clock: each function takes
 * what was already read and says what it maps to.
 */

import { recordText } from "@oip/local";
import { type Capability, type Participant, patterns } from "@oip/schema";

import { A2A_VERSION, type AgentCard } from "./card.ts";

/** The URI by which an agent declares the OIP extension for A2A (Layer 0, 3.3). */
export const OIP_EXTENSION =
  "https://github.com/wonderben-code/open-intelligence-protocol/blob/main/spec/layer-0-bridge.md#a2a-extension";

/** The media type of an OIP record, and of the data part that carries a packet (Layer 0, 3.3). */
export const OIP_MEDIA_TYPE = "application/oip+json";

/** The namespace an A2A skill's tags are given as tags of a capability. */
export const TAG_NAMESPACE = "a2a";

/** The longest `id` of a capability (Layer 1, 16.2). */
const MAX_ID = 128;
/** The most capabilities of a profile, and the most tags of one. */
const MAX_CAPABILITIES = 256;
const MAX_TAGS = 64;
/** The longest summary this gateway writes for a capability. */
const MAX_SUMMARY = 1024;

/** The longest tag of a skill that becomes a tag of a capability. */
const MAX_TAG = 128;
/** What a tag of a capability is: a name in a namespace (Layer 1, 16.2). */
const NAMESPACED = new RegExp(patterns.namespaced, "u");

/**
 * Layer 0, 3.1: the capabilities of a bridged mind, one for each skill of
 * its agent's card.
 *
 * A capability's `id` is the skill's. Its `summary` is the skill's name
 * and description, which are the agent's own words. A skill's tags are
 * free words, and a capability's are namespaced: each becomes `a2a:<tag>`.
 * A skill whose `id` a capability cannot carry, or that repeats one, is
 * left out: a profile has no two capabilities of one `id` (Layer 1, 16.2).
 * So is a tag that is no name: an empty one, or one of several lines.
 *
 * A card's texts are a stranger's. Whatever is in them, what is made here
 * is text a record holds (core 1.1), cut between characters where it is
 * too long: no card keeps a profile from being signed.
 */
export function capabilitiesOf(card: AgentCard): Capability[] {
  const taken = new Set<string>();
  const capabilities: Capability[] = [];
  for (const skill of card.skills) {
    if (capabilities.length >= MAX_CAPABILITIES) break;
    // An `id` is a name that is asked for: one that had to be mended would be another.
    if (skill.id.length > MAX_ID || recordText(skill.id) !== skill.id || taken.has(skill.id)) {
      continue;
    }
    taken.add(skill.id);
    const tags = [
      ...new Set(
        skill.tags
          .filter((tag) => tag.length <= MAX_TAG && recordText(tag) === tag)
          .map((tag) => `${TAG_NAMESPACE}:${tag}`)
          .filter((tag) => NAMESPACED.test(tag)),
      ),
    ].slice(0, MAX_TAGS);
    const summary =
      skill.name === skill.description ? skill.name : `${skill.name}: ${skill.description}`;
    capabilities.push({
      id: skill.id,
      summary: recordText(summary, MAX_SUMMARY),
      ...(tags.length === 0 ? {} : { tags }),
    });
  }
  return capabilities;
}

/** What a host supplies for the card of a mind it serves: a profile has none of it (Layer 0, 3.2). */
export interface Served {
  /** The URL of the A2A interface the host translates into OIP packets. */
  readonly url: string;
  /** The card's version: the host's to give. */
  readonly version: string;
}

/** The longest name of a skill that is taken from a capability's summary. */
const MAX_SKILL_NAME = 64;

/**
 * Layer 0, 3.2: the Agent Card of an OIP mind, from its profile.
 *
 * Capabilities become skills. A capability has one text, its `summary`: it
 * is the skill's description, and its name too where it is short enough to
 * be one, or else its `id`. The interface is spoken as JSON-RPC, in this
 * gateway's version of A2A, and the card declares the OIP extension
 * (Layer 0, 3.3): a caller that knows it can send a whole packet.
 *
 * @returns The card, as the JSON a host serves.
 */
export function cardFor(profile: Participant, served: Served): Record<string, unknown> {
  return {
    name: profile.name,
    description: profile.summary ?? profile.name,
    supportedInterfaces: [
      { url: served.url, protocolBinding: "JSONRPC", protocolVersion: A2A_VERSION },
    ],
    version: served.version,
    capabilities: {
      streaming: false,
      pushNotifications: false,
      extensions: [
        {
          uri: OIP_EXTENSION,
          description:
            "A message may carry a whole, signed OIP packet as a data part of media type application/oip+json.",
          required: false,
        },
      ],
    },
    defaultInputModes: ["text/plain", "application/json", OIP_MEDIA_TYPE],
    defaultOutputModes: ["text/plain", "application/json", OIP_MEDIA_TYPE],
    skills: (profile.capabilities ?? []).map((capability) => ({
      id: capability.id,
      name: capability.summary.length <= MAX_SKILL_NAME ? capability.summary : capability.id,
      description: capability.summary,
      // A capability's tags are namespaced already. A skill's are any words: they pass as they are.
      tags: [...(capability.tags ?? [])],
    })),
  };
}

/** The states of an A2A task, as its JSON form writes them (A2A, Section 4.1.3). */
export const TASK_STATES = [
  "TASK_STATE_SUBMITTED",
  "TASK_STATE_WORKING",
  "TASK_STATE_COMPLETED",
  "TASK_STATE_FAILED",
  "TASK_STATE_CANCELED",
  "TASK_STATE_INPUT_REQUIRED",
  "TASK_STATE_REJECTED",
  "TASK_STATE_AUTH_REQUIRED",
] as const;
/** A state of an A2A task. */
export type TaskState = (typeof TASK_STATES)[number];

/**
 * What a gateway says in OIP of a task that has reached a state (Layer 0,
 * 3.1): a Receipt with an outcome, a packet with a verb, or nothing yet.
 */
export type Said =
  | { readonly as: "receipt"; readonly outcome: "fulfilled" | "broken" | "cancelled" }
  | { readonly as: "packet"; readonly verb: "decline" | "request" }
  | { readonly as: "nothing" };

/**
 * Layer 0, 3.1: what the state of a task maps to.
 *
 * `completed` is a Receipt with outcome `fulfilled`, `failed` one with
 * `broken`, and `canceled` one with `cancelled`. `rejected` is a packet
 * with verb `decline`. `input-required` and `auth-required` are a packet
 * with verb `request`, to the requester. A task that is submitted or at
 * work has nothing said of it yet, and neither has one whose state this
 * gateway does not know: a gateway says what it observed, and no more
 * (Layer 0, 1.4).
 */
export function saidOf(state: unknown): Said {
  switch (state) {
    case "TASK_STATE_COMPLETED":
      return { as: "receipt", outcome: "fulfilled" };
    case "TASK_STATE_FAILED":
      return { as: "receipt", outcome: "broken" };
    case "TASK_STATE_CANCELED":
      return { as: "receipt", outcome: "cancelled" };
    case "TASK_STATE_REJECTED":
      return { as: "packet", verb: "decline" };
    case "TASK_STATE_INPUT_REQUIRED":
    case "TASK_STATE_AUTH_REQUIRED":
      return { as: "packet", verb: "request" };
    default:
      return { as: "nothing" };
  }
}

/** Whether a task in this state will change no more (A2A, Section 4.1.3). */
export function isTerminal(state: unknown): boolean {
  return (
    state === "TASK_STATE_COMPLETED" ||
    state === "TASK_STATE_FAILED" ||
    state === "TASK_STATE_CANCELED" ||
    state === "TASK_STATE_REJECTED"
  );
}
