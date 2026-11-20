// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * An A2A Agent Card, read as what it is to a gateway: something a stranger
 * wrote (Layer 0, 3.1).
 *
 * A card is fetched from a place its agent names, so nothing in it is
 * believed. It is read within limits, the members a gateway uses are
 * checked one by one, and what a gateway does not use is not looked at.
 * The card's digest is of the exact bytes that were served: it is what the
 * bridged mind's profile records, so that anyone can tell which card the
 * gateway saw.
 *
 * The shapes are those of A2A 1.0 (`AgentCard` and what it holds, in the
 * protocol's `a2a.proto`), in their JSON form: member names in camel case.
 */

import { sha256Digest } from "@oip/core";
import type { Issue, Validation } from "@oip/schema";

/** Where an agent's card is, under its origin (A2A, Section 8.2). */
export const CARD_PATH = "/.well-known/agent-card.json";

/** The version of A2A this gateway speaks: its major and minor number (A2A, Section 3.6). */
export const A2A_VERSION = "1.0";

/** The longest card that is read, in bytes. */
export const MAX_CARD_BYTES = 262_144;
/** The most skills, interfaces, extensions and signatures of a card that are read. */
export const MAX_CARD_ITEMS = 256;
/** The longest text of a card that is kept. */
export const MAX_CARD_TEXT = 4096;

/** How an agent can be reached: one of its interfaces. */
export interface AgentInterface {
  /** Where the interface is. */
  readonly url: string;
  /** How it is spoken: `JSONRPC`, `GRPC`, `HTTP+JSON`, or a binding of the agent's own. */
  readonly protocolBinding: string;
  /** The version of A2A it speaks. */
  readonly protocolVersion: string;
  /** What a client sets as `tenant` in every request to it, if anything. */
  readonly tenant?: string;
}

/** Something an agent says it can do. */
export interface AgentSkill {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly tags: readonly string[];
}

/** An extension an agent says it supports (A2A, Section 4.6). */
export interface AgentExtension {
  readonly uri: string;
  readonly required: boolean;
}

/** A signature on a card: the parts of a JWS (A2A, Section 8.4.2). */
export interface CardSignature {
  /** The protected header, as base64url of its JSON. */
  readonly protected: string;
  /** The signature, as base64url. */
  readonly signature: string;
}

/** The members of an Agent Card that a gateway uses. */
export interface AgentCard {
  readonly name: string;
  readonly description: string;
  /** The agent's own version: not the protocol's. */
  readonly version: string;
  /** How the agent is reached, the one it prefers first. */
  readonly supportedInterfaces: readonly AgentInterface[];
  readonly skills: readonly AgentSkill[];
  /** The extensions it says it supports. */
  readonly extensions: readonly AgentExtension[];
  /** The media types it takes and gives where a skill does not say. */
  readonly defaultInputModes: readonly string[];
  readonly defaultOutputModes: readonly string[];
  /** The signatures on it. None is a card nobody signed. */
  readonly signatures: readonly CardSignature[];
}

/** A card that was read. */
export interface ReadCard {
  /** What a gateway uses of it. */
  readonly card: AgentCard;
  /**
   * `"sha256:"` and the 64 hexadecimal digits of the digest of the exact
   * bytes: what `ext["oip.a2a"].cardDigest` records (Layer 0, 3.1).
   */
  readonly digest: string;
  /** The card as JSON, whole: what a signature on it is over. */
  readonly json: Readonly<Record<string, unknown>>;
}

const CLAUSE = "L0 3.1";

const isObject = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** Reads the members of a card, and gathers what is wrong with them. */
class Reader {
  readonly issues: Issue[] = [];

  no(path: string, message: string): undefined {
    this.issues.push({ path, message, clause: CLAUSE });
    return undefined;
  }

  /** A text that must be there. */
  text(from: Readonly<Record<string, unknown>>, name: string, path: string): string {
    const value = from[name];
    if (typeof value !== "string" || value === "") {
      this.no(`${path}/${name}`, "a text is required here");
      return "";
    }
    if (value.length > MAX_CARD_TEXT) {
      this.no(`${path}/${name}`, `a text of at most ${String(MAX_CARD_TEXT)} characters is read`);
      return "";
    }
    return value;
  }

  /** A text that may be there. An empty one says nothing, and is none. */
  optional(
    from: Readonly<Record<string, unknown>>,
    name: string,
    path: string,
  ): string | undefined {
    return from[name] === undefined || from[name] === "" ? undefined : this.text(from, name, path);
  }

  /** A list that may be absent, of no more items than are read. */
  list(from: Readonly<Record<string, unknown>>, name: string, path: string): readonly unknown[] {
    const value = from[name];
    if (value === undefined) return [];
    if (!Array.isArray(value)) {
      this.no(`${path}/${name}`, "a list is required here");
      return [];
    }
    if (value.length > MAX_CARD_ITEMS) {
      this.no(`${path}/${name}`, `a list of at most ${String(MAX_CARD_ITEMS)} items is read`);
      return [];
    }
    return value as readonly unknown[];
  }

  /** A list of texts. */
  texts(from: Readonly<Record<string, unknown>>, name: string, path: string): string[] {
    return this.list(from, name, path).flatMap((item, index) => {
      if (typeof item === "string" && item !== "" && item.length <= MAX_CARD_TEXT) return [item];
      this.no(`${path}/${name}/${String(index)}`, "a text is required here");
      return [];
    });
  }

  /** The objects of a list, each with its place. */
  objects(
    from: Readonly<Record<string, unknown>>,
    name: string,
    path: string,
  ): { item: Readonly<Record<string, unknown>>; at: string }[] {
    return this.list(from, name, path).flatMap((item, index) => {
      const at = `${path}/${name}/${String(index)}`;
      if (isObject(item)) return [{ item, at }];
      this.no(at, "an object is required here");
      return [];
    });
  }
}

/**
 * Reads an Agent Card from the bytes an agent's origin served.
 *
 * @returns The card, with its digest. A card that lacks a member A2A
 *   requires and a gateway uses, or holds something else where one
 *   belongs, is refused, with every such place.
 */
export function readCard(bytes: Uint8Array): Validation<ReadCard> {
  const refused = (message: string): Validation<ReadCard> => ({
    ok: false,
    issues: [{ path: "", message, clause: CLAUSE }],
  });
  if (bytes.length > MAX_CARD_BYTES) {
    return refused(`a card of at most ${String(MAX_CARD_BYTES)} bytes is read`);
  }
  let json: unknown;
  try {
    json = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return refused("the card is not JSON in UTF-8");
  }
  if (!isObject(json)) return refused("the card is not a JSON object");
  const read = new Reader();
  const capabilities = json["capabilities"];
  if (!isObject(capabilities)) read.no("/capabilities", "an object is required here");
  const interfaces = read.objects(json, "supportedInterfaces", "").map(({ item, at }) => {
    const tenant = read.optional(item, "tenant", at);
    return {
      url: read.text(item, "url", at),
      protocolBinding: read.text(item, "protocolBinding", at),
      protocolVersion: read.text(item, "protocolVersion", at),
      ...(tenant === undefined ? {} : { tenant }),
    };
  });
  if (interfaces.length === 0 && read.issues.length === 0) {
    read.no("/supportedInterfaces", "a card names at least one interface");
  }
  const card: AgentCard = {
    name: read.text(json, "name", ""),
    description: read.text(json, "description", ""),
    version: read.text(json, "version", ""),
    supportedInterfaces: interfaces,
    skills: read.objects(json, "skills", "").map(({ item, at }) => ({
      id: read.text(item, "id", at),
      name: read.text(item, "name", at),
      description: read.text(item, "description", at),
      tags: read.texts(item, "tags", at),
    })),
    extensions: (isObject(capabilities)
      ? read.objects(capabilities, "extensions", "/capabilities")
      : []
    ).map(({ item, at }) => ({
      uri: read.text(item, "uri", at),
      required: item["required"] === true,
    })),
    defaultInputModes: read.texts(json, "defaultInputModes", ""),
    defaultOutputModes: read.texts(json, "defaultOutputModes", ""),
    signatures: read.objects(json, "signatures", "").map(({ item, at }) => ({
      protected: read.text(item, "protected", at),
      signature: read.text(item, "signature", at),
    })),
  };
  const [first, ...rest] = read.issues;
  if (first !== undefined) return { ok: false, issues: [first, ...rest] };
  return { ok: true, value: { card, digest: sha256Digest(bytes), json } };
}

/** Whether a card says its agent supports an extension. */
export function supports(card: AgentCard, uri: string): boolean {
  return card.extensions.some((extension) => extension.uri === uri);
}

/**
 * The interface of a card this gateway speaks to: the first that is spoken
 * as JSON-RPC, in this gateway's version of A2A, at an HTTPS URL. A card
 * lists its interfaces in the order its agent prefers (A2A, Section 8.3).
 */
export function interfaceOf(card: AgentCard): AgentInterface | undefined {
  return card.supportedInterfaces.find(
    ({ url, protocolBinding, protocolVersion }) =>
      protocolBinding === "JSONRPC" &&
      protocolVersion === A2A_VERSION &&
      url.startsWith("https://"),
  );
}
