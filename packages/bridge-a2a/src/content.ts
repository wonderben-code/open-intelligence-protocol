// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What a packet carries and what an A2A message or artifact holds, each as
 * the other (Layer 0, 3.1; Layer 1, 12.2).
 *
 * A2A has four kinds of part: a text, bytes, a file by its URL, and data.
 * A packet's content is a body with its media type, or a reference with
 * the digest of its bytes. A text is a text on both sides, and data is
 * JSON on both. A file by its URL is a reference where the gateway can say
 * which bytes were there, and a URL in a text where it cannot. A packet
 * has no place for bytes: they are attested by their digest, and left out.
 */

import { type JsonObject, sha256Digest } from "@oip/core";
import { jsonText, recordText } from "@oip/local";
import type { InlineContent, Packet, ReferencedContent } from "@oip/schema";

import type { Get, Part } from "./a2a.ts";
import { OIP_MEDIA_TYPE } from "./mapping.ts";

/** One piece of a packet's content: carried, or named with its digest. */
export type Content = InlineContent | ReferencedContent;

/** The most parts of a packet's content (Layer 1, 12.2). */
const MAX_CONTENT_PARTS = 32;
/** The most evidence items of a Receipt (Layer 2, 6.1). */
const MAX_EVIDENCE = 64;
/**
 * The most of another's content one packet carries, in bytes of the
 * packet's canonical form: a packet is a record, of a megabyte at most.
 */
export const MAX_CARRIED_BYTES = 262_144;
/** The most files of one answer the gateway fetches to say which bytes were there. */
export const MAX_FETCHED = 8;

export const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

/**
 * How much of a record a text takes, in bytes of the canonical form: there
 * a control character is six bytes, and a quotation mark two (core 1.4).
 */
const carriedSize = (text: string): number => utf8(JSON.stringify(text)).length;

/** A media type as a stranger gives it, without parameters, or another where it gives none that can be told. */
export function mediaTypeOf(part: Part, otherwise: string): string {
  const given = (part.mediaType ?? "").replace(/;.*$/su, "").trim().toLowerCase();
  const told = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}$/u.test(given);
  // Who speaks A2A signs nothing: what it calls a record is carried as the data it is.
  return told && given !== OIP_MEDIA_TYPE ? given : otherwise;
}

/**
 * A URL of the web as a stranger gives it, or `undefined` for what is none.
 * It is given as a parser of URLs writes it, which is ASCII: the text a
 * stranger wrote may be nothing a record holds.
 */
function webUrl(text: string): string | undefined {
  if (text.length > 2048 || !URL.canParse(text)) return undefined;
  const { protocol, href } = new URL(text);
  return (protocol === "https:" || protocol === "http:") && href.length <= 2048 ? href : undefined;
}

/** The name of the file a URL of the web ends in, if it ends in one. */
function fileOf(ref: string): string | undefined {
  if (webUrl(ref) === undefined) return undefined;
  const last = new URL(ref).pathname.split("/").at(-1) ?? "";
  try {
    const name = decodeURIComponent(last);
    return name === "" || name.length > 255 ? undefined : name;
  } catch {
    return undefined;
  }
}

/**
 * The parts of an A2A message or artifact that say what a packet's content
 * says. A message has one part at least: content that says nothing a part
 * can is one empty text.
 */
export function partsOf(content: Packet["content"]): Part[] {
  const pieces: readonly Content[] = "parts" in content ? content.parts : [content];
  const said = pieces.flatMap((piece): Part[] => {
    const { mediaType } = piece;
    if ("ref" in piece) {
      const filename = fileOf(piece.ref);
      return [{ url: piece.ref, mediaType, ...(filename === undefined ? {} : { filename }) }];
    }
    // The record that names a session is the session's own business, and nothing anyone is asked or told.
    const { body } = piece as { body: unknown };
    if (
      mediaType === OIP_MEDIA_TYPE &&
      typeof body === "object" &&
      body !== null &&
      (body as { type?: unknown }).type === "Session"
    ) {
      return [];
    }
    return [typeof body === "string" ? { text: body, mediaType } : { data: body, mediaType }];
  });
  return said.length === 0 ? [{ text: "" }] : said;
}

/** What is made of the parts a stranger gave: content to carry, and evidence of what was there. */
export interface Gathered {
  readonly content: Content[];
  /** Evidence items (Layer 2, Section 9). None unless the bytes were to be attested. */
  readonly evidence: JsonObject[];
  /** How many parts are not carried: bytes, and what is too large or too much. */
  readonly left: number;
  /** How many of those the evidence has a digest of. */
  readonly leftAttested: number;
}

/** The digest of the bytes at a URL, or `undefined` if they cannot be had. */
async function digestAt(url: string, get: Get): Promise<string | undefined> {
  try {
    const got = await get(url);
    return got.status === 200 ? sha256Digest(got.body) : undefined;
  } catch {
    // Nothing is said of a file that could not be fetched.
    return undefined;
  }
}

/**
 * Makes content for a packet of the parts of an A2A message or artifact.
 *
 * @param parts - Each part, with the name evidence of it is given under.
 * @param attest - How a file is fetched. Given, the gateway attests what
 *   it was shown: each part is evidence of kind `hash`, and a file the
 *   gateway could fetch is evidence of kind `uri` and is carried as a
 *   reference. Left out, nothing is fetched and no evidence is made.
 */
export async function gather(
  parts: readonly { readonly part: Part; readonly ref: string }[],
  attest?: Get,
): Promise<Gathered> {
  const content: Content[] = [];
  const evidence: JsonObject[] = [];
  let room = MAX_CARRIED_BYTES;
  let fetched = 0;
  let left = 0;
  let leftAttested = 0;
  /** Carries a piece if there is room for it. Whether it is carried. */
  const carry = (one: Content, size: number): boolean => {
    // Two places are kept: for a word about what is left out, and for a Receipt.
    if (content.length >= MAX_CONTENT_PARTS - 2 || size > room) return false;
    content.push(one);
    room -= size;
    return true;
  };
  /** Makes an evidence item if evidence is made, and a Receipt has room for one more. Whether it is made. */
  const attested = (item: JsonObject): boolean => {
    if (attest === undefined || evidence.length >= MAX_EVIDENCE) return false;
    evidence.push(item);
    return true;
  };
  /** Notes a part that is not carried, and whether the evidence has its digest all the same. */
  const leave = (digested: boolean): void => {
    left += 1;
    if (digested) leftAttested += 1;
  };
  for (const { part, ref } of parts) {
    if ("text" in part || "data" in part) {
      let text: string;
      if ("text" in part) {
        // A stranger's text, as text a record holds (core 1.1).
        text = recordText(part.text);
      } else {
        try {
          // Data may hold what a record cannot, a fraction for one: it is carried as its JSON text.
          text = jsonText(part.data);
        } catch {
          // Data that has no JSON text, nested too deep to walk, say.
          leave(false);
          continue;
        }
      }
      const mediaType = mediaTypeOf(part, "text" in part ? "text/plain" : "application/json");
      const carried = carry({ mediaType, body: text }, carriedSize(text));
      // The digest is of the text as it is carried, in UTF-8: of what the requester holds.
      const digested = attested({ kind: "hash", ref, digest: sha256Digest(utf8(text)), mediaType });
      if (!carried) leave(digested);
    } else if ("raw" in part) {
      // Bytes are attested by their digest, and not carried: a packet has no place for them.
      const bytes = new Uint8Array(Buffer.from(part.raw, "base64"));
      const mediaType = mediaTypeOf(part, "application/octet-stream");
      leave(attested({ kind: "hash", ref, digest: sha256Digest(bytes), mediaType }));
    } else {
      const url = webUrl(part.url);
      if (url === undefined) {
        leave(false);
        continue;
      }
      // A file that is named. The gateway says which bytes were there, if it can get them.
      let digest: string | undefined;
      if (attest !== undefined && url.startsWith("https://") && fetched < MAX_FETCHED) {
        fetched += 1;
        digest = await digestAt(url, attest);
      }
      if (digest === undefined) {
        if (!carry({ mediaType: "text/uri-list", body: url }, carriedSize(url))) leave(false);
      } else {
        const mediaType = mediaTypeOf(part, "application/octet-stream");
        const carried = carry({ mediaType, ref: url, digest }, carriedSize(url));
        const digested = attested({ kind: "uri", ref: url, digest, mediaType });
        if (!carried) leave(digested);
      }
    }
  }
  return { content, evidence, left, leftAttested };
}

/**
 * A word about what a packet does not carry, if there is any such.
 *
 * @param whose - What the parts are of: "the agent's answer", say.
 * @param attested - Of how many of the parts left out a Receipt has the
 *   digest. Left out where no Receipt comes with the packet.
 */
export function leftOut(left: number, whose: string, attested?: number): InlineContent[] {
  if (left === 0) return [];
  const what = left === 1 ? "one part" : `${String(left)} parts`;
  // What is said of the Receipt is what the Receipt holds, and no more (Layer 0, 1.4).
  const receipt =
    attested === undefined || attested === 0
      ? ""
      : attested >= left
        ? left === 1
          ? " The Receipt has its digest."
          : " The Receipt has their digests."
        : ` The Receipt has the digests of ${String(attested)} of them.`;
  return [
    {
      mediaType: "text/plain",
      body:
        `The gateway left ${what} of ${whose} out of this packet: ` +
        "bytes, and what is too large or too much for one packet, are not carried." +
        receipt,
    },
  ];
}
