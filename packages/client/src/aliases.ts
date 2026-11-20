// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Whether the other names a mind gives itself are its own (Layer 1, 5.3;
 * Layer 0, Section 4).
 *
 * A mind lists its aliases in its identity log, and listing proves nothing:
 * anyone can list any name. An alias is verified when it points back to the
 * mind. How it points back depends on what kind of name it is, and each
 * kind is asked where that kind of name is answered for: a website, the
 * DNS, another DID's document.
 *
 * Every one of those is a stranger, and what it answers is bounded and read
 * for one thing only: whether it names this mind.
 */

import { OipError } from "@oip/core";

import { exchange, httpsOrigin, TransportError, type TransportOptions } from "./transport.ts";

/** What became of one alias a mind lists. */
export interface AliasCheck {
  /** The alias, as the mind's identity log has it. */
  readonly alias: string;
  /** Whether it points back to the mind. Only then is it the mind's (Layer 0, 4.2). */
  readonly verified: boolean;
  /**
   * Why it is not verified:
   *
   * - `not-pointing-back`: what answers for the alias does not name this mind;
   * - `unreachable`: what answers for the alias could not be asked;
   * - `unsupported`: the client has no way to ask for this kind of alias, or
   *   the kind cannot point back at all, as a `did:key` cannot.
   */
  readonly reason?: "not-pointing-back" | "unreachable" | "unsupported";
}

/** What a client asks besides HTTPS to verify aliases. Each is optional. */
export interface AliasOptions {
  /**
   * Looks up the TXT records of a DNS name, each as its character-strings:
   * in Node.js, `resolveTxt` of `node:dns/promises`. It answers an empty
   * list, or throws, for a name with none. Without it a `dns:` alias is
   * `unsupported`.
   */
  readonly dnsTxt?: (name: string) => Promise<readonly (readonly string[])[]>;
  /**
   * Resolves a DID of a method the client does not resolve itself to its
   * document, or to `undefined` if there is none. The client resolves
   * `did:oip` and `did:web`. Without it, an alias of another method is
   * `unsupported`.
   */
  readonly resolveDid?: (did: string) => Promise<DidLike | undefined>;
}

/** What is read of another DID's document. */
export interface DidLike {
  /** The DID the document is of. */
  readonly id?: unknown;
  /** The other names it gives itself. */
  readonly alsoKnownAs?: unknown;
}

/** What checking aliases needs of the client. */
export interface AliasEnvironment extends AliasOptions {
  readonly transport: TransportOptions;
  /** The aliases an OIP mind lists, for an alias that is another mind. */
  readonly aliasesOf: (mind: string) => Promise<readonly string[]>;
}

/** The most bytes read of a name that points back: an address and a line ending fit many times over. */
const MAX_TEXT_BYTES = 1024;
/** The most bytes read of another DID's document. */
const MAX_DOCUMENT_BYTES = 64 * 1024;
/** A DNS name: labels of letters, digits and hyphens, 253 characters at most. */
const DNS_NAME =
  /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/iu;

/** What an application's own lookup failed with, whatever that was: it could not be asked. */
class NotAsked extends Error {}

/** Calls something the application gave the client. That it throws is its way of saying no answer. */
async function asked<T>(work: () => Promise<T>): Promise<T> {
  try {
    return await work();
  } catch {
    throw new NotAsked();
  }
}

const verified = (alias: string): AliasCheck => ({ alias, verified: true });
const not = (alias: string, reason: NonNullable<AliasCheck["reason"]>): AliasCheck => ({
  alias,
  verified: false,
  reason,
});

/** Whether a DID document lists a name among its other names. */
const lists = (document: DidLike | undefined, name: string): boolean =>
  Array.isArray(document?.alsoKnownAs) && (document.alsoKnownAs as unknown[]).includes(name);

/** The text of a small `text/plain` answer, without the one line ending it may end with. */
async function plainText(url: string, transport: TransportOptions): Promise<string | undefined> {
  const answer = await exchange({ method: "GET", url }, { ...transport, maxBytes: MAX_TEXT_BYTES });
  if (answer.status !== 200 || answer.mediaType !== "text/plain") return undefined;
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(answer.body);
    return text.replace(/\r?\n$/u, "");
  } catch {
    return undefined;
  }
}

/**
 * The document of a `did:web` DID (W3C CCG did:web): `did:web:example.com`
 * is at `https://example.com/.well-known/did.json`, and a DID with a path
 * at that path's `did.json`. A port is written `%3A` in the DID.
 */
async function webDocument(did: string, transport: TransportOptions): Promise<DidLike | undefined> {
  const [host = "", ...path] = did.slice("did:web:".length).split(":");
  let url: string;
  try {
    const origin = `https://${decodeURIComponent(host)}`;
    if (httpsOrigin(origin) !== origin) return undefined;
    url =
      path.length === 0
        ? `${origin}/.well-known/did.json`
        : `${origin}/${path.map((part) => encodeURIComponent(decodeURIComponent(part))).join("/")}/did.json`;
  } catch {
    return undefined;
  }
  const answer = await exchange(
    { method: "GET", url },
    { ...transport, maxBytes: MAX_DOCUMENT_BYTES },
  );
  if (answer.status !== 200) return undefined;
  try {
    const document = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(answer.body),
    ) as unknown;
    // A document is that DID's only if it says so: one host serves many.
    return typeof document === "object" && document !== null && (document as DidLike).id === did
      ? document
      : undefined;
  } catch {
    return undefined;
  }
}

/** The document of a DID, by whatever resolves its method: `undefined` if nothing here does. */
async function documentOf(
  did: string,
  environment: AliasEnvironment,
): Promise<DidLike | "unsupported" | undefined> {
  if (did.startsWith("did:oip:")) {
    return { id: did, alsoKnownAs: await environment.aliasesOf(did) };
  }
  if (did.startsWith("did:web:")) return webDocument(did, environment.transport);
  // A document that cannot list other names cannot point back (Layer 1, 5.3).
  const { resolveDid } = environment;
  if (did.startsWith("did:key:") || resolveDid === undefined) return "unsupported";
  return asked(() => resolveDid(did));
}

/** The DID an AT Protocol handle stands for: by the DNS where the client can ask it, or else by HTTPS. */
async function handleDid(
  handle: string,
  environment: AliasEnvironment,
): Promise<string | undefined> {
  if (environment.dnsTxt !== undefined) {
    try {
      for (const record of await environment.dnsTxt(`_atproto.${handle}`)) {
        const value = record.join("");
        if (value.startsWith("did=")) return value.slice("did=".length);
      }
    } catch {
      // No such record: the handle may be answered for over HTTPS.
    }
  }
  return plainText(`https://${handle}/.well-known/atproto-did`, environment.transport);
}

/**
 * Layer 1, 5.3: whether an alias points back to a mind.
 *
 * It never throws for what a stranger answers, or fails to answer: that is
 * an alias that is not verified, with why.
 */
export async function checkAlias(
  alias: string,
  mind: string,
  environment: AliasEnvironment,
): Promise<AliasCheck> {
  try {
    if (alias.startsWith("https://")) {
      // An origin, and nothing after it: a page of a site is not the site.
      if (httpsOrigin(alias) !== alias) return not(alias, "unsupported");
      const said = await plainText(`${alias}/.well-known/oip/did`, environment.transport);
      return said === mind ? verified(alias) : not(alias, "not-pointing-back");
    }
    if (alias.startsWith("dns:")) {
      const name = alias.slice("dns:".length);
      const { dnsTxt } = environment;
      if (dnsTxt === undefined || !DNS_NAME.test(name)) return not(alias, "unsupported");
      const records = await asked(() => dnsTxt(`_oip.${name}`));
      return records.some((record) => record.join("") === `did=${mind}`)
        ? verified(alias)
        : not(alias, "not-pointing-back");
    }
    if (alias.startsWith("at://")) {
      const handle = alias.slice("at://".length);
      if (!DNS_NAME.test(handle)) return not(alias, "unsupported");
      const did = await handleDid(handle, environment);
      if (!did?.startsWith("did:")) return not(alias, "not-pointing-back");
      const document = await documentOf(did, environment);
      if (document === "unsupported") return not(alias, "unsupported");
      return lists(document, mind) ? verified(alias) : not(alias, "not-pointing-back");
    }
    if (alias.startsWith("did:")) {
      const document = await documentOf(alias, environment);
      if (document === "unsupported") return not(alias, "unsupported");
      return lists(document, mind) ? verified(alias) : not(alias, "not-pointing-back");
    }
    return not(alias, "unsupported");
  } catch (error) {
    // What answers for an alias is a stranger: that it failed says nothing of the mind.
    if (error instanceof TransportError || error instanceof OipError || error instanceof NotAsked) {
      return not(alias, "unreachable");
    }
    throw error;
  }
}
