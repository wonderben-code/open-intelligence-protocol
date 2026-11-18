// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Structured field values for HTTP (RFC 8941): the part of them that HTTP
 * message signatures and content digests use (RFC 9421, RFC 9530).
 *
 * A dictionary is read whose members are items or inner lists, with
 * integers, strings, tokens, byte sequences and booleans as values.
 * Decimals are not read: no field read here has one. The reading is strict
 * where the RFC lets a reader choose: a name given twice, in a dictionary
 * or among parameters, is no dictionary, so that a value is never read in
 * one way and signed in another.
 */

import { base64ToBytes, bytesToBase64 } from "@oip/core";

/** A value of a structured field, of the kinds read here. */
export type Bare =
  | { readonly kind: "integer"; readonly value: number }
  | { readonly kind: "string"; readonly value: string }
  | { readonly kind: "token"; readonly value: string }
  | { readonly kind: "bytes"; readonly value: Uint8Array }
  | { readonly kind: "boolean"; readonly value: boolean };

/** Parameters, in the order they were written. */
export type Parameters = readonly (readonly [name: string, value: Bare])[];

/** An item: a value with its parameters. */
export interface Item {
  readonly kind: "item";
  readonly value: Bare;
  readonly parameters: Parameters;
}

/** An inner list: items, with parameters of its own. */
export interface InnerList {
  readonly kind: "list";
  readonly items: readonly Item[];
  readonly parameters: Parameters;
}

/** The longest field value read: a signature of a request has a few hundred characters. */
const MAX_LENGTH = 16_384;

const KEY = /^[a-z*][a-z0-9_\-.*]*/u;
const TOKEN = /^[A-Za-z*][!#$%&'*+\-.^_`|~0-9A-Za-z:/]*/u;
const INTEGER = /^-?[0-9]{1,15}(?![0-9.])/u;
const BASE64 = /^[A-Za-z0-9+/=]*$/u;

/** Thrown inside the reader for a value that is none, and caught at its edge. */
class Malformed extends Error {}

class Reader {
  #rest: string;

  constructor(text: string) {
    this.#rest = text;
  }

  /** Whether everything has been read. */
  atEnd(): boolean {
    return this.#rest.length === 0;
  }

  peek(): string {
    return this.#rest.charAt(0);
  }

  take(pattern: RegExp): string {
    const found = pattern.exec(this.#rest)?.[0];
    if (found === undefined) throw new Malformed();
    this.#rest = this.#rest.slice(found.length);
    return found;
  }

  expect(char: string): void {
    if (this.peek() !== char) throw new Malformed();
    this.#rest = this.#rest.slice(1);
  }

  /** Skips the characters given, and says whether there were any. */
  skip(chars: string): boolean {
    let count = 0;
    while (count < this.#rest.length && chars.includes(this.#rest.charAt(count))) count++;
    this.#rest = this.#rest.slice(count);
    return count > 0;
  }

  bare(): Bare {
    const next = this.peek();
    if (next === '"') return { kind: "string", value: this.#string() };
    if (next === ":") {
      this.expect(":");
      const end = this.#rest.indexOf(":");
      if (end < 0) throw new Malformed();
      const text = this.#rest.slice(0, end);
      this.#rest = this.#rest.slice(end + 1);
      const value = BASE64.test(text) ? base64ToBytes(text) : undefined;
      if (value === undefined) throw new Malformed();
      return { kind: "bytes", value };
    }
    if (next === "?") {
      const value = this.take(/^\?[01]/u) === "?1";
      return { kind: "boolean", value };
    }
    if (next === "-" || (next >= "0" && next <= "9")) {
      return { kind: "integer", value: Number(this.take(INTEGER)) };
    }
    return { kind: "token", value: this.take(TOKEN) };
  }

  #string(): string {
    this.expect('"');
    let value = "";
    for (;;) {
      const char = this.#rest.charAt(0);
      this.#rest = this.#rest.slice(1);
      if (char === '"') return value;
      if (char === "\\") {
        const escaped = this.#rest.charAt(0);
        if (escaped !== '"' && escaped !== "\\") throw new Malformed();
        this.#rest = this.#rest.slice(1);
        value += escaped;
      } else if (char >= " " && char <= "~") {
        value += char;
      } else {
        // The end of the text, or a character a string cannot hold.
        throw new Malformed();
      }
    }
  }

  parameters(): Parameters {
    const found: [string, Bare][] = [];
    while (this.peek() === ";") {
      this.expect(";");
      this.skip(" ");
      const name = this.take(KEY);
      if (found.some(([given]) => given === name)) throw new Malformed();
      let value: Bare = { kind: "boolean", value: true };
      if (this.peek() === "=") {
        this.expect("=");
        value = this.bare();
      }
      found.push([name, value]);
    }
    return found;
  }

  item(): Item {
    const value = this.bare();
    return { kind: "item", value, parameters: this.parameters() };
  }

  member(): Item | InnerList {
    if (this.peek() !== "(") return this.item();
    this.expect("(");
    const items: Item[] = [];
    for (;;) {
      this.skip(" ");
      if (this.peek() === ")") break;
      items.push(this.item());
      if (this.peek() !== " " && this.peek() !== ")") throw new Malformed();
    }
    this.expect(")");
    return { kind: "list", items, parameters: this.parameters() };
  }
}

/**
 * Reads a dictionary (RFC 8941, 4.2.2).
 *
 * @returns Its members by name, in the order written, or `undefined` if
 *   the text is no dictionary of the kinds of value read here, or names a
 *   member twice.
 */
export function parseDictionary(text: unknown): Map<string, Item | InnerList> | undefined {
  if (typeof text !== "string" || text.length > MAX_LENGTH) return undefined;
  const reader = new Reader(text);
  const members = new Map<string, Item | InnerList>();
  try {
    reader.skip(" ");
    while (!reader.atEnd()) {
      const name = reader.take(KEY);
      if (members.has(name)) return undefined;
      if (reader.peek() === "=") {
        reader.expect("=");
        members.set(name, reader.member());
      } else {
        const value: Bare = { kind: "boolean", value: true };
        members.set(name, { kind: "item", value, parameters: reader.parameters() });
      }
      reader.skip(" \t");
      if (reader.atEnd()) break;
      reader.expect(",");
      reader.skip(" \t");
      // A comma with nothing after it.
      if (reader.atEnd()) return undefined;
    }
    return members;
  } catch (error) {
    if (error instanceof Malformed) return undefined;
    throw error;
  }
}

function writeBare(bare: Bare): string {
  switch (bare.kind) {
    case "integer":
      return String(bare.value);
    case "string":
      return `"${bare.value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
    case "token":
      return bare.value;
    case "bytes":
      return `:${bytesToBase64(bare.value)}:`;
    case "boolean":
      return bare.value ? "?1" : "?0";
  }
}

function writeParameters(parameters: Parameters): string {
  return parameters
    .map(([name, value]) =>
      value.kind === "boolean" && value.value ? `;${name}` : `;${name}=${writeBare(value)}`,
    )
    .join("");
}

/** Writes an item as RFC 8941, Section 4.1 does: the one writing of its value. */
export function writeItem(item: Item): string {
  return writeBare(item.value) + writeParameters(item.parameters);
}

/** Writes an inner list as RFC 8941, Section 4.1 does: the one writing of its value. */
export function writeInnerList(list: InnerList): string {
  return `(${list.items.map(writeItem).join(" ")})${writeParameters(list.parameters)}`;
}
