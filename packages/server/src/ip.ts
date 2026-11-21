// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * IP addresses, read to their bytes, and which of them a service may
 * connect to on behalf of a stranger (BUILD.md 3.7).
 *
 * A resolver fetches the home that a record names, and whoever wrote the
 * record chose the name. A name can resolve to the machine itself, to the
 * network behind it or to the cloud's metadata service. So an address is
 * public only if no register of special-purpose addresses lists it: the
 * ranges below are those of the IANA registries for IPv4 and IPv6, read as
 * "not for a stranger's request".
 */

import { isIP } from "node:net";

/** An address as its bytes: four for IPv4, sixteen for IPv6. */
export interface Address {
  readonly family: 4 | 6;
  readonly bytes: Uint8Array;
}

function groupsOf(part: string): string[] {
  return part === "" ? [] : part.split(":");
}

/**
 * Reads an IP address as text. An IPv6 address may be shortened, may end in
 * an IPv4 address and may carry a zone, which is dropped.
 *
 * @returns The address, or `undefined` for what is none.
 */
export function parseAddress(text: string): Address | undefined {
  const family = isIP(text);
  if (family === 4) {
    return { family: 4, bytes: Uint8Array.from(text.split("."), (part) => Number(part)) };
  }
  if (family !== 6) return undefined;
  const [address = ""] = text.split("%", 1);
  const [head = "", tail] = address.split("::", 2);
  const before = groupsOf(head);
  const after = tail === undefined ? [] : groupsOf(tail);
  const words: number[] = [];
  const push = (groups: readonly string[]): void => {
    for (const group of groups) {
      if (group.includes(".")) {
        const [a = 0, b = 0, c = 0, d = 0] = group.split(".").map(Number);
        words.push((a << 8) | b, (c << 8) | d);
      } else {
        words.push(Number.parseInt(group, 16));
      }
    }
  };
  push(before);
  const start = words.length;
  push(after);
  // What `::` stands for: as many zero groups as make eight.
  const zeros = Array.from({ length: tail === undefined ? 0 : 8 - words.length }, () => 0);
  words.splice(start, 0, ...zeros);
  const bytes = new Uint8Array(16);
  words.forEach((word, position) => {
    bytes[2 * position] = word >> 8;
    bytes[2 * position + 1] = word & 0xff;
  });
  return { family: 6, bytes };
}

/** A range of addresses: those whose first `bits` bits are those of `base`. */
type Range = readonly [base: string, bits: number];

/** IPv4 addresses that are not for a stranger's request (IANA IPv4 Special-Purpose Address Registry). */
const SPECIAL_4: readonly Range[] = [
  ["0.0.0.0", 8], // this network
  ["10.0.0.0", 8], // private
  ["100.64.0.0", 10], // shared address space of carriers
  ["127.0.0.0", 8], // loopback
  ["169.254.0.0", 16], // link-local, the cloud metadata services among them
  ["172.16.0.0", 12], // private
  ["192.0.0.0", 24], // IETF protocol assignments
  ["192.0.2.0", 24], // documentation
  ["192.88.99.0", 24], // 6to4 relays, deprecated
  ["192.168.0.0", 16], // private
  ["198.18.0.0", 15], // benchmarking
  ["198.51.100.0", 24], // documentation
  ["203.0.113.0", 24], // documentation
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved, and the broadcast address
];

/**
 * IPv6 is the other way round: only global unicast, 2000::/3, is for
 * anyone, and these ranges within it are not (IANA IPv6 Special-Purpose
 * Address Registry). Everything outside it is loopback, link-local,
 * unique-local, multicast, a mapping of IPv4 or unassigned.
 */
const GLOBAL_6: Range = ["2000::", 3];
const SPECIAL_6: readonly Range[] = [
  ["2001::", 23], // IETF protocol assignments, Teredo among them
  ["2001:db8::", 32], // documentation
  ["2002::", 16], // 6to4: an IPv4 address inside
  ["3fff::", 20], // documentation
];

function within(address: Address, [base, bits]: Range): boolean {
  const start = parseAddress(base);
  if (start?.family !== address.family) return false;
  for (let bit = 0; bit < bits; bit++) {
    const mask = 0x80 >> (bit % 8);
    if (((address.bytes[bit >> 3] ?? 0) & mask) !== ((start.bytes[bit >> 3] ?? 0) & mask))
      return false;
  }
  return true;
}

/**
 * Whether an address is one on the public internet, which a service may
 * connect to because a record named it.
 */
export function isPublicAddress(address: Address): boolean {
  if (address.family === 4) return !SPECIAL_4.some((range) => within(address, range));
  return within(address, GLOBAL_6) && !SPECIAL_6.some((range) => within(address, range));
}

/**
 * Whether an address is in a range written as `address/bits`. For the
 * ranges an operator allows besides the public ones: its own network, in
 * development.
 *
 * @throws TypeError if the range is not an address and a number of bits it can have.
 */
export function inRange(address: Address, range: string): boolean {
  const [base = "", bits = "", ...more] = range.split("/");
  const start = parseAddress(base);
  const most = start === undefined ? -1 : start.family === 4 ? 32 : 128;
  if (more.length > 0 || !/^\d{1,3}$/u.test(bits) || Number(bits) > most) {
    throw new TypeError("a range is an address, a slash and a number of bits");
  }
  return within(address, [base, Number(bits)]);
}
