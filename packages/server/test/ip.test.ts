// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { inRange, isPublicAddress, parseAddress } from "../src/ip.ts";

const hex = (bytes: Uint8Array | undefined): string | undefined =>
  bytes === undefined ? undefined : Buffer.from(bytes).toString("hex");

function publicAddress(text: string): boolean {
  const address = parseAddress(text);
  if (address === undefined) throw new Error(`${text} is no address`);
  return isPublicAddress(address);
}

describe("an IP address as text", () => {
  it("is read to its bytes: IPv4", () => {
    expect(parseAddress("203.0.113.7")).toStrictEqual({
      family: 4,
      bytes: Uint8Array.of(203, 0, 113, 7),
    });
    expect(hex(parseAddress("255.255.255.255")?.bytes)).toBe("ffffffff");
  });

  it("is read to its bytes: IPv6, however it is written", () => {
    const cases: [string, string][] = [
      ["2001:db8:1:2:3:4:5:6", "20010db8000100020003000400050006"],
      ["2001:0DB8:0001:0002:0003:0004:0005:0006", "20010db8000100020003000400050006"],
      ["::", "00000000000000000000000000000000"],
      ["::1", "00000000000000000000000000000001"],
      ["1::", "00010000000000000000000000000000"],
      ["2001:db8::1", "20010db8000000000000000000000001"],
      ["2001:db8::1:0:0:1", "20010db8000000000001000000000001"],
      ["fe80::1%eth0", "fe800000000000000000000000000001"],
      ["::ffff:192.0.2.1", "00000000000000000000ffffc0000201"],
      ["64:ff9b::192.0.2.1", "0064ff9b0000000000000000c0000201"],
      ["1:2:3:4:5:6:192.0.2.1", "000100020003000400050006c0000201"],
      ["1:2:3:4:5:6:7::", "00010002000300040005000600070000"],
      ["::2:3:4:5:6:7:8", "00000002000300040005000600070008"],
    ];
    for (const [text, bytes] of cases) {
      const address = parseAddress(text);
      expect(address?.family, text).toBe(6);
      expect(hex(address?.bytes), text).toBe(bytes);
    }
  });

  it("is none where the text is no address", () => {
    for (const text of [
      "",
      "example.com",
      "203.0.113",
      "203.0.113.256",
      "0x7f.0.0.1",
      "127.1",
      "2130706433",
      "010.0.0.1",
      "2001:db8::g",
      "1:2:3:4:5:6:7:8:9",
      ":::",
      " 203.0.113.7",
      "[::1]",
    ]) {
      expect(parseAddress(text), text).toBeUndefined();
    }
  });

  it("reads every IPv6 address as the bytes it was written from", () => {
    fc.assert(
      fc.property(fc.ipV6(), (text) => {
        const address = parseAddress(text);
        expect(address?.family).toBe(6);
        // Written out in full from the bytes, and read again, it is the same address.
        const bytes = address?.bytes ?? new Uint8Array(16);
        const full = Array.from({ length: 8 }, (_, n) =>
          (((bytes[2 * n] ?? 0) << 8) | (bytes[2 * n + 1] ?? 0)).toString(16),
        ).join(":");
        expect(hex(parseAddress(full)?.bytes)).toBe(hex(bytes));
        expect(new URL(`https://[${full}]/`).hostname).toBe(new URL(`https://[${text}]/`).hostname);
      }),
    );
  });
});

describe("an address a service may connect to for a stranger", () => {
  it("is one on the public internet", () => {
    for (const text of [
      "1.1.1.1",
      "8.8.8.8",
      "93.184.216.34",
      "100.63.255.255",
      "100.128.0.0",
      "169.253.255.255",
      "172.15.255.255",
      "172.32.0.0",
      "192.0.1.0",
      "198.17.255.255",
      "198.20.0.0",
      "223.255.255.255",
      "2606:4700:4700::1111",
      "2a00:1450:4001:81b::200e",
      "2001:200::1",
      "2003::1",
      "3ffe::1",
    ]) {
      expect(publicAddress(text), text).toBe(true);
    }
  });

  it("is not the machine, the network behind it, or the cloud's metadata service: IPv4", () => {
    for (const text of [
      "0.0.0.0",
      "0.1.2.3",
      "10.0.0.1",
      "10.255.255.255",
      "100.64.0.1",
      "100.127.255.255",
      "127.0.0.1",
      "127.255.255.254",
      "169.254.169.254",
      "169.254.0.1",
      "172.16.0.1",
      "172.31.255.255",
      "192.0.0.1",
      "192.0.2.1",
      "192.88.99.1",
      "192.168.1.1",
      "198.18.0.1",
      "198.19.255.255",
      "198.51.100.1",
      "203.0.113.1",
      "224.0.0.1",
      "239.255.255.255",
      "240.0.0.1",
      "255.255.255.255",
    ]) {
      expect(publicAddress(text), text).toBe(false);
    }
  });

  it("is not them by any IPv6 name either", () => {
    for (const text of [
      "::",
      "::1",
      // IPv4 addresses inside IPv6 ones: mapped, compatible, NAT64, 6to4, Teredo.
      "::ffff:127.0.0.1",
      "::ffff:10.0.0.1",
      "::ffff:8.8.8.8",
      "::127.0.0.1",
      "64:ff9b::127.0.0.1",
      "64:ff9b:1::1",
      "2002:7f00:1::1",
      "2001::1",
      "2001:0:4136:e378:8000:63bf:3fff:fdd2",
      // Link-local, site-local, unique-local, multicast, documentation, discard.
      "fe80::1",
      "fec0::1",
      "fc00::1",
      "fd12:3456:789a::1",
      "ff02::1",
      "2001:db8::1",
      "3fff::1",
      "3fff:fff:ffff::1",
      "100::1",
      // Not assigned to anyone.
      "4000::1",
      "1::1",
      "e000::1",
    ]) {
      expect(publicAddress(text), text).toBe(false);
    }
  });
});

describe("a range an operator allows", () => {
  const address = (text: string) => {
    const read = parseAddress(text);
    if (read === undefined) throw new Error(text);
    return read;
  };

  it("holds the addresses whose first bits are its own", () => {
    expect(inRange(address("10.1.2.3"), "10.0.0.0/8")).toBe(true);
    expect(inRange(address("11.1.2.3"), "10.0.0.0/8")).toBe(false);
    expect(inRange(address("127.0.0.1"), "127.0.0.1/32")).toBe(true);
    expect(inRange(address("127.0.0.2"), "127.0.0.1/32")).toBe(false);
    expect(inRange(address("127.0.0.2"), "127.0.0.1/31")).toBe(false);
    expect(inRange(address("127.0.0.0"), "127.0.0.1/31")).toBe(true);
    expect(inRange(address("8.8.8.8"), "0.0.0.0/0")).toBe(true);
    expect(inRange(address("fd00::1"), "fd00::/8")).toBe(true);
    expect(inRange(address("fe00::1"), "fd00::/8")).toBe(false);
    expect(inRange(address("::1"), "::1/128")).toBe(true);
  });

  it("holds no address of the other family", () => {
    expect(inRange(address("::1"), "0.0.0.0/0")).toBe(false);
    expect(inRange(address("127.0.0.1"), "::/0")).toBe(false);
    expect(inRange(address("::ffff:127.0.0.1"), "127.0.0.0/8")).toBe(false);
  });

  it("is an address, a slash and a number of bits it can have", () => {
    for (const range of [
      "10.0.0.0",
      "10.0.0.0/",
      "10.0.0.0/33",
      "::/129",
      "10.0.0.0/-1",
      "example/8",
      "10.0.0.0/8/8",
      "10.0.0.0/ 8",
      "10.0.0.0/1e1",
    ]) {
      expect(() => inRange(address("10.0.0.1"), range), range).toThrow(TypeError);
    }
  });
});
