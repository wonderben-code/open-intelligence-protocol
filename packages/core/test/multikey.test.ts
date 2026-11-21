// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { x25519 } from "@noble/curves/ed25519.js";
import { patterns } from "@oip/schema";
import { clause } from "@oip/testkit";
import { base58 } from "@scure/base";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  decodeEd25519Multikey,
  decodeX25519Multikey,
  ed25519PublicKey,
  encodeEd25519Multikey,
  encodeX25519Multikey,
  hexToBytes,
  isEd25519Multikey,
  isX25519Multikey,
  type Validation,
} from "../src/index.ts";
import { Point, smallOrderPoints } from "./curve.ts";
import { keys, negative, strings } from "./vectors.ts";

const ed = keys["amina-phone"]?.multikey ?? "";
const x = keys["x25519:amina"]?.multikey ?? "";

const clauseOf = (result: Validation<unknown>) =>
  result.ok ? "accepted" : result.issues[0].clause;

/** A Multikey built by hand, so that the tests can write what the encoder refuses to. */
const multikey = (prefix: number[], key: Uint8Array) =>
  `z${base58.encode(Uint8Array.from([...prefix, ...key]))}`;

describe(`${clause("core 4.1")} keys are written as Multikey strings`, () => {
  it("reproduces every test key of the vectors from its seed", () => {
    let ed25519Keys = 0;
    let x25519Keys = 0;
    for (const [label, key] of Object.entries(keys)) {
      const seed = hexToBytes(key.seed_hex);
      if (key.type === "X25519") {
        expect(encodeX25519Multikey(x25519.getPublicKey(seed)), label).toBe(key.multikey);
        x25519Keys++;
      } else {
        expect(encodeEd25519Multikey(ed25519PublicKey(seed)), label).toBe(key.multikey);
        ed25519Keys++;
      }
    }
    expect(ed25519Keys).toBeGreaterThan(30);
    expect(x25519Keys).toBeGreaterThan(0);
  });

  it("is z, then base58btc of the multicodec prefix and the 32 key bytes", () => {
    const key = ed25519PublicKey(new Uint8Array(32).fill(1));
    expect(encodeEd25519Multikey(key)).toBe(multikey([0xed, 0x01], key));
    expect(encodeX25519Multikey(key)).toBe(multikey([0xec, 0x01], key));
    expect([...base58.decode(ed.slice(1)).subarray(0, 2)]).toEqual([0xed, 0x01]);
    expect([...base58.decode(x.slice(1)).subarray(0, 2)]).toEqual([0xec, 0x01]);
  });

  it("always has the string prefix and the length the specification gives", () => {
    for (const fill of [0x00, 0xff, 0x7f, 0x80]) {
      const bytes = new Uint8Array(32).fill(fill);
      expect(encodeX25519Multikey(bytes)).toMatch(/^z6LS[1-9A-HJ-NP-Za-km-z]{44}$/);
      expect(multikey([0xed, 0x01], bytes)).toMatch(/^z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/);
    }
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 32, maxLength: 32 }), (bytes) => {
        expect(encodeX25519Multikey(bytes)).toMatch(new RegExp(patterns.x25519Multikey));
        expect(multikey([0xed, 0x01], bytes)).toMatch(new RegExp(patterns.ed25519Multikey));
      }),
    );
  });

  it("reads back what it writes", () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 32, maxLength: 32 }), (bytes) => {
        const decoded = decodeX25519Multikey(encodeX25519Multikey(bytes));
        expect(decoded).toEqual({ ok: true, value: bytes });
        const key = ed25519PublicKey(bytes);
        expect(decodeEd25519Multikey(encodeEd25519Multikey(key))).toEqual({ ok: true, value: key });
      }),
      { numRuns: 25 },
    );
  });

  it("returns the key bytes on their own, not a view of the prefixed bytes", () => {
    const decoded = decodeEd25519Multikey(ed);
    expect(decoded.ok && decoded.value.length).toBe(32);
    expect(decoded.ok && decoded.value.byteOffset).toBe(0);
    expect(decoded.ok && decoded.value.buffer.byteLength).toBe(32);
  });

  it("refuses to write a key of the wrong length", () => {
    for (const bad of [new Uint8Array(31), new Uint8Array(33), new Uint8Array(0), "key", null]) {
      expect(() => encodeX25519Multikey(bad as Uint8Array)).toThrow(
        new TypeError("an X25519 public key is 32 bytes"),
      );
      expect(() => encodeEd25519Multikey(bad as Uint8Array)).toThrow(
        new TypeError("an Ed25519 public key is 32 bytes"),
      );
    }
  });
});

describe(`${clause("core 4.2")} the prefix and the length are checked`, () => {
  it("accepts every key in the vectors as the type it is", () => {
    for (const [label, key] of Object.entries(keys)) {
      const isX = key.type === "X25519";
      expect(isX25519Multikey(key.multikey), label).toBe(isX);
      expect(isEd25519Multikey(key.multikey), label).toBe(!isX);
    }
  });

  it("rejects a key of the other type", () => {
    expect(clauseOf(decodeEd25519Multikey(x))).toBe("core 4.2");
    expect(clauseOf(decodeX25519Multikey(ed))).toBe("core 4.2");
    expect(clauseOf(decodeEd25519Multikey(ed))).toBe("accepted");
    expect(clauseOf(decodeX25519Multikey(x))).toBe("accepted");
    const decoded = decodeEd25519Multikey(x);
    expect(!decoded.ok && decoded.issues[0]).toEqual({
      path: "",
      message:
        'not an Ed25519 public key as a Multikey: expected "z6Mk" followed by 44 base58 characters, which decode to the prefix and 32 bytes',
      clause: "core 4.2",
    });
    const other = decodeX25519Multikey(ed);
    expect(!other.ok && other.issues[0].message).toMatch(/^not an X25519 public key.*"z6LS"/);
  });

  it("rejects other multicodec prefixes", () => {
    const key = ed25519PublicKey(new Uint8Array(32).fill(1));
    for (const prefix of [
      [0xe7, 0x01], // secp256k1
      [0x80, 0x24], // P-256
      [0xed, 0x02],
      [0xed, 0x00],
      [0xee, 0x01],
      [0xeb, 0x01],
      [0xed],
      [0x12, 0x20],
      [],
    ]) {
      const written = multikey(prefix, key);
      expect(clauseOf(decodeEd25519Multikey(written)), written).toBe("core 4.2");
      expect(clauseOf(decodeX25519Multikey(written)), written).toBe("core 4.2");
    }
  });

  it("rejects a key that is too short or too long", () => {
    const key = ed25519PublicKey(new Uint8Array(32).fill(1));
    for (const length of [0, 1, 16, 31, 33, 64]) {
      const bytes = Uint8Array.from({ length }, (_, i) => key[i % 32] ?? 0);
      expect(clauseOf(decodeEd25519Multikey(multikey([0xed, 0x01], bytes))), String(length)).toBe(
        "core 4.2",
      );
      expect(clauseOf(decodeX25519Multikey(multikey([0xec, 0x01], bytes))), String(length)).toBe(
        "core 4.2",
      );
    }
  });

  it("rejects a string of the right form that decodes to other bytes", () => {
    // The largest and smallest strings of the form lie outside the range the prefix covers.
    const high = `z6Mk${"z".repeat(44)}`;
    const low = `z6Mk${"1".repeat(44)}`;
    for (const written of [high, low])
      expect(written).toMatch(new RegExp(patterns.ed25519Multikey));
    const prefixes = [high, low].map((written) => [
      ...base58.decode(written.slice(1)).subarray(0, 2),
    ]);
    expect(prefixes.some(([first, second]) => first !== 0xed || second !== 0x01)).toBe(true);
    const rejected = [high, low].filter((written) => !decodeEd25519Multikey(written).ok);
    expect(rejected.length).toBeGreaterThanOrEqual(1);
    for (const written of [`z6LS${"z".repeat(44)}`, `z6LS${"1".repeat(44)}`]) {
      const [first, second] = base58.decode(written.slice(1));
      const expected = first === 0xec && second === 0x01;
      expect(decodeX25519Multikey(written).ok, written).toBe(expected);
    }
  });

  it("rejects everything that is not base58btc after a z", () => {
    for (const bad of [
      "",
      "z",
      ed.slice(1),
      `Z${ed.slice(1)}`,
      `m${ed.slice(1)}`,
      `${ed} `,
      ` ${ed}`,
      `${ed}\n`,
      ed.slice(0, -1),
      `${ed}1`,
      ed.replace(/.$/, "0"),
      ed.replace(/.$/, "O"),
      ed.replace(/.$/, "I"),
      ed.replace(/.$/, "l"),
      ed.replace(/.$/, "+"),
      ed.toLowerCase(),
      `did:key:${ed}`,
      `z6Mk${"1".repeat(100_000)}`,
    ]) {
      expect(clauseOf(decodeEd25519Multikey(bad)), bad.slice(0, 60)).toBe("core 4.2");
    }
    for (const notText of [null, undefined, 1, {}, [ed], new String(ed), hexToBytes("ed01")]) {
      expect(clauseOf(decodeEd25519Multikey(notText))).toBe("core 4.2");
      expect(clauseOf(decodeX25519Multikey(notText))).toBe("core 4.2");
      expect(isEd25519Multikey(notText)).toBe(false);
      expect(isX25519Multikey(notText)).toBe(false);
    }
  });
});

describe(`${clause("core 4.3")} Ed25519 for signatures, X25519 for encryption`, () => {
  it("accepts any 32 bytes as an X25519 key, and only points of order L as Ed25519 keys", () => {
    const identity = Point.ZERO.toBytes();
    expect(decodeX25519Multikey(encodeX25519Multikey(identity)).ok).toBe(true);
    expect(clauseOf(decodeEd25519Multikey(multikey([0xed, 0x01], identity)))).toBe("core 4.4");
  });
});

describe(`${clause("core 4.4")} an Ed25519 key that is not of order L is rejected wherever it appears`, () => {
  const multikeysIn = (value: unknown) => [
    ...new Set(strings(value).filter((text) => /^z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/.test(text))),
  ];

  it("rejects the identity-point key of the vectors, and accepts the keys beside it", () => {
    const found = multikeysIn(negative("identity-point-control-key")["log"]);
    const bad = found.filter((key) => !isEd25519Multikey(key));
    expect(bad).toHaveLength(1);
    expect([...base58.decode((bad[0] ?? "").slice(1)).subarray(2)]).toEqual([
      ...Point.ZERO.toBytes(),
    ]);
    expect(clauseOf(decodeEd25519Multikey(bad[0]))).toBe("core 4.4");
  });

  it("rejects the mixed-order key of the vectors, and accepts the keys beside it", () => {
    const found = multikeysIn(negative("mixed-order-operational-key")["log"]);
    expect(found.length).toBeGreaterThanOrEqual(2);
    const bad = found.filter((key) => !isEd25519Multikey(key));
    expect(bad).toHaveLength(1);
    const decoded = decodeEd25519Multikey(bad[0]);
    expect(!decoded.ok && decoded.issues[0]).toEqual({
      path: "",
      message:
        "the Ed25519 key is not the canonical encoding of a point of order L, so no signature by it is accepted",
      clause: "core 4.4",
    });
    // It is a point of the curve, and eight times it is a point of order L: only its order is wrong.
    const point = Point.fromBytes(base58.decode((bad[0] ?? "").slice(1)).subarray(2), false);
    expect(point.isTorsionFree()).toBe(false);
    expect(point.clearCofactor().isTorsionFree()).toBe(true);
    expect(point.clearCofactor().is0()).toBe(false);
  });

  it("rejects every small-order point and refuses to write one", () => {
    for (const point of smallOrderPoints()) {
      const written = multikey([0xed, 0x01], point.toBytes());
      expect(clauseOf(decodeEd25519Multikey(written)), point.toHex()).toBe("core 4.4");
      expect(isEd25519Multikey(written)).toBe(false);
      expect(() => encodeEd25519Multikey(point.toBytes())).toThrow(
        new TypeError("not an Ed25519 public key: it is not a point of order L (core 4.4)"),
      );
    }
  });

  it("rejects bytes that are no point", () => {
    const noPoint = new Uint8Array(32);
    noPoint[0] = 2;
    expect(clauseOf(decodeEd25519Multikey(multikey([0xed, 0x01], noPoint)))).toBe("core 4.4");
    expect(() => encodeEd25519Multikey(noPoint)).toThrow(TypeError);
  });
});
