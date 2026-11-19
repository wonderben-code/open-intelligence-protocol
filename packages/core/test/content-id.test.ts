// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";

import { clause, copy, type JsonObject } from "@oip/testkit";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  bytesToHex,
  canonicalBytes,
  contentId,
  contentIdOfDigest,
  digestOfContentId,
  documentHash,
  isContentId,
  keyHash,
  mindAddress,
  OipError,
  sha256,
  sha256Digest,
} from "../src/index.ts";
import {
  cases,
  keys,
  log,
  logs,
  named,
  negative,
  positiveVectorRecords,
  strings,
  vectors,
} from "./vectors.ts";

type Json = Record<string, unknown>;

const intent = named("intent");
const CONTENT_IDS = cases["content_ids"] as Record<string, string>;
const INTENT_ID = CONTENT_IDS["intent"] ?? "";

/** A base32 decoder that ignores the padding bits, as a lenient library does. */
function lenientBase32(text: string): Uint8Array {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let bits = "";
  for (const character of text.toLowerCase()) {
    bits += alphabet.indexOf(character).toString(2).padStart(5, "0");
  }
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++)
    bytes[i] = Number.parseInt(bits.slice(8 * i, 8 * i + 8), 2);
  return bytes;
}

describe("SHA-256", () => {
  it("is SHA-256 (FIPS 180-4 examples)", () => {
    const hex = (text: string) => bytesToHex(sha256(new TextEncoder().encode(text)));
    expect(hex("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect(hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")).toBe(
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    );
  });

  it("agrees with the platform on any bytes", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 300 }), (bytes) => {
        const expected = createHash("sha256").update(bytes).digest("hex");
        expect(bytesToHex(sha256(bytes))).toBe(expected);
        expect(sha256Digest(bytes)).toBe(`sha256:${expected}`);
      }),
    );
  });
});

describe(`${clause("core 3.1")} content IDs`, () => {
  it("reproduces every content ID the vectors name", () => {
    const records: Record<string, unknown> = {
      amina_genesis: log("amina_log")[0],
      amina_update: log("amina_log")[1],
      delegation: named("delegation"),
      delegation_sub: named("delegation_sub"),
      delegation_amina: named("delegation_amina"),
      intent: named("intent"),
      offer: named("offer"),
      commitment: named("commitment_proposed"),
      commitment_agents: named("commitment_agents"),
      receipt: named("receipt"),
      collective_charter: named("collective_charter"),
      session: named("session"),
      packet: named("packet"),
      checkpoint: named("checkpoint"),
      bridged_genesis: log("bridged_log")[0],
    };
    const expected = CONTENT_IDS;
    expect(Object.keys(records).sort()).toEqual(Object.keys(expected).sort());
    for (const [name, record] of Object.entries(records)) {
      expect(contentId(record), name).toBe(expected[name]);
    }
  });

  it("reproduces every mind's address from its genesis event", () => {
    for (const [name, mind] of logs) {
      const genesis = log(name)[0];
      expect(mindAddress(contentId(genesis)), mind).toBe(cases[mind]);
    }
  });

  it("reproduces every reference between records in the vectors", () => {
    // Every record in the vectors, wherever it stands: on its own, or carried in another.
    const known = new Set<string>();
    const collect = (value: unknown): void => {
      if (typeof value !== "object" || value === null) return;
      const members = Object.values(value);
      if (!Array.isArray(value) && (value as JsonObject)["oip"] === "1") {
        known.add(contentId(value));
      }
      members.forEach(collect);
    };
    const records = positiveVectorRecords().map(({ record }) => record);
    records.forEach(collect);
    const hashes = new Set(Object.values(keys).map((key) => keyHash(key.multikey)));
    // Every string of the form of a content ID, wherever it is written: alone, in an
    // address, in a version ID or in a reference. Each is the content ID of a record
    // here, or the hash of a key here. The one exception is a Merkle root.
    const root = (named("checkpoint") as { root: string }).root;
    const count = { records: 0, keyHashes: 0, roots: 0 };
    for (const text of strings(records)) {
      for (const [id] of text.matchAll(/bciq[a-p][a-z2-7]{50}[aiqy]/g)) {
        if (known.has(id)) count.records++;
        else if (hashes.has(id)) count.keyHashes++;
        else if (id === root) count.roots++;
        else throw new Error(`${id} in ${JSON.stringify(text)} is the content ID of nothing here`);
      }
    }
    expect(count).toEqual({ records: 252, keyHashes: 16, roots: 1 });
    expect(known.size).toBe(49);
    // Three of them, by name.
    expect(known.has(named("ack")["packet"] as string)).toBe(true);
    expect(named("feed_entry")["object"]).toBe(contentId(named("offer")));
    for (const [name] of logs) {
      const events = log(name);
      for (let i = 1; i < events.length; i++) {
        expect(events[i]?.["prev"], `${name}[${i}]`).toBe(contentId(events[i - 1]));
      }
    }
  });

  it("is b, then lower-case base32 of 0x12 0x20 and the SHA-256 of the canonical form", () => {
    const record = { oip: "1", type: "Example", b: 2, a: [1, "x"] };
    const digest = createHash("sha256")
      .update('{"a":[1,"x"],"b":2,"oip":"1","type":"Example"}')
      .digest();
    const id = contentId(record);
    expect(id).toHaveLength(56);
    expect(id.startsWith("bciq")).toBe(true);
    expect([...lenientBase32(id.slice(1))]).toEqual([0x12, 0x20, ...digest]);
    expect(contentIdOfDigest(digest)).toBe(id);
    expect(bytesToHex(documentHash(record))).toBe(digest.toString("hex"));
  });

  it("does not cover proof, so a signature never changes it", () => {
    const unsigned = copy(intent);
    delete unsigned["proof"];
    expect(contentId(unsigned)).toBe(INTENT_ID);
    expect(contentId({ ...intent, proof: [] })).toBe(INTENT_ID);
    expect(contentId({ ...intent, proof: "anything" })).toBe(INTENT_ID);
    const twice = [...(intent["proof"] as unknown[]), ...(intent["proof"] as unknown[])];
    expect(contentId({ ...intent, proof: twice })).toBe(INTENT_ID);
    // The proposed and the accepted commitment differ only in their proofs.
    expect(contentId(named("commitment_accepted"))).toBe(contentId(named("commitment_proposed")));
    expect(named("commitment_accepted")["proof"]).not.toEqual(
      named("commitment_proposed")["proof"],
    );
  });

  it("covers every other member, at any depth", () => {
    /** Every value in a record that is not an array or an object, with a way to replace it. */
    type Change = (value: unknown) => unknown;
    function leaves(value: unknown, found: ((change: Change) => void)[] = []) {
      if (typeof value !== "object" || value === null) return found;
      for (const [name, member] of Object.entries(value)) {
        if (typeof member === "object" && member !== null) leaves(member, found);
        else {
          found.push((change) => {
            (value as Record<string, unknown>)[name] = change(member);
          });
        }
      }
      return found;
    }
    const other = (value: unknown) => {
      if (typeof value === "string") return `${value}x`;
      if (typeof value === "number") return value + 1;
      return value === true ? false : true;
    };
    fc.assert(
      fc.property(fc.constantFrom(...positiveVectorRecords()), fc.nat(), ({ record }, pick) => {
        const changed = copy(record);
        delete changed["proof"];
        const all = leaves(changed);
        all[pick % all.length]?.(other);
        expect(contentId(changed)).not.toBe(contentId(record));
      }),
      { numRuns: 300 },
    );
    expect(contentId({ ...intent, extra: null })).not.toBe(INTENT_ID);
    expect(contentId({ ...intent, proofs: [] })).not.toBe(INTENT_ID);
  });

  it("does not depend on the order of members or on how the record was written", () => {
    const reversed = Object.fromEntries(Object.entries(intent).reverse());
    expect(contentId(reversed)).toBe(INTENT_ID);
    expect(contentId(JSON.parse(JSON.stringify(intent, null, 4)))).toBe(INTENT_ID);
  });

  it("refuses what has no canonical form or is not an object", () => {
    for (const bad of [null, [], "text", 1, true, undefined, { a: 0.5 }, { a: new Date(0) }]) {
      expect(() => contentId(bad)).toThrow(OipError);
      expect(() => documentHash(bad)).toThrow(OipError);
    }
    expect(() => contentId([])).toThrow("a record is a JSON object");
    for (const notObject of [[], null, "text", 1]) {
      let thrown: unknown;
      try {
        contentId(notObject);
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toMatchObject({ code: "invalid-record", clause: "core 1.1" });
    }
    for (const bad of [new Uint8Array(31), new Uint8Array(33), new Uint8Array(0), "digest", null]) {
      expect(() => contentIdOfDigest(bad as Uint8Array)).toThrow(
        new TypeError("a content ID carries a SHA-256 digest of 32 bytes"),
      );
    }
  });
});

describe(`${clause("core 3.2")} one canonical spelling`, () => {
  it("accepts every content ID and address in the vectors", () => {
    const found = new Set<string>();
    for (const text of strings([cases, vectors.valid, vectors.controls])) {
      for (const match of text.matchAll(/\bb[a-z2-7]{55}\b/g)) found.add(match[0]);
    }
    expect(found.size).toBeGreaterThan(50);
    for (const id of found) expect(isContentId(id), id).toBe(true);
  });

  it("has exactly one spelling for every digest, and reads it back", () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 32, maxLength: 32 }), (digest) => {
        const id = contentIdOfDigest(digest);
        expect(id).toMatch(/^bciq[a-p][a-z2-7]{50}[aiqy]$/);
        expect(isContentId(id)).toBe(true);
        expect([...(digestOfContentId(id) ?? [])]).toEqual([...digest]);
        // Every other final character decodes to the same bytes and is not the spelling.
        const classes = ["abcdefgh", "ijklmnop", "qrstuvwx", "yz234567"];
        const others = classes.find((group) => group.includes(id.slice(-1))) ?? "";
        for (const last of others.slice(1)) {
          const variant = id.slice(0, -1) + last;
          expect([...lenientBase32(variant.slice(1))]).toEqual([0x12, 0x20, ...digest]);
          expect(isContentId(variant), variant).toBe(false);
          expect(digestOfContentId(variant), variant).toBeUndefined();
        }
      }),
      { numRuns: 200 },
    );
    expect(contentIdOfDigest(new Uint8Array(32))).toBe(`bciqa${"a".repeat(51)}`);
    expect(contentIdOfDigest(new Uint8Array(32).fill(0xff))).toBe(`bciqp${"7".repeat(50)}y`);
  });

  it("rejects the non-canonical spelling of the vectors, which decodes to the same bytes", () => {
    const log = negative("non-canonical-content-id")["log"] as Json[];
    const spelled = log[1]?.["prev"] as string;
    const canonical = contentId(log[0]);
    expect(spelled).not.toBe(canonical);
    expect([...lenientBase32(spelled.slice(1))]).toEqual([...lenientBase32(canonical.slice(1))]);
    expect(isContentId(canonical)).toBe(true);
    expect(isContentId(spelled)).toBe(false);
    expect(digestOfContentId(spelled)).toBeUndefined();
  });

  it("rejects every other spelling", () => {
    for (const bad of [
      INTENT_ID.toUpperCase(),
      `B${INTENT_ID.slice(1).toUpperCase()}`,
      `${INTENT_ID}=`,
      `${INTENT_ID}a`,
      INTENT_ID.slice(0, -1),
      INTENT_ID.slice(1),
      ` ${INTENT_ID}`,
      `${INTENT_ID}\n`,
      `z${INTENT_ID.slice(1)}`,
      `f${"12".padEnd(68, "0")}`,
      // A different multihash: the fifth character must keep the length byte 0x20.
      `bciqq${INTENT_ID.slice(5)}`,
      `bciq2${INTENT_ID.slice(5)}`,
      `bcir${INTENT_ID.slice(4)}`,
      `bafk${INTENT_ID.slice(4)}`,
      INTENT_ID.replace(/.$/, "1"),
      INTENT_ID.replace(/^(.{20})./, "$10"),
      "",
    ]) {
      expect(isContentId(bad), JSON.stringify(bad)).toBe(false);
      expect(digestOfContentId(bad), JSON.stringify(bad)).toBeUndefined();
    }
    for (const notText of [null, undefined, 1, {}, [INTENT_ID], new String(INTENT_ID)]) {
      expect(isContentId(notText)).toBe(false);
      expect(digestOfContentId(notText)).toBeUndefined();
    }
  });
});

describe(`${clause("core 3.3")} the digest inside a content ID`, () => {
  it("is the SHA-256 of the canonical form without proof", () => {
    for (const { name, record } of positiveVectorRecords()) {
      const { proof: _proof, ...content } = record;
      const expected = createHash("sha256").update(canonicalBytes(content)).digest("hex");
      expect(bytesToHex(documentHash(record)), name).toBe(expected);
      expect(bytesToHex(digestOfContentId(contentId(record)) ?? new Uint8Array()), name).toBe(
        expected,
      );
    }
  });
});

describe(`${clause("core 3.4")} key hashes`, () => {
  it("is the content-ID encoding of the SHA-256 of the Multikey string", () => {
    const multikey = keys["amina-control-1"]?.multikey ?? "";
    const digest = createHash("sha256").update(multikey, "utf8").digest();
    expect(keyHash(multikey)).toBe(contentIdOfDigest(digest));
    expect(isContentId(keyHash(multikey))).toBe(true);
  });

  it("reproduces every pre-rotation commitment in the vectors", () => {
    // Each control key an event reveals was committed to, by its hash, in the event before.
    let checked = 0;
    for (const [name] of logs) {
      const events = log(name) as { controller?: { keys?: string[]; next?: string[] } }[];
      for (let i = 1; i < events.length; i++) {
        const committed = events[i - 1]?.controller?.next;
        const revealed = events[i]?.controller?.keys;
        if (committed === undefined || revealed === undefined) continue;
        for (const key of revealed) {
          expect(committed, `${name}[${i}]`).toContain(keyHash(key));
          checked++;
        }
      }
    }
    expect(checked).toBeGreaterThanOrEqual(5);
    const genesis = (log("amina_log") as { controller: { next: string[] } }[])[0];
    expect(genesis?.controller.next).toEqual([keyHash(keys["amina-control-1"]?.multikey ?? "")]);
  });

  it("hashes the string as written, so one character changes it", () => {
    const multikey = keys["amina-control-1"]?.multikey ?? "";
    expect(keyHash(`${multikey} `)).not.toBe(keyHash(multikey));
    expect(keyHash(multikey.toLowerCase())).not.toBe(keyHash(multikey));
    expect(keyHash("")).toBe(contentIdOfDigest(sha256(new Uint8Array())));
    expect(keyHash("é")).toBe(contentIdOfDigest(sha256(Uint8Array.of(0xc3, 0xa9))));
  });

  it("refuses what is not a string of valid Unicode", () => {
    for (const bad of [null, undefined, 1, new Uint8Array(34), ["z6Mk"], new String("z6Mk")]) {
      expect(() => keyHash(bad as string)).toThrow(
        new TypeError("a key hash is the hash of a string"),
      );
    }
    expect(() => keyHash("\ud800")).toThrow(TypeError);
  });
});
