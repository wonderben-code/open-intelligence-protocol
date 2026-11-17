// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { CONTAINER_RECORD_TYPES, IMPLEMENTATION_LIMIT, type OipRecord } from "@oip/schema";
import { clause, copy, type JsonObject, sampleRecords, withAmbientTrapped } from "@oip/testkit";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  canonicalBytes,
  canonicalize,
  checkSize,
  contentId,
  createProofSync,
  MAX_RECORD_BYTES,
  MAX_SEALED_BYTES,
  MAX_TEXT_LENGTH,
  MIN_ACCEPTED_RECORD_BYTES,
  parseRecord,
  signerFromPrivateKey,
  understandsCritical,
  unsupportedCritical,
  type Validation,
  verifyProofs,
  withProofs,
} from "../src/index.ts";
import { named, negative, positiveVectorRecords, privateKeyOf } from "./vectors.ts";

const utf8 = (text: string) => new TextEncoder().encode(text);
const clauseOf = (result: Validation<unknown>) =>
  result.ok ? "accepted" : result.issues[0].clause;
const sizeOf = (record: unknown) => canonicalBytes(record).length;

/** A record of the sample's type whose canonical form is exactly `size` bytes. */
function padded(type: string, size: number, member = "blob"): JsonObject {
  const base = { ...(sampleRecords[type] ?? {}), ext: { "com.example.padding": { [member]: "" } } };
  const padding = size - sizeOf(base);
  if (padding < 0) throw new Error("the sample is already larger than that");
  const record = copy(base);
  (record.ext["com.example.padding"] as Record<string, string>)[member] = "a".repeat(padding);
  expect(sizeOf(record)).toBe(size);
  return record;
}

describe("reading a record from text", () => {
  it("reads every record of the vectors, from text and from bytes", () => {
    for (const { name, record } of positiveVectorRecords()) {
      const text = JSON.stringify(record);
      const fromText = parseRecord(text);
      expect(fromText, name).toEqual({ ok: true, value: record });
      expect(parseRecord(utf8(text)), name).toEqual({ ok: true, value: record });
      expect(parseRecord(JSON.stringify(record, null, 2)), name).toEqual(fromText);
    }
  });

  it("reads a sample of every record type", () => {
    for (const [type, record] of Object.entries(sampleRecords)) {
      expect(parseRecord(JSON.stringify(record)), type).toEqual({ ok: true, value: record });
    }
    expect(Object.keys(sampleRecords)).toHaveLength(29);
  });

  it("gives a record whose proofs can then be verified", () => {
    const parsed = parseRecord(JSON.stringify(named("intent")));
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const verdicts = verifyProofs(parsed.value);
    expect(verdicts.ok && verdicts.value.every((verdict) => verdict.ok)).toBe(true);
  });

  it(`${clause("core 1.1", "core 1.2")} applies the JSON profile before anything else`, () => {
    const intent = JSON.stringify(named("intent"));
    const insert = (member: string) => `{${member},${intent.slice(1)}`;
    expect(clauseOf(parseRecord(insert('"type":"Offer"')))).toBe("core 1.1");
    expect(clauseOf(parseRecord(insert('"oip":"1"')))).toBe("core 1.1");
    expect(clauseOf(parseRecord(insert('"n":1.5')))).toBe("core 1.2");
    expect(clauseOf(parseRecord(insert('"n":9007199254740992')))).toBe("core 1.2");
    expect(clauseOf(parseRecord(insert(String.raw`"s":"\ud800"`)))).toBe("core 1.1");
    expect(clauseOf(parseRecord(insert('"n":1.0')))).toBe("accepted");
    expect(clauseOf(parseRecord(`${intent} x`))).toBe("core 1.1");
    expect(clauseOf(parseRecord(Uint8Array.from([...utf8(intent.slice(0, -1)), 0xff, 0x7d])))).toBe(
      "core 1.1",
    );
    expect(clauseOf(parseRecord(Uint8Array.from([0xef, 0xbb, 0xbf, ...utf8(intent)])))).toBe(
      "core 1.1",
    );
  });

  it("applies the schema and the rules of the record's type", () => {
    for (const name of ["packet-short-nonce", "delegation-to-self"]) {
      const record = negative(name)["record"];
      expect(parseRecord(JSON.stringify(record)).ok, name).toBe(false);
    }
    expect(clauseOf(parseRecord("[]"))).toBe("core 1.1");
    expect(clauseOf(parseRecord("null"))).toBe("core 1.1");
    expect(clauseOf(parseRecord('"record"'))).toBe("core 1.1");
    expect(clauseOf(parseRecord("{}"))).toBe("core 7");
    expect(clauseOf(parseRecord('{"oip":"2","type":"Intent"}'))).toBe("core 7");
    expect(clauseOf(parseRecord('{"oip":1,"type":"Intent"}'))).toBe("core 7");
    expect(clauseOf(parseRecord('{"oip":"1","type":"Unknown"}'))).toBe("core 11");
    expect(clauseOf(parseRecord('{"oip":"1","type":"Merge"}'))).toBe("L1 3.9");
    const { created: _created, ...undated } = named("intent");
    expect(parseRecord(JSON.stringify(undated)).ok).toBe(false);
  });

  it("never throws, whatever it is given", () => {
    for (const bad of [undefined, null, 1, {}, [], new Date(0), new ArrayBuffer(4)]) {
      expect(parseRecord(bad as string).ok).toBe(false);
    }
    fc.assert(
      fc.property(fc.oneof(fc.string(), fc.uint8Array(), fc.json()), (input) => {
        const parsed = parseRecord(input);
        expect(typeof parsed.ok).toBe("boolean");
      }),
      { numRuns: 1000 },
    );
  });

  it("reads no clock and no randomness", () => {
    const text = JSON.stringify(named("commitment_accepted"));
    const proofs = withAmbientTrapped(() => {
      const parsed = parseRecord(text);
      if (!parsed.ok) return -1;
      const verdicts = verifyProofs(parsed.value);
      return verdicts.ok ? verdicts.value.filter((verdict) => verdict.ok).length : -1;
    });
    expect(proofs).toBeGreaterThanOrEqual(2);
  });
});

describe(`${clause("core 7")} the members every record shares`, () => {
  const sample = (type: string) => sampleRecords[type] ?? {};

  it("requires oip to be the string 1", () => {
    for (const oip of ["2", "1.0", "01", " 1", "", 1, true, null, ["1"]]) {
      const parsed = parseRecord(JSON.stringify({ ...sample("Intent"), oip }));
      expect(!parsed.ok && parsed.issues[0], JSON.stringify(oip)).toMatchObject({
        path: "/oip",
        clause: "core 7",
      });
    }
    const { oip: _oip, ...without } = sample("Intent");
    expect(clauseOf(parseRecord(JSON.stringify(without)))).toBe("core 7");
  });

  it("requires type to name a record type", () => {
    for (const type of [1, null, true, ["Intent"], { name: "Intent" }]) {
      const parsed = parseRecord(JSON.stringify({ ...sample("Intent"), type }));
      expect(!parsed.ok && parsed.issues[0], JSON.stringify(type)).toMatchObject({
        path: "/type",
        clause: "core 7",
      });
    }
    const { type: _type, ...without } = sample("Intent");
    expect(clauseOf(parseRecord(JSON.stringify(without)))).toBe("core 7");
    for (const type of ["intent", "INTENT", "Intent ", "Unknown", ""]) {
      expect(parseRecord(JSON.stringify({ ...sample("Intent"), type })).ok, type).toBe(false);
    }
  });

  it("requires created in every record except the containers and Sealed", () => {
    const optional = ["Bundle", "LogPage", "FeedPage", "DuplicityEvidence", "Sealed"];
    for (const [type, record] of Object.entries(sampleRecords)) {
      const { created: _created, ...without } = record;
      expect(parseRecord(JSON.stringify(without)).ok, type).toBe(optional.includes(type));
      expect(Object.hasOwn(record, "created"), type).toBe(!optional.includes(type));
    }
    const badTime = parseRecord(
      JSON.stringify({ ...sample("Intent"), created: "2026-02-30T00:00:00Z" }),
    );
    expect(!badTime.ok && badTime.issues[0]).toMatchObject({
      path: "/created",
      clause: "core 1.4",
    });
  });

  it("checks expires, when present, as a timestamp", () => {
    expect(
      parseRecord(JSON.stringify({ ...sample("Intent"), expires: "2027-01-01T00:00:00Z" })).ok,
    ).toBe(true);
    const parsed = parseRecord(JSON.stringify({ ...sample("Intent"), expires: "tomorrow" }));
    expect(!parsed.ok && parsed.issues[0]).toMatchObject({ path: "/expires", clause: "core 1.4" });
  });
});

describe(`${clause("core 1.7")} members a reader does not recognise`, () => {
  const { proof: _proof, ...unsigned } = named("intent");
  const extended = {
    ...unsigned,
    futureMember: { nested: [1, "two", null], flag: true },
    anotherOne: "x",
  };
  const proofOf = (record: object) => {
    const first = (
      named("intent")["proof"] as { verificationMethod: string; created: string }[]
    )[0];
    const method = first?.verificationMethod ?? "";
    return createProofSync(
      record,
      { verificationMethod: method, created: first?.created ?? "" },
      signerFromPrivateKey(privateKeyOf(method.split("#")[1] ?? "")),
    );
  };

  it("are preserved: a record read and written again keeps its content ID and its proofs", () => {
    const signed = withProofs(extended, [proofOf(extended)]);
    const parsed = parseRecord(JSON.stringify(signed));
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.value).toEqual(signed);
    expect(canonicalize(parsed.value)).toBe(canonicalize(signed));
    expect(contentId(parsed.value)).toBe(contentId(extended));
    const again = parseRecord(canonicalize(parsed.value));
    const verdicts = again.ok ? verifyProofs(again.value) : again;
    expect(verdicts.ok && verdicts.value.map((verdict) => verdict.ok)).toEqual([true]);
  });

  it("are covered by the proofs: dropping one breaks the signature", () => {
    const signed = withProofs(extended, [proofOf(extended)]);
    const { futureMember: _dropped, ...stripped } = signed;
    const verdicts = verifyProofs(stripped);
    expect(verdicts.ok && verdicts.value.map((verdict) => verdict.ok)).toEqual([false]);
    expect(contentId(stripped)).not.toBe(contentId(signed));
  });

  it("are otherwise ignored: they do not make a record malformed", () => {
    for (const [type, record] of Object.entries(sampleRecords)) {
      const withUnknown = { ...record, someFutureMember: [{ a: 1 }], x: null };
      expect(parseRecord(JSON.stringify(withUnknown)).ok, type).toBe(true);
    }
  });
});

describe(`${clause("core 8.2")} an extension block may give its own version`, () => {
  it("accepts a block with v, of any JSON type, and a block without", () => {
    const sample = sampleRecords["Intent"] ?? {};
    for (const block of [
      { v: 1 },
      { v: "2.0" },
      { v: null },
      { v: { major: 1 } },
      {},
      { other: true },
    ]) {
      const record = { ...sample, ext: { "com.example.escrow": block } };
      expect(parseRecord(JSON.stringify(record)).ok, JSON.stringify(block)).toBe(true);
    }
    // A block is an object.
    for (const block of [1, "v1", null, [], true]) {
      const record = { ...sample, ext: { "com.example.escrow": block } };
      expect(clauseOf(parseRecord(JSON.stringify(record))), JSON.stringify(block)).toBe("core 8.1");
    }
  });
});

describe(`${clause("core 8.5")} members added by later revisions`, () => {
  it("lets a reader of this revision accept a record with an optional member it does not know", () => {
    const sample = sampleRecords["Offer"] ?? {};
    const later = { ...sample, addedInALaterRevision: { anything: 1 } };
    expect(parseRecord(JSON.stringify(later)).ok).toBe(true);
    expect(understandsCritical(later)).toBe(true);
  });

  it("stops a reader that does not know an oip extension a record lists as critical", () => {
    const sample = sampleRecords["Offer"] ?? {};
    const unsafe = { ...sample, ext: { "oip.escrow": { v: 1 } }, critical: ["oip.escrow"] };
    const parsed = parseRecord(JSON.stringify(unsafe));
    expect(parsed.ok).toBe(true);
    expect(understandsCritical(unsafe)).toBe(false);
    expect(unsupportedCritical(unsafe)).toEqual(["oip.escrow"]);
    expect(understandsCritical(unsafe, ["oip.escrow"])).toBe(true);
  });
});

describe(`${clause("core 1.6")} size`, () => {
  it("accepts a record whose canonical form is exactly 1 MiB, and rejects one byte more", () => {
    expect(MAX_RECORD_BYTES).toBe(1024 * 1024);
    const largest = padded("Intent", MAX_RECORD_BYTES);
    expect(parseRecord(JSON.stringify(largest)).ok).toBe(true);
    expect(checkSize(largest as unknown as OipRecord)).toEqual([]);
    const tooLarge = padded("Intent", MAX_RECORD_BYTES + 1);
    expect(parseRecord(JSON.stringify(tooLarge))).toEqual({
      ok: false,
      issues: [
        {
          path: "",
          message:
            "the canonical form is 1048577 bytes; the limit is 1048576. Carry larger content by reference",
          clause: "core 1.6",
        },
      ],
    });
  });

  it("accepts records of at least 256 KiB", () => {
    expect(MIN_ACCEPTED_RECORD_BYTES).toBe(256 * 1024);
    expect(MIN_ACCEPTED_RECORD_BYTES).toBeLessThanOrEqual(MAX_RECORD_BYTES);
    expect(parseRecord(JSON.stringify(padded("Packet", MIN_ACCEPTED_RECORD_BYTES))).ok).toBe(true);
    expect(parseRecord(JSON.stringify(padded("Participant", MIN_ACCEPTED_RECORD_BYTES))).ok).toBe(
      true,
    );
  });

  it("measures the canonical form, not the text that was sent", () => {
    // White space and escapes make the text longer than the record.
    const largest = padded("Intent", MAX_RECORD_BYTES);
    const spaced = JSON.stringify(largest, null, 8);
    expect(spaced.length).toBeGreaterThan(MAX_RECORD_BYTES);
    expect(parseRecord(spaced).ok).toBe(true);
    // Characters of several bytes count as their bytes.
    const euros = padded("Intent", MAX_RECORD_BYTES + 1);
    const block =
      (euros["ext"] as Record<string, Record<string, string>>)["com.example.padding"] ?? {};
    block["blob"] = "€".repeat(Math.ceil(MAX_RECORD_BYTES / 3));
    expect(JSON.stringify(euros).length).toBeLessThan(MAX_RECORD_BYTES);
    expect(clauseOf(parseRecord(JSON.stringify(euros)))).toBe("core 1.6");
  });

  it("counts the proofs: the limit is on the whole record", () => {
    const record = padded("Intent", MAX_RECORD_BYTES);
    const proofs = record["proof"] as unknown[];
    const more = { ...record, proof: [...proofs, ...proofs] };
    expect(clauseOf(parseRecord(JSON.stringify(more)))).toBe("core 1.6");
  });

  it("applies the limit to each record a container carries, not to the container", () => {
    expect([...CONTAINER_RECORD_TYPES].sort()).toEqual([
      "Bundle",
      "DuplicityEvidence",
      "FeedPage",
      "LogPage",
    ]);
    const big = (type: string, size = 600_000) => padded(type, size);
    const bundle = sampleRecords["Bundle"] ?? {};
    const genesis = big("Genesis");
    const large = {
      ...bundle,
      log: [genesis],
      location: big("Location"),
      participant: big("Participant"),
    };
    expect(sizeOf(large)).toBeGreaterThan(MAX_RECORD_BYTES);
    expect(parseRecord(JSON.stringify(large)).ok).toBe(true);
    const logPage = { ...(sampleRecords["LogPage"] ?? {}), events: [genesis, genesis, genesis] };
    expect(sizeOf(logPage)).toBeGreaterThan(MAX_RECORD_BYTES);
    expect(parseRecord(JSON.stringify(logPage)).ok).toBe(true);
    const feedPage = {
      ...(sampleRecords["FeedPage"] ?? {}),
      entries: [big("Entry"), big("Entry")],
    };
    expect(parseRecord(JSON.stringify(feedPage)).ok).toBe(true);
    const evidence = { ...(sampleRecords["DuplicityEvidence"] ?? {}), pairs: [[genesis, genesis]] };
    expect(sizeOf(evidence)).toBeGreaterThan(MAX_RECORD_BYTES);
    expect(parseRecord(JSON.stringify(evidence)).ok).toBe(true);
  });

  it("rejects a container that carries a record over the limit, and says which", () => {
    const over = (type: string) => padded(type, MAX_RECORD_BYTES + 1);
    const at = (type: string) => padded(type, MAX_RECORD_BYTES);
    const small = (type: string) => sampleRecords[type] ?? {};
    const options = { maxLength: 4 * MAX_TEXT_LENGTH };
    const paths = (record: unknown) => {
      const parsed = parseRecord(JSON.stringify(record), options);
      return parsed.ok ? [] : parsed.issues.map((issue) => `${issue.clause} ${issue.path}`);
    };
    const bundle = small("Bundle");
    expect(
      paths({
        ...bundle,
        log: [at("Genesis")],
        location: at("Location"),
        participant: at("Participant"),
      }),
    ).toEqual([]);
    expect(paths({ ...bundle, log: [small("Genesis"), over("Genesis")] })).toEqual([
      "core 1.6 /log/1",
    ]);
    expect(paths({ ...bundle, log: [small("Genesis")], location: over("Location") })).toEqual([
      "core 1.6 /location",
    ]);
    expect(paths({ ...bundle, log: [small("Genesis")], participant: over("Participant") })).toEqual(
      ["core 1.6 /participant"],
    );
    expect(
      paths({
        ...bundle,
        log: [over("Genesis")],
        location: over("Location"),
        participant: over("Participant"),
      }),
    ).toEqual(["core 1.6 /log/0", "core 1.6 /location", "core 1.6 /participant"]);
    expect(
      paths({ ...small("LogPage"), events: [at("Genesis"), over("Genesis"), over("Genesis")] }),
    ).toEqual(["core 1.6 /events/1", "core 1.6 /events/2"]);
    expect(paths({ ...small("FeedPage"), entries: [over("Entry"), at("Entry")] })).toEqual([
      "core 1.6 /entries/0",
    ]);
    expect(
      paths({
        ...small("DuplicityEvidence"),
        pairs: [
          [at("Genesis"), at("Genesis")],
          [at("Genesis"), over("Genesis")],
        ],
      }),
    ).toEqual(["core 1.6 /pairs/1/1"]);
  });

  it("does not treat a record that merely carries another as a container", () => {
    const forwarded = sampleRecords["Forwarded"] ?? {};
    const packet = padded("Packet", MAX_RECORD_BYTES);
    expect(clauseOf(parseRecord(JSON.stringify({ ...forwarded, packet })))).toBe("core 1.6");
    expect(parseRecord(JSON.stringify(packet)).ok).toBe(true);
  });

  it("lets a Sealed record exceed the limit by its encoding overhead, and no further", () => {
    // The cipher adds 16 bytes, base64url writes four characters for three bytes, and the other members are small.
    expect(MAX_SEALED_BYTES).toBe(Math.ceil(((MAX_RECORD_BYTES + 16) * 4) / 3) + 4096);
    expect(MAX_SEALED_BYTES).toBeGreaterThan(MAX_RECORD_BYTES);
    const sealed = (size: number) => {
      const base = { ...(sampleRecords["Sealed"] ?? {}), ciphertext: "" };
      return { ...base, ciphertext: "A".repeat(size - sizeOf(base)) };
    };
    expect(sizeOf(sealed(MAX_SEALED_BYTES))).toBe(MAX_SEALED_BYTES);
    expect(parseRecord(JSON.stringify(sealed(MAX_RECORD_BYTES + 1))).ok).toBe(true);
    expect(parseRecord(JSON.stringify(sealed(MAX_SEALED_BYTES))).ok).toBe(true);
    const over = parseRecord(JSON.stringify(sealed(MAX_SEALED_BYTES + 1)));
    expect(!over.ok && over.issues[0]).toEqual({
      path: "",
      message: `the canonical form is ${MAX_SEALED_BYTES + 1} bytes; the limit is ${MAX_SEALED_BYTES}. Carry larger content by reference`,
      clause: "core 1.6",
    });
  });

  it("stops reading a text that is far longer than any record, before parsing it", () => {
    const huge = `{"a":"${"a".repeat(MAX_TEXT_LENGTH)}"}`;
    expect(clauseOf(parseRecord(huge))).toBe(IMPLEMENTATION_LIMIT);
    expect(clauseOf(parseRecord(utf8(huge)))).toBe(IMPLEMENTATION_LIMIT);
    expect(clauseOf(parseRecord(JSON.stringify(named("intent")), { maxLength: 10 }))).toBe(
      IMPLEMENTATION_LIMIT,
    );
    expect(clauseOf(parseRecord(utf8(JSON.stringify(named("intent"))), { maxLength: 10 }))).toBe(
      IMPLEMENTATION_LIMIT,
    );
  });
});
