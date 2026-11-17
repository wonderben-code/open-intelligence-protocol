// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import {
  CONTAINER_RECORD_TYPES,
  containerParts,
  IMPLEMENTATION_LIMIT,
  type OipRecord,
  validateRecord,
} from "@oip/schema";
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
  MAX_SEALED_CIPHERTEXT_LENGTH,
  MAX_TEXT_LENGTH,
  MIN_ACCEPTED_RECORD_BYTES,
  mindAddress,
  parseExtensionRecord,
  parseRecord,
  signerFromPrivateKey,
  understandsCritical,
  unsupportedCritical,
  type Validation,
  verifyProofs,
  withProofs,
} from "../src/index.ts";
import { withStackSpent } from "./stack.ts";
import { log, named, negative, positiveVectorRecords, privateKeyOf } from "./vectors.ts";

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
    expect(verdicts.verified).toHaveLength(1);
    expect(verdicts.rejected).toEqual([]);
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
      expect(parseRecord(bad as string)).toEqual({
        ok: false,
        issues: [
          { path: "", message: "a record is read from text or from bytes", clause: "core 1.1" },
        ],
      });
    }
    fc.assert(
      fc.property(fc.oneof(fc.string(), fc.uint8Array(), fc.json()), (input) => {
        const parsed = parseRecord(input);
        expect(typeof parsed.ok).toBe("boolean");
      }),
      { numRuns: 1000 },
    );
  });

  it("answers and does not throw with the stack all but spent", () => {
    const text = JSON.stringify(named("intent"));
    const readers: (() => Validation<unknown>)[] = [
      () => parseRecord(text),
      () => parseRecord(utf8(text)),
      () => parseExtensionRecord(text),
    ];
    for (const read of readers) {
      const answers = withStackSpent(read);
      expect(answers).toHaveLength(200);
      for (const answer of answers) {
        if (!answer.ok) expect(answer.issues[0].message.length).toBeGreaterThan(0);
      }
    }
    expect(parseRecord(text).ok).toBe(true);
    for (const answer of withStackSpent(() => unsupportedCritical(named("intent")))) {
      expect(Array.isArray(answer)).toBe(true);
    }
  });

  it("reads no clock and no randomness", () => {
    const text = JSON.stringify(named("commitment_accepted"));
    const proofs = withAmbientTrapped(() => {
      const parsed = parseRecord(text);
      if (!parsed.ok) return -1;
      return verifyProofs(parsed.value).verified.length;
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

  it("reads a record of a type an extension defines with parseExtensionRecord, and only with it", () => {
    const note = {
      oip: "1",
      type: "com.example.Note",
      created: "2026-11-17T09:00:00Z",
      text: "a member this revision knows nothing of",
      ext: { "com.example": { v: 1 } },
      critical: ["com.example"],
    };
    const text = JSON.stringify(note);
    expect(parseExtensionRecord(text)).toEqual({ ok: true, value: note });
    expect(parseExtensionRecord(utf8(text)).ok).toBe(true);
    // parseRecord says where to take it.
    const refused = parseRecord(text);
    expect(!refused.ok && refused.issues[0]).toMatchObject({ path: "/type", clause: "core 11" });
    // A reader that does not understand the extension stores and forwards, and does not act.
    expect(unsupportedCritical(note)).toEqual(["com.example"]);
    expect(unsupportedCritical(note, ["com.example"])).toEqual([]);
    // It is for those records alone, and applies the same rules to them.
    const intent = JSON.stringify(sample("Intent"));
    expect(clauseOf(parseExtensionRecord(intent))).toBe("core 11");
    const { critical: _critical, ...unlisted } = note;
    expect(clauseOf(parseExtensionRecord(JSON.stringify(unlisted)))).toBe("core 7");
    expect(clauseOf(parseExtensionRecord(JSON.stringify({ ...note, n: 1.5 })))).toBe("core 1.2");
    expect(clauseOf(parseExtensionRecord(`{"a":1,"a":2}`))).toBe("core 1.1");
    const big = { ...note, text: "a".repeat(MAX_RECORD_BYTES) };
    expect(clauseOf(parseExtensionRecord(JSON.stringify(big)))).toBe("core 1.6");
    let deep: unknown = [];
    for (let i = 0; i < 63; i++) deep = [deep];
    expect(clauseOf(parseExtensionRecord(JSON.stringify({ ...note, deep })))).toBe("core 1.9");
    for (const hostile of [null, 7, {}, [], new Proxy({}, {})]) {
      expect(parseExtensionRecord(hostile as unknown as string).ok).toBe(false);
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
    expect(again.ok && verifyProofs(again.value).verified.map((proof) => proof.index)).toEqual([0]);
  });

  it("are covered by the proofs: dropping one breaks the signature", () => {
    const signed = withProofs(extended, [proofOf(extended)]);
    const { futureMember: _dropped, ...stripped } = signed;
    const verdicts = verifyProofs(stripped);
    expect(verdicts.verified).toEqual([]);
    expect(verdicts.rejected.map((entry) => entry.issues[0].clause)).toEqual(["core 4.4"]);
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
            "the record is 1048577 bytes in canonical form; the limit is 1048576. Carry larger content by reference",
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

  it("reads a Bundle with or without a location and a profile", () => {
    const whole = sampleRecords["Bundle"] ?? {};
    const { location: _location, participant: _participant, ...bare } = whole;
    expect(parseRecord(JSON.stringify(bare))).toEqual({ ok: true, value: bare });
    expect(checkSize(bare as unknown as OipRecord)).toEqual([]);
    const large = padded("Genesis", MAX_RECORD_BYTES + 1);
    const parsed = parseRecord(JSON.stringify({ ...bare, log: [large] }));
    expect(!parsed.ok && parsed.issues).toMatchObject([{ path: "/log/0", clause: "core 1.6" }]);
    for (const member of ["location", "participant"]) {
      const one = { ...bare, [member]: whole[member] };
      expect(parseRecord(JSON.stringify(one)).ok, member).toBe(true);
    }
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
    const carried = parseRecord(JSON.stringify({ ...bundle, log: [over("Genesis")] }), options);
    expect(!carried.ok && carried.issues[0].message).toBe(
      `the record is ${MAX_RECORD_BYTES + 1} bytes in canonical form; the limit is ${MAX_RECORD_BYTES}. Carry larger content by reference`,
    );
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
    // A packet of 1 MiB, the cipher's 16 bytes, and base64url at four characters for three bytes.
    expect(MAX_SEALED_CIPHERTEXT_LENGTH).toBe(Math.ceil(((MAX_RECORD_BYTES + 16) * 4) / 3));
    expect(MAX_SEALED_CIPHERTEXT_LENGTH).toBe(1_398_123);
    const base = sampleRecords["Sealed"] ?? {};
    const sealed = (ciphertext: number, extra = 0) => ({
      ...base,
      ciphertext: "A".repeat(ciphertext),
      ...(extra === 0 ? {} : { ext: { "com.example.padding": { blob: "a".repeat(extra) } } }),
    });
    const verdict = (record: unknown) => {
      const parsed = parseRecord(JSON.stringify(record));
      return parsed.ok ? "ok" : parsed.issues.map((issue) => `${issue.clause} ${issue.path}`);
    };
    // The whole record is larger than 1 MiB, and that is allowed.
    expect(sizeOf(sealed(MAX_SEALED_CIPHERTEXT_LENGTH))).toBeGreaterThan(MAX_RECORD_BYTES);
    expect(verdict(sealed(MAX_SEALED_CIPHERTEXT_LENGTH))).toBe("ok");
    expect(verdict(sealed(MAX_SEALED_CIPHERTEXT_LENGTH + 1))).toEqual(["core 1.6 /ciphertext"]);
    // The allowance is for the ciphertext only: the rest obeys the ordinary limit.
    const rest = (record: Record<string, unknown>) => {
      const { ciphertext: _ciphertext, ...others } = record;
      return sizeOf(others);
    };
    const room = MAX_RECORD_BYTES - rest(sealed(100, 1)) + 1;
    expect(rest(sealed(100, room))).toBe(MAX_RECORD_BYTES);
    expect(verdict(sealed(100, room))).toBe("ok");
    expect(verdict(sealed(100, room + 1))).toEqual(["core 1.6 "]);
    expect(verdict(sealed(MAX_SEALED_CIPHERTEXT_LENGTH + 1, room + 1))).toEqual([
      "core 1.6 /ciphertext",
      "core 1.6 ",
    ]);
    const over = parseRecord(JSON.stringify(sealed(MAX_SEALED_CIPHERTEXT_LENGTH + 1)));
    expect(!over.ok && over.issues[0].message).toBe(
      "the ciphertext is 1398124 characters; a sealed packet of 1 MiB needs at most 1398123",
    );
    const large = parseRecord(JSON.stringify(sealed(100, room + 1)));
    expect(!large.ok && large.issues[0].message).toBe(
      "the record, without its ciphertext, is 1048577 bytes in canonical form; the limit is 1048576. Carry larger content by reference",
    );
  });

  it("applies the limit to a container without the records it carries", () => {
    const paths = (record: unknown) => {
      const parsed = parseRecord(JSON.stringify(record), { maxLength: 4 * MAX_TEXT_LENGTH });
      return parsed.ok ? "ok" : parsed.issues.map((issue) => `${issue.clause} ${issue.path}`);
    };
    for (const type of ["Bundle", "LogPage", "FeedPage", "DuplicityEvidence"]) {
      const container = sampleRecords[type] ?? {};
      const parts = containerParts(container as unknown as OipRecord);
      const own = sizeOf(parts?.rest ?? {});
      const padding = (size: number) => ({
        ext: { "com.example.padding": { blob: "a".repeat(size) } },
      });
      const overhead = sizeOf({ ...parts?.rest, ...padding(0) }) - own;
      const room = MAX_RECORD_BYTES - own - overhead;
      expect(paths({ ...container, ...padding(room) }), type).toBe("ok");
      expect(paths({ ...container, ...padding(room + 1) }), type).toEqual(["core 1.6 "]);
    }
    // Both rules at once: the container's own part and a record it carries.
    const bundle = sampleRecords["Bundle"] ?? {};
    const tooLarge = padded("Genesis", MAX_RECORD_BYTES + 1);
    const both = {
      ...bundle,
      log: [tooLarge],
      ext: { "com.example.padding": { blob: "a".repeat(MAX_RECORD_BYTES) } },
    };
    expect(paths(both)).toEqual(["core 1.6 ", "core 1.6 /log/0"]);
    const message = parseRecord(JSON.stringify(both), { maxLength: 4 * MAX_TEXT_LENGTH });
    expect(!message.ok && message.issues[0].message).toMatch(
      /^the container, without the records it carries, is \d+ bytes in canonical form; the limit is 1048576/,
    );
  });

  it(`${clause("core 1.8")} counts a limit on characters in code points`, () => {
    // An Intent's want is at most 4096 characters. Each of these is one code
    // point and two UTF-16 code units, so a count of units would halve the limit.
    const intent = sampleRecords["Intent"] ?? {};
    const want = (count: number) => JSON.stringify({ ...intent, want: "😀".repeat(count) });
    expect("😀".repeat(4096)).toHaveLength(8192);
    expect(parseRecord(want(4096)).ok).toBe(true);
    expect(parseRecord(utf8(want(4096))).ok).toBe(true);
    const over = parseRecord(want(4097));
    expect(!over.ok && over.issues.map((issue) => issue.path)).toEqual(["/want"]);
    expect(parseRecord(JSON.stringify({ ...intent, want: "a".repeat(4096) })).ok).toBe(true);
    expect(parseRecord(JSON.stringify({ ...intent, want: "a".repeat(4097) })).ok).toBe(false);
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

describe(`${clause("core 1.9")} depth`, () => {
  /** A value that nests `levels` deep: an array in an array, and so on. */
  const nest = (levels: number): unknown => {
    let value: unknown = [];
    for (let i = 1; i < levels; i++) value = [value];
    return value;
  };
  // The record is depth 1, ext 2 and the block 3: the member's value starts at depth 4.
  const deep = (record: JsonObject, depth: number): JsonObject => ({
    ...record,
    ext: { "com.example.deep": { down: nest(depth - 3) } },
  });
  const read = (record: unknown) => {
    const parsed = parseRecord(JSON.stringify(record));
    return parsed.ok ? "ok" : parsed.issues.map((issue) => `${issue.clause} ${issue.path}`);
  };
  const genesis = sampleRecords["Genesis"] ?? {};

  it("lets a record nest 64 deep, and no deeper", () => {
    for (const type of ["Genesis", "Intent", "Offer", "Packet"]) {
      const record = sampleRecords[type] ?? {};
      expect(read(deep(record, 64)), type).toBe("ok");
      expect(read(deep(record, 65)), type).toEqual(["core 1.9 "]);
    }
  });

  it("counts a carried record from itself: a container can carry any record that is valid alone", () => {
    const deepest = deep(genesis, 64);
    const tooDeep = deep(genesis, 65);
    expect(read(deepest)).toBe("ok");
    const carrying = (event: JsonObject): [type: string, record: unknown, path: string][] => [
      ["LogPage", { ...sampleRecords["LogPage"], events: [event] }, "/events/0"],
      ["Bundle", { ...sampleRecords["Bundle"], log: [event] }, "/log/0"],
    ];
    for (const [type, container] of carrying(deepest)) {
      // The whole container nests deeper than 64, and is valid: nothing in it does.
      expect(read(container), type).toBe("ok");
      expect(canonicalize(container).length).toBeGreaterThan(0);
    }
    for (const [type, container, path] of carrying(tooDeep)) {
      expect(read(container), type).toEqual([`core 1.9 ${path}`]);
    }
    // A pair of events sits three levels down: the deepest a container reaches.
    const pair = (sampleRecords["DuplicityEvidence"] as { pairs: JsonObject[][] }).pairs[0] ?? [];
    const evidence = (first: JsonObject) => ({
      ...sampleRecords["DuplicityEvidence"],
      pairs: [[first, pair[1]]],
    });
    expect(read(evidence(deep(pair[0] ?? {}, 64)))).toBe("ok");
    // One level more is deeper than any container can be, and is not read far enough to say where.
    expect(read(evidence(deep(pair[0] ?? {}, 65)))).toEqual(["core 1.9 "]);
  });

  it("applies the limit to the container without the records it carries", () => {
    for (const type of CONTAINER_RECORD_TYPES) {
      const container = sampleRecords[type] ?? {};
      expect(read(deep(container, 64)), type).toBe("ok");
      expect(read(deep(container, 65)), type).toEqual(["core 1.9 "]);
    }
  });

  it("counts the entries of proof with the record that carries them", () => {
    // An entry of proof that is not a proof is carried and never counts (core 5.5),
    // but it is part of the record, and the record's limits cover it.
    const junk = (depth: number) => ({ ...genesis, proof: [{ junk: nest(depth - 3) }] });
    expect(read(junk(64))).not.toEqual(["core 1.9 "]);
    expect(read(junk(65))).toEqual(["core 1.9 "]);
    const page = (depth: number) => ({ ...sampleRecords["LogPage"], events: [junk(depth)] });
    expect(read(page(65))).toEqual(["core 1.9 /events/0"]);
  });

  it("reads a page of records that are each well formed, however much they hold together", () => {
    // Anyone can add an entry to an event's proof, where it never counts. Here each
    // of three events carries one of 400,000 values, and is still well formed alone.
    const junk = { junk: new Array<number>(400_000).fill(0) };
    const honest = [...log("amina_log"), ...log("researcher_log")].slice(0, 3);
    const events = honest.map((event) => ({
      ...event,
      proof: [...(event["proof"] as unknown[]), junk],
    }));
    expect(events).toHaveLength(3);
    for (const [i, event] of events.entries()) {
      expect(parseRecord(JSON.stringify(event)).ok, `event ${i}`).toBe(true);
      expect(contentId(event)).toBe(contentId(honest[i]));
      expect(verifyProofs(event).verified.length, `event ${i}`).toBeGreaterThan(0);
    }
    const page = {
      oip: "1",
      type: "LogPage",
      mind: mindAddress(contentId(events[0])),
      events,
    };
    const text = JSON.stringify(page);
    expect(text.length).toBeGreaterThan(2 * 1024 * 1024);
    // No limit on the page as a whole refuses it: not on depth, size or the count of values.
    expect(parseRecord(text).ok).toBe(true);
    expect(parseRecord(utf8(text)).ok).toBe(true);
    // The same for the value itself, which a server holds before it writes it.
    expect(validateRecord(page).ok).toBe(true);
    expect(canonicalize(page)).toHaveLength(text.length);
    expect(contentId(page)).toMatch(/^bciq/);
  });

  it("does not read a text deeper than any container can be", () => {
    // Three levels for the container and 64 for the record it carries.
    expect(clauseOf(parseRecord(JSON.stringify(nest(67))))).toBe("core 1.1");
    expect(clauseOf(parseRecord(JSON.stringify(nest(68))))).toBe("core 1.9");
    expect(clauseOf(parseRecord("[".repeat(1_000_000)))).toBe("core 1.9");
  });
});
