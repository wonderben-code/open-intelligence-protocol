// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { clause, copy } from "@oip/testkit";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  contentId,
  formatControlKeyRef,
  formatKeyRef,
  formatRecordRef,
  formatVersionId,
  isMindAddress,
  mindAddress,
  mindId,
  parseControlKeyRef,
  parseKeyRef,
  parseRecordRef,
  parseVerificationMethod,
  parseVersionedMind,
  parseVersionId,
  recordRefMatches,
} from "../src/index.ts";
import { cases, keys, named, show, signedRecords, strings } from "./vectors.ts";

const CID = "bciqmwrzo6zt2xnoga2rkp77b7p2yicceqwiljl2d7dxoa4xpiugbgna";
const OTHER = "bciqhzdmvqz4nu2oiwedlpwpt2zwl62utjymq6vr3a364eo3zgv5mnmq";
const MIND = `did:oip:${CID}`;
const KEY = keys["amina-phone"]?.multikey ?? "";
const KEY2 = keys["amina-laptop"]?.multikey ?? "";

const cid = fc
  .tuple(
    fc.constantFrom(..."abcdefghijklmnop".split("")),
    fc.string({
      unit: fc.constantFrom(..."abcdefghijklmnopqrstuvwxyz234567".split("")),
      minLength: 50,
      maxLength: 50,
    }),
    fc.constantFrom("a", "i", "q", "y"),
  )
  .map(([first, middle, last]) => `bciq${first}${middle}${last}`);
const multikey = fc
  .string({
    unit: fc.constantFrom(
      ..."123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".split(""),
    ),
    minLength: 1,
    maxLength: 60,
  })
  .map((body) => `z${body}`);
const seq = fc.oneof(fc.constant(0), fc.nat(1000), fc.maxSafeNat());

describe(`${clause("core 6.1")} the grammar of references`, () => {
  it("reads and writes a mind address", () => {
    expect(mindAddress(CID)).toBe(MIND);
    expect(mindId(MIND)).toBe(CID);
    expect(isMindAddress(MIND)).toBe(true);
    for (const bad of [
      CID,
      `did:oip:${CID.toUpperCase()}`,
      `DID:OIP:${CID}`,
      `did:oip:${CID}a`,
      `did:oip:${CID.slice(0, -1)}`,
      `did:oip:${CID.slice(0, -1)}b`,
      `did:web:${CID}`,
      `did:oip:${CID}?versionId=0-${CID}`,
      `did:oip:${CID}#${KEY}`,
      `did:oip:${CID}/${CID}`,
      ` ${MIND}`,
      `${MIND}\n`,
      "did:oip:",
      "",
      null,
      undefined,
      1,
      [MIND],
    ]) {
      expect(isMindAddress(bad), show(bad)).toBe(false);
      expect(mindId(bad), show(bad)).toBeUndefined();
    }
    for (const bad of ["", "abc", CID.slice(1), CID.toUpperCase(), MIND, null]) {
      expect(() => mindAddress(bad!)).toThrow(
        new TypeError("a mind address is made from a content ID"),
      );
    }
  });

  it("reads and writes a version-id", () => {
    expect(parseVersionId(`0-${CID}`)).toEqual({ seq: 0, contentId: CID });
    expect(parseVersionId(`17-${OTHER}`)).toEqual({ seq: 17, contentId: OTHER });
    expect(parseVersionId(`9007199254740991-${CID}`)).toEqual({
      seq: Number.MAX_SAFE_INTEGER,
      contentId: CID,
    });
    expect(formatVersionId(0, CID)).toBe(`0-${CID}`);
    expect(formatVersionId(1234, CID)).toBe(`1234-${CID}`);
    for (const bad of [
      CID,
      `-${CID}`,
      `00-${CID}`,
      `01-${CID}`,
      `-1-${CID}`,
      `+1-${CID}`,
      `1.0-${CID}`,
      `1e2-${CID}`,
      `0x1-${CID}`,
      ` 1-${CID}`,
      `1 -${CID}`,
      `1-${CID} `,
      `1_${CID}`,
      `1-${CID.toUpperCase()}`,
      `1-${CID.slice(0, -1)}b`,
      `1-${CID}-${CID}`,
      `١-${CID}`,
      "1-",
      "",
      null,
      1,
      { seq: 1, contentId: CID },
    ]) {
      expect(parseVersionId(bad), show(bad)).toBeUndefined();
    }
    for (const bad of [-1, 1.5, Number.NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, "1"]) {
      expect(() => formatVersionId(bad as number, CID)).toThrow(
        new TypeError("a position in a log is a non-negative integer"),
      );
    }
    expect(() => formatVersionId(1, "abc")).toThrow(
      new TypeError("a version names its event by content ID"),
    );
  });

  it("does not read a position that no log has", () => {
    // The grammar allows any run of digits; a position is an integer of a record (core 1.2).
    expect(parseVersionId(`9007199254740992-${CID}`)).toBeUndefined();
    expect(parseVersionId(`9007199254740993-${CID}`)).toBeUndefined();
    expect(parseVersionId(`${"9".repeat(400)}-${CID}`)).toBeUndefined();
    expect(parseVersionedMind(`${MIND}?versionId=9007199254740992-${CID}`)).toBeUndefined();
    expect(parseKeyRef(`${MIND}?versionId=9007199254740992-${CID}#${KEY}`)).toBeUndefined();
    expect(parseKeyRef(`${MIND}?versionId=9007199254740991-${CID}#${KEY}`)?.version.seq).toBe(
      Number.MAX_SAFE_INTEGER,
    );
  });

  it("reads a versioned-mind", () => {
    expect(parseVersionedMind(`${MIND}?versionId=3-${OTHER}`)).toEqual({
      mind: MIND,
      versionId: `3-${OTHER}`,
      version: { seq: 3, contentId: OTHER },
    });
    for (const bad of [
      MIND,
      `${MIND}?versionId=`,
      `${MIND}?versionid=3-${OTHER}`,
      `${MIND}?versionId=3-${OTHER}#${KEY}`,
      `${MIND}?versionId=3-${OTHER}&x=1`,
      `${MIND}?x=1&versionId=3-${OTHER}`,
      `${MIND}&versionId=3-${OTHER}`,
      `${MIND}?versionId=03-${OTHER}`,
      `${CID}?versionId=3-${OTHER}`,
      null,
    ]) {
      expect(parseVersionedMind(bad), show(bad)).toBeUndefined();
    }
  });

  it("reads and writes a key-ref", () => {
    const written = `${MIND}?versionId=2-${OTHER}#${KEY}`;
    expect(parseKeyRef(written)).toEqual({
      kind: "key",
      mind: MIND,
      versionId: `2-${OTHER}`,
      version: { seq: 2, contentId: OTHER },
      key: KEY,
    });
    expect(formatKeyRef(MIND, `2-${OTHER}`, KEY)).toBe(written);
    for (const bad of [
      `${MIND}#${KEY}`,
      `${MIND}?versionId=2-${OTHER}`,
      `${MIND}?versionId=2-${OTHER}#`,
      `${MIND}?versionId=2-${OTHER}#z`,
      `${MIND}?versionId=2-${OTHER}#${KEY.slice(1)}`,
      `${MIND}?versionId=2-${OTHER}#${KEY}#${KEY}`,
      `${MIND}?versionId=2-${OTHER}#${KEY} `,
      `${MIND}?versionId=2-${OTHER}#${KEY}0`,
      `${MIND}?versionId=2-${OTHER}#key-1`,
      `${MIND}?versionId=2-${OTHER.toUpperCase()}#${KEY}`,
      `did:key:${KEY}#${KEY}`,
      `${MIND}/${OTHER}`,
      "",
      null,
      [written],
    ]) {
      expect(parseKeyRef(bad), show(bad)).toBeUndefined();
    }
    expect(() => formatKeyRef(CID, `2-${OTHER}`, KEY)).toThrow(
      new TypeError("a key reference starts with a mind address"),
    );
    expect(() => formatKeyRef(MIND, OTHER, KEY)).toThrow(
      new TypeError("a key reference pins a version of the identity"),
    );
    for (const bad of ["", "z", KEY.slice(1), `${KEY}#`, `${KEY}0`, null]) {
      expect(() => formatKeyRef(MIND, `2-${OTHER}`, bad!)).toThrow(
        new TypeError("a key reference names a Multikey"),
      );
      expect(() => formatControlKeyRef(bad!)).toThrow(
        new TypeError("a key reference names a Multikey"),
      );
    }
  });

  it("reads and writes a record-ref", () => {
    expect(parseRecordRef(`${MIND}/${OTHER}`)).toEqual({ mind: MIND, contentId: OTHER });
    expect(formatRecordRef(MIND, OTHER)).toBe(`${MIND}/${OTHER}`);
    for (const bad of [
      MIND,
      OTHER,
      `${MIND}/`,
      `${MIND}//${OTHER}`,
      `${MIND}/${OTHER}/`,
      `${MIND}/${OTHER}/${OTHER}`,
      `${MIND}/${OTHER.slice(0, -1)}b`,
      `${MIND}/${OTHER.toUpperCase()}`,
      `${MIND}#${OTHER}`,
      `${CID}/${OTHER}`,
      `${MIND}/${OTHER}?x`,
      ` ${MIND}/${OTHER}`,
      "",
      null,
      { mind: MIND, contentId: OTHER },
    ]) {
      expect(parseRecordRef(bad), show(bad)).toBeUndefined();
    }
    expect(() => formatRecordRef(CID, OTHER)).toThrow(
      new TypeError("a record reference starts with a mind address"),
    );
    expect(() => formatRecordRef(MIND, MIND)).toThrow(
      new TypeError("a record reference names a content ID"),
    );
  });

  it("reads back whatever it writes", () => {
    fc.assert(
      fc.property(cid, cid, seq, multikey, (genesis, event, position, key) => {
        const mind = mindAddress(genesis);
        const versionId = formatVersionId(position, event);
        expect(parseVersionId(versionId)).toEqual({ seq: position, contentId: event });
        expect(parseKeyRef(formatKeyRef(mind, versionId, key))).toEqual({
          kind: "key",
          mind,
          versionId,
          version: { seq: position, contentId: event },
          key,
        });
        expect(parseControlKeyRef(formatControlKeyRef(key))).toEqual({ kind: "control", key });
        expect(parseRecordRef(formatRecordRef(mind, event))).toEqual({ mind, contentId: event });
      }),
      { numRuns: 300 },
    );
  });

  it("reads every reference in the vectors", () => {
    const all = strings(cases);
    const keyRefs = all.filter((text) => text.includes("?versionId=") && text.includes("#"));
    const controlRefs = all.filter((text) => text.startsWith("did:key:"));
    const recordRefs = all.filter((text) => /^did:oip:[a-z2-7]+\/b/.test(text));
    expect(keyRefs.length).toBeGreaterThan(20);
    expect(controlRefs.length).toBeGreaterThan(10);
    expect(recordRefs.length).toBeGreaterThan(5);
    for (const ref of keyRefs) expect(parseKeyRef(ref)?.kind, ref).toBe("key");
    for (const ref of controlRefs) expect(parseControlKeyRef(ref)?.kind, ref).toBe("control");
    for (const ref of recordRefs) expect(parseRecordRef(ref), ref).toBeDefined();
    for (const { name, record } of signedRecords) {
      for (const proof of record["proof"] as { verificationMethod: string }[]) {
        expect(parseVerificationMethod(proof.verificationMethod), name).toBeDefined();
      }
    }
  });
});

describe(`${clause("core 6.2")} which reference a proof uses`, () => {
  it("reads a control-key-ref only when both occurrences of the key are identical", () => {
    expect(parseControlKeyRef(`did:key:${KEY}#${KEY}`)).toEqual({ kind: "control", key: KEY });
    expect(formatControlKeyRef(KEY)).toBe(`did:key:${KEY}#${KEY}`);
    for (const bad of [
      `did:key:${KEY}#${KEY2}`,
      `did:key:${KEY}#${KEY.slice(0, -1)}`,
      `did:key:${KEY.slice(0, -1)}#${KEY}`,
      `did:key:${KEY}#${KEY}x`.replace("x", "1"),
      `did:key:${KEY}`,
      `did:key:${KEY}#`,
      `did:key:#${KEY}`,
      `did:key:${KEY}#${KEY}#${KEY}`,
      `did:key:${KEY.slice(1)}#${KEY.slice(1)}`,
      `did:KEY:${KEY}#${KEY}`,
      `did:oip:${KEY}#${KEY}`,
      `${KEY}#${KEY}`,
      "",
      null,
    ]) {
      expect(parseControlKeyRef(bad), show(bad)).toBeUndefined();
    }
  });

  it("tells the two kinds of verification method apart", () => {
    const keyRef = `${MIND}?versionId=0-${CID}#${KEY}`;
    expect(parseVerificationMethod(keyRef)).toEqual(parseKeyRef(keyRef));
    expect(parseVerificationMethod(keyRef)?.kind).toBe("key");
    expect(parseVerificationMethod(formatControlKeyRef(KEY))).toEqual({
      kind: "control",
      key: KEY,
    });
    for (const bad of [
      MIND,
      KEY,
      `${MIND}#${KEY}`,
      `did:key:${KEY}#${KEY2}`,
      "did:web:example.com#key",
      null,
    ]) {
      expect(parseVerificationMethod(bad), show(bad)).toBeUndefined();
    }
  });
});

describe(`${clause("core 6.3")} a record-ref matches by content ID alone`, () => {
  const offer = named("offer");
  const id = contentId(offer);

  it("matches the record whose content ID it names", () => {
    expect(recordRefMatches(`${offer["author"] as string}/${id}`, offer)).toBe(true);
    const unsigned = copy(offer);
    delete unsigned["proof"];
    expect(recordRefMatches(`${offer["author"] as string}/${id}`, unsigned)).toBe(true);
  });

  it("ignores the mind part", () => {
    expect(recordRefMatches(`${MIND}/${id}`, offer)).toBe(true);
    expect(recordRefMatches(`did:oip:${OTHER}/${id}`, offer)).toBe(true);
  });

  it("matches nothing else", () => {
    expect(recordRefMatches(`${MIND}/${OTHER}`, offer)).toBe(false);
    expect(recordRefMatches(`${MIND}/${id}`, { ...offer, provides: "something else" })).toBe(false);
    expect(recordRefMatches(id, offer)).toBe(false);
    expect(recordRefMatches(`${MIND}/${id.slice(0, -1)}b`, offer)).toBe(false);
    expect(recordRefMatches(null, offer)).toBe(false);
    for (const notRecord of [undefined, null, [], "text", 1]) {
      expect(recordRefMatches(`${MIND}/${id}`, notRecord)).toBe(false);
    }
    expect(recordRefMatches(`${MIND}/${id}`, { a: 0.5 })).toBe(false);
  });

  it("resolves the references between records of the vectors", () => {
    const delegation = named("delegation");
    const commitment = named("commitment_agents");
    const refs = (commitment["proof"] as { authority?: unknown[] }[]).flatMap(
      (proof) => proof.authority ?? [],
    );
    expect(refs.some((ref) => recordRefMatches(ref, delegation))).toBe(true);
  });
});

describe(`${clause("core 6.4")} abbreviated addresses`, () => {
  it("are not addresses: nothing shortened is read as a reference", () => {
    for (const short of [
      `did:oip:${CID.slice(0, 12)}`,
      `did:oip:${CID.slice(0, 8)}…${CID.slice(-4)}`,
      `did:oip:${CID.slice(0, 55)}`,
    ]) {
      expect(isMindAddress(short)).toBe(false);
      expect(parseRecordRef(`${short}/${OTHER}`)).toBeUndefined();
      expect(parseKeyRef(`${short}?versionId=0-${CID}#${KEY}`)).toBeUndefined();
    }
  });
});
