// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A check that was cut short, in this package (ADR-0010).
 *
 * Each function that turns a failure into an answer notes one that says
 * nothing of the value judged, and each that judges for a caller refuses
 * when one was noted. And the count never moves for what arrives from
 * outside, however it is malformed: a signature that is no signature must
 * be rejected as that, and must not make a verifier refuse the record it
 * came on for want of room.
 */

import { CUT_SHORT, cutShortCount, noteCutShort } from "@oip/schema";
import { clause, inNode } from "@oip/testkit";
import { base58 } from "@scure/base";
import fc from "fast-check";
import { afterEach, describe, expect, it, vi } from "vitest";

import { BoundedCache } from "../src/cache.ts";
import {
  contentId,
  decodeEd25519Multikey,
  decodeX25519Multikey,
  ed25519PublicKey,
  encodeEd25519Multikey,
  encodeX25519Multikey,
  hexToBytes,
  isEd25519Multikey,
  isEd25519PublicKey,
  parseExtensionRecord,
  parseJson,
  parseJsonBytes,
  parseRecord,
  recordRefMatches,
  signEd25519,
  unsupportedCritical,
  verifyEd25519,
  verifyProof,
  verifyProofs,
} from "../src/index.ts";
import { named } from "./vectors.ts";

/** By how much the count moves while `work` runs. */
function moved(work: () => unknown): number {
  const before = cutShortCount();
  work();
  return cutShortCount() - before;
}

const overflow = (): RangeError => new RangeError("Maximum call stack size exceeded");

/** A value that throws `error` as soon as anything is asked of it. */
function failing(error: unknown): object {
  const refuse = (): never => {
    throw error;
  };
  return new Proxy(
    {},
    {
      ownKeys: refuse,
      get: refuse,
      has: refuse,
      getOwnPropertyDescriptor: refuse,
      getPrototypeOf: refuse,
    },
  );
}

const revoked = (): object => {
  const { proxy, revoke } = Proxy.revocable({}, {});
  revoke();
  return proxy;
};

const SPENT = {
  ok: false,
  issues: [{ path: "", message: CUT_SHORT, clause: "implementation limit" }],
};

/** A reference to the Intent of the vectors, which a record is matched against by its content ID. */
const reference = `${named("intent")["author"] as string}/${contentId(named("intent"))}`;

const seed = new Uint8Array(32).fill(5);
const key = ed25519PublicKey(seed);
const message = new TextEncoder().encode("a message");
const signature = signEd25519(message, seed);

/** Encodings of a y-coordinate that is no field element: the library reports them in a `RangeError`. */
const NOT_CANONICAL = [
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
].map((hex) => hexToBytes(hex));

describe(`${clause("core 4.4")} a signature that is none, from outside`, () => {
  it("is rejected as that, and notes nothing: not an R or a key that is no canonical encoding", () => {
    for (const encoding of NOT_CANONICAL) {
      const withR = Uint8Array.from(signature);
      withR.set(encoding, 0);
      expect(moved(() => expect(verifyEd25519(withR, message, key)).toBe(false))).toBe(0);
      expect(moved(() => expect(verifyEd25519(signature, message, encoding)).toBe(false))).toBe(0);
      expect(moved(() => expect(isEd25519PublicKey(encoding)).toBe(false))).toBe(0);
    }
  });

  it("is rejected as that, and notes nothing: not an S that is not below L", () => {
    const big = Uint8Array.from(signature);
    big.fill(0xff, 32, 63);
    big[63] = 0x1f;
    expect(moved(() => expect(verifyEd25519(big, message, key)).toBe(false))).toBe(0);
  });

  it("notes nothing, whatever the bytes", () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 64, maxLength: 64 }),
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        (sig, publicKey) => {
          expect(moved(() => verifyEd25519(sig, message, publicKey))).toBe(0);
          expect(moved(() => verifyEd25519(sig, message, key))).toBe(0);
          expect(moved(() => isEd25519PublicKey(publicKey))).toBe(0);
        },
      ),
      { numRuns: 200 },
    );
  });

  it("leaves the other proofs on its record to be judged", () => {
    // Anyone can add an entry to a copy of a record. One whose R is no canonical encoding is a
    // proof that does not verify (core 5.5), and takes nothing from the proof beside it.
    const intent = named("intent");
    const [proof] = intent["proof"] as [Record<string, unknown>];
    const bent = base58.decode(String(proof["proofValue"]).slice(1));
    bent.set(NOT_CANONICAL[0]!, 0);
    const garbage = { ...proof, proofValue: `z${base58.encode(bent)}` };
    const copy = { ...intent, proof: [proof, garbage] };
    let verdicts: ReturnType<typeof verifyProofs> | undefined;
    expect(
      moved(() => {
        verdicts = verifyProofs(copy);
      }),
    ).toBe(0);
    expect(verdicts?.verified).toHaveLength(1);
    expect(verdicts?.rejected).toMatchObject([{ index: 1, issues: [{ clause: "core 4.4" }] }]);
    expect(verdicts?.issues).toStrictEqual([]);
    // Alone on the record, it is a proof that does not verify, and still no sign of anything else.
    expect(moved(() => verifyProof(copy, garbage))).toBe(0);
    expect(verifyProof(copy, garbage)).toMatchObject({
      ok: false,
      issues: [{ clause: "core 4.4" }],
    });
  });
});

describe("what is read from outside", () => {
  it("never moves the count: no text, whatever it says", () => {
    const quoting = [
      '"Maximum call stack size exceeded"',
      '{"oip":"1","type":"Maximum call stack size exceeded"}',
      "Maximum call stack size exceeded",
      '{"a":"too much recursion"',
    ];
    for (const text of quoting) {
      expect(
        moved(() => {
          parseJson(text);
          parseRecord(text);
          parseExtensionRecord(text);
          parseJsonBytes(new TextEncoder().encode(text));
        }),
        text,
      ).toBe(0);
    }
    fc.assert(
      fc.property(fc.oneof(fc.string(), fc.json()), (text) => {
        expect(
          moved(() => {
            parseJson(text);
            parseRecord(text);
            parseExtensionRecord(text);
          }),
        ).toBe(0);
      }),
      { numRuns: 300 },
    );
  });

  it("never moves the count: no value of JSON given as a record or as a proof", () => {
    fc.assert(
      fc.property(fc.jsonValue(), fc.jsonValue(), (record, proof) => {
        expect(
          moved(() => {
            verifyProof(record, proof);
            verifyProofs(record);
            recordRefMatches(reference, record);
          }),
        ).toBe(0);
      }),
      { numRuns: 200 },
    );
  });
});

describe(`${clause("core 4.4")} a judge of this package, where a check is cut short`, () => {
  const intent = named("intent");
  const [proof] = intent["proof"] as [object];

  it("refuses for want of room: `verifyProof` does not call the proof unreadable", () => {
    expect(verifyProof(failing(overflow()), proof)).toStrictEqual(SPENT);
    expect(verifyProof(intent, failing(overflow()))).toStrictEqual(SPENT);
    // A value that throws anything else cannot be read as plain data, and that is said.
    expect(verifyProof(failing(new Error("no")), proof)).toMatchObject({
      ok: false,
      issues: [{ clause: "core 1.2" }],
    });
  });

  it("judges no proof: `verifyProofs` does not list one as rejected", () => {
    expect(verifyProofs(failing(overflow()))).toStrictEqual({
      verified: [],
      rejected: [],
      issues: SPENT.issues,
    });
    expect(verifyProofs(failing(new Error("no"))).issues).toMatchObject([{ clause: "core 1.2" }]);
  });

  it("refuses for want of room: the readers, for options that could not be read", () => {
    const text = JSON.stringify(intent);
    for (const read of [parseJson, parseRecord, parseExtensionRecord]) {
      expect(read(text, failing(overflow()) as never), read.name).toStrictEqual(SPENT);
    }
    expect(
      parseJsonBytes(new TextEncoder().encode(text), failing(overflow()) as never),
    ).toStrictEqual(SPENT);
    expect(parseJson(text).ok).toBe(true);
  });

  it("notes it, where the answer is one that cannot say why", () => {
    // A check of a signature, a content ID and the critical extensions answer with no reason:
    // a caller that keeps what they answer reads the count.
    expect(
      moved(() => expect(verifyEd25519(failing(overflow()) as never, message, key)).toBe(false)),
    ).toBe(1);
    expect(moved(() => expect(isEd25519PublicKey(failing(overflow()) as never)).toBe(false))).toBe(
      1,
    );
    expect(moved(() => expect(recordRefMatches(reference, failing(overflow()))).toBe(false))).toBe(
      1,
    );
    expect(moved(() => unsupportedCritical(failing(overflow()) as never))).toBe(1);
    // And notes nothing for a value that fails otherwise.
    expect(moved(() => verifyEd25519(failing(new Error("no")) as never, message, key))).toBe(0);
    expect(moved(() => recordRefMatches(reference, failing(new Error("no"))))).toBe(0);
    expect(moved(() => unsupportedCritical(failing(new Error("no")) as never))).toBe(0);
  });

  it("answers, and does not throw, for a value that throws what cannot be looked at", () => {
    const sly = new Error("plain");
    Object.defineProperty(sly, "name", {
      get: () => {
        // Not an error, and not a thing that can be looked at.
        throw revoked() as Error;
      },
    });
    for (const thrown of [revoked(), sly, failing(new Error("deeper"))]) {
      const value = failing(thrown);
      expect(verifyProof(value, proof).ok).toBe(false);
      expect(verifyProofs(value).verified).toStrictEqual([]);
      expect(recordRefMatches(reference, value)).toBe(false);
      expect(verifyEd25519(value as never, message, key)).toBe(false);
      expect(parseJson("{}", value as never).ok).toBe(false);
    }
    // The value itself may be one that cannot be looked at.
    expect(verifyProof(revoked(), proof).ok).toBe(false);
    expect(verifyEd25519(revoked() as never, message, key)).toBe(false);
  });

  it("is noted from inside the work: a refusal built on it is refused", () => {
    // As an evidence view or a member's log would note it, in the packages above.
    const noting = new Proxy(intent, {
      ownKeys: (target) => {
        noteCutShort(overflow());
        return Reflect.ownKeys(target);
      },
    });
    expect(verifyProof(noting, proof)).toStrictEqual(SPENT);
    expect(verifyProofs(noting).issues).toStrictEqual(SPENT.issues);
    expect(verifyProof(intent, proof).ok).toBe(true);
  });
});

describe(`${clause("core 4.4")} the first signature a process checks, near the end of the call stack`, () => {
  /** The answers at each depth of a range, each asked of a process of its own, and the depths that gave them. */
  function answersAt(depths: readonly number[], ...mode: string[]): Map<string, number[]> {
    const answers = new Map<string, number[]>();
    for (const frames of depths) {
      const report = inNode(new URL("./first-verify.node.ts", import.meta.url), [
        String(frames),
        ...mode,
      ]) as {
        readonly remembered: boolean;
        readonly answer: string;
        readonly where: string;
        readonly afterwards: boolean;
      };
      // The run asked what it was meant to: of a key the process had checked before, or not.
      expect(report.remembered).toBe(!mode.includes("cold"));
      // A check that throws could not be entered: the failure is the caller's call, not its own.
      const answer =
        report.answer === "threw" && !report.where.startsWith("at descend")
          ? `threw from inside: ${report.where}`
          : report.answer;
      answers.set(answer, [...(answers.get(answer) ?? []), frames]);
      expect(report.afterwards).toBe(true);
    }
    return answers;
  }

  const DEPTHS = Array.from({ length: 31 }, (_, n) => 290 + n);

  /** Nothing but: a throw before the check began, a no that was noted, or a yes. */
  function expectNoSilentNo(answers: Map<string, number[]>): void {
    expect([...answers.keys()].sort()).toStrictEqual([
      "false, noted",
      "threw",
      "true, nothing noted",
    ]);
    // The depths asked reach from where the check cannot be entered to where it has room: the
    // depths at which a `catch` meets the end of the stack are among them.
    expect(Math.min(...(answers.get("true, nothing noted") ?? []))).toBeGreaterThan(
      Math.max(...(answers.get("threw") ?? [])),
    );
  }

  it("is never called invalid for want of room without that being noted", () => {
    // The library answers `false` from a `catch` of its own for whatever is thrown while it
    // decodes the key and R and multiplies the base point, a spent stack included. Each depth
    // is asked of a process of its own, where the code is cold and the frames at their largest.
    expectNoSilentNo(answersAt(DEPTHS));
  });

  it("is never called invalid so by the check of its key's order either", () => {
    // The key is one the process has not checked before, so the first thing to find no room
    // is the check that its point has order L, which this package makes itself.
    expectNoSilentNo(answersAt(DEPTHS, "cold"));
  });

  it("is never called invalid so by code that has verified often, whose frames are other sizes", () => {
    // The steps the library guards are taken again from deeper than the library took them.
    // Taken from no deeper, they find room where the library found none: this is where that
    // shows, at one depth in some hundreds. Each depth is asked below frames of another
    // size as well, so that the depths asked lie closer together than one frame.
    const report = inNode(new URL("./warm-verify.node.ts", import.meta.url)) as {
      readonly answers: Readonly<Record<string, number>>;
      readonly silent: readonly string[];
      readonly afterwards: boolean;
    };
    expect(report.silent).toStrictEqual([]);
    expect(Object.keys(report.answers).sort()).toStrictEqual([
      "false, noted",
      "threw",
      "true, nothing noted",
    ]);
    expect(report.afterwards).toBe(true);
  });
});

describe(`${clause("core 4.4")} a spent stack inside what this package calls`, () => {
  // The engine is given bytes, which cannot be made to throw. A spy stands in for the call
  // that found no room. The library's own calls cannot be replaced, and are asked with the
  // stack really spent (below).
  afterEach(() => {
    vi.restoreAllMocks();
  });

  const spent = (): never => {
    throw overflow();
  };

  it("is refused by the reader of bytes, which does not call them text that is not UTF-8", () => {
    const bytes = new TextEncoder().encode(JSON.stringify(named("intent")));
    vi.spyOn(TextDecoder.prototype, "decode").mockImplementationOnce(spent);
    expect(parseJsonBytes(bytes)).toStrictEqual(SPENT);
    expect(parseJsonBytes(bytes).ok).toBe(true);
    // Bytes that are not UTF-8 are refused as that.
    let answer: ReturnType<typeof parseJsonBytes> | undefined;
    expect(
      moved(() => {
        answer = parseJsonBytes(Uint8Array.of(0x22, 0xff, 0x22));
      }),
    ).toBe(0);
    expect(answer).toMatchObject({ ok: false, issues: [{ clause: "core 1.1" }] });
  });

  it("is refused by the reader of a key, which does not call it a key no signature counts by", () => {
    const multikey = encodeEd25519Multikey(key);
    // The check of the key's order looks first at the keys it remembers.
    vi.spyOn(BoundedCache.prototype, "has").mockImplementationOnce(spent);
    expect(decodeEd25519Multikey(multikey)).toStrictEqual(SPENT);
    expect(decodeEd25519Multikey(multikey)).toStrictEqual({ ok: true, value: key });
    // The question with a yes or a no for an answer gives the no, and notes it.
    vi.spyOn(BoundedCache.prototype, "has").mockImplementationOnce(spent);
    expect(moved(() => expect(isEd25519Multikey(multikey)).toBe(false))).toBe(1);
    expect(isEd25519Multikey(multikey)).toBe(true);
    // A key of small order is refused as that: the encoding of the identity point, here.
    const small = `z${base58.encode(Uint8Array.of(0xed, 0x01, 1, ...new Uint8Array(31)))}`;
    let answer: ReturnType<typeof decodeEd25519Multikey> | undefined;
    expect(
      moved(() => {
        answer = decodeEd25519Multikey(small);
      }),
    ).toBe(0);
    expect(answer).toMatchObject({ ok: false, issues: [{ clause: "core 4.4" }] });
  });

  it("is refused by the reader of an agreement key, which does not throw", () => {
    const bytes = new Uint8Array(32).fill(9);
    const multikey = encodeX25519Multikey(bytes);
    // The form of the string is looked at first.
    vi.spyOn(RegExp.prototype, "test").mockImplementationOnce(spent);
    expect(decodeX25519Multikey(multikey)).toStrictEqual(SPENT);
    expect(decodeX25519Multikey(multikey)).toStrictEqual({ ok: true, value: bytes });
  });
});

describe("a process that can serialise nothing", () => {
  /** What `work` answers while every object has a `toJSON`, as other code in a process may leave it. */
  function unfit<T>(work: () => T): T {
    Object.defineProperty(Object.prototype, "toJSON", {
      value: () => "all the same",
      configurable: true,
      writable: true,
    });
    try {
      return work();
    } finally {
      delete (Object.prototype as { toJSON?: unknown }).toJSON;
    }
  }

  it("is noted where the answer cannot say why", () => {
    const intent = named("intent");
    const text = JSON.stringify(intent);
    // No content ID can be worked out, so nothing matches.
    const matched = unfit(() => {
      const before = cutShortCount();
      const matches = recordRefMatches(reference, intent);
      return { matches, noted: cutShortCount() - before };
    });
    expect(matched).toStrictEqual({ matches: false, noted: 1 });
    // Reading serialises nothing, and is as it was: a record's size is counted, not written.
    const read = unfit(() => [parseRecord(text), parseJson(text)]);
    expect(read.map((one) => one.ok)).toStrictEqual([true, true]);
    expect(recordRefMatches(reference, intent)).toBe(true);
  });
});
