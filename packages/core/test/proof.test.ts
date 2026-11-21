// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";

import { CUT_SHORT, type Proof, UNSIGNED_RECORD_TYPES } from "@oip/schema";
import { clause, copy, type JsonObject } from "@oip/testkit";
import { base58 } from "@scure/base";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  bytesToHex,
  canonicalBytes,
  canonicalize,
  contentId,
  createProof,
  createProofSync,
  documentHash,
  formatControlKeyRef,
  MAX_PROOFS,
  MAX_RECORD_BYTES,
  OipError,
  parseJson,
  parseTimestamp,
  proofDigest,
  proofHashData,
  type ProofOptions,
  purposeFor,
  recordRefMatches,
  signEd25519,
  type Signer,
  signerFromPrivateKey,
  type SyncSigner,
  type Validation,
  verifyProof,
  verifyProofs,
  withProofs,
} from "../src/index.ts";
import { contentIdIfAny } from "../src/content-id.ts";
import { craftSignature, expand, Point, smallOrderPoints, unreduced } from "./curve.ts";
import { at, keys, log, named, negative, privateKeyOf, signedRecords } from "./vectors.ts";

type AnyProof = Record<string, unknown>;

const intent = named("intent");
const intentProof = (intent["proof"] as AnyProof[])[0]!;
const genesis = at(log("amina_log"));
const hello = named("hello");
const session = named("session");

/** The key that signed the Intent of the vectors, and a signer for it. */
const phoneMethod = intentProof["verificationMethod"] as string;
const phone = phoneMethod.split("#")[1] ?? "";
const phoneKey = privateKeyOf(phone);
const phoneSigner = signerFromPrivateKey(phoneKey);
/** Another test key, which did not sign it. */
const laptop = signerFromPrivateKey(
  privateKeyOf(
    Object.values(keys).find((key) => key.type !== "X25519" && key.multikey !== phone)?.multikey ??
      "",
  ),
);
const laptopMethod = phoneMethod.replace(phone, laptop.publicKey);

/** When the Intent's own proof was made, and a later time. Neither is before the Intent's `created`. */
const WHEN = intentProof["created"] as string;
const LATER = "2026-10-31T00:00:00Z";

const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest();

/** A proof with exactly the options given and an honest signature over them, valid or not. */
function handSigned(record: unknown, options: AnyProof, privateKey = phoneKey): AnyProof {
  const signature = signEd25519(proofHashData(record, options), privateKey);
  return { ...options, proofValue: `z${base58.encode(signature)}` };
}

const baseOptions = (record: JsonObject, method = phoneMethod): AnyProof => ({
  type: "DataIntegrityProof",
  cryptosuite: "eddsa-jcs-2022",
  verificationMethod: method,
  proofPurpose: purposeFor(record["type"] as string),
  created: WHEN,
});

/** What a function throws, or `undefined` if it returns. */
function thrownBy(run: () => unknown): unknown {
  try {
    run();
  } catch (error) {
    return error;
  }
  return undefined;
}

/**
 * What `verifyProofs` found, entry by entry: "accepted", or the clause of the
 * entry's rejection. If no proof was judged at all, the clause of the reason.
 */
function verdictsOf(record: unknown): string[] | string {
  const { verified, rejected, issues } = verifyProofs(record);
  if (issues[0] !== undefined) return `not judged: ${issues[0].clause}`;
  const verdicts: string[] = [];
  for (const proof of verified) verdicts[proof.index] = "accepted";
  for (const entry of rejected) verdicts[entry.index] = entry.issues[0].clause;
  return verdicts;
}

function issueOf(result: Validation<unknown>) {
  if (result.ok) throw new Error("accepted");
  return result.issues[0];
}

const clauseOf = (result: Validation<unknown>) =>
  result.ok ? "accepted" : result.issues[0].clause;

describe(`${clause("core 5.6")} proof purposes`, () => {
  it("gives every record type the purpose of the table", () => {
    for (const type of ["Genesis", "Update", "Fork", "Merge", "Retire"]) {
      expect(purposeFor(type), type).toBe("capabilityInvocation");
    }
    expect(purposeFor("Delegation")).toBe("capabilityDelegation");
    expect(purposeFor("Hello")).toBe("authentication");
    for (const type of [
      "Revocation",
      "Lineage",
      "Collective",
      "Intent",
      "Offer",
      "Commitment",
      "Receipt",
      "Packet",
      "Entry",
      "Checkpoint",
      "Ack",
      "QueryResult",
      "Forwarded",
      "Location",
      "Participant",
      "com.example.Unknown",
      "genesis",
      "",
    ]) {
      expect(purposeFor(type), type).toBe("assertionMethod");
    }
  });

  it("agrees with every proof in the vectors", () => {
    for (const { name, record } of signedRecords) {
      for (const proof of record["proof"] as AnyProof[]) {
        expect(proof["proofPurpose"], name).toBe(purposeFor(record["type"] as string));
      }
    }
  });

  it("does not count a proof with any other purpose, however valid its signature", () => {
    const purposes = [
      "capabilityInvocation",
      "capabilityDelegation",
      "authentication",
      "assertionMethod",
    ];
    for (const record of [intent, genesis, named("delegation"), hello]) {
      const key = privateKeyOf(
        ((record["proof"] as AnyProof[])[0]?.["verificationMethod"] as string).split("#")[1] ?? "",
      );
      const method = (record["proof"] as AnyProof[])[0]?.["verificationMethod"] as string;
      for (const proofPurpose of purposes) {
        const proof = handSigned(record, { ...baseOptions(record, method), proofPurpose }, key);
        const right = proofPurpose === purposeFor(record["type"] as string);
        expect(
          clauseOf(verifyProof(record, proof)),
          `${String(record["type"])} ${proofPurpose}`,
        ).toBe(right ? "accepted" : "core 5.6");
      }
    }
    // A type name from the input is quoted only up to a length.
    const longType = { ...intent, type: "T".repeat(5000) };
    const onLong = handSigned(longType, {
      ...baseOptions(longType),
      proofPurpose: "authentication",
    });
    expect(issueOf(verifyProof(longType, onLong)).message).toBe(
      `a record of type "${"T".repeat(64)}…" needs a proof with the purpose assertionMethod; this proof's purpose is authentication`,
    );
    // And it is quoted, so that it cannot pass for part of the message or break a log line.
    const odd = { ...intent, type: 'X" is valid.\nINFO a "' };
    const onOdd = handSigned(odd, { ...baseOptions(odd), proofPurpose: "authentication" });
    expect(issueOf(verifyProof(odd, onOdd)).message).toBe(
      String.raw`a record of type "X\" is valid.\nINFO a \"" needs a proof with the purpose assertionMethod; this proof's purpose is authentication`,
    );
    const wrong = handSigned(intent, { ...baseOptions(intent), proofPurpose: "authentication" });
    expect(issueOf(verifyProof(intent, wrong))).toEqual({
      path: "/proofPurpose",
      message:
        'a record of type "Intent" needs a proof with the purpose assertionMethod; this proof\'s purpose is authentication',
      clause: "core 5.6",
    });
  });

  it("rejects the wrong-purpose case of the vectors", () => {
    const record = negative("wrong-proof-purpose")["record"] as JsonObject;
    expect(verdictsOf(record)).toEqual(["core 5.6"]);
    expect(verifyProofs(record).verified).toEqual([]);
  });
});

describe(`${clause("core 5.3")} creating a proof`, () => {
  it("reproduces every proofValue in the vectors from its test key", async () => {
    let reproduced = 0;
    for (const { name, record } of signedRecords) {
      for (const proof of record["proof"] as (Proof & AnyProof)[]) {
        const key = proof.verificationMethod.split("#")[1] ?? "";
        const options: ProofOptions = {
          verificationMethod: proof.verificationMethod,
          created: proof.created,
          ...(proof.challenge === undefined ? {} : { challenge: proof.challenge }),
          ...(proof.domain === undefined ? {} : { domain: proof.domain }),
          ...(proof.authority === undefined ? {} : { authority: proof.authority }),
        };
        const created = await createProof(record, options, signerFromPrivateKey(privateKeyOf(key)));
        expect(created, name).toEqual(proof);
        expect(JSON.stringify(created), name).toBe(JSON.stringify(proof));
        reproduced++;
      }
    }
    expect(reproduced).toBe(58);
  });

  it("signs SHA-256(JCS(options)) followed by SHA-256(JCS(record without proof))", () => {
    const { proofValue: _proofValue, ...options } = intentProof;
    const { proof: _proof, ...content } = intent;
    const expected = Buffer.concat([
      sha256(canonicalBytes(options)),
      sha256(canonicalBytes(content)),
    ]);
    expect(bytesToHex(proofHashData(intent, options))).toBe(expected.toString("hex"));
    expect(proofHashData(intent, options)).toHaveLength(64);
    const signature = signEd25519(proofHashData(intent, options), phoneKey);
    expect(`z${base58.encode(signature)}`).toBe(intentProof["proofValue"]);
  });

  it("covers the record without proof, so proofs are made in any order and merged by union", async () => {
    const { proof: _proof, ...unsigned } = intent;
    const first = await createProof(
      unsigned,
      { verificationMethod: phoneMethod, created: WHEN },
      phoneSigner,
    );
    const second = await createProof(
      unsigned,
      { verificationMethod: laptopMethod, created: LATER },
      laptop,
    );
    // The second signer signs the record with or without the first proof on it: the same proof.
    const afterFirst = await createProof(
      withProofs(unsigned, [first]),
      { verificationMethod: laptopMethod, created: LATER },
      laptop,
    );
    expect(afterFirst).toEqual(second);
    for (const order of [
      [first, second],
      [second, first],
    ]) {
      const signed = withProofs(unsigned, order);
      expect(verdictsOf(signed)).toEqual(["accepted", "accepted"]);
      expect(contentId(signed)).toBe(contentId(unsigned));
    }
  });

  it("covers everything in the options, including authority", () => {
    const record = named("commitment_agents");
    const proof = (record["proof"] as (Proof & AnyProof)[]).find(
      (item) => item.authority !== undefined,
    );
    expect(proof).toBeDefined();
    expect(verifyProof(record, proof).ok).toBe(true);
    const options = ["verificationMethod", "proofPurpose", "created", "authority"] as const;
    for (const member of options) {
      const changed = copy(proof) as AnyProof;
      if (member === "authority") (changed["authority"] as unknown[]).reverse().push("extra");
      else if (member === "created") changed["created"] = "2026-10-30T09:59:59Z";
      else if (member === "proofPurpose") changed["proofPurpose"] = "authentication";
      else
        changed["verificationMethod"] = String(changed["verificationMethod"]).replace(
          "versionId=1",
          "versionId=2",
        );
      expect(verifyProof(record, changed).ok, member).toBe(false);
    }
    const without = copy(proof) as AnyProof;
    delete without["authority"];
    expect(clauseOf(verifyProof(record, without))).toBe("core 4.4");
  });

  it("derives the purpose from the record's type and copies @context from the record", async () => {
    const withContext = {
      ...intent,
      "@context": ["https://www.w3.org/ns/credentials/v2", { a: 1 }],
    };
    const proof = await createProof(
      withContext,
      { verificationMethod: phoneMethod, created: WHEN },
      phoneSigner,
    );
    expect(Object.keys(proof)).toEqual([
      "type",
      "cryptosuite",
      "verificationMethod",
      "proofPurpose",
      "created",
      "@context",
      "proofValue",
    ]);
    expect(proof["@context"]).toEqual(withContext["@context"]);
    expect(proof.proofPurpose).toBe("assertionMethod");
    expect(verifyProof(withContext, proof).ok).toBe(true);
    const plain = await createProof(
      intent,
      { verificationMethod: phoneMethod, created: WHEN },
      phoneSigner,
    );
    expect(Object.hasOwn(plain, "@context")).toBe(false);
    const forGenesis = await createProof(
      genesis,
      { verificationMethod: formatControlKeyRef(phone), created: "2026-10-30T09:00:00Z" },
      phoneSigner,
    );
    expect(forGenesis.proofPurpose).toBe("capabilityInvocation");
    const forHello = await createProof(
      hello,
      {
        verificationMethod: phoneMethod,
        created: "2026-10-30T10:06:00Z",
        challenge: "c",
        domain: "d",
      },
      phoneSigner,
    );
    expect(forHello).toMatchObject({ proofPurpose: "authentication", challenge: "c", domain: "d" });
    expect(verifyProof(hello, forHello).ok).toBe(true);
  });

  it("does not change the record it signs", async () => {
    const frozen = Object.freeze(copy(intent));
    const before = JSON.stringify(frozen);
    await createProof(frozen, { verificationMethod: phoneMethod, created: WHEN }, phoneSigner);
    expect(JSON.stringify(frozen)).toBe(before);
  });

  it("works with a signer that answers later", async () => {
    const remote: Signer = {
      publicKey: phone,
      sign: (message) =>
        new Promise((resolve) =>
          setTimeout(() => {
            resolve(signEd25519(message, phoneKey));
          }, 1),
        ),
    };
    const proof = await createProof(
      intent,
      { verificationMethod: phoneMethod, created: intentProof["created"] as string },
      remote,
    );
    expect(proof).toEqual(intentProof);
  });

  it("refuses to make a proof that would not verify, and says why", async () => {
    const options = { verificationMethod: phoneMethod, created: WHEN };
    const failure = async (run: Promise<unknown>) => {
      try {
        await run;
      } catch (error) {
        expect(error).toBeInstanceOf(OipError);
        return error as OipError;
      }
      throw new Error("a proof was created");
    };
    // The verification method names another key.
    const other = await failure(
      createProof(intent, { ...options, verificationMethod: laptopMethod }, phoneSigner),
    );
    expect([other.code, other.clause]).toEqual(["invalid-proof", "core 6.2"]);
    expect(other.detail).toBe(
      "the verification method must be a key reference that names the signer's own key",
    );
    const notRef = await failure(
      createProof(intent, { ...options, verificationMethod: phone }, phoneSigner),
    );
    expect(notRef.clause).toBe("core 6.2");
    // Options that 5.2 does not allow.
    const badTime = await failure(
      createProof(intent, { ...options, created: "2026-02-30T00:00:00Z" }, phoneSigner),
    );
    expect([badTime.code, badTime.clause]).toEqual(["invalid-proof", "core 1.4"]);
    const challenge = await failure(
      createProof(intent, { ...options, challenge: "x" }, phoneSigner),
    );
    expect(challenge.code).toBe("invalid-proof");
    const emptyAuthority = await failure(
      createProof(intent, { ...options, authority: [] }, phoneSigner),
    );
    expect(emptyAuthority.clause).toBe("core 5.2");
    const longAuthority = await failure(
      createProof(
        intent,
        { ...options, authority: Array.from({ length: 9 }, () => "x") },
        phoneSigner,
      ),
    );
    expect(longAuthority.clause).toBe("core 5.2");
    // A record that is not one.
    for (const bad of [null, [], "text", { type: 1 }, {}, { type: "Intent", a: 0.5 }]) {
      const error = await failure(createProof(bad, options, phoneSigner));
      expect(error.code).toBe("invalid-record");
    }
    expect(await failure(createProof({}, options, phoneSigner))).toMatchObject({
      clause: "core 7",
      detail: "type must name a record type",
    });
    expect((await failure(createProof([], options, phoneSigner))).detail).toBe(
      "a record is a JSON object",
    );
    // An unsigned type carries no proof.
    const unsigned = await failure(createProof(session, options, phoneSigner));
    expect([unsigned.code, unsigned.clause]).toEqual(["invalid-proof", "core 5.1"]);
  });

  it("does not take a signer with no key for the signer a reference names", () => {
    // A reference that names no key and a signer that has none must not pass as a match.
    let asked = 0;
    const keyless = {
      publicKey: undefined as unknown as string,
      sign: (message: Uint8Array) => {
        asked++;
        return signEd25519(message, phoneKey);
      },
    };
    for (const verificationMethod of ["not a reference", "", phone, `${phoneMethod}x y`]) {
      expect(
        thrownBy(() => createProofSync(intent, { verificationMethod, created: WHEN }, keyless)),
        verificationMethod,
      ).toMatchObject({
        code: "invalid-proof",
        clause: "core 6.2",
        detail: "the verification method must be a key reference that names the signer's own key",
      });
    }
    expect(asked).toBe(0);
  });

  it("never asks the signer to sign options that are not a proof's", async () => {
    let asked = 0;
    const counting: Signer = {
      publicKey: phone,
      sign: (message) => {
        asked++;
        return signEd25519(message, phoneKey);
      },
    };
    await expect(
      createProof(intent, { verificationMethod: phoneMethod, created: "not a time" }, counting),
    ).rejects.toThrow(OipError);
    await expect(
      createProof(
        intent,
        { verificationMethod: phoneMethod, created: WHEN, domain: "d" },
        counting,
      ),
    ).rejects.toThrow(OipError);
    expect(asked).toBe(0);
    await createProof(intent, { verificationMethod: phoneMethod, created: WHEN }, counting);
    expect(asked).toBe(1);
  });

  it("never asks the signer to sign a record that is not well formed", async () => {
    let asked = 0;
    const counting: SyncSigner = {
      publicKey: phone,
      sign: (message) => {
        asked++;
        return signEd25519(message, phoneKey);
      },
    };
    const options = { verificationMethod: phoneMethod, created: LATER };
    const { want: _want, ...withoutWant } = intent;
    const { proof: _proof, ...unsigned } = intent;
    const padded = (blob: string) => ({
      ...unsigned,
      ext: { "com.example.padding": { blob } },
      proof: [],
    });
    const full = Array.from({ length: MAX_PROOFS }, (_, i) => ({
      ...intentProof,
      created: `2026-10-30T10:00:00.${String(i).padStart(3, "0")}Z`,
    }));
    const malformed: [what: string, record: unknown, code: string][] = [
      ["a required member is missing", withoutWant, "invalid-record"],
      ["created is not a timestamp", { ...intent, created: "yesterday" }, "invalid-record"],
      [
        "the author is not an address",
        { ...intent, author: "did:web:example.com" },
        "invalid-record",
      ],
      ["oip is not 1", { ...intent, oip: "2" }, "invalid-record"],
      [
        "a critical extension is not in ext",
        { ...intent, critical: ["com.example"] },
        "invalid-record",
      ],
      [
        "a type nobody defined, with no critical",
        { ...intent, type: "com.example.Thing" },
        "invalid-record",
      ],
      ["an entry of proof is not an object", { ...intent, proof: ["junk"] }, "invalid-record"],
      ["no place is left for another proof", { ...intent, proof: full }, "invalid-record"],
      ["a number with a fraction", { ...intent, extra: 0.5 }, "invalid-record"],
      [
        "a member longer than its type allows",
        { ...intent, want: "w".repeat(70_000) },
        "invalid-record",
      ],
      ["a record over the size limit", padded("w".repeat(MAX_RECORD_BYTES)), "too-large"],
    ];
    for (const [what, record, code] of malformed) {
      await expect(createProof(record, options, counting), what).rejects.toMatchObject({ code });
      expect(
        thrownBy(() => createProofSync(record, options, counting)),
        what,
      ).toMatchObject({
        code,
      });
    }
    // The size is judged with the new proof on the record: a record that fits only without it is refused.
    const room = MAX_RECORD_BYTES - canonicalBytes(padded("")).length;
    const exact = padded("w".repeat(room));
    expect(canonicalBytes(exact)).toHaveLength(MAX_RECORD_BYTES);
    await expect(createProof(exact, options, counting)).rejects.toMatchObject({
      code: "too-large",
      clause: "core 1.6",
    });
    expect(asked).toBe(0);
    // A well-formed record of an extension type is signed.
    const extension = {
      oip: "1",
      type: "com.example.Thing",
      created: WHEN,
      ext: { "com.example": {} },
      critical: ["com.example"],
    };
    expect(verifyProof(extension, await createProof(extension, options, counting)).ok).toBe(true);
    expect(asked).toBe(1);
  });

  it("does not ask the signer to sign a record of an unsigned type", async () => {
    let asked = 0;
    const counting: Signer = {
      publicKey: phone,
      sign: (message) => {
        asked++;
        return signEd25519(message, phoneKey);
      },
    };
    for (const type of ["Session", "Bundle", "Sealed"]) {
      await expect(
        createProof(
          { ...session, type },
          { verificationMethod: phoneMethod, created: LATER },
          counting,
        ),
      ).rejects.toMatchObject({
        code: "invalid-proof",
        clause: "core 5.1",
        detail: `a ${type} record is unsigned: it carries no proof`,
      });
    }
    expect(asked).toBe(0);
  });

  it("creates the same proof at once, for a signer that answers at once", async () => {
    const options = { verificationMethod: phoneMethod, created: WHEN };
    const proof = createProofSync(intent, options, phoneSigner);
    expect(proof).toEqual(intentProof);
    expect(proof).toEqual(await createProof(intent, options, phoneSigner));
    expect(() => createProofSync(intent, { ...options, created: "never" }, phoneSigner)).toThrow(
      OipError,
    );
    expect(() => createProofSync(session, options, phoneSigner)).toThrow(
      "a Session record is unsigned: it carries no proof",
    );
    // A signer that answers later is not one that answers at once.
    const later = {
      publicKey: phone,
      sign: (message: Uint8Array) => Promise.resolve(signEd25519(message, phoneKey)),
    };
    expect(() => createProofSync(intent, options, later as never)).toThrow(
      "the signer did not return a signature of 64 bytes",
    );
  });

  it("catches a faulty signer before anyone else does", async () => {
    const options = { verificationMethod: phoneMethod, created: WHEN };
    const faulty = (sign: Signer["sign"]): Signer => ({ publicKey: phone, sign });
    const cases: [string, Signer["sign"], string][] = [
      ["too short", () => new Uint8Array(63), "core 5.2"],
      ["too long", () => new Uint8Array(65), "core 5.2"],
      ["not bytes", () => "signature" as unknown as Uint8Array, "core 5.2"],
      ["an array", () => Array.from({ length: 64 }, () => 0) as unknown as Uint8Array, "core 5.2"],
      [
        "signs with another key",
        (message) => signEd25519(message, privateKeyOf(laptop.publicKey)),
        "core 4.4",
      ],
      ["signs another message", () => signEd25519(new Uint8Array(64), phoneKey), "core 4.4"],
      [
        "a signature with S not reduced",
        (message) => unreduced(signEd25519(message, phoneKey)),
        "core 4.4",
      ],
      ["zeros", () => new Uint8Array(64), "core 4.4"],
    ];
    for (const [name, sign, expected] of cases) {
      const run = createProof(intent, options, faulty(sign));
      await expect(run, name).rejects.toMatchObject({ code: "invalid-proof", clause: expected });
      if (expected === "core 5.2") {
        await expect(createProof(intent, options, faulty(sign)), name).rejects.toThrow(
          "the signer did not return a signature of 64 bytes",
        );
      }
    }
    expect(
      await createProof(
        intent,
        options,
        faulty((message) => signEd25519(message, phoneKey)),
      ),
    ).toMatchObject({ proofPurpose: "assertionMethod" });
  });

  it("refuses options that already hold a proofValue", () => {
    expect(() => proofHashData(intent, intentProof)).toThrow(OipError);
    expect(() => proofHashData(intent, intentProof)).toThrow(
      "the options of a proof do not include proofValue",
    );
    expect(thrownBy(() => proofHashData(intent, intentProof))).toMatchObject({
      code: "invalid-proof",
      clause: "core 5.3",
    });
    for (const bad of [null, [], "x", { a: 0.1 }]) {
      expect(() => proofHashData(intent, bad)).toThrow(OipError);
      expect(() => proofHashData(bad, {})).toThrow(OipError);
    }
    expect(() => proofHashData(intent, [])).toThrow("a proof's options is a JSON object");
    expect(() => proofHashData([], {})).toThrow("a record is a JSON object");
  });
});

describe(`${clause("core 5.7")} a proof is not dated before its record`, () => {
  const created = intent["created"] as string;
  const before = "2026-10-30T09:59:59.999999999Z";

  it("holds for every proof in the vectors", () => {
    let compared = 0;
    for (const { name, record } of signedRecords) {
      const recordCreated = parseTimestamp(record["created"]);
      if (recordCreated === undefined) continue;
      for (const proof of record["proof"] as AnyProof[]) {
        const proofCreated = parseTimestamp(proof["created"]);
        expect(proofCreated, name).toBeDefined();
        // Instants are compared, never the strings (core 1.4).
        expect(proofCreated! >= recordCreated, name).toBe(true);
        compared++;
      }
    }
    expect(compared).toBeGreaterThan(40);
  });

  it("is followed when a proof is created", async () => {
    expect(created).toBe("2026-10-30T10:00:00Z");
    await expect(
      createProof(intent, { verificationMethod: phoneMethod, created: before }, phoneSigner),
    ).rejects.toMatchObject({
      code: "invalid-proof",
      clause: "core 5.7",
      detail:
        "a proof's created should not be earlier than its record's created: sign with the later of the two times, or set earlierThanRecord",
    });
    expect(() =>
      createProofSync(intent, { verificationMethod: phoneMethod, created: before }, phoneSigner),
    ).toThrow(OipError);
    // The same instant, and any later one, are fine. Instants are compared, not strings.
    for (const when of [
      created,
      "2026-10-30T10:00:00.000Z",
      "2026-10-30T10:00:00.000000001Z",
      LATER,
    ]) {
      const proof = createProofSync(
        intent,
        { verificationMethod: phoneMethod, created: when },
        phoneSigner,
      );
      expect(proof.created, when).toBe(when);
    }
  });

  it("is advice to signers, not a rule for verifiers: an earlier proof still verifies", () => {
    const early = handSigned(intent, { ...baseOptions(intent), created: before });
    expect(verifyProof(intent, early).ok).toBe(true);
  });

  it("gives way when the signer says the earlier time is meant", () => {
    // core 5.7 is a SHOULD: a signer that has a reason may date a proof earlier.
    const proof = createProofSync(
      intent,
      { verificationMethod: phoneMethod, created: before, earlierThanRecord: true },
      phoneSigner,
    );
    expect(proof.created).toBe(before);
    expect(verifyProof(intent, proof).ok).toBe(true);
    // Only the value true says so.
    for (const other of [false, undefined, 1, "true"]) {
      expect(() =>
        createProofSync(
          intent,
          {
            verificationMethod: phoneMethod,
            created: before,
            earlierThanRecord: other as boolean,
          },
          phoneSigner,
        ),
      ).toThrow("or set earlierThanRecord");
    }
  });

  it("applies to every record that is signed: none is without created", () => {
    // core 7 requires created in every record but the containers and Sealed, which
    // are not signed. A record without it, or with one that is no time, is malformed,
    // and nothing is signed.
    const undated = {
      oip: "1",
      type: "com.example.Note",
      author: intent["author"],
      ext: { "com.example": { text: "a note" } },
      critical: ["com.example"],
    };
    const options = { verificationMethod: phoneMethod, created: "2020-01-01T00:00:00Z" };
    expect(thrownBy(() => createProofSync(undated, options, phoneSigner))).toMatchObject({
      code: "invalid-record",
    });
    const odd = { ...intent, created: "not a time" };
    expect(thrownBy(() => createProofSync(odd, options, phoneSigner))).toMatchObject({
      code: "invalid-record",
    });
    // With created, a record of a type an extension defines is signed like any other.
    const dated = { ...undated, created: "2020-01-01T00:00:00Z" };
    const proof = createProofSync(dated, options, phoneSigner);
    expect(verifyProof(dated, proof).ok).toBe(true);
    expect(
      thrownBy(() =>
        createProofSync(dated, { ...options, created: "2019-12-31T23:59:59Z" }, phoneSigner),
      ),
    ).toMatchObject({ clause: "core 5.7" });
  });

  it("reads each option once: what is checked is what is signed", () => {
    // Options that answer one thing when they are checked and another when they are used.
    const flipping = (first: Partial<ProofOptions>, later: Partial<ProofOptions>): ProofOptions => {
      const reads = new Map<string, number>();
      const base: ProofOptions = { verificationMethod: phoneMethod, created: WHEN };
      return new Proxy(base, {
        get(target, name) {
          const count = (reads.get(String(name)) ?? 0) + 1;
          reads.set(String(name), count);
          const source = count === 1 ? first : later;
          return name in source
            ? source[name as keyof ProofOptions]
            : target[name as keyof ProofOptions];
        },
      });
    };
    let asked = 0;
    const counting: SyncSigner = {
      publicKey: phone,
      sign: (message) => {
        asked++;
        return signEd25519(message, phoneKey);
      },
    };
    // A method that names the signer's key when it is checked, and another key afterwards.
    const proof = createProofSync(
      intent,
      flipping({ verificationMethod: phoneMethod }, { verificationMethod: laptopMethod }),
      counting,
    );
    expect(proof.verificationMethod).toBe(phoneMethod);
    expect(asked).toBe(1);
    // A time that is late enough when it is checked, and earlier afterwards.
    const dated = createProofSync(
      intent,
      flipping({ created: LATER }, { created: "2020-01-01T00:00:00Z" }),
      counting,
    );
    expect(dated.created).toBe(LATER);
    // And the other way about: early when checked is refused, whatever it says later.
    expect(
      thrownBy(() =>
        createProofSync(
          intent,
          flipping({ created: "2020-01-01T00:00:00Z" }, { created: LATER }),
          counting,
        ),
      ),
    ).toMatchObject({ clause: "core 5.7" });
    expect(asked).toBe(2);
  });
});

describe(`${clause("core 5.4")} verifying a proof`, () => {
  it("verifies every proof in the vectors", () => {
    let verified = 0;
    for (const { name, record } of signedRecords) {
      const verdicts = verifyProofs(record);
      const proofs = record["proof"] as unknown[];
      expect(verdicts.issues, name).toEqual([]);
      expect(verdicts.rejected, name).toEqual([]);
      expect(
        verdicts.verified.map((proof) => proof.index),
        name,
      ).toEqual(proofs.map((_, i) => i));
      for (const { index, ...proof } of verdicts.verified) {
        // The same verdict as verifying that proof on its own.
        expect(verifyProof(record, proofs[index])).toEqual({ ok: true, value: proof });
        verified++;
      }
    }
    expect(verified).toBe(58);
  });

  it("says what it verified: the key, the reference, the digest and the claimed time", () => {
    const verdict = verifyProof(intent, intentProof);
    expect(verdict).toEqual({
      ok: true,
      value: {
        proof: intentProof,
        method: {
          kind: "key",
          mind: intent["author"],
          versionId: phoneMethod.split("versionId=")[1]?.split("#")[0],
          version: {
            seq: Number(phoneMethod.split("versionId=")[1]?.split("-")[0]),
            contentId: phoneMethod.split("-")[1]?.split("#")[0],
          },
          key: phone,
        },
        key: phone,
        digest: proofDigest(intentProof),
        // 2026-10-30T10:00:00Z, in nanoseconds since 1970.
        created: 1_793_354_400_000_000_000n,
      },
    } satisfies Validation<unknown>);
    expect(intentProof["created"]).toBe("2026-10-30T10:00:00Z");
    const control = verifyProof(genesis, (genesis["proof"] as unknown[])[0]);
    expect(control.ok && control.value.method).toEqual({
      kind: "control",
      key: (genesis["controller"] as { keys: string[] }).keys[0],
    });
    expect(control.ok && control.value.key).toBe(
      (genesis["controller"] as { keys: string[] }).keys[0],
    );
  });

  it("gives the claimed time at full precision, to the nanosecond", () => {
    // Evidence rules compare instants (core 1.4): a time cut to milliseconds would
    // put a proof before a rotation it came after.
    for (const [written, instant] of [
      ["2026-10-30T10:00:00.000000001Z", 1_793_354_400_000_000_001n],
      ["2026-10-30T10:00:00.123456789Z", 1_793_354_400_123_456_789n],
      ["2026-10-30T10:00:00.999999999Z", 1_793_354_400_999_999_999n],
      ["2026-10-30T10:00:00.0001Z", 1_793_354_400_000_100_000n],
      ["2026-10-30T10:00:00.5Z", 1_793_354_400_500_000_000n],
    ] as const) {
      const proof = createProofSync(
        intent,
        { verificationMethod: phoneMethod, created: written },
        phoneSigner,
      );
      const verdict = verifyProof(intent, proof);
      expect(verdict.ok && verdict.value.created, written).toBe(instant);
      const placed = verifyProofs({ ...intent, proof: [proof] }).verified[0];
      expect(placed?.created, written).toBe(instant);
    }
  });

  it(`${clause("core 5.2")} requires exactly the members 5.2 allows`, () => {
    for (const extra of ["id", "previousProof", "nonce", "expires", "proofValue2", "ext"]) {
      const proof = handSigned(intent, { ...baseOptions(intent), [extra]: "x" });
      expect(clauseOf(verifyProof(intent, proof)), extra).toBe("core 5.2");
    }
    for (const missing of [
      "type",
      "cryptosuite",
      "verificationMethod",
      "proofPurpose",
      "created",
      "proofValue",
    ]) {
      const proof = copy(intentProof);
      delete proof[missing];
      expect(clauseOf(verifyProof(intent, proof)), missing).toBe("core 5.2");
    }
    // challenge and domain belong to authentication proofs only.
    for (const member of ["challenge", "domain"]) {
      const onIntent = handSigned(intent, { ...baseOptions(intent), [member]: "x" });
      expect(clauseOf(verifyProof(intent, onIntent)), member).toBe("core 5.2");
      const onHello = handSigned(hello, { ...baseOptions(hello), [member]: "x" });
      expect(clauseOf(verifyProof(hello, onHello)), member).toBe("accepted");
    }
  });

  it(`${clause("core 5.2")} requires the type and the cryptosuite of this revision`, () => {
    for (const [member, value] of [
      ["type", "Ed25519Signature2020"],
      ["type", "dataIntegrityProof"],
      ["cryptosuite", "eddsa-rdfc-2022"],
      ["cryptosuite", "ecdsa-jcs-2019"],
      ["cryptosuite", "eddsa-jcs-2022 "],
    ] as const) {
      const proof = handSigned(intent, { ...baseOptions(intent), [member]: value });
      expect(clauseOf(verifyProof(intent, proof)), value).toBe("core 5.2");
    }
  });

  it(`${clause("core 5.2")} requires @context on the proof exactly when the record has it, with the same value`, () => {
    const context = ["https://www.w3.org/ns/credentials/v2", { b: 1, a: [true] }];
    const withContext = { ...intent, "@context": context };
    const signedWith = (record: JsonObject, value?: unknown) =>
      handSigned(record, {
        ...baseOptions(record),
        ...(value === undefined ? {} : { "@context": value }),
      });

    expect(clauseOf(verifyProof(withContext, signedWith(withContext, context)))).toBe("accepted");
    // The same value, with its members written in another order.
    expect(
      clauseOf(
        verifyProof(withContext, signedWith(withContext, [context[0], { a: [true], b: 1 }])),
      ),
    ).toBe("accepted");
    expect(issueOf(verifyProof(withContext, signedWith(withContext)))).toEqual({
      path: "/@context",
      message: "the proof's @context must be present and equal to the record's",
      clause: "core 5.2",
    });
    for (const other of [
      [context[0]],
      [context[0], { a: [false], b: 1 }],
      "https://www.w3.org/ns/credentials/v2",
      null,
      context.toReversed(),
    ]) {
      expect(
        clauseOf(verifyProof(withContext, signedWith(withContext, other))),
        JSON.stringify(other),
      ).toBe("core 5.2");
    }
    expect(issueOf(verifyProof(intent, signedWith(intent, context)))).toEqual({
      path: "/@context",
      message: "the proof has @context but the record has none",
      clause: "core 5.2",
    });
    // A record whose @context is null still has one.
    const nullContext = { ...intent, "@context": null };
    expect(clauseOf(verifyProof(nullContext, signedWith(nullContext, null)))).toBe("accepted");
    expect(clauseOf(verifyProof(nullContext, signedWith(nullContext)))).toBe("core 5.2");
  });

  it(`${clause("core 4.3")} requires a key reference whose key is an Ed25519 key of order L: no other key signs`, () => {
    const x25519 = keys["x25519:amina"]?.multikey ?? "";
    expect(x25519).toMatch(/^z6LS/);
    const reject = (method: string, expected: string, path = "/verificationMethod") => {
      const proof = handSigned(intent, { ...baseOptions(intent), verificationMethod: method });
      const issue = issueOf(verifyProof(intent, proof));
      expect([issue.clause, issue.path], method.slice(0, 90)).toEqual([expected, path]);
    };
    reject(phoneMethod.replace(phone, x25519), "core 4.2");
    reject(formatControlKeyRef(x25519), "core 4.2");
    // Keys of other signature schemes, as Multikey writes them: P-256, secp256k1, BLS12-381 G2.
    for (const [prefix, length] of [
      [[0x80, 0x24], 33],
      [[0xe7, 0x01], 33],
      [[0xeb, 0x01], 96],
    ] as const) {
      const other = `z${base58.encode(Uint8Array.from([...prefix, ...new Uint8Array(length).fill(2)]))}`;
      const proof = handSigned(intent, {
        ...baseOptions(intent),
        verificationMethod: formatControlKeyRef(other),
      });
      expect(verifyProof(intent, proof).ok, other.slice(0, 12)).toBe(false);
      expect(verifyProofs({ ...intent, proof: [proof] }).verified, other.slice(0, 12)).toEqual([]);
    }
    // An Ed25519 prefix on a key of the wrong length.
    for (const length of [31, 33]) {
      const odd = `z${base58.encode(Uint8Array.from([0xed, 0x01, ...new Uint8Array(length).fill(2)]))}`;
      const proof = handSigned(intent, {
        ...baseOptions(intent),
        verificationMethod: formatControlKeyRef(odd),
      });
      expect(verifyProof(intent, proof).ok, `${length} bytes`).toBe(false);
    }
    reject(`did:key:${phone}#${laptop.publicKey}`, "core 6.2");
    reject(phoneMethod.replace(/versionId=[0-9]+/, "versionId=9007199254740992"), "core 6.1");
    const beyond = handSigned(intent, {
      ...baseOptions(intent),
      verificationMethod: phoneMethod.replace(/versionId=[0-9]+/, "versionId=9007199254740992"),
    });
    expect(issueOf(verifyProof(intent, beyond)).message).toBe(
      "the verification method pins a position beyond 2^53-1, which no identity log has",
    );
    reject(phoneMethod.replace(/versionId=[0-9]+/, "versionId=01"), "core 6.1");
    reject(phone, "core 6.1");
    reject(`${intent["author"] as string}#${phone}`, "core 6.1");
    reject("did:web:example.com#key-1", "core 6.1");
    for (const point of smallOrderPoints()) {
      const key = `z${base58.encode(Uint8Array.from([0xed, 0x01, ...point.toBytes()]))}`;
      reject(formatControlKeyRef(key), "core 4.4");
      reject(phoneMethod.replace(phone, key), "core 4.4");
    }
    // The same key through both kinds of reference verifies: who may use which is decided above.
    const control = handSigned(intent, {
      ...baseOptions(intent),
      verificationMethod: formatControlKeyRef(phone),
    });
    expect(clauseOf(verifyProof(intent, control))).toBe("accepted");
  });

  it(`${clause("core 5.2")} requires proofValue to be z and the base58btc form of 64 bytes`, () => {
    const signature = base58.decode((intentProof["proofValue"] as string).slice(1));
    const withValue = (proofValue: unknown) => verifyProof(intent, { ...intentProof, proofValue });
    expect(clauseOf(withValue(`z${base58.encode(signature)}`))).toBe("accepted");
    for (const bytes of [
      signature.subarray(0, 63),
      Uint8Array.from([...signature, 0]),
      Uint8Array.from([0, ...signature]),
      signature.subarray(0, 48),
    ]) {
      const issue = issueOf(withValue(`z${base58.encode(bytes)}`));
      expect([issue.clause, issue.path], String(bytes.length)).toEqual(["core 5.2", "/proofValue"]);
    }
    for (const bad of [
      base58.encode(signature),
      `m${base58.encode(signature)}`,
      `z${base58.encode(signature)}0`,
      `z${base58.encode(signature)} `,
      `z${"1".repeat(89)}`,
      "z",
      "",
      null,
      [intentProof["proofValue"]],
      bytesToHex(signature),
    ]) {
      expect(clauseOf(withValue(bad)), String(bad)).toBe("core 5.2");
    }
    // Sixty-five zero bytes: the right form, the wrong length.
    expect(issueOf(withValue(`z${"1".repeat(65)}`)).message).toBe(
      "proofValue is not a signature of 64 bytes",
    );
    // Sixty-four zero bytes have the length of a signature and are not one.
    expect(clauseOf(withValue(`z${"1".repeat(64)}`))).toBe("core 4.4");
  });

  it("rejects a signature that is not the signer's over this record and these options", () => {
    const reject = (record: unknown, proof: unknown) => {
      expect(issueOf(verifyProof(record, proof))).toMatchObject({
        clause: "core 4.4",
        path: "/proofValue",
      });
    };
    // The record changed after signing.
    reject({ ...intent, want: `${intent["want"] as string}!` }, intentProof);
    reject({ ...intent, extra: 1 }, intentProof);
    const { created: _created, ...withoutCreated } = intent;
    reject(withoutCreated, intentProof);
    // The proof changed after signing.
    reject(intent, { ...intentProof, created: "2026-10-30T09:30:01Z" });
    reject(intent, { ...intentProof, verificationMethod: laptopMethod });
    // A proof made for another record.
    reject(named("offer"), { ...intentProof });
    reject(intent, (named("intent_edit")["proof"] as unknown[])[0]);
    // Another signer's signature under this key's name.
    reject(intent, handSigned(intent, baseOptions(intent), privateKeyOf(laptop.publicKey)));
    expect(issueOf(verifyProof({ ...intent, extra: 1 }, intentProof)).message).toMatch(
      /^the signature does not verify/,
    );
  });

  it("does not care how the record or the proof was written", () => {
    const reordered = Object.fromEntries(Object.entries(intent).reverse());
    const reorderedProof = Object.fromEntries(Object.entries(intentProof).reverse());
    expect(verifyProof(reordered, reorderedProof).ok).toBe(true);
    const reparsed = parseJson(JSON.stringify(intent, null, 2));
    expect(reparsed.ok && verifyProof(reparsed.value, intentProof).ok).toBe(true);
    // The record's own proof member is not covered, whatever it holds.
    expect(verifyProof({ ...intent, proof: [] }, intentProof).ok).toBe(true);
    expect(verifyProof({ ...intent, proof: "junk" }, intentProof).ok).toBe(true);
    const { proof: _proof, ...unsigned } = intent;
    expect(verifyProof(unsigned, intentProof).ok).toBe(true);
  });

  it("rejects what is not a record, without throwing", () => {
    expect(issueOf(verifyProof([], intentProof))).toEqual({
      path: "",
      message: "a record is a JSON object",
      clause: "core 1.1",
    });
    expect(issueOf(verifyProof({ oip: "1" }, intentProof))).toEqual({
      path: "/type",
      message: "type must name a record type",
      clause: "core 7",
    });
    expect(clauseOf(verifyProof({ type: 1 }, intentProof))).toBe("core 7");
    expect(clauseOf(verifyProof({ ...intent, n: 0.5 }, intentProof))).toBe("core 1.2");
    expect(clauseOf(verifyProof({ ...intent, s: "\ud800" }, intentProof))).toBe("core 1.1");
    for (const bad of [null, undefined, "text", 1, new Date(0), new Map()]) {
      expect(verifyProof(bad, intentProof).ok).toBe(false);
      expect(verifyProofs(bad)).toMatchObject({ verified: [], rejected: [] });
      expect(verifyProofs(bad).issues.length).toBeGreaterThan(0);
    }
    for (const bad of [null, undefined, "text", 1, [], [intentProof], new Date(0)]) {
      expect(clauseOf(verifyProof(intent, bad))).not.toBe("accepted");
    }
  });

  it("never throws, whatever it is given", () => {
    const hostile = new Proxy(
      {},
      {
        get: () => {
          throw new Error("trap");
        },
        ownKeys: () => {
          throw new Error("trap");
        },
      },
    );
    expect(verifyProof(hostile, intentProof).ok).toBe(false);
    expect(verifyProof(intent, hostile).ok).toBe(false);
    expect(verifyProofs(hostile).verified).toEqual([]);
    // A proxy that throws only when a member is read, one that cannot be listed, one that is gone.
    const revoked = Proxy.revocable({}, {});
    revoked.revoke();
    const boom = () => {
      throw new Error("boom");
    };
    const reference = `${intent["author"] as string}/${contentId(intent)}`;
    for (const value of [
      new Proxy({}, { get: boom }),
      new Proxy({ ...intent }, { getOwnPropertyDescriptor: boom }),
      new Proxy({ ...intent }, { ownKeys: boom }),
      new Proxy({ ...intent }, { getPrototypeOf: boom }),
      new Proxy([], { get: boom }),
      revoked.proxy,
      Object.defineProperty({ ...intent }, "want", { get: boom, enumerable: true }),
      Object.defineProperty({ ...intent }, "proof", { get: boom, enumerable: true }),
    ]) {
      expect(verifyProof(value, intentProof).ok).toBe(false);
      expect(verifyProof(intent, value).ok).toBe(false);
      const verdicts = verifyProofs(value);
      expect(verdicts.verified).toEqual([]);
      expect(verdicts.issues.length).toBeGreaterThan(0);
      expect(recordRefMatches(reference, value)).toBe(false);
    }
    expect(contentIdIfAny(revoked.proxy)).toBeUndefined();
    expect(contentIdIfAny(new Proxy({ ...intent }, { ownKeys: boom }))).toBeUndefined();
    expect(
      contentIdIfAny(Object.defineProperty({ ...intent }, "want", { get: boom, enumerable: true })),
    ).toBeUndefined();
    // A record is read once, through its property descriptors, into a plain copy.
    // A proxy whose trap is never reached is therefore read as the data behind it,
    // and what is verified is that data: no getter and no get trap is ever called.
    let calls = 0;
    const counted = new Proxy(
      { ...intent },
      {
        get(target, name, receiver) {
          calls++;
          return Reflect.get(target, name, receiver) as unknown;
        },
      },
    );
    expect(verifyProofs(counted).verified).toHaveLength(1);
    expect(verifyProof(counted, intentProof).ok).toBe(true);
    expect(recordRefMatches(reference, counted)).toBe(true);
    expect(calls).toBe(0);
    fc.assert(
      fc.property(fc.anything(), fc.anything(), (record, proof) => {
        expect(verifyProof(record, proof).ok).toBe(false);
        expect(verifyProof(intent, proof).ok).toBe(false);
        expect(verifyProofs(record).verified).toEqual([]);
      }),
      { numRuns: 300 },
    );
  });
});

describe("what is judged is what was validated", () => {
  // A proof that holds one thing in its members and answers another when asked.
  const forged = `z${"1".repeat(88)}`;
  const twoFaced = (): Proof =>
    new Proxy({ ...intentProof } as unknown as Proof, {
      get(target, name, receiver) {
        return name === "proofValue" ? forged : (Reflect.get(target, name, receiver) as unknown);
      },
    });

  it("verifies the members a proof holds, and gives back a plain copy of them", () => {
    const asked = twoFaced();
    expect(asked.proofValue).toBe(forged);
    const verdict = verifyProof(intent, asked);
    // What its descriptors hold is the honest proof, and that is what is verified.
    expect(verdict.ok && verdict.value.proof).toEqual(intentProof);
    expect(verdict.ok && verdict.value.proof).not.toBe(asked);
    expect(verdict.ok && verdict.value.proof.proofValue).toBe(intentProof["proofValue"]);
    expect(verdict.ok && verdict.value.digest).toBe(proofDigest(intentProof));
    const set = verifyProofs({ ...intent, proof: [asked] });
    expect(set.verified.map((proof) => proof.proof)).toEqual([intentProof]);
    expect(set.verified[0]?.proof).not.toBe(asked);
  });

  it("adds to a record a plain copy of a proof, never the object it was given", () => {
    const { proof: _proof, ...unsigned } = intent;
    const asked = twoFaced();
    const merged = withProofs(unsigned, [asked]);
    expect(merged.proof).toEqual([intentProof]);
    expect(merged.proof[0]).not.toBe(asked);
    expect(merged.proof[0]?.proofValue).toBe(intentProof["proofValue"]);
    expect(verifyProofs(merged).verified).toHaveLength(1);
    // And the record it returns shares nothing with the one it was given.
    const given = { ...unsigned, constraints: { ...(unsigned["constraints"] as object) } };
    const result = withProofs(given, [intentProof as unknown as Proof]) as JsonObject;
    expect(result["constraints"]).toEqual(given.constraints);
    expect(result["constraints"]).not.toBe(given.constraints);
  });
});

describe("a container has no proofs of its own", () => {
  it("says so of a page that nests deeper than a signed record may", () => {
    let deep: unknown = [];
    for (let i = 0; i < 60; i++) deep = [deep];
    const event = { ...genesis, proof: [...(genesis["proof"] as unknown[]), { junk: deep }] };
    const page = { oip: "1", type: "LogPage", mind: intent["author"], events: [event] };
    // 66 deep as a whole, and well formed. The reason is that it is unsigned.
    expect(verifyProofs(page).issues).toEqual([
      {
        path: "/proof",
        message: "a LogPage record is unsigned: no proof on it counts",
        clause: "core 5.1",
      },
    ]);
    expect(verifyProofs(event).verified).toHaveLength(1);
    // A signed record that deep is refused for its depth.
    const tooDeep = { ...intent, ext: { "com.example.deep": { down: [[[deep]]] } } };
    expect(verifyProofs(tooDeep).issues[0]?.clause).toBe("core 1.9");
  });
});

describe("judging while nothing can be serialised", () => {
  it("answers and does not throw, and is right again afterwards", () => {
    // Other code in the process has put a toJSON on a prototype. No canonical
    // form can be trusted then, so no proof is accepted; but a judge still answers. What it
    // answers says so, and says nothing of the record: nothing was judged (ADR-0010).
    const reference = `${intent["author"] as string}/${contentId(intent)}`;
    const unjudged = [{ path: "", message: CUT_SHORT, clause: "implementation limit" }];
    for (const prototype of [Object.prototype, Array.prototype] as object[]) {
      Object.defineProperty(prototype, "toJSON", {
        value: () => "all the same",
        configurable: true,
        writable: true,
      });
      let one, all, matches;
      try {
        one = verifyProof(intent, intentProof);
        all = verifyProofs(intent);
        matches = recordRefMatches(reference, intent);
      } finally {
        delete (prototype as { toJSON?: unknown }).toJSON;
      }
      expect(one).toEqual({ ok: false, issues: unjudged });
      expect(all).toEqual({ verified: [], rejected: [], issues: unjudged });
      expect(matches).toBe(false);
    }
    expect(verifyProof(intent, intentProof).ok).toBe(true);
    expect(verifyProofs(intent).verified).toHaveLength(1);
    expect(recordRefMatches(reference, intent)).toBe(true);
  });
});

describe(`${clause("core 4.4")} the Ed25519 cases of the vectors`, () => {
  it("rejects a signature whose S is not reduced, and accepts the signature it was made from", () => {
    const record = negative("signature-s-not-reduced")["record"] as JsonObject;
    expect(verdictsOf(record)).toEqual(["core 4.4"]);
    // The same record and options with S reduced again verify: only S is at fault.
    const proof = (record["proof"] as AnyProof[])[0]!;
    const { proofValue: _proofValue, ...options } = proof;
    expect(verifyProof(record, handSigned(record, options)).ok).toBe(true);
    expect(verdictsOf(intent)).toEqual(["accepted"]);
  });

  it("rejects a signature whose R is the identity point, and accepts an honest one beside it", () => {
    const record = negative("signature-r-identity")["record"] as JsonObject;
    const proof = (record["proof"] as AnyProof[])[0]!;
    const signature = base58.decode((proof["proofValue"] as string).slice(1));
    expect(bytesToHex(signature.subarray(0, 32))).toBe(Point.ZERO.toHex());
    expect(verdictsOf(record)).toEqual(["core 4.4"]);
    const { proofValue: _proofValue, ...options } = proof;
    expect(verifyProof(record, handSigned(record, options)).ok).toBe(true);
  });

  it("rejects a proof whose R has a small-order component, which the vectors do not cover", () => {
    const { scalar, publicKey } = expand(phoneKey);
    const options = baseOptions(intent);
    const data = proofHashData(intent, options);
    for (const point of smallOrderPoints().filter((candidate) => !candidate.is0())) {
      const signature = craftSignature(scalar, publicKey, data, 31337n, point);
      const proof = { ...options, proofValue: `z${base58.encode(signature)}` };
      expect(clauseOf(verifyProof(intent, proof)), point.toHex()).toBe("core 4.4");
    }
    const honest = craftSignature(scalar, publicKey, data, 31337n);
    expect(verifyProof(intent, { ...options, proofValue: `z${base58.encode(honest)}` }).ok).toBe(
      true,
    );
  });
});

describe(`${clause("core 5.1")} the proof set`, () => {
  it("does not judge proofs on a record of an unsigned type", () => {
    for (const type of [
      "Session",
      "Resume",
      "Branch",
      "Bundle",
      "LogPage",
      "FeedPage",
      "DuplicityEvidence",
      "Sealed",
    ]) {
      const record = { ...session, type, proof: [intentProof] };
      const proof = handSigned(record, baseOptions(record));
      expect(issueOf(verifyProof(record, proof)), type).toEqual({
        path: "/proof",
        message: `a ${type} record is unsigned: no proof on it counts`,
        clause: "core 5.1",
      });
      expect(verdictsOf(record), type).toBe("not judged: core 5.1");
    }
  });

  it("needs an array of 1 to 256 proofs", () => {
    const { proof: _proof, ...unsigned } = intent;
    const many = (count: number) => ({
      ...unsigned,
      proof: Array.from({ length: count }, () => intentProof),
    });
    for (const bad of [
      unsigned,
      { ...unsigned, proof: [] },
      { ...unsigned, proof: intentProof },
      { ...unsigned, proof: "x" },
      { ...unsigned, proof: null },
      many(MAX_PROOFS + 1),
      // An entry that is not an object makes the record malformed: nothing is judged.
      { ...unsigned, proof: [42, intentProof] },
      { ...unsigned, proof: [intentProof, null] },
      { ...unsigned, proof: [intentProof, "proof"] },
      { ...unsigned, proof: [[intentProof]] },
    ]) {
      expect(verifyProofs(bad)).toEqual({
        verified: [],
        rejected: [],
        issues: [
          {
            path: "/proof",
            message:
              "a signed record carries a proof member that is an array of 1 to 256 proof objects",
            clause: "core 5.1",
          },
        ],
      });
    }
    expect(MAX_PROOFS).toBe(256);
    expect(verdictsOf(many(1))).toEqual(["accepted"]);
    // The largest set is judged in full. The signatures are malformed here, to keep the test quick.
    const largest = verifyProofs({
      ...unsigned,
      proof: Array.from({ length: MAX_PROOFS }, (_, i) => ({ n: i })),
    });
    expect(largest.issues).toEqual([]);
    expect(largest.rejected).toHaveLength(MAX_PROOFS);
    expect(largest.rejected.map((entry) => entry.index)).toEqual(
      Array.from({ length: MAX_PROOFS }, (_, i) => i),
    );
  });

  it("verifies a proof that is repeated once, and reports it at each of its places", () => {
    const { proof: _proof, ...unsigned } = intent;
    const tampered = { ...intentProof, created: "2026-10-30T23:59:59Z" };
    const repeated = {
      ...unsigned,
      proof: [intentProof, tampered, intentProof, tampered, intentProof],
    };
    const verdicts = verifyProofs(repeated);
    expect(verdicts.verified.map((proof) => proof.index)).toEqual([0, 2, 4]);
    expect(verdicts.rejected.map((entry) => entry.index)).toEqual([1, 3]);
    expect(verdicts.rejected.map((entry) => entry.issues[0].path)).toEqual([
      "/proof/1/proofValue",
      "/proof/3/proofValue",
    ]);
    // Three entries, one key and one digest: whoever counts signatures counts keys.
    expect(new Set(verdicts.verified.map((proof) => proof.key)).size).toBe(1);
    expect(new Set(verdicts.verified.map((proof) => proof.digest)).size).toBe(1);
    // 256 copies cost one signature check, not 256.
    const started = performance.now();
    const flood = verifyProofs({
      ...unsigned,
      proof: Array.from({ length: MAX_PROOFS }, () => intentProof),
    });
    expect(flood.verified).toHaveLength(MAX_PROOFS);
    expect(performance.now() - started).toBeLessThan(250);
  });
});

describe(`${clause("core 5.5")} each proof is evaluated independently`, () => {
  it("counts the good proofs of a record that also carries bad ones", () => {
    const tampered = { ...intentProof, created: "2026-10-30T09:30:01Z" };
    // Objects that are not proofs: junk that anyone relaying the record could add.
    const junk = [
      {},
      { type: "DataIntegrityProof" },
      { ...intentProof, id: "urn:x" },
      { a: [1, { b: null }] },
    ];
    const record = {
      ...intent,
      proof: [junk[0], tampered, intentProof, junk[1], junk[2], junk[3], intentProof],
    };
    expect(verdictsOf(record)).toEqual([
      "core 5.2",
      "core 4.4",
      "accepted",
      "core 5.2",
      "core 5.2",
      "core 5.2",
      "accepted",
    ]);
    const verdicts = verifyProofs(record);
    expect(verdicts.verified.map((proof) => proof.index)).toEqual([2, 6]);
    // Each rejection says which proof it is about.
    expect(verdicts.rejected[1]).toMatchObject({
      index: 1,
      issues: [{ path: "/proof/1/proofValue", clause: "core 4.4" }],
    });
    expect(verdicts.rejected[2]?.issues[0].path).toMatch(/^\/proof\/3/);
    expect(contentId(record)).toBe(contentId(intent));
  });

  it("gives each proof the verdict it has on its own", () => {
    const record = named("commitment_accepted");
    const proofs = record["proof"] as unknown[];
    expect(proofs.length).toBeGreaterThanOrEqual(2);
    const together = verifyProofs(record);
    expect(together.verified).toHaveLength(proofs.length);
    proofs.forEach((proof, i) => {
      const alone = verifyProofs({ ...record, proof: [proof] });
      expect(alone.verified).toEqual([{ ...together.verified[i], index: 0 }]);
    });
  });
});

describe("the proof set of a record", () => {
  const { proof: _proof, ...unsigned } = intent;
  const other = handSigned(intent, {
    ...baseOptions(intent),
    created: LATER,
  }) as unknown as Proof;
  const first = intentProof as unknown as Proof;

  it("adds proofs without changing the record or its content ID", () => {
    const original = copy(intent);
    const signed = withProofs(intent, [other]);
    expect(signed.proof).toEqual([first, other]);
    expect(intent).toEqual(original);
    expect(contentId(signed)).toBe(contentId(intent));
    expect(withProofs(unsigned, [first])).toEqual(intent);
    expect(Object.keys(withProofs(unsigned, [first])).at(-1)).toBe("proof");
    expect(withProofs(unsigned, []).proof).toEqual([]);
  });

  it("merges by union: a proof already there is not added again", () => {
    expect(withProofs(intent, [first]).proof).toEqual([first]);
    expect(withProofs(unsigned, [first, other, first, other]).proof).toEqual([first, other]);
    // The same proof with its members in another order is the same proof.
    const reordered = Object.fromEntries(Object.entries(first).reverse()) as unknown as Proof;
    expect(withProofs(intent, [reordered]).proof).toEqual([first]);
    expect(withProofs(withProofs(unsigned, [other]), [first]).proof).toEqual([other, first]);
  });

  it("holds at most 256 proofs", () => {
    const distinct = (count: number) =>
      Array.from({ length: count }, (_, i) => ({
        ...first,
        created: `2026-10-30T09:30:00.${String(i).padStart(3, "0")}Z`,
      }));
    expect(withProofs(unsigned, distinct(MAX_PROOFS)).proof).toHaveLength(MAX_PROOFS);
    expect(() => withProofs(unsigned, distinct(MAX_PROOFS + 1))).toThrow(
      "a record carries at most 256 proofs",
    );
    expect(() => withProofs(withProofs(unsigned, distinct(MAX_PROOFS)), [first])).toThrow(OipError);
    // Adding what is already there to a full set changes nothing.
    const full = withProofs(unsigned, distinct(MAX_PROOFS));
    expect(withProofs(full, distinct(3)).proof).toHaveLength(MAX_PROOFS);
  });

  it("refuses a record or a proof that is not JSON within the profile", () => {
    expect(() => withProofs({ ...unsigned, proof: "x" }, [first])).toThrow(
      "proof must be an array",
    );
    expect(thrownBy(() => withProofs({ ...unsigned, proof: "x" }, [first]))).toMatchObject({
      code: "invalid-record",
      clause: "core 5.1",
    });
    const tooMany = Array.from({ length: MAX_PROOFS + 1 }, (_, i) => ({
      ...first,
      created: `2026-10-30T10:00:00.${String(i).padStart(3, "0")}Z`,
    }));
    // More than 256 is a matter of size, and has the code for it.
    expect(thrownBy(() => withProofs(unsigned, tooMany))).toMatchObject({
      code: "too-large",
      clause: "core 5.1",
    });
    expect(() => withProofs({ ...unsigned, proof: { a: 1 } }, [first])).toThrow(OipError);
    expect(() => withProofs([], [first])).toThrow("a record is a JSON object");
    expect(() => withProofs({ ...unsigned, n: 0.5 }, [first])).toThrow(OipError);
    expect(() => withProofs({ ...unsigned, proof: [first, "x"] }, [other])).toThrow(OipError);
  });

  it("adds only what has the form of a proof", () => {
    // Anything merged takes one of the 256 places, so junk is never merged.
    for (const junk of [
      "proof",
      null,
      7,
      [],
      {},
      { a: 1 },
      { ...first, created: new Date(0) },
      { ...first, proofValue: "z" },
      { ...first, extra: 1 },
      { ...first, cryptosuite: "ecdsa-jcs-2019" },
      (() => {
        const { proofValue: _proofValue, ...withoutValue } = first;
        return withoutValue;
      })(),
    ]) {
      expect(
        thrownBy(() => withProofs(unsigned, [junk as unknown as Proof])),
        JSON.stringify(junk),
      ).toMatchObject({ code: "invalid-proof" });
      expect(
        thrownBy(() => withProofs(intent, [other, junk as unknown as Proof])),
        JSON.stringify(junk),
      ).toMatchObject({ code: "invalid-proof" });
    }
    // The form of a proof is not its verification: that is the caller's to do first.
    const forged = { ...first, proofValue: `z${"1".repeat(88)}` };
    expect(withProofs(unsigned, [forged]).proof).toEqual([forged]);
    expect(verifyProofs(withProofs(unsigned, [forged])).rejected).toHaveLength(1);
  });

  it("is not for a record of a type that is never signed", () => {
    for (const type of UNSIGNED_RECORD_TYPES) {
      expect(
        thrownBy(() => withProofs({ oip: "1", type }, [first])),
        type,
      ).toMatchObject({
        code: "invalid-proof",
        clause: "core 5.1",
      });
      expect(
        thrownBy(() => withProofs({ oip: "1", type }, [])),
        type,
      ).toMatchObject({
        code: "invalid-proof",
      });
    }
    expect(thrownBy(() => withProofs({ oip: "1" }, [first]))).toMatchObject({
      code: "invalid-record",
      clause: "core 7",
    });
  });

  it("keeps the result within the size limit", () => {
    const big = { ...unsigned, want: "w".repeat(MAX_RECORD_BYTES - 900) };
    expect(thrownBy(() => withProofs(big, [first, other]))).toMatchObject({
      code: "too-large",
      clause: "core 1.6",
    });
    // Exactly at the limit is within it, and one byte more is not.
    const padded = (blob: string) => ({ ...unsigned, ext: { "com.example.padding": { blob } } });
    const room = MAX_RECORD_BYTES - canonicalBytes(withProofs(padded(""), [first])).length;
    const exact = withProofs(padded("a".repeat(room)), [first]);
    expect(canonicalBytes(exact)).toHaveLength(MAX_RECORD_BYTES);
    expect(thrownBy(() => withProofs(padded("a".repeat(room + 1)), [first]))).toMatchObject({
      code: "too-large",
      clause: "core 1.6",
      detail: `with these proofs the record is more than ${MAX_RECORD_BYTES} bytes in canonical form`,
    });
  });
});

describe(`${clause("core 9.4")} evidence is keyed by the proof's digest`, () => {
  it('is "sha256:" and the hex of SHA-256(JCS(proof))', () => {
    const expected = sha256(new TextEncoder().encode(canonicalize(intentProof))).toString("hex");
    expect(proofDigest(intentProof)).toBe(`sha256:${expected}`);
    expect(proofDigest(intentProof)).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("reproduces the digests a feed entry of the vectors commits to", () => {
    const offer = named("offer");
    expect(named("feed_entry")["proofs"]).toEqual((offer["proof"] as unknown[]).map(proofDigest));
    const seen = Object.keys(
      (negative("removed-key-backdated")["seen"] ?? {}) as Record<string, string>,
    ).filter((key) => key.startsWith("sha256:"));
    const record = negative("removed-key-backdated")["record"] as JsonObject;
    expect(seen).toEqual((record["proof"] as unknown[]).map(proofDigest));
  });

  it("differs for each proof on one record, and for one proof when anything in it changes", () => {
    const record = named("commitment_accepted");
    const digests = (record["proof"] as unknown[]).map(proofDigest);
    expect(new Set(digests).size).toBe(digests.length);
    expect(proofDigest({ ...intentProof, created: "2026-10-30T09:30:01Z" })).not.toBe(
      proofDigest(intentProof),
    );
    expect(proofDigest({ ...intentProof, proofValue: "z1" })).not.toBe(proofDigest(intentProof));
    expect(proofDigest(Object.fromEntries(Object.entries(intentProof).reverse()))).toBe(
      proofDigest(intentProof),
    );
  });

  it("refuses what has no canonical form", () => {
    for (const bad of [null, [], "proof", 1, { a: 0.5 }, undefined]) {
      expect(() => proofDigest(bad)).toThrow(OipError);
    }
    expect(thrownBy(() => proofDigest([]))).toMatchObject({
      code: "invalid-record",
      clause: "core 5.2",
      detail: "a proof is a JSON object",
    });
    // What is wrong with the value is said, not only that it is no proof.
    expect(thrownBy(() => proofDigest({ a: 0.5 }))).toMatchObject({
      code: "invalid-record",
      clause: "core 1.2",
    });
    expect(thrownBy(() => contentId({ a: 0.5 }))).toMatchObject({
      code: "invalid-record",
      clause: "core 1.2",
    });
    expect(thrownBy(() => proofHashData(intent, { a: "\ud800" }))).toMatchObject({
      code: "invalid-record",
      clause: "core 1.1",
    });
  });
});

describe(`${clause("core 3.3")} one digest for the content ID and for every proof`, () => {
  it("is the second half of what each proof signs", () => {
    for (const { name, record } of signedRecords.slice(0, 20)) {
      const { proofValue: _proofValue, ...options } = (record["proof"] as AnyProof[])[0]!;
      const data = proofHashData(record, options);
      expect(bytesToHex(data.subarray(32)), name).toBe(bytesToHex(documentHash(record)));
    }
  });
});

describe("changing any byte of any vector record makes verification fail", () => {
  /** How many of a record's proofs verify, reading it from text as a receiver does. */
  function verifiedIn(text: Uint8Array): number {
    let decoded: string;
    try {
      decoded = new TextDecoder("utf-8", { fatal: true }).decode(text);
    } catch {
      return 0;
    }
    const parsed = parseJson(decoded);
    if (!parsed.ok) return 0;
    return verifyProofs(parsed.value).verified.length;
  }

  it("for any record, any position and any other byte", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...signedRecords),
        fc.nat(),
        fc.integer({ min: 1, max: 255 }),
        ({ record }, position, difference) => {
          const text = canonicalBytes(record);
          const proofs = (record["proof"] as unknown[]).length;
          const changed = Uint8Array.from(text);
          const at = position % changed.length;
          changed[at] = ((changed[at] ?? 0) + difference) % 256;
          expect(verifiedIn(changed)).toBeLessThan(proofs);
        },
      ),
      { numRuns: 400 },
    );
  });

  it("for every byte of one record", () => {
    const text = canonicalBytes(intent);
    expect(verifiedIn(text)).toBe(1);
    for (let at = 0; at < text.length; at++) {
      const changed = Uint8Array.from(text);
      changed[at] = (changed[at] ?? 0) ^ 0x01;
      expect(verifiedIn(changed), `byte ${at}`).toBe(0);
    }
  });

  it("and a change to one proof leaves the others standing", () => {
    const record = named("commitment_accepted");
    const proofs = copy(record["proof"] as AnyProof[]);
    proofs[0]!["created"] = "2026-10-30T23:59:59Z";
    expect(verdictsOf({ ...record, proof: proofs })).toEqual([
      "core 4.4",
      ...proofs.slice(1).map(() => "accepted"),
    ]);
  });
});
