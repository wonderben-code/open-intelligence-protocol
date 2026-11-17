// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";

import type { Proof } from "@oip/schema";
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
  documentHash,
  formatControlKeyRef,
  MAX_PROOFS,
  OipError,
  parseJson,
  proofDigest,
  proofHashData,
  type ProofOptions,
  purposeFor,
  signEd25519,
  type Signer,
  signerFromPrivateKey,
  type Validation,
  verifyProof,
  verifyProofs,
  withProofs,
} from "../src/index.ts";
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
  created: "2026-10-30T09:30:00Z",
});

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
    const wrong = handSigned(intent, { ...baseOptions(intent), proofPurpose: "authentication" });
    expect(issueOf(verifyProof(intent, wrong))).toEqual({
      path: "/proofPurpose",
      message:
        "a Intent record needs a proof with the purpose assertionMethod; this proof's purpose is authentication",
      clause: "core 5.6",
    });
  });

  it("rejects the wrong-purpose case of the vectors", () => {
    const record = negative("wrong-proof-purpose")["record"] as JsonObject;
    const verdicts = verifyProofs(record);
    expect(verdicts.ok && verdicts.value.map(clauseOf)).toEqual(["core 5.6"]);
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
    expect(reproduced).toBe(56);
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
      { verificationMethod: phoneMethod, created: "2026-10-30T09:30:00Z" },
      phoneSigner,
    );
    const second = await createProof(
      unsigned,
      { verificationMethod: laptopMethod, created: "2026-10-30T09:31:00Z" },
      laptop,
    );
    // The second signer signs the record with or without the first proof on it: the same proof.
    const afterFirst = await createProof(
      withProofs(unsigned, [first]),
      { verificationMethod: laptopMethod, created: "2026-10-30T09:31:00Z" },
      laptop,
    );
    expect(afterFirst).toEqual(second);
    for (const order of [
      [first, second],
      [second, first],
    ]) {
      const signed = withProofs(unsigned, order);
      const verdicts = verifyProofs(signed);
      expect(verdicts.ok && verdicts.value.every((verdict) => verdict.ok)).toBe(true);
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
      { verificationMethod: phoneMethod, created: "2026-10-30T09:30:00Z" },
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
      { verificationMethod: phoneMethod, created: "2026-10-30T09:30:00Z" },
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
    await createProof(
      frozen,
      { verificationMethod: phoneMethod, created: "2026-10-30T09:30:00Z" },
      phoneSigner,
    );
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
    const options = { verificationMethod: phoneMethod, created: "2026-10-30T09:30:00Z" };
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
    expect((await failure(createProof({}, options, phoneSigner))).clause).toBe("core 7");
    // An unsigned type carries no proof.
    const unsigned = await failure(createProof(session, options, phoneSigner));
    expect([unsigned.code, unsigned.clause]).toEqual(["invalid-proof", "core 5.1"]);
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
        { verificationMethod: phoneMethod, created: "2026-10-30T09:30:00Z", domain: "d" },
        counting,
      ),
    ).rejects.toThrow(OipError);
    expect(asked).toBe(0);
    await createProof(
      intent,
      { verificationMethod: phoneMethod, created: "2026-10-30T09:30:00Z" },
      counting,
    );
    expect(asked).toBe(1);
  });

  it("catches a faulty signer before anyone else does", async () => {
    const options = { verificationMethod: phoneMethod, created: "2026-10-30T09:30:00Z" };
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
    for (const bad of [null, [], "x", { a: 0.1 }]) {
      expect(() => proofHashData(intent, bad)).toThrow(OipError);
      expect(() => proofHashData(bad, {})).toThrow(OipError);
    }
    expect(() => proofHashData(intent, [])).toThrow("a proof's options is a JSON object");
    expect(() => proofHashData([], {})).toThrow("a record is a JSON object");
  });
});

describe(`${clause("core 5.4")} verifying a proof`, () => {
  it("verifies every proof in the vectors", () => {
    let verified = 0;
    for (const { name, record } of signedRecords) {
      const verdicts = verifyProofs(record);
      expect(verdicts.ok, name).toBe(true);
      if (!verdicts.ok) continue;
      expect(verdicts.value).toHaveLength((record["proof"] as unknown[]).length);
      verdicts.value.forEach((verdict, i) => {
        expect(verdict.ok, `${name} proof ${i}`).toBe(true);
        expect(verifyProof(record, (record["proof"] as unknown[])[i])).toEqual(verdict);
        verified++;
      });
    }
    expect(verified).toBe(56);
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
        created: BigInt(Date.parse(intentProof["created"] as string)) * 1_000_000n,
      },
    } satisfies Validation<unknown>);
    const control = verifyProof(genesis, (genesis["proof"] as unknown[])[0]);
    expect(control.ok && control.value.method).toEqual({
      kind: "control",
      key: (genesis["controller"] as { keys: string[] }).keys[0],
    });
    expect(control.ok && control.value.key).toBe(
      (genesis["controller"] as { keys: string[] }).keys[0],
    );
  });

  it("requires exactly the members 5.2 allows", () => {
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

  it("requires the type and the cryptosuite of this revision", () => {
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

  it("requires @context on the proof exactly when the record has it, with the same value", () => {
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

  it("requires a key reference whose key is an Ed25519 key of order L", () => {
    const x25519 = keys["x25519:amina"]?.multikey ?? "";
    const reject = (method: string, expected: string, path = "/verificationMethod") => {
      const proof = handSigned(intent, { ...baseOptions(intent), verificationMethod: method });
      const issue = issueOf(verifyProof(intent, proof));
      expect([issue.clause, issue.path], method.slice(0, 90)).toEqual([expected, path]);
    };
    reject(phoneMethod.replace(phone, x25519), "core 4.2");
    reject(formatControlKeyRef(x25519), "core 4.2");
    reject(`did:key:${phone}#${laptop.publicKey}`, "core 6.2");
    reject(phoneMethod.replace(/versionId=[0-9]+/, "versionId=9007199254740992"), "core 6.1");
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

  it("requires proofValue to be z and the base58btc form of 64 bytes", () => {
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
      expect(verifyProofs(bad).ok).toBe(false);
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
    expect(verifyProofs(hostile).ok).toBe(false);
    fc.assert(
      fc.property(fc.anything(), fc.anything(), (record, proof) => {
        expect(verifyProof(record, proof).ok).toBe(false);
        expect(verifyProof(intent, proof).ok).toBe(false);
        const verdicts = verifyProofs(record);
        expect(!verdicts.ok || verdicts.value.every((verdict) => !verdict.ok)).toBe(true);
      }),
      { numRuns: 300 },
    );
  });
});

describe(`${clause("core 4.4")} the Ed25519 cases of the vectors`, () => {
  const control = verifyProofs(intent);

  it("rejects a signature whose S is not reduced, and accepts the signature it was made from", () => {
    const record = negative("signature-s-not-reduced")["record"] as JsonObject;
    const verdicts = verifyProofs(record);
    expect(verdicts.ok && verdicts.value.map(clauseOf)).toEqual(["core 4.4"]);
    // The same record and options with S reduced again verify: only S is at fault.
    const proof = (record["proof"] as AnyProof[])[0]!;
    const { proofValue: _proofValue, ...options } = proof;
    expect(verifyProof(record, handSigned(record, options)).ok).toBe(true);
    expect(control.ok && control.value.every((verdict) => verdict.ok)).toBe(true);
  });

  it("rejects a signature whose R is the identity point, and accepts an honest one beside it", () => {
    const record = negative("signature-r-identity")["record"] as JsonObject;
    const proof = (record["proof"] as AnyProof[])[0]!;
    const signature = base58.decode((proof["proofValue"] as string).slice(1));
    expect(bytesToHex(signature.subarray(0, 32))).toBe(Point.ZERO.toHex());
    const verdicts = verifyProofs(record);
    expect(verdicts.ok && verdicts.value.map(clauseOf)).toEqual(["core 4.4"]);
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
      expect(clauseOf(verifyProofs(record)), type).toBe("core 5.1");
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
    ]) {
      expect(issueOf(verifyProofs(bad))).toEqual({
        path: "/proof",
        message: "a signed record carries a proof member that is an array of 1 to 256 proofs",
        clause: "core 5.1",
      });
    }
    expect(MAX_PROOFS).toBe(256);
    const one = verifyProofs(many(1));
    expect(one.ok && one.value).toHaveLength(1);
    // The largest set is judged in full. The signatures are malformed here, to keep the test quick.
    const largest = verifyProofs({
      ...unsigned,
      proof: Array.from({ length: MAX_PROOFS }, () => ({})),
    });
    expect(largest.ok && largest.value).toHaveLength(MAX_PROOFS);
  });
});

describe(`${clause("core 5.5")} each proof is evaluated independently`, () => {
  it("counts the good proofs of a record that also carries bad ones", () => {
    const tampered = { ...intentProof, created: "2026-10-30T09:30:01Z" };
    const record = {
      ...intent,
      proof: [42, tampered, intentProof, null, {}, "proof", [intentProof], intentProof],
    };
    const verdicts = verifyProofs(record);
    expect(verdicts.ok && verdicts.value.map(clauseOf)).toEqual([
      "core 5.2",
      "core 4.4",
      "accepted",
      "core 5.2",
      "core 5.2",
      "core 5.2",
      "core 5.2",
      "accepted",
    ]);
    // Each rejection says which proof it is about.
    expect(verdicts.ok && issueOf(verdicts.value[1]!).path).toBe("/proof/1/proofValue");
    expect(verdicts.ok && issueOf(verdicts.value[4]!).path).toMatch(/^\/proof\/4/);
    expect(contentId(record)).toBe(contentId(intent));
  });

  it("gives each proof the verdict it has on its own", () => {
    const record = named("commitment_accepted");
    const proofs = record["proof"] as unknown[];
    expect(proofs.length).toBeGreaterThanOrEqual(2);
    const together = verifyProofs(record);
    proofs.forEach((proof, i) => {
      const alone = verifyProofs({ ...record, proof: [proof] });
      expect(alone.ok && together.ok && alone.value[0]).toEqual(together.ok && together.value[i]);
    });
  });
});

describe("the proof set of a record", () => {
  const { proof: _proof, ...unsigned } = intent;
  const other = handSigned(intent, {
    ...baseOptions(intent),
    created: "2026-10-30T09:31:00Z",
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
    expect(() => withProofs({ ...unsigned, proof: { a: 1 } }, [first])).toThrow(OipError);
    expect(() => withProofs([], [first])).toThrow("a record is a JSON object");
    expect(() => withProofs({ ...unsigned, n: 0.5 }, [first])).toThrow(OipError);
    expect(() =>
      withProofs(unsigned, [{ ...first, created: new Date(0) } as unknown as Proof]),
    ).toThrow(OipError);
    expect(() => withProofs(unsigned, ["proof" as unknown as Proof])).toThrow(
      "a proof is a JSON object",
    );
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
    const verdicts = verifyProofs(parsed.value);
    return verdicts.ok ? verdicts.value.filter((verdict) => verdict.ok).length : 0;
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
    const verdicts = verifyProofs({ ...record, proof: proofs });
    expect(verdicts.ok && verdicts.value.map((verdict) => verdict.ok)).toEqual([
      false,
      ...proofs.slice(1).map(() => true),
    ]);
  });
});
