# @oip/core

The foundation every record of the [Open Intelligence Protocol](../../README.md) stands on: the rules of [OIP Core](../../spec/core.md), Sections 1 to 8 and 10.

It answers two questions about a record. **Is this text a well-formed record?** And: **which of its proofs are well formed, with a valid signature by the key they name?** Whether that key may sign for anyone, and from when, is decided by the packages above this one, from identity logs and evidence.

- **The JSON profile** (core 1). A strict parser: no duplicate member names, valid Unicode, and numbers that are safe integers, judged by value. `JSON.parse` is not used for records, because it keeps the last of two members with one name and turns numbers into floats before anyone can judge them.
- **Canonical form** (core 2), **content IDs** in their one spelling and **key hashes** (core 3).
- **Multikey**, with its prefix and length checks (core 4.1 to 4.3).
- **Ed25519 under the one rule of core 4.4**: `S < L`, canonical encodings, and `A` and `R` of order exactly L. The arithmetic is `@noble/curves`; this package decides what to accept.
- **`eddsa-jcs-2022` proofs** (core 5): create one, verify one, verify a set, each proof on its own.
- **References** (core 6), **extensions** (core 8), **timestamps, durations and decimals** as exact values (core 1.3 to 1.5), and the **problem types** (core 10).

It is pure: no I/O, and it never reads the clock. It uses no Node.js API, so that it can run in browsers, Deno and Bun as well. CI tests it on Node.js today; the other runtimes join the CI matrix with the client (M6).

## Use

```ts
import {
  contentId,
  createProof,
  formatControlKeyRef,
  keyHash,
  mindAddress,
  parseRecord,
  signerFromPrivateKey,
  verifyProofs,
  withProofs,
} from "@oip/core";

/**
 * Writes the first event of a mind's identity log, signs it, and reads it
 * back as a receiver does: from text, trusting nothing.
 */
export async function example(controlKey: Uint8Array, nextKey: Uint8Array): Promise<string[]> {
  const control = signerFromPrivateKey(controlKey);
  const next = signerFromPrivateKey(nextKey);
  const created = "2026-11-17T09:00:00Z";
  const genesis = {
    oip: "1",
    type: "Genesis",
    kind: "agent",
    created,
    // The next control key is committed to by its hash, and stays secret until it is used.
    controller: { keys: [control.publicKey], next: [keyHash(next.publicKey)], nextThreshold: 1 },
  };
  const proof = await createProof(
    genesis,
    { verificationMethod: formatControlKeyRef(control.publicKey), created },
    control,
  );
  const sent = JSON.stringify(withProofs(genesis, [proof]));

  // The receiver. Validate: is this text a well-formed record?
  const received = parseRecord(sent);
  if (!received.ok) {
    return received.issues.map((issue) => `${issue.clause} ${issue.path}: ${issue.message}`);
  }
  // Verify: which of its proofs are well formed, with a valid signature?
  const verdicts = verifyProofs(received.value);
  if (!verdicts.ok) return [`${verdicts.issues[0].clause}: ${verdicts.issues[0].message}`];
  return [
    `a well-formed ${received.value.type}`,
    // A mind's address is the content ID of its first event.
    `address: ${mindAddress(contentId(received.value))}`,
    ...verdicts.value.map((verdict, i) =>
      verdict.ok
        ? `proof ${i}: a valid signature by ${verdict.value.key}`
        : `proof ${i}: ${verdict.issues[0].clause} ${verdict.issues[0].message}`,
    ),
  ];
}
```

This is [`examples/sign-and-verify.ts`](examples/sign-and-verify.ts); a test runs it and checks that this page shows it unchanged. With two test keys it returns:

```
a well-formed Genesis
address: did:oip:bciqgrshjkigvq5xijqhr7ji7l5zduzyatgorvoxujtf63koekhnrsqa
proof 0: a valid signature by z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX
```

The example signs with a key held in memory. A program that must not hold private keys passes any `Signer`: an object with a `publicKey` and a `sign` method, behind which a keystore or a hardware key can stand.

A valid signature is not yet authority. Verifying this event as the start of an identity log, and deciding whose records a key may sign, is the work of `@oip/identity` (M2).

## What it exports

| Export                                                                                                                                                                           | What it does                                                                                                         |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `parseRecord(text)`                                                                                                                                                              | Reads a record from text or bytes: the JSON profile, the schema and rules of its type, and the size limit (core 1.6) |
| `parseJson(text)`, `parseJsonBytes(bytes)`                                                                                                                                       | The parser of the JSON profile on its own                                                                            |
| `canonicalize(value)`, `canonicalBytes(value)`                                                                                                                                   | Canonical form, RFC 8785                                                                                             |
| `contentId(record)`, `keyHash(multikey)`, `isContentId`, `digestOfContentId`, `contentIdOfDigest`, `documentHash`                                                                | Content IDs and key hashes                                                                                           |
| `verifyProofs(record)`, `verifyProof(record, proof)`                                                                                                                             | Verifies the proofs of a record, each on its own                                                                     |
| `createProof(record, options, signer)`, `createProofSync`, `withProofs`, `proofHashData`, `purposeFor`                                                                           | Creates a proof and adds proofs to a record                                                                          |
| `proofDigest(proof)`                                                                                                                                                             | The digest by which evidence of a proof is keyed (core 9.4)                                                          |
| `Signer`, `SyncSigner`, `signerFromPrivateKey`                                                                                                                                   | What signs                                                                                                           |
| `verifyEd25519`, `signEd25519`, `ed25519PublicKey`, `isEd25519PublicKey`                                                                                                         | Ed25519 under core 4.4                                                                                               |
| `encodeEd25519Multikey`, `decodeEd25519Multikey`, `encodeX25519Multikey`, `decodeX25519Multikey`, `isEd25519Multikey`, `isX25519Multikey`                                        | Multikey                                                                                                             |
| `mindAddress`, `mindId`, `parseKeyRef`, `parseControlKeyRef`, `parseVerificationMethod`, `parseRecordRef`, `parseVersionId`, `parseVersionedMind`, `recordRefMatches`, `format…` | References                                                                                                           |
| `parseTimestamp`, `formatTimestamp`, `parseDuration`, `CLOCK_SKEW`, `Instant`                                                                                                    | Time values. An instant is a `bigint` of nanoseconds; nothing here reads a clock                                     |
| `compareDecimals`, `isDecimal`, `isAmount`                                                                                                                                       | Decimal quantities, compared exactly                                                                                 |
| `unsupportedCritical`, `understandsCritical`, `isNamespace`                                                                                                                      | Critical extensions                                                                                                  |
| `OipError`, `PROBLEMS`, `problemDetails`, `problemType`, `problemCode`, `errorFrom`, `MEDIA_TYPE`                                                                                | Problem types and the one error this implementation throws                                                           |
| `sha256`, `sha256Digest`, `utf8`, `decodeUtf8`, `codePointLength`, `isWellFormed`, `bytesToHex`, `hexToBytes`, `bytesEqual`                                                      | Hashing, text and bytes                                                                                              |

The API report is [`etc/core.api.md`](etc/core.api.md).

## Results and errors

- **A function that judges input returns a result and never throws**, whatever it is given: `parseJson`, `parseRecord`, `verifyProof`, `verifyProofs`, `verifyEd25519`, and every `parse…`, `decode…` and `is…` function. A rejection carries issues, each with the clause of the specification it comes from:

  ```
  core 4.4 /proof/0/proofValue: the signature does not verify: …
  ```

- **A function that computes or creates throws `OipError`** when the value it was given is not a record, a proof or JSON within the profile: `canonicalize`, `contentId`, `createProof`, `withProofs`. Nothing outside the profile is ever hashed or signed.
- **A wrong argument throws `TypeError`**: a private key that is not 32 bytes, for example. Its message never repeats the value ([ADR-0007](../../docs/adr/0007-programming-errors.md)).

## What verifying a proof covers

`verifyProof` checks, in the order of core 5.4: that the proof has exactly the members core 5.2 allows; that its purpose is the one the record's type requires (core 5.6); that it has `@context` exactly when the record has, with the same value; that its verification method is a key reference whose key is an Ed25519 key of order L; and that the signature is valid under core 4.4 over the proof's options and the record without its `proof` member.

It does **not** check that the record is well formed (use `parseRecord` or `validateRecord` first), that the key belongs to the mind the reference names, or anything about time. A proof's `created` is the signer's claim, never evidence (core 9.2).

Every proof is judged on its own (core 5.5). A bad proof never invalidates a record or another proof, and never counts.

## Limits

| Limit                                  | Value                                                  | From                                                                 |
| -------------------------------------- | ------------------------------------------------------ | -------------------------------------------------------------------- |
| Canonical form of a record             | 1 MiB; a container is limited per record it carries    | core 1.6                                                             |
| Canonical form of a `Sealed` record    | 1 MiB plus the cipher's 16 bytes, base64url, and 4 KiB | this implementation's reading of "its encoding overhead" in core 1.6 |
| Proofs on a record                     | 256                                                    | core 5.1                                                             |
| Nesting of arrays and objects          | 64                                                     | core 1.9                                                             |
| Text parsed in one call                | 8 MiB by default; set `maxLength` to change it         | this implementation                                                  |
| Order checks of public keys remembered | 4,096                                                  | this implementation                                                  |

## Tests

- The golden vectors: every canonical form, content ID, address, key hash and `proofValue` reproduces, and every proof verifies.
- RFC 8032 and FIPS 180-4 examples, and the examples of RFC 8785.
- Signatures made on the wrong side of core 4.4 with a known secret: `S` not reduced, `R` the identity, `R` and `A` with a small-order component. The library alone accepts several of them; the tests show which, and that this package rejects them all.
- Changing any byte of any vector record makes verification fail.
- The parser is run on a million generated inputs and compared with an oracle that shares nothing with it.
- Mutation testing (`pnpm mutation`).

The decisions behind the package are in [ADR-0002](../../docs/adr/0002-cryptography-libraries.md), [ADR-0005](../../docs/adr/0005-cryptography-libraries-as-adopted.md) and [ADR-0006](../../docs/adr/0006-performance-budgets.md).
