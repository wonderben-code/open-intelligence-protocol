# OIP Core: Records, Identifiers and Proofs

**Revision 2026-10-31 · Status: Draft · Licensed under CC BY 4.0**

This document defines what every OIP record has in common, at every layer. See [README.md](README.md) for conventions.

## 1. Records

1.1. A **record** is a JSON object (RFC 8259), encoded as UTF-8, that is also an I-JSON message (RFC 7493): it MUST NOT contain duplicate member names, and every string MUST be valid Unicode (no unpaired surrogates). Receivers SHOULD reject records with duplicate member names. Content IDs and proofs cover the record as parsed, so a receiver that cannot detect duplicates may disagree with others about whether a record is valid, but never accepts a value its signer did not sign.

1.2. The values permitted anywhere in a record are objects, arrays, strings, `true`, `false`, `null`, and numbers whose value is an integer `n` with −(2⁵³−1) ≤ `n` ≤ 2⁵³−1. A record containing a number whose value has a fractional part, or lies outside that range, MUST be rejected. Validity depends on a number's value, not on how it is written: `1.0` and `1e2` are the integers 1 and 100, which canonical form writes as `1` and `100`. Producers MUST write integers without a fraction or exponent.

1.3. **Decimal quantities** (prices, amounts, scores) MUST be strings matching `^-?(0|[1-9][0-9]*)(\.[0-9]+)?$`, using the ASCII digits only. **Amounts** (prices, budgets and other sums of money or assets) MUST be non-negative, matching `^(0|[1-9][0-9]*)(\.[0-9]+)?$`. Wherever this specification compares two decimal strings, the comparison is numeric. Ordering comparisons (less than, greater than) are defined only between decimals; a string that does not match the pattern is not a decimal, however it looks (`"1,000"`, `"1e2"`, `" 400 "`, `"-Infinity"` and full-width digits are not decimals).

1.4. **Timestamps** MUST be RFC 3339 strings in UTC matching `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$`. Timestamps are compared as instants, never as strings.

1.5. **Durations** MUST be ISO 8601 durations of the form `P[nD][T[nH][nM][nS]]`, for example `P30D` or `PT15M`.

1.6. **Size.** The canonical form (Section 2) of a record MUST NOT exceed 1 MiB. Implementations MAY apply lower limits to particular record types but MUST accept records of at least 256 KiB. Larger content is carried by reference (Layer 1, Section 12).

1.7. **Field names** use camelCase. Implementations MUST preserve fields they do not recognise when storing or forwarding a record, because those fields are covered by its proofs, and MUST otherwise ignore them (Section 8).

## 2. Canonical form

2.1. The canonical form of a JSON value is its serialisation under the JSON Canonicalization Scheme, RFC 8785 (JCS). Object members are sorted by the UTF-16 code units of their names, no insignificant whitespace is emitted, and strings use the minimal escaping that RFC 8785 specifies.

2.2. Because Section 1.2 restricts numbers to safe integers, JCS number serialisation reduces to the shortest decimal form of the integer, and `-0` serialises as `0`.

## 3. Content identifiers

3.1. The **content ID** of a record `r` is:

```
contentId(r) = "b" + base32lower( 0x12 ‖ 0x20 ‖ SHA-256( JCS( r without member "proof" ) ) )
```

`base32lower` is the RFC 4648 base32 alphabet in lower case without padding. The bytes `0x12 0x20` are the multihash prefix for a 32-byte SHA-256 digest, and `b` is the multibase prefix for lower-case base32.

3.2. A content ID MUST match `^b[a-z2-7]{55}$` (56 characters, lower case only). In this revision the multihash prefix MUST be `0x12 0x20`; content IDs with any other prefix MUST be rejected. A later revision that adds a hash function will change the length of content IDs as well as the prefix.

An OIP content ID is a multibase-encoded multihash. It is not an IPFS CID: storing OIP records in a content-addressed store such as IPFS requires a mapping to a CIDv1, and the stored bytes (the canonical form without proofs) do not carry the record's proofs.

3.3. The 32-byte digest inside a content ID equals the `transformedDocumentHash` of every `eddsa-jcs-2022` proof on the record (Section 5).

3.4. The **key hash** of a Multikey string `k`, used for pre-rotation commitments, is `"b" + base32lower(0x12 ‖ 0x20 ‖ SHA-256(UTF-8(k)))`.

## 4. Keys

4.1. Public keys are written as **Multikey** strings: `"z"` followed by the base58btc encoding of a multicodec prefix and the raw key bytes.

| Key type | Multicodec prefix | Raw length | String prefix |
|---|---|---|---|
| Ed25519 public key | `0xed 0x01` | 32 bytes | `z6Mk` |
| X25519 public key | `0xec 0x01` | 32 bytes | `z6LS` |

4.2. Implementations MUST check the prefix and length of every Multikey they use and reject any that do not match the expected type.

4.3. This revision requires Ed25519 for signatures and X25519 for encryption. Other key types are reserved for later revisions; adding one is a change to the verification rules, not only to the format, because verifiers of this revision reject proofs by keys of other types.

4.4. **Ed25519 verification.** Every implementation MUST apply the same rule, so that all verifiers agree on which signatures are valid: verification follows RFC 8032 Section 5.1.7 with the equation [S]B = R + [k]A, and MUST reject a signature whose `S` is not less than the group order L, or whose `R` or public key `A` is not a canonical encoding or is a point of small order.

## 5. Proofs

5.1. A signed record carries a member `proof` whose value MUST be a non-empty array of at most 256 proof objects (a W3C Data Integrity *proof set*). Records that this specification defines as unsigned (such as `Bundle`, `Session` and `Sealed`) MUST NOT carry `proof`.

5.2. Each proof object MUST conform to W3C Data Integrity 1.0 with the `eddsa-jcs-2022` cryptosuite, and MUST contain exactly these members, plus any optional members listed:

| Member | Required | Value |
|---|---|---|
| `type` | yes | `"DataIntegrityProof"` |
| `cryptosuite` | yes | `"eddsa-jcs-2022"` |
| `verificationMethod` | yes | A key reference (Section 6) |
| `proofPurpose` | yes | See 5.6 |
| `created` | yes | A timestamp |
| `proofValue` | yes | `"z"` + base58btc of the 64-byte Ed25519 signature |
| `challenge`, `domain` | no | Only in `authentication` proofs (Layer 1, Section 13.3) |
| `@context` | no | Present if and only if the record has `@context`, with the same value |

A proof MUST NOT contain `id`, `previousProof` or any other member in this revision.

5.3. **Creating a proof.** Let `options` be the proof object without `proofValue`. Compute

```
hashData = SHA-256(JCS(options)) ‖ SHA-256(JCS(record without "proof"))
proofValue = "z" + base58btc( Ed25519-Sign(privateKey, hashData) )
```

and append `options` plus `proofValue` to the record's `proof` array. Every proof in a set is computed over the record without its `proof` member, so proofs can be created in any order and merged by union.

5.4. **Verifying a proof.** Check that the proof has exactly the members 5.2 allows; remove `proofValue` from a copy of the proof to obtain `options`; check that `type` and `cryptosuite` have the required values and that `proofPurpose` is the one 5.6 requires for the record's type; if the record has `@context`, check that the proof's `@context` has the same value; compute `hashData` as in 5.3; resolve the verification method to an Ed25519 public key (Section 6 and Layer 1, Section 6); and verify the signature as in 4.4.

5.5. A record MAY carry proofs that are irrelevant to its validity. Each proof is evaluated independently; an invalid proof does not invalidate the record, but it never counts towards any requirement. Because every proof covers only the record's content (5.3), one proof is never evidence that another proof existed.

5.6. **Proof purposes.**

| Records | `proofPurpose` |
|---|---|
| Identity-log events (`Genesis`, `Update`, `Fork`, `Merge`, `Retire`) | `capabilityInvocation` |
| `Delegation` | `capabilityDelegation` |
| `Hello` (authentication) | `authentication` |
| All other signed records | `assertionMethod` |

A proof with any other purpose MUST NOT count towards the validity of the record.

5.7. A proof's `created` SHOULD NOT be earlier than the record's `created`.

## 6. References

6.1. References use DID syntax (W3C DID Core) and are defined by this grammar (ABNF, RFC 5234):

```
content-id       = "b" 55base32char
base32char       = %x61-7A / %x32-37            ; a-z, 2-7
mind-address     = "did:oip:" content-id
seq              = "0" / (%x31-39 *DIGIT)
version-id       = seq "-" content-id
versioned-mind   = mind-address "?versionId=" version-id
multikey         = "z" 1*base58char
key-ref          = versioned-mind "#" multikey
control-key-ref  = "did:key:" multikey "#" multikey
record-ref       = mind-address "/" content-id
```

6.2. A proof by a mind's operational key MUST use a `key-ref`, which pins the version of the mind's identity at which the key is asserted to be valid. A proof by a control key MUST use a `control-key-ref` in which both occurrences of the Multikey are identical.

6.3. A `record-ref` names a record by its content ID and says which mind's records to fetch it from. The content ID alone is sufficient to check that a fetched record is the one referenced.

6.4. User interfaces MAY abbreviate addresses for display. Abbreviated forms MUST NOT be used in records or for verification.

## 7. Common fields

| Field | Meaning |
|---|---|
| `oip` | REQUIRED in every record. The string `"1"`. Records with any other value MUST be rejected. |
| `type` | REQUIRED in every record. A record type defined by this specification or by a critical extension. |
| `author` | The mind making a statement. Identity events use `mind` and packets use `from` instead. |
| `created` | REQUIRED in every record except `Bundle` and `Sealed`. The author's claimed creation time: a claim, never evidence of when the record existed (Section 9). |
| `expires` | OPTIONAL. After this instant the record is closed for any purpose that depends on it being open. |
| `ext` | OPTIONAL. Extension blocks (Section 8). |
| `critical` | OPTIONAL. Extension namespaces the reader must understand (Section 8). |
| `proof` | The proof set (Section 5). |

## 8. Extensions and forward compatibility

8.1. `ext` is an object whose member names are **namespaces** and whose values are objects. A namespace is one of:
- a reverse-DNS name matching `^[a-z0-9-]+(\.[a-z0-9-]+)+$`, such as `com.example.escrow`;
- a short name recognised by this specification: `x402`, `ap2`, `acp`, `l402`, `vc`, `as2`;
- a name beginning `oip.`, reserved for profiles published by the OIP project.

8.2. An extension block MAY contain a member `v` giving its own version.

8.3. `critical` is an array of namespaces, each of which MUST also appear in `ext`. An implementation that does not understand a namespace listed in `critical` MAY store and forward the record but MUST NOT act on it or treat it as valid for any decision.

8.4. Extensions MUST NOT change the validity of a record under this specification unless they are listed in `critical`.

8.5. Within major version `"1"`, later revisions MAY add OPTIONAL members. A member whose being ignored by an older implementation would be unsafe MUST instead be introduced as an `oip.*` extension that records list in `critical`.

## 9. Time

9.1. Implementations MUST tolerate clock skew of up to 300 seconds when checking whether a record is from the future, has expired or is fresh.

9.2. `created`, in a record or in a proof, is asserted by the signer. A signer holding a stolen, removed or expired key can write any `created` it likes, so no rule that protects anyone may depend on `created` alone.

9.3. **Evaluation time.** Every rule that depends on when a proof was made (key removal and compromise, retirement, delegation `notBefore` and `expires`, revocation, collective membership and charter roles) is evaluated at the proof's **evaluation time**

```
t(p) = max( p.created, τ(p) )
```

where `τ(p)` is the earliest time for which the verifier holds evidence (9.4) that the proof existed. A verifier that holds no such evidence uses the time at which it first obtained the proof, so for a proof received live `t(p)` is the time of receipt. A proof whose `created` is more than 300 seconds after `τ(p)` MUST NOT count for anything.

9.4. **Evidence that a proof existed** at time `t` is one of:
1. the verifier's own record that it obtained the proof at `t`;
2. the record of a witness the verifier chooses to trust, such as its resolver or indexer, that it first saw the proof at `t` (Layer 1, Section 17);
3. an anchored checkpoint (Layer 1, Section 10) covering a feed entry that commits to the proof, where `t` is the anchor's time;
4. an `Ack` (Layer 1, Section 13.2) covering a packet that carries the proof, signed by a recipient the verifier trusts for this purpose, where `t` is its `received` time.

A proof's own `created` is never evidence, and neither is another proof on the same record (5.5).

9.5. **Identity events** are statements by a mind's controllers about the mind itself. The times at which they remove keys, declare compromise, change membership or retire the mind are taken from their own `created` (Layer 1, Section 6). Controllers who backdate such an event repudiate records they made, which is attributable to them; it gives them no power they lack otherwise.

9.6. **Consequence.** A verifier that first sees a record long after it was made can count its proofs only from that moment, unless evidence shows they existed earlier. To keep records verifiable after the keys that signed them are removed or a delegation expires, minds publish them in feeds whose checkpoints are anchored (Layer 1, Section 10).

## 10. Media type and errors

10.1. OIP records are exchanged as `application/oip+json`.

10.2. HTTP APIs report errors as RFC 9457 problem details with a `type` of the form `urn:oip:error:<code>`:

| Code | HTTP status | Meaning |
|---|---|---|
| `invalid-record` | 400 | Not a well-formed record of the expected type |
| `invalid-proof` | 400 | A required proof is missing or does not verify |
| `unsupported-critical` | 400 | The record lists a critical extension the server does not understand |
| `expired` | 400 | The record has expired or is too old |
| `stale-version` | 409 | The record pins an identity version the server cannot reach or that has been superseded where the latest is required |
| `duplicity` | 409 | The mind's identity log is duplicitous |
| `unauthorised` | 401 | Authentication is missing or invalid |
| `forbidden` | 403 | Authenticated, but not permitted |
| `not-found` | 404 | Unknown mind or record |
| `too-large` | 413 | The record exceeds a size limit |
| `rate-limited` | 429 | Too many requests |

## 11. Security considerations

The security analysis of the protocol is in Section 8 of the technical architecture paper. Three rules from this document are essential: proofs are evaluated independently, so an attacker cannot invalidate a record by adding a bad proof; unknown fields are preserved, so a record can never be altered silently by an implementation that does not understand part of it; and time rules use evidence rather than claims (Section 9), so a stolen or retired key cannot be used by writing an earlier date.
