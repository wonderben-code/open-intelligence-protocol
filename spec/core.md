# OIP Core: Records, Identifiers and Proofs

**Revision 2026-11-17 · Status: Draft · Licensed under CC BY 4.0**

This document defines what every OIP record has in common, at every layer. See [README.md](README.md) for conventions.

## 1. Records

1.1. A **record** is a JSON object (RFC 8259), encoded as UTF-8, that is also an I-JSON message (RFC 7493): it MUST NOT contain duplicate member names, and every string, member names included, MUST be valid Unicode with no noncharacter in it: no unpaired surrogate, no code point from U+FDD0 to U+FDEF, and no code point whose last sixteen bits are FFFE or FFFF (RFC 7493, Section 2.1). Receivers SHOULD reject records with duplicate member names. Content IDs and proofs cover the record as parsed, so a receiver that cannot detect duplicates may disagree with others about whether a record is valid, but never accepts a value its signer did not sign.

1.2. The values permitted anywhere in a record are objects, arrays, strings, `true`, `false`, `null`, and numbers whose value is an integer `n` with −(2⁵³−1) ≤ `n` ≤ 2⁵³−1. A record containing a number whose value has a fractional part, or lies outside that range, MUST be rejected. Validity depends on a number's value, not on how it is written: `1.0` and `1e2` are the integers 1 and 100, which canonical form writes as `1` and `100`. Producers MUST write integers without a fraction or exponent.

1.3. **Decimal quantities** (prices, amounts, scores) MUST be strings matching `^-?(0|[1-9][0-9]*)(\.[0-9]+)?$`, using the ASCII digits only. **Amounts** (prices, budgets and other sums of money or assets) MUST be non-negative, matching `^(0|[1-9][0-9]*)(\.[0-9]+)?$`. Wherever this specification compares two decimal strings, the comparison is numeric. Ordering comparisons (less than, greater than) are defined only between decimals; a string that does not match the pattern is not a decimal, however it looks (`"1,000"`, `"1e2"`, `" 400 "`, `"-Infinity"` and full-width digits are not decimals). A decimal string MUST NOT exceed 64 characters, and decimals are compared with exact decimal arithmetic, never binary floating point. `"-0"`, with or without a fraction of zeros, is a decimal equal to `"0"`; it is not an amount, because an amount has no sign.

1.4. **Timestamps** MUST be RFC 3339 strings in UTC matching `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$` that name a real date and time (no month 13, no second 60 or above). Years run from `0000` to `9999` of the proleptic Gregorian calendar, as in RFC 3339; year `0000` is a leap year. Timestamps are compared as instants at full precision (up to nanoseconds), never as strings.

1.5. **Durations** MUST be ISO 8601 durations matching `^P(?!$)([0-9]+D)?(T(?=[0-9])([0-9]+H)?([0-9]+M)?([0-9]+S)?)?$`, for example `P30D` or `PT15M`. A duration string MUST NOT exceed 64 characters.

1.6. **Size.** The canonical form (Section 2) of a record, with its `proof` member, MUST NOT exceed 1 MiB. Implementations MAY apply lower limits to particular record types but MUST accept records of at least 256 KiB. Larger content is carried by reference (Layer 1, Section 12). `Bundle`, `LogPage`, `FeedPage` and `DuplicityEvidence` are containers: the limit applies to each record they contain, and to the container without the members that hold those records (`log`, `location` and `participant` of a `Bundle`; `events`; `entries`; `pairs`). It does not apply to the two together. A `Sealed` record MAY exceed the limit by its encoding overhead.

1.7. **Field names** use camelCase. Implementations MUST preserve fields they do not recognise when storing or forwarding a record, because those fields are covered by its proofs, and MUST otherwise ignore them (Section 8).

1.8. **String lengths** ("at most N characters") are counted in Unicode code points.

1.9. **Depth.** The arrays and objects of a record MUST NOT nest more than 64 deep: the record itself is at depth 1, and a value that is neither an array nor an object adds no depth. A record that nests more deeply MUST be rejected. For a container (1.6), the limit applies to each record it contains, counted from that record, and to the container without the members that hold them, so that a container can carry any record that is valid alone. The rules of this section apply to the whole record, including every entry of `proof`.

## 2. Canonical form

2.1. The canonical form of a JSON value is its serialisation under the JSON Canonicalization Scheme, RFC 8785 (JCS). Object members are sorted by the UTF-16 code units of their names, no insignificant whitespace is emitted, and strings use the minimal escaping that RFC 8785 specifies.

2.2. Because Section 1.2 restricts numbers to safe integers, JCS number serialisation reduces to the shortest decimal form of the integer, and `-0` serialises as `0`.

## 3. Content identifiers

3.1. The **content ID** of a record `r` is:

```
contentId(r) = "b" + base32lower( 0x12 ‖ 0x20 ‖ SHA-256( JCS( r without member "proof" ) ) )
```

`base32lower` is the RFC 4648 base32 alphabet in lower case without padding. The bytes `0x12 0x20` are the multihash prefix for a 32-byte SHA-256 digest, and `b` is the multibase prefix for lower-case base32.

3.2. In this revision a content ID MUST match `^bciq[a-p][a-z2-7]{50}[aiqy]$` (56 characters, lower case only). The fixed start encodes the multihash prefix `0x12 0x20`, and the last character carries only two bits of the digest, so this pattern admits exactly one spelling of each digest. Content IDs are compared as strings; a spelling that decodes to the same bytes but does not match the pattern MUST be rejected. A later revision that adds a hash function will change the pattern and the length of content IDs.

An OIP content ID is a multibase-encoded multihash. It is not an IPFS CID: storing OIP records in a content-addressed store such as IPFS requires a mapping to a CIDv1, and the stored bytes (the canonical form without proofs) do not carry the record's proofs.

3.3. The 32-byte digest inside a content ID equals the `transformedDocumentHash` of every `eddsa-jcs-2022` proof on the record (Section 5).

3.4. The **key hash** of a Multikey string `k`, used for pre-rotation commitments, is `"b" + base32lower(0x12 ‖ 0x20 ‖ SHA-256(UTF-8(k)))`. A key hash has the form of a content ID and MUST match the pattern of 3.2.

## 4. Keys

4.1. Public keys are written as **Multikey** strings: `"z"` followed by the base58btc encoding of a multicodec prefix and the raw key bytes.

| Key type | Multicodec prefix | Raw length | String prefix |
|---|---|---|---|
| Ed25519 public key | `0xed 0x01` | 32 bytes | `z6Mk` |
| X25519 public key | `0xec 0x01` | 32 bytes | `z6LS` |

4.2. Implementations MUST check the prefix and length of every Multikey they use and reject any that do not match the expected type.

4.3. This revision requires Ed25519 for signatures and X25519 for encryption. Other key types are reserved for later revisions; adding one is a change to the verification rules, not only to the format, because verifiers of this revision reject proofs by keys of other types.

4.4. **Ed25519 verification.** Every implementation MUST apply the same rule, so that all verifiers agree on which signatures are valid. A signature (`R`, `S`) by public key `A` is valid only if all of these hold:
1. `S` is less than the group order L;
2. `A` and `R` are canonical encodings of curve points, decoded as in RFC 8032, Section 5.1.3 (in particular, the encoded y-coordinate is less than 2²⁵⁵ − 19);
3. `A` and `R` each have order exactly L: [L]P is the identity and P is not the identity. This excludes the identity point, for which anyone can sign anything, and every point with a small-order component;
4. [S]B = R + [k]A, with k as in RFC 8032, Section 5.1.7.

Because no point with a torsion component is accepted, the cofactored and cofactorless forms of the equation agree. An Ed25519 public key that does not have order exactly L MUST be rejected wherever it appears, including in identity logs. Libraries whose defaults are more permissive (OpenSSL accepts small-order and mixed-order points, and ZIP 215 rules also accept non-canonical encodings) MUST be configured or wrapped to apply this rule. The test vectors include keys and signatures on each side of it.

## 5. Proofs

5.1. A signed record carries a member `proof` whose value MUST be a non-empty array of at most 256 proof objects (a W3C Data Integrity *proof set*). Every entry MUST be a JSON object. An entry that is an object but is not a valid proof does not count (5.5) and does not make the record malformed. Records that this specification defines as unsigned (such as `Bundle`, `Session` and `Sealed`) MUST NOT carry `proof`.

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
| `authority` | no | What this proof relies on to count for a mind other than its signer: exactly one delegation chain, as 1–8 `record-ref`s or inline `Delegation` records, root first (Layer 1, Section 11.6); or exactly one charter, as a `record-ref` or an inline `Collective` record (Layer 2, Section 7.1) |
| `@context` | no | Present if and only if the record has `@context`, with the same value |

A proof MUST NOT contain `id`, `previousProof` or any other member in this revision.

5.3. **Creating a proof.** Let `options` be the proof object without `proofValue`. Compute

```
hashData = SHA-256(JCS(options)) ‖ SHA-256(JCS(record without "proof"))
proofValue = "z" + base58btc( Ed25519-Sign(privateKey, hashData) )
```

and append `options` plus `proofValue` to the record's `proof` array. Every proof in a set is computed over the record without its `proof` member, so proofs can be created in any order and merged by union. Everything in `options`, including `authority`, is covered by that proof's signature.

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
content-id       = "bciq" %x61-70 50base32char final-char
base32char       = %x61-7A / %x32-37            ; a-z, 2-7
final-char       = "a" / "i" / "q" / "y"         ; low bits zero
base58char       = %x31-39 / %x41-48 / %x4A-4E / %x50-5A / %x61-6B / %x6D-7A
mind-address     = "did:oip:" content-id
seq              = "0" / (%x31-39 *DIGIT)
version-id       = seq "-" content-id
versioned-mind   = mind-address "?versionId=" version-id
multikey         = "z" 1*base58char
key-ref          = versioned-mind "#" multikey
control-key-ref  = "did:key:" multikey "#" multikey
record-ref       = mind-address "/" content-id
```

`seq` is the position of an identity event in its log, which is an integer of a record (1.2): a `seq` greater than 2⁵³−1 names no event.

6.2. A proof by a mind's operational key MUST use a `key-ref`, which pins the version of the mind's identity at which the key is asserted to be valid. A proof by a control key MUST use a `control-key-ref` in which both occurrences of the Multikey are identical.

6.3. A `record-ref` names a record by its content ID and says which mind's records to fetch it from. A record-ref matches a record when its content ID equals the record's content ID; the mind part is only a hint for fetching and MUST be ignored when matching. The content ID alone is sufficient to check that a fetched record is the one referenced.

6.4. User interfaces MAY abbreviate addresses for display. Abbreviated forms MUST NOT be used in records or for verification.

## 7. Common fields

| Field | Meaning |
|---|---|
| `oip` | REQUIRED in every record. The string `"1"`. Records with any other value MUST be rejected. |
| `type` | REQUIRED in every record. A record type defined by this specification or by a critical extension: a record whose `type` this specification does not define MUST list in `critical` the namespace of the extension that defines it, and a reader that does not understand that extension treats the record as Section 8.3 says. |
| `author` | The mind making a statement. Identity events use `mind` and packets use `from` instead. |
| `created` | REQUIRED in every record except the containers and `Sealed` (Section 11), which have no such member: a reader ignores one there, as it ignores any member it does not recognise (Section 1.7). The author's claimed creation time: a claim, never evidence of when the record existed (Section 9). |
| `expires` | OPTIONAL. After this instant the record is closed for any purpose that depends on it being open. |
| `ext` | OPTIONAL. Extension blocks (Section 8). |
| `critical` | OPTIONAL. Extension namespaces the reader must understand (Section 8). |
| `proof` | The proof set (Section 5). |

## 8. Extensions and forward compatibility

8.1. `ext` is an object whose member names are **namespaces** and whose values are objects. A namespace is one of:
- a reverse-DNS name matching `^[a-z0-9-]+(\.[a-z0-9-]+)+$`, such as `com.example.escrow`;
- a short name recognised by this specification: `x402`, `ap2`, `acp`, `l402`, `vc`, `as2`;
- a name beginning `oip.`, reserved for profiles published by the OIP project.

A record whose `ext` has a member with any other name is malformed.

8.2. An extension block MAY contain a member `v` giving its own version.

8.3. `critical` is an array of namespaces, each of which MUST also appear in `ext`. Naming a namespace more than once has the effect of naming it once. An implementation that does not understand a namespace listed in `critical` MAY store and forward the record but MUST NOT act on it or treat it as valid for any decision.

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

A proof's own `created` is never evidence, and neither is another proof on the same record (5.5). Evidence concerns one proof: adding a proof does not change a record's content ID (5.3), so evidence that a record existed with some proofs is not evidence for a proof added to it later. Implementations therefore key evidence by the proof's digest, `"sha256:" + hex(SHA-256(JCS(proof)))` (Layer 1, Section 10.1). For identity events, evidence concerns the event as a whole (9.5).

**Holding the evidence.** Comparing two times means something only if both come from evidence. Before counting a proof `p` by a key of mind `X`, a verifier MUST hold `X`'s identity log as a witness it trusts (Layer 1, Section 17) served it at some time no earlier than `τ(p)`, together with that witness's first-seen times, unless the verifier has itself followed `X`'s log as a witness since before `τ(p)`. It MUST take the evaluation times of `X`'s events from the earliest evidence it holds (the witness's first-seen times, or anchors), never from its own later first sight of them. Otherwise the former holder of a removed key could sign after the removal and win the race against the verifier's own first sight of it. The same is required of each log that decides whether the proof counts: the log of a collective under whose threshold the proof is counted (Layer 1, Section 9.5), held as served no earlier than `τ(p)`; and, for a member's proof on an identity event `e`, the member's log, held as served no earlier than the latest `τ` among `e` and the events before it in its log, since `e` takes effect no earlier than they do (9.5).

9.5. **Identity events.** The evaluation time of an identity event `e` is `max(e.created, τ(e))`, where `τ(e)` is the earliest time for which the verifier holds evidence that `e` existed with proofs meeting Layer 1, Section 4: its own first-seen record, a trusted witness's first-seen record, or an anchored checkpoint covering a feed entry for `e`. It is never earlier than the evaluation time of the event before it in the same log, and an event whose `created` is more than 300 seconds after `τ(e)` does not verify for that verifier. An event that removes a key, changes membership or retires a mind takes effect at its evaluation time, so a backdated event cannot withdraw records already made. Members' proofs on a collective's identity events are judged at the event's evaluation time (Layer 1, Section 6.4). Evidence for an event is evidence for the proofs it stood with, and for no proof added to it later: a verifier or a witness records its first sight of an event only once the event has verified, never on sight of its content alone, which the content ID names with or without valid proofs. It does so as soon as the event verifies for it, with every proof it holds for the event, in however many copies they came (Layer 1, 7.1), and with the logs those proofs are judged by: recorded later, a proof by a key the event removes that was first seen in between would count. For the same reason a feed entry is evidence for an event only if it commits to proofs that make the event valid (Layer 1, Section 10.1): anyone can list a content ID in a feed of their own. For a proof on an identity event, `τ(p)` is `τ(e)`: a proof there whose `created` is more than 300 seconds after `τ(e)` does not count (9.3), and one evaluated more than 300 seconds after the event's `expires` does not count (9.6). The one deliberately retroactive statement is `compromisedSince` (Layer 1, Section 6.2), and it reaches back only over the mind's own records: it is public and attributable, and a Commitment that loses a party's signature this way shows as `disputed` (Layer 2, Section 8.3) rather than silently changing.

9.6. **Expiry.** A proof whose evaluation time is more than 300 seconds after its record's `expires` does not count.

9.7. **Consequence.** A verifier that first sees a record long after it was made can count its proofs only from that moment, unless evidence shows they existed earlier. To keep records verifiable after the keys that signed them are removed or a delegation expires, minds publish them in feeds whose checkpoints are anchored (Layer 1, Section 10). The same holds for a collective's identity: once a member has removed the invocation key that signed one of its events, only evidence shows that the event came first (Layer 1, Section 9.6).

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

## 11. Record types

| Record | Signed | Signed by | `proofPurpose` | Key rule (Layer 1) | Defined in |
|---|---|---|---|---|---|
| `Genesis`, `Update`, `Fork`, `Retire` | yes | Control keys (key-controlled); members' invocation keys (collectives) | `capabilityInvocation` | Pre-rotation (4.3); members' keys at the event's evaluation time (6.4) | Layer 1, 3–4 |
| `Merge` | reserved | | | | Layer 1, 3.9 |
| `Delegation` | yes | Author's own authority | `capabilityDelegation` | 6.1 | Layer 1, 11 |
| `Revocation`, `Lineage`, `Collective` | yes | Author's own authority | `assertionMethod` | 6.1 | Layer 1, 8 and 11; Layer 2, 6 |
| `Intent`, `Offer`, `Commitment`, `Receipt` | yes | Author, or parties through delegation or roles | `assertionMethod` | 6.1 | Layer 2 |
| `Packet` | yes | Sender | `assertionMethod` | 6.1 | Layer 1, 12 |
| `Entry`, `Checkpoint`, `Ack`, `QueryResult`, `Forwarded` | yes | Author | `assertionMethod` | 6.1 | Layer 1, 10, 13, 18 |
| `Location`, `Participant` | yes | Author's own authority | `assertionMethod` | 6.1 with the current-state rule; a collective's threshold under its latest membership | Layer 1, 15–16 |
| `Hello` | yes | Author's own key | `authentication` | 6.1 with the current-state rule | Layer 1, 13.3 |
| `Session`, `Resume`, `Branch` | no | | | | Layer 1, 14 |
| `Bundle`, `LogPage`, `FeedPage`, `DuplicityEvidence`, `Sealed` | no | | | Containers (1.6) | Layer 1, 7, 12–13, 17 |

"Own authority" means one of the author's valid operational keys or, for a collective, its member threshold (Layer 2, Section 7.2). Records marked unsigned MUST NOT carry `proof`; the containers carry no `created`.

## 12. Security considerations

The security analysis of the protocol is in Section 8 of the technical architecture paper. Three rules from this document are essential: proofs are evaluated independently, so an attacker cannot invalidate a record by adding a bad proof (for an identity event that a verifier holds in several copies, Layer 1, Section 7.1 says which copies' proofs count), and the limits on size and depth (1.6, 1.9) are applied to each record a container carries and never to the container as a whole, so an attacker cannot stop a log or a feed from being served by adding one; unknown fields are preserved, so a record can never be altered silently by an implementation that does not understand part of it; and time rules use evidence rather than claims (Section 9), so a stolen or retired key cannot be used by writing an earlier date.
