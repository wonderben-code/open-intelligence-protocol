# OIP Layer 1: the Mind Network

**Revision 2026-10-31 · Status: Draft · Licensed under CC BY 4.0**

This document specifies mind addresses, identity logs, lineage, collectives, delegation, feeds, packets, sessions, location records, profiles, resolution and capability routing. It depends on [core.md](core.md). Rationale is in Section 5 of the [technical architecture paper](../papers/02-technical-architecture.md). "Evaluation time" and `t(p)` are defined in core, Section 9.

## 1. Overview

Every mind has an **identity log** (who it is), a **location record** (where it is), a **Participant profile** (what it is and can do) and a **public feed** (what it has published). Its address is derived from the first event of its identity log.

## 2. Mind addresses: the `did:oip` method

2.1. The DID method name is `oip`. The method-specific identifier is a content ID (core, Section 3).

2.2. A mind's address is `did:oip:` followed by the content ID of the mind's `Genesis` event.

2.3. **Create** is the creation of a `Genesis` event. **Read** is the replay of the identity log (Section 4) and the projection described in Section 5. **Update** is the appending of an `Update` or `Fork` event (`Merge` is reserved). **Deactivate** is the appending of a `Retire` event.

2.4. Resolution MUST support the DID parameter `versionId`, whose value is a `version-id` (core, Section 6): the document is produced from the log up to and including the identified event.

## 3. Identity-log events

3.1. An identity log is an ordered array of events. The first is a `Genesis`; each later event is an `Update`, `Fork`, `Merge` or `Retire`.

3.2. **Common fields of later events.** Every event after the genesis MUST contain `mind` (the address), `seq` (an integer one greater than the previous event's, the genesis having position 0) and `prev` (the content ID of the previous event), and its `created` MUST NOT be earlier than the previous event's. A `Genesis` MUST NOT contain `mind`, `seq` or `prev`.

3.3. **Version identifiers.** The version identifier of an event is `<seq>-<contentId>`, with `seq` = 0 for the genesis.

3.4. **Controllers.** A mind is either key-controlled or member-controlled, fixed at genesis.

A **key controller** is an object:

| Member | Type | Rules |
|---|---|---|
| `keys` | array of Ed25519 Multikeys | 1–16 distinct keys revealed by this event |
| `next` | array of key hashes (core 3.4) | 0–16 distinct entries; commitments to the keys that will sign the next event. An empty array means the log can never be extended. |
| `nextThreshold` | integer | When `next` is non-empty: OPTIONAL, default 1, and 1 ≤ `nextThreshold` ≤ length of `next` and 2 × `nextThreshold` > length of `next`. When `next` is empty: MUST be absent. |

A **member controller** is an object:

| Member | Type | Rules |
|---|---|---|
| `members` | array of mind addresses | 1–256 distinct addresses, not including the mind itself |
| `threshold` | integer | 1 ≤ `threshold` ≤ length of `members`, and 2 × `threshold` > length of `members` |

Thresholds are majorities so that any two valid events at the same position share at least one signer: duplicity (Section 7) is then always attributable to a key or member that signed twice. Lower thresholds for routine work belong in a collective's charter (Layer 2, Section 6.2), not in its identity log.

3.5. **Key entries.** `keys` at the top level of an event lists operational signing keys as objects `{ "key": <Ed25519 Multikey>, "label": <string, optional, at most 64 characters> }`, at most 64 entries. `agreement` lists encryption keys in the same form with X25519 Multikeys, at most 16 entries.

3.6. **`Genesis`.**

| Member | Required | Value |
|---|---|---|
| `oip`, `type`, `created`, `proof` | yes | core |
| `kind` | yes | `human`, `agent`, `collective`, `institution`, `service`, or another string of at most 64 characters |
| `controller` | yes | A key controller or a member controller |
| `keys` | no | Operational keys (3.5) |
| `agreement` | no | Encryption keys (3.5) |
| `homes` | no | 0–8 HTTPS origins that serve the mind's records |
| `alsoKnownAs` | no | 0–16 URIs (Section 5.3) |
| `parents` | no | 0–16 objects `{ "mind": <address>, "at": <version-id> }` (Section 8) |
| `inherits` | no | An object describing what a fork started with; a claim only |
| `ext`, `critical` | no | core |

If `kind` is `collective`, the controller MUST be a member controller.

3.7. **`Update`.** In addition to the common fields of 3.2: `controller` (REQUIRED for key-controlled minds, revealing the keys committed by the previous event and committing new ones; OPTIONAL for member-controlled minds, present only when membership or threshold changes); and any of `keys`, `agreement`, `homes`, `alsoKnownAs`, which replace the previous values when present; and `revoked`, an array of `{ "key": <Multikey>, "compromisedSince": <timestamp, optional> }`. Leaving a key out of `keys` removes it: it can sign nothing after this event (Section 6). Listing it in `revoked` with `compromisedSince` also withdraws what it signed from that time on.

3.8. **`Fork`.** In addition to the common fields: `child` (REQUIRED, the address of the child mind), `controller` (as in 3.7) and `terms` (OPTIONAL object describing what the child received). A `Fork` records lineage in the identity log itself; a `Lineage` record (Section 8.3) acknowledges a child without using the control keys.

3.9. **`Merge`** is reserved. A verifier of this revision MUST reject a log that contains a `Merge` event. A later revision will define it; that will be a change to the verification rules, not only to the format.

3.10. **`Retire`.** In addition to the common fields: `controller` (as in 3.7, with `next` empty for key-controlled minds), `successor` (OPTIONAL address) and `reason` (OPTIONAL string). No event may follow a `Retire`, whether the mind is key-controlled or member-controlled. After a `Retire`, the mind's keys can sign nothing (Section 6).

3.11. Identity events are signed with `proofPurpose` `capabilityInvocation`. Proofs by control keys use `control-key-ref` verification methods; proofs by members use those members' `key-ref`s, with keys valid under Section 6.

3.12. **Reserved names.** The member name `recovery` is reserved in identity events for key recovery in a later revision. A verifier of this revision MUST reject an event that contains it.

## 4. Verifying an identity log

A verifier MUST reject a log unless all of the following hold.

4.1. **Genesis.** The first event has `type` `Genesis` and no `mind`, `seq` or `prev`, and its controller satisfies Section 3.4. If key-controlled, every key in `controller.keys` has a valid proof on the genesis with its own `control-key-ref`. If member-controlled, every member in `controller.members` has a proof on the genesis by one of its own valid operational keys (Section 6). The mind's address is `did:oip:` + `contentId(genesis)`.

4.2. **Chain.** Every later event has `mind` equal to the address, `seq` equal to the previous `seq` plus one, `prev` equal to the content ID of the previous event, and a `created` not earlier than the previous event's.

4.3. **Key-controlled authority.** For each later event `e` with predecessor state `S`: `e.controller` satisfies Section 3.4; `S.next` is non-empty; `e.controller.keys`, whose entries are distinct, has at least `S.nextThreshold` entries; the key hash of each is in `S.next`; and each has a valid proof on `e` with its own `control-key-ref` and `proofPurpose` `capabilityInvocation`. The new state takes `next` and `nextThreshold` from `e.controller`.

4.4. **Member-controlled authority.** For each later event `e` with predecessor state `S`: at least `S.threshold` distinct members of `S.members` have proofs on `e` by their own valid operational keys (Section 6); if `e.controller` is present it satisfies Section 3.4, and every member it adds has such a proof on `e`. If `e.controller` is present, the new state takes `members` and `threshold` from it.

4.5. **Fields.** `keys`, `agreement`, `homes` and `alsoKnownAs` replace the state's values when present. Keys listed in `revoked` MUST NOT appear in the resulting `keys`; if `revoked` is present and `keys` is absent, the resulting keys are the previous keys minus the revoked ones. The state records each revoked key's `compromisedSince`, keeping the earliest if a key is revoked more than once.

4.6. **Types and termination.** Every event's `type` is checked: the first is `Genesis` and every later one is `Update`, `Fork` or `Retire`. A log containing any other type, including `Merge`, or an event containing `recovery`, is rejected. No event follows a `Retire`.

4.7. **Nesting and work.** Verifying a member's proof requires verifying that member's own log. Verifiers MUST bound this recursion to a depth of 4 collectives, and MAY refuse logs longer, or records with more proofs, than they are configured to process, but MUST accept logs of at least 1,000 events and records with up to 256 proofs.

## 5. Identity state and the DID document

5.1. Replaying a log produces the **identity state**: address, kind, controller state (`next` and `nextThreshold`, or `members` and `threshold`), operational keys, agreement keys, homes, aliases, parents, acknowledged children, revocations with their compromise times, the latest version identifier, and whether the mind is retired.

5.2. **DID document.** Resolving a `did:oip` address produces a DID Core document:
- `id`: the address.
- `verificationMethod`: one entry per operational key and per agreement key, `{ "id": <address> "#" <multikey>, "type": "Multikey", "controller": <address>, "publicKeyMultibase": <multikey> }`. When the document is produced for a `versionId`, each `id` is the versioned form `<address>?versionId=<version-id>#<multikey>`, so that a key reference in a proof matches a verification method's `id` exactly.
- `authentication`, `assertionMethod`, `capabilityInvocation`, `capabilityDelegation`: the operational keys' ids (operational keys sign collective identity events with `capabilityInvocation`). `keyAgreement`: the agreement keys' ids. Control keys are not listed.
- `service`: one entry per home, `{ "id": <address> "#home-" <n>, "type": "OIPHome", "serviceEndpoint": <origin> }`, and, if a current location record is known, one per endpoint, of type `OIPEndpoint`.
- `alsoKnownAs`: the aliases that have been verified in both directions (5.3).
- DID document metadata includes `versionId`, `nextKeyHashes` and `nextThreshold` (or `members` and `threshold`), `parents`, `children` and `deactivated` (true when retired).

5.3. **Aliases.** An entry in `alsoKnownAs` is verified only when the alias points back to the mind: another DID whose document lists this address in its own `alsoKnownAs`; or an HTTPS origin that serves this address, alone, as `text/plain` at `/.well-known/oip/did`; or a DNS name with a TXT record at `_oip.<name>` whose value is `did=<address>`. A DID whose documents cannot list `alsoKnownAs`, such as `did:key`, cannot be a verified alias. Unverified aliases MUST NOT be presented as verified.

## 6. Key validity

6.1. A proof `p` on a record of type `T`, whose verification method is `did:oip:X?versionId=V#K`, is by a **valid operational key** of `X` if, and only if, all of these hold:
1. `X`'s log verifies and `V` identifies an event in it;
2. `K` is in the operational keys of the state at `V`;
3. if a later event in the log removes `K` from the operational keys, or retires the mind, `t(p)` is earlier than that event's `created`;
4. no revocation of `K` in the log has a `compromisedSince` at or before `t(p)`;
5. `p.proofPurpose` is the purpose core 5.6 requires for `T`;
6. for records that describe a mind's **current** state (`Location`, `Participant`, `Entry`, `Checkpoint`, `Ack`, `QueryResult` and `Hello`), `K` is also in the operational keys of the latest state of `X` that the verifier knows, and the mind is not retired;
7. the signature verifies (core 5.4).

`t(p)` is the proof's evaluation time (core 9.3). Removal and compromise times are taken from the identity events (core 9.5).

6.2. Removing a key stops it signing anything new while leaving what it signed earlier valid, provided a verifier has evidence of when those proofs existed (core 9.6). Marking a key compromised also withdraws what it signed from the compromise time on.

6.3. When a verifier encounters a `versionId` it does not have, it SHOULD fetch the missing events (Section 17) before deciding. A verifier that does not know about a later event cannot apply it, so verifiers SHOULD refresh a mind's log from their resolver before decisions whose value warrants it.

## 7. Duplicity

7.1. Two different events in logs with the same genesis, at the same `seq`, each valid against the same predecessor, constitute **duplicity**. Because thresholds are majorities (Section 3.4), every case of duplicity has at least one control key or member that signed both events.

7.2. Resolvers MUST retain the first valid event they saw at each position of each log, MUST record when they first saw it, and MUST publish any conflicting valid event as evidence (Section 17).

7.3. **Resolution.** A verifier MUST NOT choose between conflicting branches by their length or by which is more recent. It resolves duplicity at the point of divergence by evidence (core 9.4): the branch whose event at that position has the earlier evidence wins. If its evidence cannot separate the branches, the mind is **duplicitous** for that verifier, which MUST NOT accept records from the mind that are pinned to versions after the point of divergence, or current-state records. Records pinned to versions before the divergence remain valid.

7.4. **Protecting the log.** Implementations MUST destroy a control key's private part once the event it signs has been published, so that a used control key cannot sign an alternative event. Minds SHOULD publish each identity event to at least two independent resolvers, which act as witnesses, and MAY anchor their logs (Section 10.6). After a custody handover (Layer 0, Section 6) has been witnessed, the former custodian can only create duplicity, which this rule resolves against it.

## 8. Lineage

8.1. A **fork** is a new mind whose genesis lists a parent in `parents`, with `at` naming the version of the parent from which it was forked.

8.2. Lineage is **acknowledged** when the child's `at` names a version of the parent and either the parent's log contains, at or after that version, a `Fork` event whose `child` is the child's address, or the parent has signed a valid `Lineage` record naming the child. Otherwise the lineage is **claimed**.

8.3. A **`Lineage`** record acknowledges a child without using the parent's control keys:

| Member | Required | Value |
|---|---|---|
| `author` | yes | The parent |
| `child` | yes | The child's address |
| `terms` | no | Object describing what the child received; a claim only |
| `created`, `proof` | yes | Signed by the parent's own authority: one of its valid operational keys, or for a collective its threshold (not by a delegate) |

8.4. A fork does not inherit its parent's operational keys, delegations, commitments or sessions.

8.5. Merges are reserved (Section 3.9).

## 9. Collectives

9.1. A collective is a mind with a member controller.

9.2. **Genesis consent.** Every founding member MUST sign the genesis with one of its own valid operational keys (Section 6.1). Members MUST be distinct, a member MUST NOT be the collective itself, and the threshold MUST be a majority (Section 3.4).

9.3. **Changes.** Later identity events require the threshold of current members, plus every newly added member (Section 4.4).

9.4. **Members sign with their own keys.** A member's proof counts for a collective only if it is by one of that member's own valid operational keys (Section 6.1); a delegate of a member cannot sign for it here. A collective that is a member of another collective signs there with operational keys it has authorised through its own `keys`. Recursive threshold signing (a collective's members signing for it inside another collective) is reserved.

9.5. **Acting as one.** The **state of a collective at time `T`** is its identity state after the last event whose `created` is at or before `T`. A record is signed by a collective at the earliest time `T` at which the members of the collective's state at `T` that have proofs on the record with `t(p)` ≤ `T` number at least that state's threshold, the state not being retired. A member holding a role in the collective's charter also signs for it within the role's powers (Layer 2, Section 7). A collective MAY also authorise operational keys of its own through `keys`, in which case proofs by those keys count as for any mind.

## 10. Feeds and checkpoints

10.1. A mind's **public feed** is a sequence of `Entry` records:

| Member | Required | Value |
|---|---|---|
| `author` | yes | The mind |
| `seq` | yes | 0 for the first entry, then +1 |
| `prev` | if `seq` > 0 | Content ID of the previous entry |
| `created` | yes | |
| `object` | yes | Content ID of the published record |
| `objectType` | yes | The published record's `type` |
| `proofs` | no | Array of the digests `"sha256:" + hex(SHA-256(JCS(proof)))` of the proofs on the published record as it stood when the entry was made, so that a checkpoint covering the entry is evidence for those proofs (core 9.4) |
| `proof` | yes | By a valid operational key of the author (Section 6.1, current-state rule) |

10.2. A feed MAY list records authored by other minds, such as Commitments the mind is a party to. A host MUST serve every record listed in a feed it serves. When a record gains proofs (for example, a co-signature), the mind MAY publish a new entry for the same record with the new set of `proofs`.

10.3. A feed has a **single writer** at a time: a mind that runs several instances coordinates them so that only one appends to its feed (for example, by routing publication through its host). Two different valid entries with the same `author` and `seq` constitute feed equivocation and are published and treated as evidence in the same way as duplicity.

10.4. After an operational key is revoked with a compromise time, entries it signed whose evaluation time is at or after that time are invalid, and the mind continues its feed from its last valid entry. Invalid entries never count as equivocation.

10.5. A **`Checkpoint`** has `author`, `created`, `size` (the number of entries covered, from `seq` 0), `head` (content ID of the last covered entry), `root` and `proof`. `root` is the RFC 9162 Merkle Tree Hash over the covered entries in `seq` order, where each leaf is the 32-byte digest inside the entry's content ID, encoded as a content ID (`"b" + base32lower(0x12 ‖ 0x20 ‖ root)`).

10.6. A checkpoint MAY be anchored in a public append-only log or in the Bitcoin blockchain through OpenTimestamps. An anchor's attestation establishes that the checkpoint existed no later than the anchored time, and is evidence (core 9.4) for every proof that a covered entry commits to. Anchoring detects a split view (two checkpoints for the same feed position) rather than preventing one.

## 11. Delegation and revocation

11.1. A **`Delegation`** record:

| Member | Required | Value | UCAN 1.0 |
|---|---|---|---|
| `author` | yes | The grantor | `iss` |
| `delegate` | yes | The grantee | `aud` |
| `subject` | yes | The mind whose authority is delegated | `sub` |
| `command` | yes | A command (11.2) | `cmd` |
| `policy` | no | A policy (11.3); default `[]` | `pol` |
| `notBefore` | no | Timestamp | `nbf` |
| `expires` | yes | Timestamp | `exp` |
| `nonce` | yes | String of 8–64 characters | `nonce` |
| `created`, `proof` | yes | Signed by the `author`'s own authority (Layer 2, Section 7.2) with `proofPurpose` `capabilityDelegation` | |

The semantics follow UCAN 1.0 (a release candidate at the time of writing). As in UCAN, a delegation does not name its parents: the record that relies on a chain lists every delegation in it (11.6), as a UCAN invocation lists its proofs in `prf`.

11.2. **Commands** match `^/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`. A command `g` **covers** a command `c` when `c` equals `g` or `c` begins with `g` followed by `/`. The commands under `/oip` are exactly:

| Command | Grants |
|---|---|
| `/oip/sign/Intent`, `/oip/sign/Offer`, `/oip/sign/Commitment`, `/oip/sign/Receipt` | Signing records of that type for the subject (the **delegable** types, Layer 2, Section 7.2) |
| `/oip/send` | Sending packets on the subject's behalf: the packet is signed by its sender and names the subject in `provenance.onBehalfOf` |

Every other command beginning `/oip`, including `/oip` and `/oip/sign` themselves, is reserved: a delegation using one is invalid in this revision, so there are no blanket grants. Records of other types (`Delegation`, `Revocation`, `Collective`, `Lineage`, identity events and current-state records) cannot be signed under delegation. Extensions define further commands under their own first segment, such as `/x402/pay`.

11.3. **Policies.** A policy is an array of statements, all of which must hold. A statement is `[op, selector, value]`:
- `op` is one of `==`, `!=`, `<`, `<=`, `>`, `>=`.
- `selector` matches `^(\.[A-Za-z0-9_]+)+$` and selects a member path in the record being authorised; a missing path makes the statement false.
- `<`, `<=`, `>` and `>=` hold only when both the selected value and `value` are integers or decimal strings (core 1.3), compared numerically; for any other values they are false.
- `==` and `!=` compare numerically when both values are integers or decimal strings, and otherwise compare canonical forms (core Section 2).

Further operators from UCAN (`and`, `or`, `not`, `like`, `all`, `any`) are reserved. A policy constrains only the members it names, so a policy should constrain every term that matters; for a price, both `amount` and `currency`.

11.4. **Validity of a delegation chain** for a record `r` carrying a proof `p` by a valid operational key of mind `D`, on behalf of mind `P`, where the delegations are `d₁ … dₙ` (`n` ≤ 8, root first, the last being the one that names `D`), all listed in `r.authority`:
1. Every `dᵢ` is a valid `Delegation` signed by its `author`'s own authority, and the evaluation time of that signature is not after `t(p)`.
2. `d₁.author` = `d₁.subject` = `P`, and every `dᵢ.subject` = `P`.
3. `dᵢ.delegate` = `dᵢ₊₁.author` for every `i` < `n`, and `dₙ.delegate` = `D`.
4. `dᵢ.command` covers `dᵢ₊₁.command`; every policy statement of `dᵢ` appears in `dᵢ₊₁.policy`; `dᵢ₊₁.expires` is not after `dᵢ.expires`.
5. `t(p)` is not before any `notBefore` and not after any `expires`.
6. `r`'s type is delegable, `dₙ.command` covers `/oip/sign/<r.type>`, and every statement of every `dᵢ.policy` holds for `r`.
7. No `dᵢ` has been revoked (11.5) by a revocation whose evaluation time is at or before `t(p)`.

Because time rules use `t(p)` (core 9.3), a delegate cannot use an expired or revoked delegation by writing an earlier `created`.

11.5. A **`Revocation`** record has `author` (the author of the revoked delegation), `revokes` (its `record-ref`), `created` and `proof`, and is signed by the author's own authority. It takes effect from its own evaluation time, so a backdated revocation cannot void records that evidence shows came before it. Authors SHOULD publish revocations in their feeds. Verifiers SHOULD check the issuer's feed for revocations when the value at stake warrants it. Expiry bounds how long a delegation can be used even when a revocation is missed, so delegations SHOULD be no longer than their purpose needs.

11.6. **Use.** A record signed under delegation lists in its member `authority` the delegations it relies on, as `record-ref`s or inline records, at most 16. A proof by `D` counts for `P` when some sequence of the listed delegations forms a valid chain from `P` to `D` (11.4). Packets SHOULD carry delegations inline.

## 12. Packets and sealing

12.1. A **`Packet`**:

| Member | Required | Value |
|---|---|---|
| `from` | yes | Sender's address; the packet MUST carry a valid proof by one of the sender's operational keys |
| `to` | yes | An array of 1–64 addresses; or `{ "query": <capability query>, "brokers": <array of 1–8 broker addresses, optional>, "maxFanout": <integer 1–50, optional, default 10> }` (Section 18.5); or `{ "subject": <subject pattern> }` (reserved) |
| `created` | yes | |
| `expires` | if `session` is absent | When `to` is a query, at most one hour after `created` |
| `nonce` | yes | String of 8–64 characters |
| `session`, `seq` | together | Section 14 |
| `prev` | when `seq` > 0 | Section 14.3 |
| `instance` | no | String of at most 64 characters naming the sending instance of a mind that runs several (Section 14.3) |
| `thread`, `parentThread`, `replyTo` | no | Content IDs or other strings of at most 128 characters |
| `purpose` | yes | `{ "verb": <verb>, "goal": <string, optional, at most 256 characters>, "schema": <URI, optional> }` |
| `content` | yes | 12.2 |
| `context` | no | Object: `refs` (array of record-refs or URLs), `summary`, `assumptions`, `language` (BCP 47), `stateDoc` |
| `provenance` | no | Object: `derivedFrom` (array of refs), `generatedBy` (`{ "model", "version", "tool" }`), `onBehalfOf` (address) |
| `constraints` | no | Object: `retention` (duration or `"none"`), `allowedUses`, `prohibitedUses` (arrays of strings such as `train`, `redistribute`, `store`), `confidentiality`, `licence` (SPDX identifier or URL), `jurisdiction`, `forwardOk` (boolean), `maxHops` (integer) |
| `authority` | no | Delegations (Section 11.6) |
| `hints` | no | Object mapping addresses to arrays of HTTPS URLs where their records can be fetched |
| `ext`, `critical`, `proof` | | core |

A packet's identifier is its content ID.

12.2. **Content.** One of:
- `{ "mediaType": <media type>, "body": <JSON value> }`. With `application/oip+json`, `body` is a record.
- `{ "mediaType": <media type>, "ref": <URL or record-ref>, "digest": "sha256:<64 lower-case hex digits>" }`, for large or external content. The digest is REQUIRED.
- `{ "parts": [ <content>, … ] }`, at most 32 parts, none of which is itself a `parts` object.

12.3. **Verbs** (advisory): `inform`, `request`, `query`, `propose`, `accept`, `decline`, `deliver`, `ack`, `error`, `open`, `resume`, `branch`, `close`, or a namespaced verb `<namespace>:<name>`. Verbs MUST NOT be treated as binding; binding statements are Layer 2 records carried in `content`.

12.4. **Receiving.** A receiver MUST verify the packet's proof and, if `to` lists addresses, that it is one of them; if `to` is a query, MUST accept the packet only inside a `Forwarded` record from a broker (Section 18.5), and only from a broker listed in `brokers` when that member is present; MUST reject packets whose `created` is more than 300 seconds in the future or whose `expires` has passed; and MUST discard duplicates by content ID. Receivers MAY discard their duplicate-detection state for a packet after its `expires`. Packets in a session are additionally checked under Section 14.

12.5. **Treat content as data.** Receivers MUST NOT treat the content of a packet as conferring authority. Authority comes only from identity logs, delegations and Layer 2 records. This stops a packet from granting authority; it does not stop a model that already holds authority from being persuaded to use it, which is why Layer 0, Section 2.2 keeps keys outside the model and asks for confirmation before binding acts.

12.6. **`Sealed`.** To send a packet privately, the sender encrypts it to one of the recipient's agreement keys with HPKE (RFC 9180) in base mode, with KEM DHKEM(X25519, HKDF-SHA256), KDF HKDF-SHA256 and AEAD ChaCha20-Poly1305; `info` = the UTF-8 bytes of `oip/1 sealed`; `aad` = the UTF-8 bytes of the recipient's address; plaintext = the canonical form of the signed packet. The result is an unsigned record:

| Member | Value |
|---|---|
| `oip`, `type` | `"1"`, `"Sealed"` |
| `to` | The recipient's address |
| `key` | The recipient agreement key used |
| `suite` | `"hpke-base-x25519-sha256-chacha20poly1305"` |
| `enc` | base64url (no padding) of the encapsulated key |
| `ciphertext` | base64url (no padding) of the ciphertext |

The recipient decrypts, then verifies the inner packet as in 12.4. Intermediaries handle `Sealed` records without being able to read them. Sealing in this revision gives neither forward secrecy nor post-quantum confidentiality: anyone who later obtains the recipient's agreement key can read packets sealed to it. Minds SHOULD rotate agreement keys, and parties needing forward secrecy SHOULD use a binding that provides it (Section 13.6).

## 13. Bindings

13.1. **Well-known resources.** A host serving mind `M` (with content ID `m`) MUST serve:
- `GET /.well-known/oip/mind/m` returning a `Bundle`: `{ "oip": "1", "type": "Bundle", "mind": M, "log": [events], "location": <Location, optional>, "participant": <Participant, optional>, "firstSeen": <object, optional> }`. `firstSeen`, served by resolvers (Section 17), maps the content IDs of the bundle's events and records to the times the resolver first saw them.
- `GET /.well-known/oip/mind/m/feed?after=<seq>&limit=<n>` returning `{ "oip": "1", "type": "FeedPage", "mind": M, "entries": [ … in seq order … ], "next": <seq, optional> }`. `after` is exclusive; `limit` defaults to 100 and MAY be capped by the host.
- `GET /.well-known/oip/mind/m/obj/<contentId>` returning the record.

Hosts MAY serve A2A Agent Cards (Layer 0) and domain aliases at `/.well-known/oip/did`.

13.2. **Inbox and acknowledgement.** `POST {endpoint}/inbox` with a body of a `Packet` or `Sealed` record, media type `application/oip+json`. On success the endpoint returns `202` with an **`Ack`**: `{ "oip": "1", "type": "Ack", "author": <recipient>, "packet": <content ID>, "received": <timestamp>, "created": <timestamp>, "proof": [ … ] }`, signed by a valid operational key of the recipient. Delivery of a duplicate returns `202` with the same acknowledgement. Errors use core Section 10. An `Ack` is evidence (core 9.4) that the packet, with the sender's proof, existed at its `received` time; senders SHOULD keep the acknowledgements of packets that carry binding records.

13.3. **Authentication.**
- A **`Hello`** record `{ "oip": "1", "type": "Hello", "author": <mind>, "created": <timestamp>, "proof": [ … ] }` carries a single proof with `proofPurpose` `authentication`, `challenge` set to a nonce issued by the server and `domain` set to the server's origin. Servers MUST check the challenge was issued by them within the last 300 seconds and has not been used before.
- **HTTP requests** that need authentication (mailbox draining, publication to resolvers or indexers where required) MUST carry an RFC 9421 HTTP Message Signature with algorithm `ed25519`, `keyid` equal to a `key-ref` of the requesting mind, covered components `@method`, `@target-uri` and (when there is a body) `content-digest` (RFC 9530), and parameters `created`, `expires` (at most 300 seconds later) and `nonce`. This profile is for OIP endpoints. Requests to ordinary websites that expect the IETF Web Bot Auth profile follow that profile instead (a JWK-thumbprint `keyid` and a `Signature-Agent` directory), with the directory listing the mind's key (Layer 0, Section 5).

13.4. **WebSocket.** `GET {endpoint}/ws` upgrades to WebSocket with subprotocol `oip.v1`. The server's first message is `{ "type": "Challenge", "nonce": <base64url, at least 16 random bytes>, "domain": <origin> }`. The client replies with a `Hello` (13.3); the server replies `{ "type": "Welcome", "mind": <authenticated address> }` or closes with code 4401. Afterwards each message is one record. A mind's own instance may hold a socket open to its host to receive packets addressed to it.

13.5. **Mailbox.** A mailbox endpoint accepts `POST {mailbox}` with a `Sealed` or `Packet` record and returns `202` with `{ "stored": true }`. The mailbox owner drains it with an authenticated (13.3) `GET {mailbox}?after=<cursor>`, which returns `{ "items": [ { "cursor": <string>, "record": <record> } ], "next": <cursor, optional> }`, and removes items with an authenticated `DELETE {mailbox}/<cursor>`. Mailboxes SHOULD retain items for at least 30 days.

13.6. Further bindings (DIDComm, libp2p, iroh, NATS, MQTT) are reserved for later revisions. Every binding carries the same records.

## 14. Sessions

14.1. A **`Session`** record is unsigned: `{ "oip": "1", "type": "Session", "participants": [addresses, sorted by code point, distinct, 2–256], "nonce": <string of 8–64 characters>, "created": <timestamp> }`. The session ID is its content ID.

14.2. The first packet a participant sends in a session MUST include the `Session` record in its `content` (as a body or a part), unless the receiver has already been shown it. Any verb may open a session; `open` is available when the packet has no other purpose.

14.3. Each **sending chain** in a session is identified by the sender's address and its `instance` (absent counts as one instance). Each chain numbers its packets from `seq` 0; each packet after the first carries `prev`, the content ID of the previous packet in the same chain. A mind running several instances either gives each its own `instance` or lets only one instance send in a given session. A receiver that detects a gap MUST NOT treat later packets of that chain as in order until the gap is filled, and SHOULD send a `Resume`.

14.4. **`Resume`** (the content of a packet with verb `resume`): `{ "oip": "1", "type": "Resume", "session": <id>, "lastSent": { "seq": <n>, "packet": <content ID>, "instance": <string, optional> }, "lastReceived": [ { "mind": <address>, "instance": <string, optional>, "seq": <n>, "packet": <content ID> } ], "created": <timestamp> }`. The receiver verifies the chains and retransmits the packets the sender lacks.

14.5. **`Branch`** (the content of a packet with verb `branch`): `{ "oip": "1", "type": "Branch", "parentSession": <id>, "fork": <the parent's Fork event as a versioned-mind reference>, "created": <timestamp> }`. A fork MUST NOT send packets in its parent's sessions; it MAY propose a branch, which the counterpart may accept by opening a new session with it.

## 15. Location records

15.1. A **`Location`** record:

| Member | Required | Value |
|---|---|---|
| `author` | yes | The mind |
| `seq` | yes | Integer; each new record has a higher `seq` than the last |
| `created` | yes | |
| `ttl` | yes | Integer seconds, 60–86400 |
| `status` | yes | `active`, `paused` or `migrating` |
| `resumeAfter` | no | Timestamp |
| `endpoints` | yes | 0–32 objects `{ "binding": <binding>, "url": <URL>, "instance": <string, optional>, "priority": <integer, lower first> }` |
| `homes` | no | HTTPS origins |
| `participant` | no | Content ID of the current Participant profile |
| `feed` | no | `{ "seq": <n>, "head": <content ID of the latest Entry> }` |
| `proof` | yes | By a valid operational key under the current-state rule (Section 6.1, item 6) |

15.2. Among the location records of a mind whose proofs are valid under the current-state rule (Section 6.1, item 6), the one with the highest `seq` is current. A record is stale after `created` + `ttl`, but MAY still be used as a hint.

15.3. Senders SHOULD try endpoints in priority order and SHOULD use `mailbox` endpoints when no other endpoint accepts the packet or when `status` is `paused`.

15.4. **Changing hosts.** Anyone holding one of the mind's operational keys can publish location records for it. A host that holds such a key can therefore keep publishing location records with higher `seq` after the mind moves away, until an `Update` removes that key (Section 6); after that, its records no longer verify under the current-state rule. A mind moving away from a host that holds one of its keys MUST remove that key. Hosts SHOULD serve minds without holding their keys wherever the mind can sign its own records.

## 16. Participant profiles

16.1. A **`Participant`** record:

| Member | Required | Value |
|---|---|---|
| `author` | yes | The mind described |
| `created` | yes | |
| `name` | yes | At most 128 characters |
| `kind` | yes | As in the genesis |
| `summary` | no | At most 1024 characters |
| `capabilities` | no | 0–256 capability objects (16.2) |
| `actsFor` | no | Array of `{ "mind": <address>, "authority": <record-ref of a Delegation> }` |
| `interfaces` | no | Object mapping protocol names (`a2a`, `mcp`, `openapi`, `activitypub`, …) to URLs |
| `languages` | no | BCP 47 tags |
| `attestations` | no | Record-refs or URLs of credentials about the mind |
| `supersedes` | no | Content ID of the previous profile |
| `ext`, `critical`, `proof` | | The proof is by a valid operational key under the current-state rule (Section 6.1, item 6) |

16.2. A **capability** object: `id` (REQUIRED, at most 128 characters, unique within the profile), `summary` (REQUIRED), `tags` (array of at most 64 strings, each `<namespace>:<value>`), `subject` (OPTIONAL, matching `^[a-z0-9_-]+(\.[a-z0-9_-]+)*$`), `inputs` and `outputs` (media types), `terms` (as in a Layer 2 Offer), `evidence` (Layer 2 evidence items) and `attestations`.

16.3. Tag namespaces include `oasf` (the OASF skills and domains taxonomy), `domain`, `lang` (BCP 47) and `schema` (schema.org types). Others are allowed.

16.4. The current profile is the one referenced by the current location record; failing that, the most recent valid profile in the mind's feed.

## 17. Resolvers

17.1. A resolver MUST implement:
- `GET /oip/v1/resolve/<mindId>`: returns a `Bundle` (13.1) with the log it holds, which at every position is the first valid event it saw (never chosen by length), the current location record, and `firstSeen`; `404` if unknown.
- `PUT /oip/v1/resolve/<mindId>`: accepts a `Bundle`, verifies everything in it, and merges it into its store; returns `202`, or `409` with type `urn:oip:error:duplicity` if it reveals duplicity.
- `GET /oip/v1/stream?since=<cursor>`: a server-sent event stream whose events carry `{ "cursor": <string>, "mind": <address>, "record": <identity event or Location> }`.
- `GET /oip/v1/duplicity/<mindId>`: returns `{ "oip": "1", "type": "DuplicityEvidence", "mind": <address>, "pairs": [ [<event>, <event>] ] }`.

17.2. A resolver MUST verify every record before storing or serving it, evaluating proofs at the time it receives them (core 9.3), MUST keep the first valid event it saw at each log position and the time it first saw it (Section 7), and MUST NOT serve records it cannot verify. A resolver is a witness: verifiers that trust it MAY use its `firstSeen` times as evidence (core 9.4).

17.3. Resolvers MAY require authenticated publication (13.3) and MAY rate-limit.

## 18. Indexers and capability routing

18.1. An indexer MUST implement:
- `POST /oip/v1/submit` with body `{ "records": [ … ] }` containing `Bundle`, `Participant`, `Offer` and `Intent` records; returns `202`. Indexers MAY also collect records by crawling homes and following resolver streams.
- `POST /oip/v1/query` with a **capability query**, returning a signed `QueryResult`.

18.2. A **capability query**: `want` (free text, at most 1024 characters), `tags` (array; a value ending in `/*` matches any value with that prefix), `kinds` (record types to search: `Participant`, `Offer`, `Intent`; default `Participant`), `constraints` (object), `evidence` (object, for example `{ "minReceipts": 20 }`), `limit` (integer, at most 100).

18.3. A **`QueryResult`**: `{ "oip": "1", "type": "QueryResult", "author": <indexer's address>, "created": <timestamp>, "query": <the query>, "results": [ { "mind": <address>, "record": <content ID>, "capability": <id, optional>, "score": <decimal string from "0" to "1">, "why": <string, optional>, "hints": [URLs] } ], "proof": [ … ] }`.

18.4. Clients MUST fetch and verify the records named in results before acting on them. Ranking is the indexer's own policy.

18.5. **Brokered delivery.** An indexer MAY accept `POST {endpoint}/inbox` packets whose `to` is a capability query. If the packet's `to.brokers` is present and does not list the indexer, it MUST refuse the packet. Otherwise it forwards the unchanged packet to at most `to.maxFanout` matching minds (default 10, at most 50), each wrapped as `{ "oip": "1", "type": "Forwarded", "broker": <indexer address>, "to": <recipient address>, "packet": <packet>, "created": <timestamp>, "proof": [ … ] }`, signed by the broker. Because `brokers` and `maxFanout` are inside the signed packet, a broker cannot widen them, and recipients discard repeated deliveries by the packet's content ID. Recipients reply to the packet's `from` directly. Brokers MUST rate-limit.

## 19. Limits

| Item | Limit |
|---|---|
| Record size (canonical form) | 1 MiB (core 1.6) |
| Proofs per record | 256 (core 5.1) |
| Collective nesting depth | 4 |
| Delegation chain length | 8 |
| Delegations listed in `authority` | 16 |
| Packet recipients | 64 |
| Brokered fan-out | 50 |
| Content parts | 32 |
| Location endpoints | 32 |
| Clock skew tolerance | 300 seconds |
| Challenge lifetime | 300 seconds |
