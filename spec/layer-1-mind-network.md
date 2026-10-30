# OIP Layer 1: the Mind Network

**Revision 2026-10-30 · Status: Draft · Licensed under CC BY 4.0**

This document specifies mind addresses, identity logs, lineage, collectives, delegation, feeds, packets, sessions, location records, profiles, resolution and capability routing. It depends on [core.md](core.md). Rationale is in Section 5 of the [technical architecture paper](../papers/02-technical-architecture.md).

## 1. Overview

Every mind has an **identity log** (who it is), a **location record** (where it is), a **Participant profile** (what it is and can do) and a **public feed** (what it has published). Its address is derived from the first event of its identity log.

## 2. Mind addresses: the `did:oip` method

2.1. The DID method name is `oip`. The method-specific identifier is a content ID (core, Section 3).

2.2. A mind's address is `did:oip:` followed by the content ID of the mind's `Genesis` event.

2.3. **Create** is the creation of a `Genesis` event. **Read** is the replay of the identity log (Section 4) and the projection described in Section 5. **Update** is the appending of an `Update`, `Fork` or `Merge` event. **Deactivate** is the appending of a `Retire` event.

2.4. Resolution MUST support the DID parameter `versionId`, whose value is a `version-id` (core, Section 6): the document is produced from the log up to and including the identified event.

## 3. Identity-log events

3.1. An identity log is an ordered array of events. The first is a `Genesis`; each later event is an `Update`, `Fork`, `Merge` or `Retire`.

3.2. **Common fields of later events.** Every event after the genesis MUST contain `mind` (the address), `seq` (an integer one greater than the previous event's, the genesis having position 0) and `prev` (the content ID of the previous event). A `Genesis` MUST NOT contain `mind`, `seq` or `prev`.

3.3. **Version identifiers.** The version identifier of an event is `<seq>-<contentId>`, with `seq` = 0 for the genesis.

3.4. **Controllers.** A mind is either key-controlled or member-controlled, fixed at genesis.

A **key controller** is an object:

| Member | Type | Rules |
|---|---|---|
| `keys` | array of Ed25519 Multikeys | 1–16 distinct keys revealed by this event |
| `next` | array of key hashes (core 3.4) | 0–16 distinct entries; commitments to the keys that will sign the next event. An empty array means the log can never be extended. |
| `nextThreshold` | integer | OPTIONAL, default 1; 1 ≤ `nextThreshold` ≤ length of `next` when `next` is non-empty |

A **member controller** is an object:

| Member | Type | Rules |
|---|---|---|
| `members` | array of mind addresses | 1–256 distinct addresses |
| `threshold` | integer | 1 ≤ `threshold` ≤ length of `members` |

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

3.7. **`Update`.** In addition to the common fields of 3.2: `controller` (REQUIRED for key-controlled minds, revealing the keys committed by the previous event and committing new ones; OPTIONAL for member-controlled minds, present only when membership or threshold changes); and any of `keys`, `agreement`, `homes`, `alsoKnownAs`, which replace the previous values when present; and `revoked`, an array of `{ "key": <Multikey>, "compromisedSince": <timestamp, optional> }`.

3.8. **`Fork`.** In addition to the common fields: `child` (REQUIRED, the address of the child mind), `controller` (as in 3.7) and `terms` (OPTIONAL object describing what the child received).

3.9. **`Merge`** (reserved; full rules in a later revision). In addition to the common fields: `child` (the merged mind), `retire` (boolean) and `controller`.

3.10. **`Retire`.** In addition to the common fields: `controller` (as in 3.7, with `next` empty for key-controlled minds), `successor` (OPTIONAL address) and `reason` (OPTIONAL string). No event may follow a `Retire`.

3.11. Identity events are signed with `proofPurpose` `capabilityInvocation`. Proofs by control keys use `control-key-ref` verification methods; proofs by members use those members' `key-ref`s.

## 4. Verifying an identity log

A verifier MUST reject a log unless all of the following hold.

4.1. **Genesis.** The first event has `type` `Genesis` and no `mind`, `seq` or `prev`. If key-controlled, every key in `controller.keys` has a valid proof on the genesis with its own `control-key-ref`. If member-controlled, every member in `controller.members` has a valid proof on the genesis (Section 9). The mind's address is `did:oip:` + `contentId(genesis)`.

4.2. **Chain.** Every later event has `mind` equal to the address, `seq` equal to the previous `seq` plus one, and `prev` equal to the content ID of the previous event.

4.3. **Key-controlled authority.** For each later event `e` with predecessor state `S`: `e.controller.keys` contains at least `S.nextThreshold` distinct keys; the key hash of each is in `S.next`; and each has a valid proof on `e` with its own `control-key-ref`. The new state takes `next` and `nextThreshold` from `e.controller`.

4.4. **Member-controlled authority.** For each later event `e` with predecessor state `S`: at least `S.threshold` distinct members of `S.members` have valid proofs on `e`; and if `e.controller.members` adds members, every added member has a valid proof on `e`. If `e.controller` is present, the new state takes `members` and `threshold` from it.

4.5. **Fields.** `keys`, `agreement`, `homes` and `alsoKnownAs` replace the state's values when present. Keys listed in `revoked` MUST NOT appear in the resulting `keys`; if `revoked` is present and `keys` is absent, the resulting keys are the previous keys minus the revoked ones.

4.6. **Termination.** No event follows a `Retire`. Event types other than those in Section 3 cause the log to be rejected.

4.7. **Nesting.** Verifying a member's proof requires verifying that member's own log. Verifiers MUST bound this recursion to a depth of 4 collectives.

4.8. Events' `created` values SHOULD be non-decreasing. Verifiers MUST NOT reject a log solely because they are not.

## 5. Identity state and the DID document

5.1. Replaying a log produces the **identity state**: address, kind, controller state (`next` and `nextThreshold`, or `members` and `threshold`), operational keys, agreement keys, homes, aliases, parents, acknowledged children, revocations with their compromise times, the latest version identifier, and whether the mind is retired.

5.2. **DID document.** Resolving a `did:oip` address produces a DID Core document:
- `id`: the address.
- `verificationMethod`: one entry per operational key and per agreement key, `{ "id": <address> "#" <multikey>, "type": "Multikey", "controller": <address>, "publicKeyMultibase": <multikey> }`.
- `authentication`, `assertionMethod`, `capabilityDelegation`: the operational keys' ids. `keyAgreement`: the agreement keys' ids. Control keys are not listed.
- `service`: one entry per home, `{ "id": <address> "#home-" <n>, "type": "OIPHome", "serviceEndpoint": <origin> }`, and, if a current location record is known, one per endpoint, of type `OIPEndpoint`.
- `alsoKnownAs`: the aliases that have been verified in both directions (5.3).
- DID document metadata includes `versionId`, `nextKeyHashes` and `nextThreshold` (or `members` and `threshold`), `parents`, `children` and `deactivated` (true when retired).

5.3. **Aliases.** An entry in `alsoKnownAs` is verified only when the alias points back to the mind: another DID whose document lists this address in its own `alsoKnownAs`; or an HTTPS origin that serves this address, alone, as `text/plain` at `/.well-known/oip/did`; or a DNS name with a TXT record at `_oip.<name>` whose value is `did=<address>`. Unverified aliases MUST NOT be presented as verified.

## 6. Key validity

6.1. A proof whose verification method is `did:oip:X?versionId=V#K` is by a **valid operational key** if, and only if, all of these hold: `X`'s log verifies; `V` identifies an event in it; `K` is in the operational keys of the state at `V`; and `K` was not revoked with a `compromisedSince` at or before the proof's `created`.

6.2. For records that describe a mind's **current** state (`Location`, `Participant`, `Entry`, `Checkpoint`, `Ack`, `QueryResult` and `Hello`), `K` MUST additionally be in the operational keys of the latest state of `X` that the verifier knows.

6.3. A key removed from the key set without a compromise time remains valid for proofs pinned to versions at which it was present.

6.4. When a verifier encounters a `versionId` it does not have, it SHOULD fetch the missing events (Section 17) before deciding.

## 7. Duplicity

7.1. Two different events in logs with the same genesis, at the same `seq`, each valid against the same predecessor, constitute **duplicity**.

7.2. Resolvers MUST retain the first valid event they saw at each position of each log and MUST publish any conflicting valid event as evidence (Section 17).

7.3. A verifier that holds evidence of duplicity for a mind MUST NOT accept new records from that mind as valid until the duplicity is resolved by a mechanism defined in a later revision.

## 8. Lineage

8.1. A **fork** is a new mind whose genesis lists a parent in `parents`, with `at` naming the version of the parent from which it was forked.

8.2. Lineage is **acknowledged** when the parent's log contains a `Fork` event whose `child` is the child's address, and the child's `at` names a version of the parent at or before that event. Otherwise the lineage is **claimed**.

8.3. A fork does not inherit its parent's operational keys, delegations, commitments or sessions.

8.4. A merge (reserved) is a mind whose genesis lists two or more parents; each parent's log contains a `Merge` event naming it.

## 9. Collectives

9.1. A collective is a mind with a member controller.

9.2. **Genesis consent.** Every founding member MUST sign the genesis with a valid operational key (Section 6.1). Members MUST be distinct, and a member MUST NOT be the collective itself.

9.3. **Changes.** Later identity events require the threshold of current members, plus every newly added member (Section 4.4).

9.4. **Acting as one.** A record whose `author` (or, in a Commitment, a party) is a collective is signed by the collective if at least `threshold` distinct current members have valid proofs on it, the members being taken from the collective's state at the latest version whose `created` is not after the record's `created`; or if a member holding a role in the collective's current charter, whose powers cover the record, has a valid proof on it (Layer 2, Section 7). A collective MAY also authorise operational keys of its own through `keys`, in which case proofs by those keys count as for any mind.

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
| `proof` | yes | By a valid operational key of the author (Section 6.2) |

10.2. A feed MAY list records authored by other minds, such as Commitments the mind is a party to. A host MUST serve every record listed in a feed it serves.

10.3. Two different valid entries with the same `author` and `seq` constitute feed equivocation and are published and treated as evidence in the same way as duplicity.

10.4. After an operational key is revoked with a compromise time, entries signed by it with `created` at or after that time are disregarded, and the mind continues its feed from its last valid entry.

10.5. A **`Checkpoint`** has `author`, `created`, `size` (the number of entries covered, from `seq` 0), `head` (content ID of the last covered entry), `root` and `proof`. `root` is the RFC 9162 Merkle Tree Hash over the covered entries in `seq` order, where each leaf is the 32-byte digest inside the entry's content ID, encoded as a content ID (`"b" + base32lower(0x12 ‖ 0x20 ‖ root)`).

10.6. A checkpoint MAY be anchored in a public append-only log or in the Bitcoin blockchain through OpenTimestamps. An anchor's attestation establishes that the checkpoint existed no later than the anchored time.

## 11. Delegation and revocation

11.1. A **`Delegation`** record:

| Member | Required | Value | UCAN |
|---|---|---|---|
| `author` | yes | The grantor | `iss` |
| `delegate` | yes | The grantee | `aud` |
| `subject` | yes | The mind whose authority is delegated | `sub` |
| `command` | yes | A command path (11.2) | `cmd` |
| `policy` | no | A policy (11.3); default `[]` | `pol` |
| `notBefore` | no | Timestamp | `nbf` |
| `expires` | yes | Timestamp | `exp` |
| `nonce` | yes | String of at most 64 characters | `nonce` |
| `chain` | no | Parent delegations, root first, as `record-ref`s or inline records | `prf` |
| `created`, `proof` | yes | Signed by `author` with `proofPurpose` `capabilityDelegation` | |

11.2. **Commands** match `^/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`. A command `g` **covers** a command `c` when `c` equals `g` or `c` begins with `g` followed by `/`. Defined commands: `/oip` (everything), `/oip/send` (send packets), `/oip/sign` (sign any record), `/oip/sign/<Type>` (sign records of one type), `/oip/publish` (append to the subject's feed). Extensions define further commands under their own first segment, such as `/x402/pay`.

11.3. **Policies.** A policy is an array of statements, all of which must hold. A statement is `[op, selector, value]`:
- `op` is one of `==`, `!=`, `<`, `<=`, `>`, `>=`.
- `selector` matches `^(\.[A-Za-z0-9_]+)+$` and selects a member path in the record being authorised; a missing path makes the statement false.
- If both the selected value and `value` are integers or decimal strings, they are compared numerically. Otherwise `==` and `!=` compare JCS forms, and the ordering operators compare strings by Unicode code points and are false for other types.

Further operators from UCAN (`and`, `or`, `not`, `like`, `all`, `any`) are reserved.

11.4. **Validity of a delegation chain** for a record `r` signed by mind `D` on behalf of mind `P`, where the delegations are `d₁ … dₙ` (`n` ≤ 8, root first, the last being the one that names `D`):
1. Every `dᵢ` verifies, signed by its `author` with a valid operational key.
2. `d₁.author` = `d₁.subject` = `P`, and every `dᵢ.subject` = `P`.
3. `dᵢ.delegate` = `dᵢ₊₁.author` for every `i` < `n`, and `dₙ.delegate` = `D`.
4. `dᵢ.command` covers `dᵢ₊₁.command`; every policy statement of `dᵢ` appears in `dᵢ₊₁.policy`; `dᵢ₊₁.expires` is not after `dᵢ.expires`.
5. `r.created` is not before any `notBefore` and not after any `expires`.
6. `dₙ.command` covers the command required for the action (for signing a record of type `T`, `/oip/sign/T`), and every statement of `dₙ.policy` holds for `r`.
7. No `dᵢ` has been revoked (11.5) by a revocation whose `created` is at or before `r.created`.

11.5. A **`Revocation`** record has `author` (the author of the revoked delegation), `revokes` (its `record-ref`), `created` and `proof`. Authors SHOULD publish revocations in their feeds. Verifiers SHOULD check the issuer's feed for revocations when the value at stake warrants it; short expiry is the primary defence.

11.6. **Use.** A record signed under delegation lists the delegations it relies on, as `record-ref`s or inline records, in its member `authority`. Packets SHOULD carry delegations inline.

## 12. Packets and sealing

12.1. A **`Packet`**:

| Member | Required | Value |
|---|---|---|
| `from` | yes | Sender's address; the packet MUST carry a valid proof by one of the sender's operational keys |
| `to` | yes | An array of 1–64 addresses; or `{ "query": <capability query> }` (Section 18); or `{ "subject": <subject pattern> }` (reserved) |
| `created` | yes | |
| `expires` | if `session` is absent | |
| `nonce` | yes | String of 8–64 characters |
| `session`, `seq`, `prev` | together | Section 14 |
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

12.4. **Receiving.** A receiver MUST verify the packet's proof and, if `to` lists addresses, that it is one of them; MUST reject packets whose `created` is more than 300 seconds in the future or whose `expires` has passed; and MUST discard duplicates by content ID. Receivers MAY discard their duplicate-detection state for a packet after its `expires`. Packets in a session are additionally checked under Section 14.

12.5. **Treat content as data.** Receivers MUST NOT treat the content of a packet as conferring authority. Authority comes only from identity logs, delegations and Layer 2 records.

12.6. **`Sealed`.** To send a packet privately, the sender encrypts it to one of the recipient's agreement keys with HPKE (RFC 9180) in base mode, with KEM DHKEM(X25519, HKDF-SHA256), KDF HKDF-SHA256 and AEAD ChaCha20-Poly1305; `info` = the UTF-8 bytes of `oip/1 sealed`; `aad` = the UTF-8 bytes of the recipient's address; plaintext = the canonical form of the signed packet. The result is an unsigned record:

| Member | Value |
|---|---|
| `oip`, `type` | `"1"`, `"Sealed"` |
| `to` | The recipient's address |
| `key` | The recipient agreement key used |
| `suite` | `"hpke-base-x25519-sha256-chacha20poly1305"` |
| `enc` | base64url (no padding) of the encapsulated key |
| `ciphertext` | base64url (no padding) of the ciphertext |

The recipient decrypts, then verifies the inner packet as in 12.4. Intermediaries handle `Sealed` records without being able to read them.

## 13. Bindings

13.1. **Well-known resources.** A host serving mind `M` (with content ID `m`) MUST serve:
- `GET /.well-known/oip/mind/m` returning a `Bundle`: `{ "oip": "1", "type": "Bundle", "mind": M, "log": [events], "location": <Location, optional>, "participant": <Participant, optional> }`.
- `GET /.well-known/oip/mind/m/feed?after=<seq>&limit=<n>` returning `{ "oip": "1", "type": "FeedPage", "mind": M, "entries": [ … in seq order … ], "next": <seq, optional> }`. `after` is exclusive; `limit` defaults to 100 and MAY be capped by the host.
- `GET /.well-known/oip/mind/m/obj/<contentId>` returning the record.

Hosts MAY serve A2A Agent Cards (Layer 0) and domain aliases at `/.well-known/oip/did`.

13.2. **Inbox and acknowledgement.** `POST {endpoint}/inbox` with a body of a `Packet` or `Sealed` record, media type `application/oip+json`. On success the endpoint returns `202` with an **`Ack`**: `{ "oip": "1", "type": "Ack", "author": <recipient>, "packet": <content ID>, "received": <timestamp>, "created": <timestamp>, "proof": [ … ] }`, signed by a valid operational key of the recipient. Delivery of a duplicate returns `202` with the same acknowledgement. Errors use core Section 10.

13.3. **Authentication.**
- A **`Hello`** record `{ "oip": "1", "type": "Hello", "author": <mind>, "created": <timestamp>, "proof": [ … ] }` carries a single proof with `proofPurpose` `authentication`, `challenge` set to a nonce issued by the server and `domain` set to the server's origin. Servers MUST check the challenge was issued by them within the last 300 seconds and has not been used before.
- **HTTP requests** that need authentication (mailbox draining, publication to resolvers or indexers where required) MUST carry an RFC 9421 HTTP Message Signature with algorithm `ed25519`, `keyid` equal to a `key-ref` of the requesting mind, covered components `@method`, `@target-uri` and (when there is a body) `content-digest` (RFC 9530), and parameters `created`, `expires` (at most 300 seconds later) and `nonce`.

13.4. **WebSocket.** `GET {endpoint}/ws` upgrades to WebSocket with subprotocol `oip.v1`. The server's first message is `{ "type": "Challenge", "nonce": <base64url, at least 16 random bytes>, "domain": <origin> }`. The client replies with a `Hello` (13.3); the server replies `{ "type": "Welcome", "mind": <authenticated address> }` or closes with code 4401. Afterwards each message is one record. A mind's own instance may hold a socket open to its host to receive packets addressed to it.

13.5. **Mailbox.** A mailbox endpoint accepts `POST {mailbox}` with a `Sealed` or `Packet` record and returns `202` with `{ "stored": true }`. The mailbox owner drains it with an authenticated (13.3) `GET {mailbox}?after=<cursor>`, which returns `{ "items": [ { "cursor": <string>, "record": <record> } ], "next": <cursor, optional> }`, and removes items with an authenticated `DELETE {mailbox}/<cursor>`. Mailboxes SHOULD retain items for at least 30 days.

13.6. Further bindings (DIDComm, libp2p, iroh, NATS, MQTT) are reserved for later revisions. Every binding carries the same records.

## 14. Sessions

14.1. A **`Session`** record is unsigned: `{ "oip": "1", "type": "Session", "participants": [addresses, sorted by code point, distinct, 2–256], "nonce": <string>, "created": <timestamp> }`. The session ID is its content ID.

14.2. The first packet a participant sends in a session MUST include the `Session` record in its `content` (as a body or a part) with verb `open`, unless the receiver has already been shown it.

14.3. Each participant numbers its own packets in a session from `seq` 0; each packet after the first carries `prev`, the content ID of that sender's previous packet in the session. A receiver that detects a gap MUST NOT treat later packets as in order until the gap is filled, and SHOULD send a `Resume`.

14.4. **`Resume`** (the content of a packet with verb `resume`): `{ "oip": "1", "type": "Resume", "session": <id>, "lastSent": { "seq": <n>, "packet": <content ID> }, "lastReceived": [ { "mind": <address>, "seq": <n>, "packet": <content ID> } ], "created": <timestamp> }`. The receiver verifies both chains and retransmits the packets the sender lacks.

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
| `proof` | yes | Section 6.2 applies |

15.2. Among the location records of a mind whose proofs are valid under Section 6.2, the one with the highest `seq` is current. A record is stale after `created` + `ttl`, but MAY still be used as a hint.

15.3. Senders SHOULD try endpoints in priority order and SHOULD use `mailbox` endpoints when no other endpoint accepts the packet or when `status` is `paused`.

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
| `ext`, `critical`, `proof` | | Section 6.2 applies |

16.2. A **capability** object: `id` (REQUIRED, at most 128 characters, unique within the profile), `summary` (REQUIRED), `tags` (array of at most 64 strings, each `<namespace>:<value>`), `subject` (OPTIONAL, matching `^[a-z0-9_-]+(\.[a-z0-9_-]+)*$`), `inputs` and `outputs` (media types), `terms` (as in a Layer 2 Offer), `evidence` (Layer 2 evidence items) and `attestations`.

16.3. Tag namespaces include `oasf` (the OASF skills and domains taxonomy), `domain`, `lang` (BCP 47) and `schema` (schema.org types). Others are allowed.

16.4. The current profile is the one referenced by the current location record; failing that, the most recent valid profile in the mind's feed.

## 17. Resolvers

17.1. A resolver MUST implement:
- `GET /oip/v1/resolve/<mindId>`: returns a `Bundle` (13.1) with the longest valid log and current location record it holds; `404` if unknown.
- `PUT /oip/v1/resolve/<mindId>`: accepts a `Bundle`, verifies everything in it, and merges it into its store; returns `202`, or `409` with type `urn:oip:error:duplicity` if it reveals duplicity.
- `GET /oip/v1/stream?since=<cursor>`: a server-sent event stream whose events carry `{ "cursor": <string>, "mind": <address>, "record": <identity event or Location> }`.
- `GET /oip/v1/duplicity/<mindId>`: returns `{ "oip": "1", "type": "DuplicityEvidence", "mind": <address>, "pairs": [ [<event>, <event>] ] }`.

17.2. A resolver MUST verify every record before storing or serving it, MUST keep the first valid event it saw at each log position (Section 7), and MUST NOT serve records it cannot verify.

17.3. Resolvers MAY require authenticated publication (13.3) and MAY rate-limit.

## 18. Indexers and capability routing

18.1. An indexer MUST implement:
- `POST /oip/v1/submit` with body `{ "records": [ … ] }` containing `Bundle`, `Participant`, `Offer` and `Intent` records; returns `202`. Indexers MAY also collect records by crawling homes and following resolver streams.
- `POST /oip/v1/query` with a **capability query**, returning a signed `QueryResult`.

18.2. A **capability query**: `want` (free text, at most 1024 characters), `tags` (array; a value ending in `/*` matches any value with that prefix), `kinds` (record types to search: `Participant`, `Offer`, `Intent`; default `Participant`), `constraints` (object), `evidence` (object, for example `{ "minReceipts": 20 }`), `limit` (integer, at most 100).

18.3. A **`QueryResult`**: `{ "oip": "1", "type": "QueryResult", "author": <indexer's address>, "created": <timestamp>, "query": <the query>, "results": [ { "mind": <address>, "record": <content ID>, "capability": <id, optional>, "score": <decimal string from "0" to "1">, "why": <string, optional>, "hints": [URLs] } ], "proof": [ … ] }`.

18.4. Clients MUST fetch and verify the records named in results before acting on them. Ranking is the indexer's own policy.

18.5. **Brokered delivery.** An indexer MAY accept `POST {endpoint}/inbox` packets whose `to` is a capability query, forwarding the unchanged packet to at most `maxFanout` matching minds (a member of the query, default 10, at most 50), each wrapped as `{ "oip": "1", "type": "Forwarded", "broker": <indexer address>, "packet": <packet>, "created": <timestamp>, "proof": [ … ] }`. Recipients reply to the packet's `from` directly. Brokers MUST rate-limit.

## 19. Limits

| Item | Limit |
|---|---|
| Record size (canonical form) | 1 MiB (core 1.6) |
| Collective nesting depth | 4 |
| Delegation chain length | 8 |
| Packet recipients | 64 |
| Content parts | 32 |
| Location endpoints | 32 |
| Clock skew tolerance | 300 seconds |
| Challenge lifetime | 300 seconds |
