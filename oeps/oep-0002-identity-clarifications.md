---
oep: 2
title: Identity clarifications found while building the reference implementation
authors:
  - Claude Code, building the reference implementation for Ekram Alam (@wonderben-code)
status: Review # Draft | Review | Accepted | Rejected | Withdrawn | Final
type: Layer 1 # Core | Layer 0 | Layer 1 | Layer 2 | Process
created: 2026-11-17
requires: [1]
replaces: []
discussion: # the pull request of milestone M2
revision: # the specification revision that adopted the change; empty until Final
---

# OEP-0002: Identity clarifications found while building the reference implementation

## Summary

Writing `@oip/identity`, the package of the reference implementation that verifies identity logs and judges whether a key may sign, showed seven places where Layer 1 (revision 2026-11-17, with OEP-0001) allows two readings, sets no rule, or sets a rule that does not do what the text beside it says. This proposal settles each one. Six choose the reading both existing implementations already follow or make an informal term exact. One closes a gap: a retired mind's keys could go on signing. No address, content ID or proof in the test vectors changes. It concerns anyone writing a verifier of identity logs or of signatures.

## Motivation

A mind's address is the content ID of its `Genesis`. Two verifiers that disagree about whether a genesis is valid disagree about whether a mind exists, and no later message can reconcile them. Each item below is a case where they might disagree, or where a rule fails to protect what it is there to protect.

1. **Must an event be a well-formed record?** Section 4 lists what a verifier checks in a log and does not say that each event satisfies Section 3. The Python checker verified a signed genesis with nine homes, seventeen aliases or a malformed `expires`; the JSON Schemas reject each. Both read Section 4 fairly.
2. **What is an "HTTPS origin"?** Section 3.6 allows up to eight in `homes` and gives no syntax. Is `https://example.com/` one, with its slash? `https://EXAMPLE.com`? A host in another script? A genesis is valid or not depending on the answer.
3. **May a controller or a key entry carry other members?** Sections 3.4 and 3.5 give tables of members. core 1.7 says a reader ignores a member it does not recognise. Both implementations reject an unknown member there, because a controller is what decides who may extend a log, and a member one verifier reads and another ignores is the start of a disagreement.
4. **Do the key sets apply on `Fork` and `Retire`?** Sections 3.8 and 3.10 list the members of those events and do not list `keys`, `invocation`, `agreement`, `homes`, `alsoKnownAs` or `revoked`. Section 4.5 applies them to every event. Both implementations follow 4.5.
5. **Where is `recovery` reserved?** Section 3.12 rejects "an event that contains it". An event contains a great deal: an extension block, `inherits`, `terms`. Both implementations reject the name as a member of the event itself and nowhere else.
6. **A retired mind's keys go on signing.** A `Retire` leaves a mind's keys in their sets. Section 6.1 asks that the key be in the operational keys of the state at the version the proof pins (item 2), and that no _later_ event removed it or retired the mind before the proof's evaluation time (item 3). A proof that pins the `Retire` event itself meets both: the key is in the state, and no event follows. So the holder of a retired mind's operational key could sign new records in its name for ever, against Section 3.10 ("after a `Retire`, the mind's keys can sign nothing"). Section 6.4 has the same shape, so a retired member's invocation key could go on signing a collective's identity events. The Python checker accepted both. A test of the reference implementation found it.
7. **May a container carry `created`?** core 7 requires `created` "in every record except the containers and `Sealed`". It does not say whether one may be present there, or what a reader does with it.

The extension mechanism (core 8) does not help: these are rules about which logs verify and which keys may sign, which every verifier must share.

## Specification

Written against revision 2026-11-17 as amended by OEP-0001.

**Layer 1, 3.4**, add before "Thresholds are majorities":

> A controller has no other members.

**Layer 1, 3.5**, the sentence that introduces the key sets. Current: "each as an array of objects `{ "key": <Multikey>, "label": <string, optional, at most 64 characters> }` with distinct keys:". Proposed:

> each as an array of objects `{ "key": <Multikey>, "label": <string, optional, at most 64 characters> }` with distinct keys and no other members:

**Layer 1, 3.6**, the row for `homes`. Current: "0–8 HTTPS origins that serve the mind's records". Proposed:

> 0–8 HTTPS origins (3.13) that serve the mind's records

**Layer 1, 3.8**, the first sentence. Current: "In addition to the common fields: `child` (REQUIRED, the address of the child mind), `controller` (as in 3.7) and `terms` (OPTIONAL object describing what the child received)." Proposed:

> In addition to the common fields: `child` (REQUIRED, the address of the child mind), `controller` (as in 3.7), `terms` (OPTIONAL object describing what the child received), and any of `keys`, `invocation`, `agreement`, `homes`, `alsoKnownAs` and `revoked`, with the meaning they have in an `Update` (3.7).

**Layer 1, 3.10**, the first sentence. Current: "In addition to the common fields: `controller` (as in 3.7, with `next` empty for key-controlled minds), `successor` (OPTIONAL address) and `reason` (OPTIONAL string)." Proposed:

> In addition to the common fields: `controller` (as in 3.7, with `next` empty for key-controlled minds), `successor` (OPTIONAL address), `reason` (OPTIONAL string), and any of `keys`, `invocation`, `agreement`, `homes`, `alsoKnownAs` and `revoked`, with the meaning they have in an `Update` (3.7).

**Layer 1, 3.12**. Current: "The member name `recovery` is reserved in identity events for key recovery in a later revision. A verifier of this revision MUST reject an event that contains it." Proposed:

> The member name `recovery` is reserved in identity events for key recovery in a later revision. A verifier of this revision MUST reject an event that has a member of that name. The name is reserved as a member of the event itself; inside another member, such as `inherits` or an extension block, it has no meaning and is not an error.

**Layer 1, 3.13**, new, after 3.12:

> **HTTPS origins.** An HTTPS origin is the string `https://` followed by a host and an optional port, written with one or more of the ASCII letters and digits and the characters `.`, `-`, `:`, `[` and `]`, and with nothing else: no user information, path, query or fragment, and no character outside ASCII. A name in another script is written in its A-label form (`xn--…`). The grammar bounds the characters, so that every implementation accepts the same strings; it does not show that the host exists.

As a pattern: `^https://[A-Za-z0-9.:\[\]-]+$`.

**Layer 1, 4.8**, new, after 4.7:

> **Well-formed events.** Every event is a well-formed record of its type: it satisfies core, Sections 1, 5.1 and 7, and Section 3 of this document, with every limit Section 3 sets. A log that contains an event that is not is rejected, whoever signed the event. A mind's address is the content ID of its genesis, so two verifiers that disagreed about which events are well formed would disagree about which minds exist.

**Layer 1, 6.1**, item 2. Current: "`K` is in the operational keys of the state at `V`;". Proposed:

> `K` is in the operational keys of the state at `V`, and the event `V` identifies is not a `Retire`;

**Layer 1, 6.4**, item 2. Current: "`K` is an invocation key of `M` at `V`;". Proposed:

> `K` is an invocation key of `M` at `V`, and the event `V` identifies is not a `Retire`;

**Layer 1, 15**, the row for `homes` of a `Location`. Current: "HTTPS origins". Proposed: "HTTPS origins (Section 3.13)".

**core 7**, the row for `created`. Current: "REQUIRED in every record except the containers and `Sealed` (Section 11). The author's claimed creation time: a claim, never evidence of when the record existed (Section 9)." Proposed:

> REQUIRED in every record except the containers and `Sealed` (Section 11), which have no such member: a reader ignores one there, as it ignores any member it does not recognise (Section 1.7). The author's claimed creation time: a claim, never evidence of when the record existed (Section 9).

**New names.** None. One new clause number in Section 3 (3.13) and one in Section 4 (4.8).

## Rationale and alternatives

**Well-formed events.** The alternative is to let a log verify by Section 4 alone and treat Section 3 as advice to writers. Then the limits of Section 3 (eight homes, sixteen aliases, the sizes of the key sets) bind nobody who can sign, and a verifier that enforces them rejects a mind that another accepts. One rule for every verifier is the only stable answer, and the stricter one is the one the schemas already publish.

**HTTPS origins.** Three definitions were weighed.

- _The origin of RFC 6454, exactly_: a host in lower case, no port when it is 443, a registrable name. It gives every origin one spelling, which is attractive for comparing homes. It needs a grammar for host names, IPv4 and IPv6 literals and ports, with look-ahead or a hand-written parser, and the schemas' patterns avoid look-ahead so that linear-time engines can run them. It would also make a genesis invalid for a spelling its author's URL library produced.
- _What the schemas had_: any characters after `https://` except `/`, `?`, `#`, `@` and white space. "White space" is not the same set in every regular-expression engine, so two implementations could still disagree, and a home could hold any other character of Unicode.
- _A character set_ (chosen): ASCII letters, digits and five punctuation marks. It is one line in any language, every engine agrees on it, and it admits every host name, address literal and port. It does not give an origin one spelling; a client that compares homes compares them as origins, in lower case and with the default port removed, as a web client does.

**Closed controllers and key entries.** The alternative, core 1.7's rule of ignoring what is not recognised, is right for records that grow by extension. A controller is not that: a future revision that gave a controller a new member would change who may extend a log, and a verifier of this revision must reject such a log, not read it wrongly. Extensions to identity events go in `ext`, at the top level.

**`Fork` and `Retire`.** The alternative is to forbid the key sets there, which would make a fork that also rotates an operational key take two events. Section 4.5 already applies them to every event and both implementations follow it.

**`recovery`.** Reserving the name at every depth would reject a genesis whose `inherits`, which is a free-form claim, happens to use the word. The later revision that defines recovery will define a member of the event.

**A proof pinned to a `Retire`.** Three ways to close it were weighed: treat a `Retire` as removing every key from the state; evaluate item 3 at the pinned event as well as at later ones; or refuse the pinned version outright. The first changes what the state of a retired mind looks like, and a DID document for a retired mind would no longer show the keys that signed its history. The second depends on a comparison of two evaluation times that can be made equal. The third (chosen) is one condition with no time in it: nothing is ever signed _as of_ a retirement. Records signed before the retirement pin earlier versions and stand, as before.

**`created` on a container.** The alternative is to reject it. A container is assembled by whoever serves it and signed by nobody, so a stray member there harms no one, and core 1.7 already says what a reader does.

Doing nothing leaves items 1 to 5 and 7 to each implementer's reading and leaves item 6 open. None of these can be an extension: they define which logs verify.

## Backwards compatibility

A rule change, in the sense that a verifier of the unamended revision may accept logs and proofs that this proposal rejects.

- **Does any record or identity log that is valid today become invalid, or the reverse?** Under one reading of today's text, yes: a log with an event that breaks Section 3, a log with an event whose `homes` holds a string outside 3.13, and a proof pinned to a `Retire`. No such log or proof is known outside test suites: both implementations already rejected everything in items 1 to 5 where they checked it, except that the Python checker did not apply Section 3 to each event. Nothing becomes valid that was invalid under both readings.
- **Does any golden value change?** No. `vectors.json` gains cases and loses none; every existing value is byte for byte what it was.
- **What does an implementation of the earlier revision do with a record that uses the change?** There is nothing to use: the change removes readings, and adds no member, type or name.
- **What must existing minds, hosts, resolvers, indexers and gateways do, and by when?** Nothing, unless a mind has published an event that breaks Section 3, in which case its log does not verify under this proposal and never verified under the schemas.

## Security and privacy considerations

Item 6 is a security fix. Before it, retiring a mind did not stop its operational keys: whoever held one, a former employee or a thief the retirement was meant to defeat, could sign new Intents, Offers, Commitments and delegations in the mind's name by pinning the `Retire`. Records that describe the present were already protected by the current-state rule; historical records were not. A retired member's invocation key could likewise go on signing a collective's identity events.

Item 1 removes a way to split verifiers: an attacker with a mind's control key could publish a genesis that some verifiers accept and others reject, and so a mind that exists for some and not for others. Item 3 removes a quieter version of the same split.

Item 2 bounds what a home may contain. A home is fetched by clients, so a string with a user part, a path or characters that render as another host is a phishing aid; the character set excludes them. It does not make a home trustworthy: a client still treats what a home serves as untrusted until verified.

No item changes what a record reveals about anyone.

## Test vectors

Added to `vectors.json` by `oip_vectors.py`, and accepted or rejected by both implementations:

| Case                                    | Kind        | Section                           | Item |
| --------------------------------------- | ----------- | --------------------------------- | ---- |
| `genesis-with-nine-homes`               | `log`       | negative, with a control of eight | 1    |
| `event-with-malformed-expires`          | `log`       | negative, with a control          | 1    |
| `home-with-a-path`                      | `log`       | negative, with a control          | 2    |
| `controller-with-an-unknown-member`     | `log`       | negative, with a control          | 3    |
| `key-added-by-a-fork`                   | `countsFor` | must accept                       | 4    |
| `recovery-inside-another-member`        | `log`       | must accept                       | 5    |
| `proof-pinned-to-a-retire`              | `countsFor` | negative, with a control          | 6    |
| `retired-member-signs-for-a-collective` | `log`       | negative, with a control          | 6    |
| `container-with-created`                | `record`    | must accept                       | 7    |

The differential tests compare the two implementations on generated logs, each with something done to it (an event moved, a member changed with or without signing again, the wrong key, evidence of another time), under the rule that the verdicts are the same.

## Reference implementation

`@oip/identity` (BUILD.md, M2) and the Python checker `spec/test-vectors/oip_vectors.py` implement every item. The schemas of `@oip/schema` carry the pattern of 3.13. The checker now applies the shape of Section 3 to every event of a log (`event_ok`), which it did not before.

## Open questions

- **Should a home have one spelling?** If clients come to compare homes as strings, a later revision can require lower case and no default port. That would be a further restriction, compatible with this one.
- **The log a verifier must hold (core 9.4).** A verifier holds a signer's log "as a witness served it at some time no earlier than `τ(p)`", and judges the proof at `t(p)`, which is later than `τ(p)` when the proof is dated up to 300 seconds ahead of the clock that received it. A removal whose evaluation time falls between the two is not yet known to that verifier, and decides the proof once it is. The verdict on such a proof can therefore change within 300 seconds. Asking for the log as of `t(p)` would close this, at the price of making a verifier wait before counting a proof from a signer whose clock runs fast. This proposal leaves core 9.4 as it is.
- **The clause each negative case breaks.** BUILD.md asks that each negative case be rejected "for its stated reason". The vectors state reasons as prose, and the controls show that each case fails for its reason alone. Giving each case the clause it breaks would let a verdict's own reason be checked. It is left for the milestone that judges the delegation cases, which are most of them.

## Copyright

This document is licensed under the [Creative Commons Attribution 4.0 International Licence](https://creativecommons.org/licenses/by/4.0/) (CC BY 4.0).
