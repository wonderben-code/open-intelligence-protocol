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

Writing `@oip/identity`, the package of the reference implementation that verifies identity logs and judges whether a key may sign, showed seven places where Layer 1 (revision 2026-11-17, with OEP-0001) allows two readings, sets no rule, or sets a rule that does not do what the text beside it says. Two independent reviews of that package, and a third of the fixes, then found twelve more, in Layer 1 and in core Sections 8 and 9. This proposal settles each one. Most choose one of two readings, or make an informal term exact. Six close gaps that protect someone: a retired mind's keys could go on signing (item 6); a log or a record with a critical extension nobody implements was treated as valid (item 8); a duplicitous collective went on signing with the members it had before its branches parted (item 9); a conflicting branch was passed over if any later event of it was invalid (item 10); a member's proof made as a delegate counted as the member's own on an identity event (item 12); and nothing said what a verifier may keep of a log whose next event it cannot judge, so one that kept the part it had verified went on counting a key which that event removed (item 19). No address, content ID or proof in the test vectors changes. It concerns anyone writing a verifier of identity logs or of signatures.

## Motivation

A mind's address is the content ID of its `Genesis`. Two verifiers that disagree about whether a genesis is valid disagree about whether a mind exists, and no later message can reconcile them. Each item below is a case where they might disagree, or where a rule fails to protect what it is there to protect.

1. **Must an event be a well-formed record?** Section 4 lists what a verifier checks in a log and does not say that each event satisfies Section 3. The Python checker verified a signed genesis with nine homes, seventeen aliases or a malformed `expires`; the JSON Schemas reject each. Both read Section 4 fairly.
2. **What is an "HTTPS origin"?** Section 3.6 allows up to eight in `homes` and gives no syntax. Is `https://example.com/` one, with its slash? `https://EXAMPLE.com`? A host in another script? A genesis is valid or not depending on the answer.
3. **May a controller or a key entry carry other members?** Sections 3.4 and 3.5 give tables of members. core 1.7 says a reader ignores a member it does not recognise. Both implementations reject an unknown member there, because a controller is what decides who may extend a log, and a member one verifier reads and another ignores is the start of a disagreement.
4. **Do the key sets apply on `Fork` and `Retire`?** Sections 3.8 and 3.10 list the members of those events and do not list `keys`, `invocation`, `agreement`, `homes`, `alsoKnownAs` or `revoked`. Section 4.5 applies them to every event. Both implementations follow 4.5.
5. **Where is `recovery` reserved?** Section 3.12 rejects "an event that contains it". An event contains a great deal: an extension block, `inherits`, `terms`. Both implementations reject the name as a member of the event itself and nowhere else.
6. **A retired mind's keys go on signing.** A `Retire` leaves a mind's keys in their sets. Section 6.1 asks that the key be in the operational keys of the state at the version the proof pins (item 2), and that no _later_ event removed it or retired the mind before the proof's evaluation time (item 3). A proof that pins the `Retire` event itself meets both: the key is in the state, and no event follows. So the holder of a retired mind's operational key could sign new records in its name for ever, against Section 3.10 ("after a `Retire`, the mind's keys can sign nothing"). Section 6.4 has the same shape, so a retired member's invocation key could go on signing a collective's identity events. The Python checker accepted both. A test of the reference implementation found it.
7. **May a container carry `created`?** core 7 requires `created` "in every record except the containers and `Sealed`". It does not say whether one may be present there, or what a reader does with it.

The reviews of `@oip/identity` (recorded in `reviews/build/M2-identity.md`) found the rest. In each of items 8 to 13 both implementations gave the same answer, and it was not the one the text gives or needs, which is where comparing two implementations shows nothing.

8. **A critical extension on an identity event or a record.** core 8.3 says an implementation that does not understand a namespace listed in `critical` "MUST NOT act on it or treat it as valid for any decision". Section 4.8 said which sections of core an event satisfies and left out Section 8. Both implementations verified a log whose `Update` listed a critical extension and replaced the mind's keys, and counted a record with a critical extension for its author.
9. **A duplicitous collective.** When evidence cannot separate two branches, Section 7.3 lets only the events before the divergence stand, and says that records "pinned to versions" after it are not accepted. A record signed under a collective's threshold pins no version of the collective: it is judged against "the state at T" (9.5). On a log that stops before the divergence, that state is the last one before it, for every later T, for ever. So a collective that was retired in one branch, and had a member removed in the other, went on signing with its old members for a verifier that held both branches, though it signed nothing for a verifier that held either. 7.3 says duplicity "never revives a key"; here it revived a member.
10. **A branch with an event that does not verify.** 7.1 defines duplicity by two events at one position, each valid against the same predecessor, and 7.3 gives the position to the event with the earlier evidence. Both implementations verified each branch as a whole and threw away a branch that failed anywhere. A valid conflicting event followed by one invalid event therefore vanished, and the other branch won although its event was seen later. The same happened to a branch longer than a verifier is set to read (4.7).
11. **What does a verifier do with the events before one that fails?** Section 4 says a log with an event that fails is rejected. It does not say whether the events before it are then the mind's log. For an event that is simply invalid, they are: a copy damaged on the way must not take the log away. For an event the verifier cannot judge, they are not: it may be a removal. The text did not tell the two apart, and a verifier that kept "what verified" of a log whose next event carried a critical extension went on counting a key that event removed.
12. **Which times is "the earliest time T" of 9.5 taken over?** Both implementations tried the evaluation times of the proofs. A record signed by two minds, one of which becomes a member later, is by the text signed from the moment the membership changes; the implementations said never, unless some proof happened to be dated after the change. 9.5 also left open whether a `Hello`, which 6.1 lists with `Location` and `Participant`, can be signed under a threshold; core 11 gives it to the author's own key, and the implementations counted a threshold for it.
13. **A member's proof that names an `authority`.** Under 9.5 a proof that names an authority does not count towards a collective's threshold on a record: it acts for that principal. 6.4, for identity events, did not say so, and 9.4 says a delegate of a member cannot sign for it there.
14. **The dates and the expiry of an identity event.** core 9.3 says a proof whose `created` is more than 300 seconds after `τ(p)` "MUST NOT count for anything", and core 9.6 that a proof evaluated more than 300 seconds after its record's `expires` does not count. For a proof on an identity event neither implementation read the proof's `created`, or the event's `expires`, at all.
15. **What is evidence for an identity event?** core 9.5 says `τ(e)` is evidence that `e` existed "with proofs meeting Layer 1, Section 4". An event's content ID does not cover its proofs. An implementation that records the time it first saw an event's content, signed or not, later judges a signature made with a removed key at that early time. The text was right and easy to implement wrongly.
16. **Which logs must a verifier hold, and as of when?** core 9.4 requires the log of the mind whose key signed, as served no earlier than `τ(p)`. Whether the signer is still a member is read from the collective's log, which 9.4 does not name. And an identity event takes effect no earlier than the event before it (9.5), which may be later than its own evidence.
17. **May an entry of `revoked` or of `parents` carry other members, and how many keys may one event revoke?** Item 3 closed controllers and key entries. An entry of `revoked` carries `compromisedSince`, which withdraws signatures; a misspelt one was ignored in silence. And `revoked` was the one set in an event with no limit: an event of a megabyte could name seventeen thousand keys.
18. **3.13 said "a host and an optional port"** and both implementations apply a character set. A reader of the text alone could require a host.
19. **The DID document of a duplicitous mind** looked like any other.

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

> **HTTPS origins.** An HTTPS origin is a string that matches `^https://[A-Za-z0-9.:\[\]-]+$` from its first character to its last: `https://` followed by one or more of the ASCII letters and digits and the characters `.`, `-`, `:`, `[` and `]`, and nothing else. It is meant to hold a host and an optional port, and it can hold no user information, path, query or fragment, no line terminator, and no character outside ASCII. A name in another script is written in its A-label form (`xn--…`). The grammar bounds the characters and nothing more, so that every implementation accepts the same strings: it does not show that the host exists, nor that what follows the scheme is a host and a port, and `https://:::` matches. A client that fetches from a home treats it as any URL it was handed by a stranger.

**Layer 1, 4.8**, new, after 4.7:

> **Well-formed events.** Every event is a well-formed record of its type: it satisfies core, Sections 1, 5.1 and 7, and Section 3 of this document, with every limit Section 3 sets. A log that contains an event that is not is rejected, whoever signed the event. A mind's address is the content ID of its genesis, so two verifiers that disagreed about which events are well formed would disagree about which minds exist. An event is also a record under core, Sections 8 and 9. A verifier that does not implement an extension that an event lists in `critical` MUST NOT treat the event as valid (core 8.3), so it rejects the log: here two verifiers of this revision may disagree about a log, and it is the event's author that chose it. 4.9 says what else may differ from one verifier to the next, and what never does. An event that has `expires` is subject to core 9.6: evaluated more than 300 seconds after it, the event has no proof that counts.

**Layer 1, 4.9**, new, after 4.8:

> 4.9. **Invalid, and undecided.** A log with an event that fails this section is rejected. What a verifier may hold in the log's place depends on why the event failed.
>
> A verifier cannot **read** an event whose `oip` is a string other than this version's (core 7); whose `type` is a string that names no type of event this revision defines, `Merge` among them (3.9, 4.6); that has the reserved member (3.12); or that lists in `critical` an extension the verifier does not implement, or has a `critical` that is no list of names (4.8). Such an event may depend on rules the verifier does not have, for its form, its place and its signatures alike.
>
> - An event is **invalid** if the verifier can read it and one of the following holds. Each is so whoever judges the event, and whenever, because it can be seen in the event and the events before it and in nothing else.
>   - It is not well formed (4.8).
>   - It is not in its place: it does not follow the event before it (4.1, 4.2, 4.6), or it sets keys that the state before it does not allow (3.5, 4.5).
>   - The proofs on it could not authorise it, whatever evidence and whatever logs a verifier holds. For a key-controlled mind, they are not the proofs that 4.1 and 4.3 require, counting every proof that verifies, whatever its date. For a member-controlled mind, too few of the members that 4.1 and 4.4 require have a proof on it at all: one that verifies under a key reference of that member's (3.11) and names no authority.
>
>   An invalid event is no event. A log that contains one is rejected, like any other that fails this section. A verifier that holds such a copy of a mind's log treats the copy as ending before the invalid event: it takes nothing from that event or from anything after it, and loses nothing by it.
>
> - An event that fails and is not invalid is **undecided**: the verifier cannot judge it. It cannot read the event; or it holds no evidence for the event, or evidence under which the event or a proof on it fails core 9.3, 9.5 or 9.6, which other evidence might not; or a member's proof on it does not count (6.4), or a member is too tall (4.7), which is read from the member's log as the verifier holds it; or the event exceeds a limit that the verifier sets and this specification does not (4.7; core 1.6), or is refused under a rule on which core lets verifiers differ (core 1.1). An undecided event may be an event of the log, and may remove a key. A verifier MUST NOT take the events before it as the mind's log: it does not know the mind's state from that event on, and treats the log as not verified until it can judge the event.
>
> A verifier that has not shown an event to be invalid treats it as undecided.
>
> A verifier relies on a copy of a log because a source it trusts to serve the whole log served it (core 9.4). What it has been shown, it keeps: every event of every copy, in its position, and every proof on each (7.1). No copy takes anything away. An earlier state of the log does not; nor does a copy without an event the verifier holds, whether that event verifies or is undecided; nor a copy with another event in that event's position, which is held beside it (7.3). What a verifier makes of the events it holds is decided when it is asked, with the evidence and the logs it holds then, and never when a copy arrives. A copy from a source the verifier does not trust in that way is no reason to stop relying on one that is.

**Layer 1, 3.6**, the row for `parents`, and **3.7**, the description of `revoked`: each gains "with no other members". `revoked` becomes "an array of at most 80 objects", with a row in the table of limits (Section 19): 80 is every operational and invocation key a state can hold.

**Layer 1, 5.2**, the item on metadata, add:

> When the mind is duplicitous for the resolver (Section 7.3), the document is produced from the state before the point of divergence, and the metadata also includes `duplicitous`, with the value true.

**Layer 1, 6.4**, items 4 and 5. Current: "`p.proofPurpose` is `capabilityInvocation`;" and "the signature verifies (core 5.4)." Proposed:

> 4. `p.proofPurpose` is `capabilityInvocation`, and `p` has no `authority`: a proof that names an authority is made for that principal, not by the member for itself;
> 5. the signature verifies (core 5.4), and `p.created` is not more than 300 seconds after the evidence for `e` (core 9.3, 9.5).

**Layer 1, 7.3**, add after "so duplicity never revives a key.":

> A collective's records pin no version of the collective, so for them the rule is one of time: nothing is signed under the threshold of a duplicitous collective at or after the evaluation time of its earliest conflicting event (Section 9.5).
>
> A verifier resolves the events it holds position by position, from the genesis (4.9). At each position it judges every event it holds there that follows the events before. One that is invalid is no event. If one is undecided, the log does not verify for that verifier, whatever else it holds at that position: the event may be the mind's own, so another event does not take the position for want of a judgement. If one event verifies there, the log goes on with it. If several verify, the evidence decides between them as above, and what follows an event that lost is not judged and changes nothing. Where the evidence cannot separate them, every event the verifier holds after each of them applies, so each is judged in the same way, and an undecided one among them stops the log.

**Layer 1, 7.1**. Current: "The same event with a different set of proofs is not duplicity." Proposed:

> The same event with a different set of proofs is not duplicity: it is one event, and a verifier that holds it with different sets of proofs judges it with all of them, since each proof stands on its own (core 5.5).

**Layer 1, 9.5**, add after the sentence that defines when a record is signed by a collective:

> The threshold can first be met when a proof is made or when an event of the collective changes its members or its threshold, so `T` ranges over the evaluation times of the proofs and of the collective's own events. A proof counts towards the threshold only if the verifier holds the collective's log as core 9.4 requires of a signer's log for that proof. For a duplicitous collective, `T` is earlier than the evaluation time of its earliest conflicting event (Section 7.3).

and, before the sentence on records of the collective's current state:

> A `Hello` is not signed under a threshold: it carries one proof, by a key of the author's own (Section 13.3; core 11).

**core 9.4**, "Holding the evidence", add at the end:

> The same is required of each log that decides whether the proof counts: the log of a collective under whose threshold the proof is counted (Layer 1, Section 9.5), held as served no earlier than `τ(p)`; and, for a member's proof on an identity event `e`, the member's log, held as served no earlier than the latest `τ` among `e` and the events before it in its log, since `e` takes effect no earlier than they do (9.5).

**core 9.5**. Current: "and an event whose `created` is more than 300 seconds after `τ(e)` is invalid." Proposed, because that failure depends on the evidence a verifier holds, and "invalid" now says that it does not (Layer 1, 4.9):

> and an event whose `created` is more than 300 seconds after `τ(e)` does not verify for that verifier.

**core 9.5**, add after "Members' proofs on a collective's identity events are judged at the event's evaluation time (Layer 1, Section 6.4).":

> Evidence for an event is evidence for the proofs it stood with, and for no proof added to it later: a verifier or a witness records its first sight of an event only once the event has verified, never on sight of its content alone, which the content ID names with or without valid proofs. For the same reason a feed entry is evidence for an event only if it commits to proofs that make the event valid (Layer 1, Section 10.1): anyone can list a content ID in a feed of their own. For a proof on an identity event, `τ(p)` is `τ(e)`: a proof there whose `created` is more than 300 seconds after `τ(e)` does not count (9.3), and one evaluated more than 300 seconds after the event's `expires` does not count (9.6).

**Layer 1, 6.1**, item 2. Current: "`K` is in the operational keys of the state at `V`;". Proposed:

> `K` is in the operational keys of the state at `V`, and the event `V` identifies is not a `Retire`;

**Layer 1, 6.4**, item 2. Current: "`K` is an invocation key of `M` at `V`;". Proposed:

> `K` is an invocation key of `M` at `V`, and the event `V` identifies is not a `Retire`;

**Layer 1, 15**, the row for `homes` of a `Location`. Current: "HTTPS origins". Proposed: "HTTPS origins (Section 3.13)".

**core 7**, the row for `created`. Current: "REQUIRED in every record except the containers and `Sealed` (Section 11). The author's claimed creation time: a claim, never evidence of when the record existed (Section 9)." Proposed:

> REQUIRED in every record except the containers and `Sealed` (Section 11), which have no such member: a reader ignores one there, as it ignores any member it does not recognise (Section 1.7). The author's claimed creation time: a claim, never evidence of when the record existed (Section 9).

**New names.** One member of DID document metadata, `duplicitous`. One new clause number in Section 3 (3.13) and two in Section 4 (4.8, 4.9).

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

**A critical extension on an identity event (item 8).** Two answers were weighed. Forbidding `critical` in identity events would keep every verifier in agreement about every log. But core 8.5 makes `critical` the one safe way to add a member that must not be ignored, and this proposal itself sends future changes to identity events to `ext`; a later profile for key recovery would need exactly this. So core 8.3 applies as it is written: a verifier that does not implement the extension does not treat the event as valid, and for an identity event that means the log. The author of such an event chooses to exist only for verifiers that implement the extension.

**A duplicitous collective (item 9).** The alternative is to apply every branch's removals and retirements member by member: a member counts at `T` only if every branch still has it. That is more work to state, and it leaves a threshold whose size differs between branches undefined. Refusing everything from the first conflicting event on is one condition, it never revives a member, and a collective whose members signed two events for one position has forfeited being heard until a verifier's evidence separates them.

**A branch that does not verify to its end (item 10).** Three answers were weighed. Dropping the branch (what both implementations did) lets anyone who can append one junk event to a copy of a log make the other branch win. Treating the events that verify as the whole branch is right for an event that is invalid for everyone, and wrong for one that this verifier merely cannot judge (it holds no evidence for it, or it is past the length the verifier reads): such an event may be a removal. The rule chosen keeps the branch in the contest with what verifies, and refuses the log if the contest leaves a branch whose end the verifier does not know. A verifier that takes logs from outside keeps only what it could verify, so a junk event appended in transit costs it nothing.

**Invalid, and undecided (item 19).** Two simpler rules were weighed. "Keep what verified, whatever failed next" is what an implementation does by default, and it is unsafe: the event that failed may be a removal the verifier could not read. "Keep nothing of a copy with an event that fails" is safe, and makes every damaged copy a lost mind. The rule here keeps the second and relaxes it where that is provably safe.

- _Invalid is defined, and undecided is the rest._ An event is invalid only if it is shown to be, by what can be seen in the event and the events before it. So the unsafe mistake, taking for junk an event that may be real, needs a positive finding.
- _Nothing that reads another log makes an event invalid._ For a key-controlled mind the signatures are a matter of the log alone. For a collective, whether a member's proof counts is read from the member's log, and a verifier's copy of that log is not a fact about the event: it may lag, the member may be duplicitous for one verifier and not for another, and a version a proof names may be published later, when the same event verifies unchanged. So for a collective the test is only whether enough members have a proof on the event at all.
- _What a verifier cannot read is undecided, signed or not._ A reserved type such as `Merge` is, as 3.9 already demands; a verifier of this revision cannot check the signatures of an event whose rules it does not have. An event that lists a critical extension the verifier does not implement is treated the same way, before anything else about it is asked, because an extension listed in `critical` may change what authorises the event: a profile for recovering a mind whose keys are lost would do exactly that.
- _An invalid event is no event, for every verifier alike._ An earlier draft said a verifier MAY hold the events before an invalid event. Two implementations then gave two answers for the same copies, and no test vector could say which. The rule is now one: a copy ends before its invalid event.

**What a verifier keeps (item 19, and 7.1, 7.3).** The reference implementation went through three designs before this text was right, and each failure was the same in kind. A verifier that sums a copy up when it arrives, and lets a later copy take its place if the later one "shows as much", has to decide what a copy shows with the evidence and the logs it holds at that moment. A copy whose second event waits on a member's log shows little today and everything tomorrow; summed up today, it is replaced by a shorter copy, and the removal in its third event is gone. So the rule is about what is kept, and says nothing of comparing copies: a verifier keeps every event it is shown, in its position, with every proof, and judges them when it is asked.

- _Every proof of an event counts._ 7.1 already says that the same event with other proofs is not duplicity. It follows that a verifier with two copies of an event, each with some of its proofs, holds one event with all of them.
- _An undecided event holds its position._ 7.3 as first amended let a copy take part "with the events it has that verify", so an undecided event took no part, and a valid event of another copy took the position by default. A verifier that held the mind's own event, with a critical extension and seen first, beside a rival signed with the same control key and seen long after, accepted the rival, and a key the first event removed went on counting. 7.3 now stops the log there.
- _What follows an event that lost is not judged._ It cannot change the log, and judging it lets a hostile set of logs make a verifier work without end.

**What this costs.** Anyone can write an event that a verifier of this revision cannot read: an object with the type `Merge` is enough. A verifier that is served a copy with one, by a source it trusts for the whole log, cannot tell it from the mind's own event, and stops relying on the log until it can judge the event or decides to drop what it holds. So the invalid class protects against damage, and not against a source the verifier trusts that serves an unreadable event on purpose. A verifier with several such sources is worse off than if one of them had merely withheld the log: one unreadable event from one source stops the mind for it. That is the price of never counting a key that an unread event may have removed, and it is why 4.9 says where a copy comes from: a verifier does not take a copy from a source it does not trust for the whole log.

**The times of 9.5 (item 11).** The alternative is to say in 9.5 that `T` ranges over the proofs alone. Then whether two signers' proofs complete a threshold after a membership change depends on whether either happened to be dated after the change, which is no rule anyone would choose. The text as written is the consistent one, so the implementations follow it.

**The dates and expiry of an identity event (item 13).** Forbidding `expires` on identity events was weighed. core 7 allows it on every record and core 9.6 already says what it does; an exception would be a new rule where applying the existing one suffices.

Doing nothing leaves items 1 to 5, 7, 11 and 14 to 18 to each implementer's reading and leaves items 6, 8, 9, 10, 12 and 13 open. None of these can be an extension: they define which logs verify.

## Backwards compatibility

A rule change, in the sense that a verifier of the unamended revision may accept logs and proofs that this proposal rejects.

- **Does any record or identity log that is valid today become invalid, or the reverse?** Under one reading of today's text, yes: a log with an event that breaks Section 3, a log with an event whose `homes` holds a string outside 3.13, and a proof pinned to a `Retire`; and, from items 8 to 13 and 16, a log or record with a critical extension the verifier does not implement, a record signed by a duplicitous collective after its branches part, a record pinned to a branch that wins only because the other could not be read, a member's proof with an `authority` on an identity event, an identity event with a proof dated more than 300 seconds after its evidence or evaluated after its `expires`, an entry of `revoked` or `parents` with another member, and an event that revokes more than 80 keys. No such log or proof is known outside test suites. One thing becomes valid that both implementations refused: a record whose signers complete a collective's threshold when its membership changes (item 11), which the text of 9.5 already said.
- **Does any golden value change?** No. `vectors.json` gains cases and loses none; every existing value is byte for byte what it was.
- **What does an implementation of the earlier revision do with a record that uses the change?** There is nothing to use: the change removes readings, and adds no member, type or name.
- **What must existing minds, hosts, resolvers, indexers and gateways do, and by when?** Nothing, unless a mind has published an event that breaks Section 3, in which case its log does not verify under this proposal and never verified under the schemas.

## Security and privacy considerations

Item 6 is a security fix. Before it, retiring a mind did not stop its operational keys: whoever held one, a former employee or a thief the retirement was meant to defeat, could sign new Intents, Offers, Commitments and delegations in the mind's name by pinning the `Retire`. Records that describe the present were already protected by the current-state rule; historical records were not. A retired member's invocation key could likewise go on signing a collective's identity events.

Item 1 removes a way to split verifiers: an attacker with a mind's control key could publish a genesis that some verifiers accept and others reject, and so a mind that exists for some and not for others. Item 3 removes a quieter version of the same split.

Items 8, 9, 10 and 12 are security fixes too.

- _Item 8._ `critical` exists so that a record can depend on a rule that must not be ignored. A verifier that ignored it on an identity event would apply the event's keys without the rule the event's author made them depend on.
- _Item 9._ A past majority of a collective's members can always sign a second event for an old position. A verifier with no witness that obtains both branches at once records the same first sight for both, and cannot separate them. Before this change that verifier accepted records from members the collective had removed, and from a collective that had been retired.
- _Item 10._ Before this change, appending one junk event to a copy of the honest branch was enough to make a verifier that held both take the other branch, and count records pinned to it.
- _Item 12._ A delegate of a member cannot sign a collective's identity events for it (9.4). The condition is now in the rule that decides it.

Item 19 closes a gap that a careful implementation walks into. "Record first sight only of what verified" (item 14) leads an implementation to keep the part of a log that verified. If the next event is one it cannot judge, that part is a state of the mind that the mind may have left: a key the event removed goes on counting. The same loss came back in the reference implementation four times before the rule was whole: through a later copy that was an earlier state of the log; through a copy with another event at the position; through a collective's event that one verifier could verify and another, with an older copy of a member's log, took for junk; and through a copy that was summed up before the log it waited on arrived. The rule is therefore stated once, for what a verifier keeps: every event it has been shown, the ones it cannot judge included, with every proof, judged when it is asked and never when a copy arrives.

Item 14 states what evidence for an event is. An implementation that gets it wrong reopens the attack of Layer 1, 9.6: a thief with a removed invocation key signs an event whose content was shown to a verifier before the removal. The reference implementation records first sight only through an operation that has verified the event first.

Item 2 bounds what a home may contain. A home is fetched by clients, so a string with a user part, a path, a space or a control character is a phishing aid; the character set excludes them. It does not exclude a name that a client may show as characters resembling another host: an internationalised name is written in ASCII (`xn--…`), and that is within the set. Nor does it make a home trustworthy: a client still treats what a home serves as untrusted until verified.

No item changes what a record reveals about anyone.

## Test vectors

Added to `vectors.json` by `oip_vectors.py`, and accepted or rejected by both implementations:

| Case                                                      | Kind        | Section                                                         | Item |
| --------------------------------------------------------- | ----------- | --------------------------------------------------------------- | ---- |
| `genesis-with-nine-homes`                                 | `log`       | negative, with a control of eight                               | 1    |
| `event-with-malformed-expires`                            | `log`       | negative, with a control                                        | 1    |
| `home-with-a-path`                                        | `log`       | negative, with a control                                        | 2    |
| `controller-with-an-unknown-member`                       | `log`       | negative, with a control                                        | 3    |
| `key-added-by-a-fork`                                     | `countsFor` | must accept                                                     | 4    |
| `recovery-inside-another-member`                          | `log`       | must accept                                                     | 5    |
| `proof-pinned-to-a-retire`                                | `countsFor` | negative, with a control                                        | 6    |
| `retired-member-signs-for-a-collective`                   | `log`       | negative, with a control                                        | 6    |
| `container-with-created`                                  | `record`    | must accept                                                     | 7    |
| `event-with-a-critical-extension`                         | `log`       | negative, with a control                                        | 8    |
| `record-with-a-critical-extension`                        | `countsFor` | negative, with a control                                        | 8    |
| `duplicitous-collective-signs-after-the-divergence`       | `countsFor` | negative, with a control                                        | 9    |
| `branch-ending-in-an-invalid-event-is-not-passed-over`    | `countsFor` | negative, with a control                                        | 10   |
| `collective-threshold-not-met-before-its-members-change`  | `countsFor` | negative; its control is the must-accept case                   | 11   |
| `member-proof-names-an-authority`                         | `log`       | negative, with a control                                        | 12   |
| `event-proof-dated-after-the-evidence`                    | `log`       | negative, with a control at 300 seconds                         | 13   |
| `event-evaluated-after-it-expires`                        | `log`       | negative, with a control at 300 seconds                         | 13   |
| `revoked-entry-with-an-unknown-member`                    | `log`       | negative, with a control                                        | 16   |
| `event-revoking-81-keys`                                  | `log`       | negative, with a control of 80                                  | 16   |
| `parent-with-an-unknown-member`                           | `log`       | negative, with a control                                        | 16   |
| `collective-event-with-a-null-controller`                 | `log`       | negative, with a control                                        | 3    |
| `home-that-is-no-host`                                    | `log`       | must accept                                                     | 17   |
| `winning-branch-ending-in-an-event-that-cannot-be-judged` | `countsFor` | negative, with a control                                        | 19   |
| `rival-to-an-event-that-cannot-be-judged`                 | `countsFor` | negative, with a control                                        | 19   |
| `event-held-with-too-few-of-its-proofs`                   | `countsFor` | negative; its control holds a second copy with the other proofs | 19   |
| `copy-with-an-invalid-event-after-the-log`                | `countsFor` | must accept                                                     | 19   |
| `duplicitous-collective-whose-branches-keep-the-signers`  | `countsFor` | negative, with a control of one branch                          | 9    |

Items 14 and 15 concern what a verifier holds and when it obtained it. The vectors state evidence for each case and take every log as complete, so no case can show them; the reference implementation's own tests do. A case gives every copy the verifier holds at once, so no case shows that the order of arrival does not matter either; the reference implementation tests that with generated sequences.

The differential tests compare the two implementations on generated logs, each with something done to it (an event moved, a member changed with or without signing again, the wrong key, evidence of another time), under the rule that the verdicts are the same.

## Reference implementation

`@oip/identity` (BUILD.md, M2) and the Python checker `spec/test-vectors/oip_vectors.py` implement every item, except that the checker takes every log as complete and holds every copy a case gives, and so has nothing to do for item 15 or for the order copies arrive in. Both say whether a failing event is invalid or undecided, the checker from the text of 4.9 alone (`invalid_event`), and the differential tests compare the two on every generated log with an event that fails, and on sets of copies with junk after them, with proofs lost and with proofs split between copies. The schemas of `@oip/schema` carry the pattern of 3.13 and the closed entries of item 16. The checker now applies the shape of Section 3 to every event of a log (`event_ok`), which it did not before, and reads a member whose value is `null` as present. Neither implementation implements any extension, so each refuses every critical one; `@oip/identity` takes the namespaces its caller implements as a parameter.

## Open questions

- **Should a home have one spelling?** If clients come to compare homes as strings, a later revision can require lower case and no default port. That would be a further restriction, compatible with this one.
- **The log a verifier must hold (core 9.4).** A verifier holds a signer's log "as a witness served it at some time no earlier than `τ(p)`", and judges the proof at `t(p)`, which is later than `τ(p)` when the proof is dated up to 300 seconds ahead of the clock that received it. A removal whose evaluation time falls between the two is not yet known to that verifier, and decides the proof once it is. The verdict on such a proof can therefore change within 300 seconds. Asking for the log as of `t(p)` would close this, at the price of making a verifier wait before counting a proof from a signer whose clock runs fast. This proposal leaves core 9.4 as it is.
- **A member's event with a critical extension.** A collective's event needs its members' logs (9.4), and a member's log with an event the verifier cannot judge does not verify. One member that adopts a critical extension therefore stops every collective it belongs to from verifying, for every verifier that does not implement the extension, from the first event the member signs after it. That is what `critical` means, and it is also a lever one member holds over the others. A profile that defines a critical extension for identity events should say what collectives do about it.
- **The clause each negative case breaks.** BUILD.md asks that each negative case be rejected "for its stated reason". The vectors state reasons as prose, and the controls show that each case fails for its reason alone. Giving each case the clause it breaks would let a verdict's own reason be checked. It is left for the milestone that judges the delegation cases, which are most of them.

## Copyright

This document is licensed under the [Creative Commons Attribution 4.0 International Licence](https://creativecommons.org/licenses/by/4.0/) (CC BY 4.0).
