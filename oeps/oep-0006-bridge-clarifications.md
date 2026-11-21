---
oep: 6
title: Bridge clarifications found while building the MCP server and the gateways
authors:
  - Claude Code, building the reference implementation for Ekram Alam (@wonderben-code)
status: Review # Draft | Review | Accepted | Rejected | Withdrawn | Final
type: Layer 0 # Core | Layer 0 | Layer 1 | Layer 2 | Process (item 4 also changes Layer 1, 16.2, and item 7 Layer 1, 5.2)
created: 2026-11-20
requires: [1, 2, 3, 4, 5]
replaces: []
discussion: # the pull requests of milestones M8 and M9
revision: # the specification revision that adopted the change; empty until Final
---

# OEP-0006: Bridge clarifications found while building the MCP server and the gateways

## Summary

Writing the OIP MCP server showed one place where Layer 0 (revision 2026-11-17, with OEP-0001 to OEP-0005) protects the user from one kind of record and not from another that needs it as much. Writing the rule that tells a bridged mind from one that only says it is showed one place where two implementations read the same sentence differently. Writing the gateway for MCP servers showed three places where 2.1 asks for something a record cannot hold, or does not say what a gateway does. The independent reviews of the gateways and of the DID resolver showed two more: one in what a DID document says of a mind that has retired, and one in what a verifier makes of a profile that is no record. This proposal settles all of them.

## Motivation

An OIP MCP server gives a model the use of a mind. The model reads what strangers wrote, and Layer 0, 2.2 says why that matters: a packet cannot grant authority, but its content can still try to persuade a model to use authority the model already holds. So the server should ask the user before it signs a Commitment or a Delegation.

1. **What of a Receipt?** A Receipt binds nobody, and 2.2 does not name it. But a Commitment is fulfilled once a creditor says so (Layer 2, Section 8), and broken or disputed by the word of any party. The debtor of a Commitment can send its creditor a packet that tells the creditor's assistant to publish a `fulfilled` Receipt. An assistant that does as it is told gives up what the user is owed, in the user's name, in public and for good. The prompt-injection suite of the reference server makes this attack, and without a confirmation it succeeds.

A verifier labels a mind `bridged` only on the gateway's own word (1.3).

2. **How is the gateway's entry named?** 1.2 says the profile carries `attestation`, "the `record-ref` of that entry". 1.3 says "the entry the profile names". A profile can carry the entry itself where the reference belongs, and an extension block may hold any JSON. The independent checker took such an entry as named, and answered `bridged`. The reference implementation looked the reference up among the records it holds, found no reference, and answered `claimed`.

3. **Is a mind `native` if its profile says nothing of a bridge and its genesis names a gateway?** 1.3 says `native` means that no gateway has declared the mind bridged, and that a block without an attestation is `claimed`. It speaks of the profile's block and does not say whether the block of the `Genesis` is a declaration. Both implementations read the profile alone, and called such a mind `native`.

A gateway that bridges an MCP server (2.1) writes a profile with a capability for each tool, and turns a request packet into a call of a tool.

4. **Where is a tool's input schema?** 2.1 puts it "under `ext["oip.mcp"].inputSchema`", in a sentence about the capability. Layer 1, 16.2 lists the members of a capability, and `ext` is not among them. A schema in the profile's own `ext` would need a map from tools to schemas that 2.1 does not describe.

5. **What of JSON that a record cannot hold?** A record has no number with a fraction (core 1.2). An input schema may say `"maximum": 0.5`, a requester may ask for a temperature of `0.7`, and a tool may answer with a price. As 2.1 is written, the profile, the request and the answer would each be no record at all.

6. **What is returned when there is no result, and what is the digest of?** 2.1 says the result is returned in a packet with verb `deliver`. A tool can fail, and MCP then gives a result marked `isError`. A server can refuse a call, and a gateway can refuse one too, for want of authority. 2.1 asks for "the tool result's digest" as evidence, and does not say which bytes are digested, or how a request says which Commitment it is made under. A tool may also have no description, and a capability must have a `summary`.

7. **Of which state is `deactivated`?** Layer 1, 5.2 lists `deactivated` among the metadata of a DID document, "true when retired". A document may be of an earlier version (2.4), and every proof names its key by a version. Both implementations said `deactivated` of the version asked for. A verifier of the DID ecosystem that follows the key reference of a proof was therefore never told that the mind had retired: the mind had not, at that version.

8. **What of a profile that is not a well-formed record?** 1.3 speaks of "its profile". The reference implementation judges a record before it reads it, and answers `claimed` for one that is none. The independent checker asked whether the profile was signed, and not whether it was a well-formed `Participant`: for a bridged mind's profile with a capability that is malformed it answered `bridged`.

9. **What does a gateway do where 2.1 is silent?** The two independent reviews of the gateways found seven places where a second gateway, written from the text, would differ from the first.
   - 2.1 as item 6 left it says that a packet with verb `error` says why "where the gateway does not make the call". A requester the operator's checks do not cover is such a case, and `decline` is the verb for it: 3.1 uses it for a task an agent rejects.
   - 2.1 says the result is "the `body` of content". It does not say where a Receipt goes, and a gateway that sends one must put it somewhere.
   - Layer 2, Section 9 requires a `ref` in an evidence item. 2.1 defined the digest and not what `ref` names.
   - 2.1 does not give the Receipt's outcome. The reference gateway said `fulfilled`. But a Commitment may promise more than one call, or something a call does not show, and 1.4 forbids a gateway to claim more than it observed. A `fulfilled` Receipt by the debtor of a Commitment also changes how the Commitment stands (Layer 2, 8.3).
   - A request may name several Commitments, and as many references as a packet holds. 2.1 does not say which Commitment a Receipt is about, or how far a gateway looks.
   - 2.1 as item 5 left it gives JSON text as the way to carry what a record cannot hold. Text is parsed by whoever reads it, and `JSON.parse` and most parsers take the last of two members with one name where some take the first. Text such as `{"tool":"harmless","tool":"send_money"}` is two calls to two readers. A number such as `1e999` is JSON, and no number a program has.
   - Item 5 named a record's size among the limits that text gets round. Text is no smaller than what it says.
   - 2.1 forbids an action "that the requester's authority (identity or delegation) does not cover". Layer 1, 11.5 says a verifier reads an author's feed for Revocations "when the value at stake warrants it", and a proof is judged as of when it was made (core 9). A gateway that judged a request once, on arrival, went on calling tools for a delegate whose delegation its author had since taken back and published.

10. **Must a gateway publish every Receipt?** Layer 2, 10.2 says a party SHOULD publish the Receipts it authors. A gateway for A2A agents signs a Receipt for every task that ends (3.1), about the request that began it. In the bridged mind's feed, each would say in public and for good who asked which agent for something, when, and how it ended. The requester asked the agent, and did not ask for that.

## Specification

Each item is a change to `spec/layer-0-bridge.md`, made in the same commits as the code. Item 4 changes `spec/layer-1-mind-network.md` too.

1. **A Receipt is confirmed too (2.2).** The server SHOULD require the human user's confirmation before signing a Commitment, a Receipt or a Delegation unless the user has configured a policy that permits it.
2. **An attestation is named, not carried (1.3).** The profile names the entry by its `record-ref` (1.2): an entry carried in the profile in place of the reference names none, and the mind is `claimed`.
3. **A genesis that names a gateway is a declaration (1.3).** A mind is `native` where neither its `Genesis` nor its profile carries an `oip.bridge` block. Where its `Genesis` carries one and its profile does not, the mind is `claimed`.
4. **A capability carries `ext` (Layer 1, 16.2; Layer 0, 2.1).** A capability object has an optional member `ext`: extension blocks about that capability, as core, Section 8.1 defines them for a record. A capability has no `critical`: a reader ignores a block of a capability that it does not understand. 2.1 says that the input schema is under `ext["oip.mcp"].inputSchema` of the capability.
5. **JSON that a record cannot hold is carried as text (2.1).** An input schema, a call's arguments and a tool's result are each carried as they are where the record can hold them, and otherwise as their JSON text, a string. A gateway MUST take the `body` of a request in either form, and a requester does the same for a result. A gateway MAY leave an input schema out of a profile, and leaves out those the profile has no room for.
6. **A call that fails, and the evidence of a call (2.1).** The result is returned as the `body` of content with media type `application/json`. A result that the server marks as an error is returned in the same way, in a packet with verb `error`. Where the gateway does not make the call, or the server gives no result, a packet with verb `error` and the same `replyTo` says why. The evidence in a Receipt is an item of kind `hash` whose digest is of the canonical form of the `body` returned, or of the UTF-8 bytes of the `body` where it is JSON text. A request names the Commitment it is made under in `context.refs`. A capability's `summary` is the tool's description, or its title, or else its name.

7. **`deactivated` is of the mind (Layer 1, 5.2).** `deactivated` is of the mind as its log stands. Where the document is of an earlier version, the other members of the metadata are of that version, and `deactivated` still says whether the mind has retired since.
8. **A profile that is no record shows nothing (1.3).** A profile that is not a well-formed record shows nothing: the level is `claimed`.
9. **A call, its checks and its Receipt (2.1).**
   - Where the operator's checks do not cover the requester, the gateway makes no call, and answers with a packet with verb `decline`. A packet with verb `error` says why where the content is no call, the server gives no result, or the result is one the gateway cannot return.
   - A delegation covers a request only while it stands. When it acts, a gateway checks that no delegation the request rests on has expired or been revoked, and SHOULD first read the feeds of those delegations' authors for Revocations (Layer 1, 11.5).
   - JSON text in which an object has a member name twice is no call, and neither is text with a number that is not finite once it is read.
   - A result that a packet has no room for (core 1.6) is not returned: the gateway answers with verb `error`, and says that the tool ran. Item 5's sentence no longer names size among the limits that JSON text gets round.
   - A Receipt about a call has outcome `progress`.
   - Its evidence item's `ref` is the `record-ref` of the request. The digest is of the `body` returned for that request.
   - The Commitment a request is made under is the first of its `context.refs` that names a Commitment under which the bridged mind is a debtor and the requester, or the mind the request was sent for, is a creditor, and whose status is `accepted` or `overdue`. A gateway MAY look at the first eight references only.
   - A gateway that signs a Receipt for a call returns it with the result: the content of the packet has two parts, the result first and the Receipt second.
10. **A Receipt about no Commitment need not be published (1.4).** A gateway brings a Receipt to the mind whose request it is about. It SHOULD publish a Receipt about a Commitment, as a party does (Layer 2, 10.2), and MAY leave unpublished a Receipt about a request made under no Commitment.

## Rationale and alternatives

- **Item 1: confirm only a Receipt that settles a Commitment the user is owed.** That is where the harm is greatest. But a `broken` or `disputed` Receipt is an accusation in the user's name, and a server that must work out which Receipts matter will be wrong about some. One rule for every Receipt is simpler to state, to implement and to explain to the user, and a policy lets the user wave through the kinds they do not want to be asked about, such as `progress`.
- **Item 1: leave it to the MCP host, which asks before a tool is called.** A host shows the arguments the model chose. It does not show what the record is about, and it cannot: only the server holds the Commitment the Receipt names. The server's question shows the outcome, the user's own statement, and the promise the Receipt is about, word for word.
- **Item 1: confirm an Intent, an Offer and a packet as well.** They bind nobody and settle nothing. A user who is asked about every message learns to say yes without reading, and then the question protects nothing.

- **Item 2: take an entry that is carried, since it is signed all the same.** The signature would verify. But a verifier would then judge a record it was handed inside another, in a place where a reference belongs, and each such place is one more way for two implementations to differ. A record that is named is looked up by its content ID among the records the verifier holds, with the evidence the verifier has of when its proofs came (core 9.4). The reference is also what 1.2 already says.

- **Item 3: `native` for a profile that says nothing.** The label would then be the profile's to choose, and a mind that was made as a bridged mind could present itself as native by leaving a block out of a record it can rewrite at will. The genesis cannot be rewritten: it is what the address is made from. A gateway that never declared anything is still not found out, as 1.3 says: this closes only the case that records can show.

- **Item 4: the schemas in the profile's own `ext`, by tool name.** It needs no new member. But it says the same thing in two places that must agree, and a reader that wants one capability must read a second table. A block beside the thing it describes is what `ext` is everywhere else in the protocol.
- **Item 4: `critical` for a capability.** A critical block says "do not act on this record unless you understand me". A capability is a description, and a reader that does not understand a block of it loses a detail. A profile whose whole meaning depends on an extension can say so with its own `critical`.

- **Item 5: always text.** One form is simpler than two. But 2.1 already writes the request's `body` as an object, most schemas and most arguments are JSON that a record holds, and an object can be read without a second parse. Text is the way out for the rest, and nothing is lost in it.
- **Item 5: turn fractions into decimal strings.** A record writes a price as a string (core 1.3). But a schema that says `"maximum": "0.5"` is another schema, and a tool that is sent `"0.7"` for a number refuses it. The gateway would have to guess which strings to turn back.
- **Item 5: leave out the schema that does not fit.** A gateway may: a schema is a help to the requester and not a promise. But a requester that cannot see what a tool takes cannot call it well, so the text is carried where there is room.

- **Item 6: `deliver` for every result.** An `isError` result is a result, and MCP returns it as one so that a model can read it. But a verb says what a packet is for, and a requester that is not a model should not have to open the content to learn that nothing was delivered. Verbs bind nobody (Layer 1, 12.3), so a reader that ignores the verb loses nothing.
- **Item 6: the digest of what the server sent.** The bytes of the server's own answer are the truest evidence. But the requester never sees them: it sees a record. A digest of what the requester holds is one it can check.

- **Item 7: `deactivated` of the version asked for.** It is what the words "the document as it stood" suggest. But `deactivated` is DID Core's word for a property of the DID, and a resolver that answers `false` for a retired mind tells a verifier to go on trusting keys that sign nothing any more (Layer 1, 3.10). Whoever wants the state at a version has the events.
- **Item 8: judge the block of a profile that is malformed elsewhere.** The block may be sound where a capability is not. But a verifier that reads part of a record it would refuse whole has two answers to "is this a profile", and the two implementations showed how they come apart.

- **Item 9: `error` for a requester the checks do not cover.** One verb for every packet that carries no result is simpler. But `error` says that something went wrong, and nothing did: the operator has not opened the tool to that mind. A requester that is no model can tell "ask someone else" from "ask again" by the verb alone.
- **Item 9: `fulfilled`, where the Commitment names the tool.** A promise such as "one call of `echo`" is kept by one call, and a gateway could be told so. It would need a convention for promises that a gateway can check, which is open question 2. Until there is one, the gateway cannot tell such a promise from another, and says what it saw.
- **Item 9: a `ref` that names the answer.** The digest is of the answer's body, and a `ref` to the answer would name the same thing. But the Receipt is carried in the answer, so the answer's content ID is not known when the Receipt is signed. The request is known, is held by both sides, and says which call the result is of.
- **Item 9: take the last of two members with one name, as most parsers do.** A rule would make readers agree. But a gateway cannot know which parser stood before it, and a filter that read `harmless` where the gateway reads `send_money` is the harm. A record may not have a member name twice (core 1.1), and text that stands for a record's member is held to the same.
- **Item 9: every reference of a request.** A request may name a thousand things. Looking each up is cheap, and working out the status of each Commitment among them is not. Eight is more than a request under a promise needs.
- **Item 9: judge a delegation once, when the request arrives.** It is what core 9 does for a proof, and it is right for what a record binds its principal to. Whether to act for a delegate now is another question. An author that has revoked and published has done all that 11.5 asks of it, and a gateway that holds credentials is where "the value at stake warrants it".
- **Item 10: publish every Receipt, as 10.2 says.** A Receipt about a Commitment is evidence that third parties rely on: the Commitment is public where its parties published it, and so is how it ended. A Receipt about a bare request has no such reader. The requester holds it, signed, and can show it to whoever it likes.

## Backwards compatibility

No record format changes for items 1 to 3. Item 4 adds an optional member, as core 8.5 allows within major version `"1"`. A profile whose capability had an `ext` was well formed before, because a reader ignores what it does not recognise (core 1.7); it is malformed now if that `ext` is not as core 8.1 says. No such profile is known. Items 5 and 6 say what 2.1 left open: a gateway built to the earlier text returned every result with `deliver` and could carry no fraction.

Item 1 is a SHOULD, as it was: a server built to the earlier text conforms as before, and protects its user less. Item 2 says what 1.2 said already: a gateway that followed 1.2 wrote a reference, and nothing changes for it. A verifier that took a carried entry now answers `claimed` where it answered `bridged`. For item 3, a verifier that holds the mind's log now answers `claimed` for a profile without a block where the genesis has one, and `native` as before where it does not.

For item 7, a resolver that said `deactivated: false` of an earlier version of a mind that has retired now says `true`. No record changes: the metadata of a DID document is made by whoever resolves, and is signed by nobody. For item 8, a verifier that answered `bridged` for a profile that is not well formed now answers `claimed`. The reference implementation did so already.

For item 9, a gateway built to the earlier text answered a requester it would not serve with `error`, signed Receipts with outcome `fulfilled`, and judged a delegation on arrival. A requester that read `error` for a refusal reads `decline` now. A Commitment that such a gateway's Receipt settled stands open under this text, until a party says how it ended. No gateway but the reference one is known, and it was not released. For item 10, nothing a gateway published is withdrawn.

## Security and privacy considerations

Item 1 closes a way to make a user give up a claim, or accuse another party, without knowing it. The question is put by the server and written from the records themselves, so that a model which was talked into the Receipt cannot describe it kindly. An answer counts for the Receipt it was given to, and for no other.

A policy is a standing yes. A user who permits every Receipt has the protection of the earlier text and no more.

Items 2 and 3 err toward `claimed`, the label that promises nothing.

Items 4 to 6 are about JSON that strangers write: the MCP server writes the schemas and the results, and the requester writes the arguments. A schema in a profile is data about a tool, and is no instruction to whoever reads it (Layer 1, 12.5 says the same of a packet's content). JSON text is parsed by whoever reads it, within the limits of a record's size, and a reader bounds its depth as it does for any JSON from outside. A digest is of what the requester received, so the gateway cannot be held to bytes it never passed on, and can be held to those it did.

Item 9 closes two ways to have a tool called without authority: through a parser that reads a member name twice otherwise than the gateway does, and through a delegation its author has taken back. Reading an author's feed costs a request to a home that a stranger chose: a gateway bounds it as it bounds every fetch, and does not act where it cannot read. A Receipt with outcome `progress` cannot be used to settle a promise the gateway knows nothing of.

Item 10 keeps who asked what of whom out of a public feed. A requester that wants a public record of a call makes the request under a Commitment.

## Test vectors

For item 2, one negative case of kind `assurance`: `bridge-attestation-inline`, the bridged mind of the vectors with its gateway's own entry in its profile where the reference belongs. It is `claimed`. For item 3, one more: `bridge-profile-omits-block`, the same mind with a profile that has no block, which is `claimed` too. Item 1 is about what a server does before it signs, and no record shows it.

For item 4, three cases of kind `participant`: `profile-with-an-extension-of-a-capability`, which is the agent's current profile, and `profile-with-a-capability-extension-of-no-namespace` with its control, a profile that is nobody's because the block of its capability is named `mcp`. Items 5 and 6 are about what a gateway does with a packet, and the vectors hold no gateway at work.

For the rule of 1.3 as a whole, five negative cases of kind `assurance`, each with a control that is `bridged`: an entry that names the gateway and that the bridged mind signed (`bridge-entry-not-signed-by-the-gateway`), an entry of the gateway's that calls the genesis a `Participant` (`bridge-entry-of-another-type`), the profile signed by the gateway (`bridge-profile-signed-by-the-gateway`), a mind whose genesis names another gateway than its profile and the entry do (`bridge-genesis-names-another-gateway`), and, for item 8, a profile with a capability whose `ext` names no namespace (`bridge-profile-not-well-formed`). With the three cases there were, an implementation that never asked whether the entry counts for the gateway passed.

Items 9 and 10 are about what a gateway does with a packet, and the vectors hold no gateway at work. The reference gateways' tests hold them.

For item 7, a mind that has retired among the positive cases, `retired`, with the DID document of its first version, `did_document_retired_at_genesis`: `deactivated` is true there.

## Reference implementation

`@oip/mcp-server`, in `packages/mcp-server`: `tools/web.ts` (the confirmation before `oip_receipt` signs), `question.ts` (the question), `policy.ts` (the part of `policy.json` for Receipts). Its tests: `tools.test.ts` and `injection.test.ts`.

`assuranceOf` of `@oip/web`, in `packages/web/src/assurance.ts` (items 2 and 3), and the campaign of the differential tests that found the difference: `packages/conformance/test/differential.delegation.test.ts`.

`Capability` of `@oip/schema`, in `packages/schema/src/records/net.ts` (item 4). `@oip/bridge-mcp`, in `packages/bridge-mcp` (items 4 to 6, and 9: `relay.ts` and `json.ts`). `@oip/bridge-a2a`, in `packages/bridge-a2a` (item 10: `relay.ts`). `Mind.holdRevocations` and `Mind.delegationsStand` of `@oip/client` (item 9).

## Open questions

1. **A Delegation.** 2.2 names it, and no tool of 2.2 signs one. A server that adds such a tool is bound by the rule. The reference server adds none: an assistant is given the use of a mind, and no way to hand that use on.
2. **How a bridged mind enters into a Commitment.** 2.1 speaks of "any Commitment it entered into" and does not say how a gateway comes to sign one. The reference gateway signs none by itself: its operator signs for the bridged mind, with the mind's own directory. A convention by which a requester proposes a Commitment for one call, in words the gateway can check, would let a gateway enter into it unasked. It is left for a later proposal.
3. **One entry of a feed.** A verifier that works out an assurance level needs one entry of the gateway's feed, which the profile names by its content ID. Layer 1, 13.1 serves a feed page by page from its start, and an object by its content ID, and an entry is no object. The reference client reads pages until it has the entry, and gives up where it stops reading a feed (10,000 entries): a mind whose attestation lies further on reads as `claimed`. A way to ask a home for one entry by its content ID would end that. It is left for a later proposal, with a place to fetch a checkpoint from (10.5), which 13.1 does not name either.
4. **A gateway that is a collective.** 1.1 and 1.2 say a gateway and a bridged mind are key-controlled minds. 1.3 does not ask a verifier to check it, and neither implementation does: a mind that a collective attests is `bridged`. Whether a verifier should check, and what a collective's custody of a bridged mind's keys would mean, is left open.

## Copyright

This document is licensed under the [Creative Commons Attribution 4.0 International Licence](https://creativecommons.org/licenses/by/4.0/) (CC BY 4.0).
