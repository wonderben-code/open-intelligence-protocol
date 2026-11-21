---
oep: 6
title: Bridge clarifications found while building the MCP server and the gateways
authors:
  - Claude Code, building the reference implementation for Ekram Alam (@wonderben-code)
status: Review # Draft | Review | Accepted | Rejected | Withdrawn | Final
type: Layer 0 # Core | Layer 0 | Layer 1 | Layer 2 | Process (item 4 also changes Layer 1, 16.2)
created: 2026-11-20
requires: [1, 2, 3, 4, 5]
replaces: []
discussion: # the pull requests of milestones M8 and M9
revision: # the specification revision that adopted the change; empty until Final
---

# OEP-0006: Bridge clarifications found while building the MCP server and the gateways

## Summary

Writing the OIP MCP server showed one place where Layer 0 (revision 2026-11-17, with OEP-0001 to OEP-0005) protects the user from one kind of record and not from another that needs it as much. Writing the rule that tells a bridged mind from one that only says it is showed one place where two implementations read the same sentence differently. Writing the gateway for MCP servers showed three places where 2.1 asks for something a record cannot hold, or does not say what a gateway does. This proposal settles all of them.

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

## Specification

Each item is a change to `spec/layer-0-bridge.md`, made in the same commits as the code. Item 4 changes `spec/layer-1-mind-network.md` too.

1. **A Receipt is confirmed too (2.2).** The server SHOULD require the human user's confirmation before signing a Commitment, a Receipt or a Delegation unless the user has configured a policy that permits it.
2. **An attestation is named, not carried (1.3).** The profile names the entry by its `record-ref` (1.2): an entry carried in the profile in place of the reference names none, and the mind is `claimed`.
3. **A genesis that names a gateway is a declaration (1.3).** A mind is `native` where neither its `Genesis` nor its profile carries an `oip.bridge` block. Where its `Genesis` carries one and its profile does not, the mind is `claimed`.
4. **A capability carries `ext` (Layer 1, 16.2; Layer 0, 2.1).** A capability object has an optional member `ext`: extension blocks about that capability, as core, Section 8.1 defines them for a record. A capability has no `critical`: a reader ignores a block of a capability that it does not understand. 2.1 says that the input schema is under `ext["oip.mcp"].inputSchema` of the capability.
5. **JSON that a record cannot hold is carried as text (2.1).** An input schema, a call's arguments and a tool's result are each carried as they are where the record can hold them, and otherwise as their JSON text, a string. A gateway MUST take the `body` of a request in either form, and a requester does the same for a result. A gateway MAY leave an input schema out of a profile, and leaves out those the profile has no room for.
6. **A call that fails, and the evidence of a call (2.1).** The result is returned as the `body` of content with media type `application/json`. A result that the server marks as an error is returned in the same way, in a packet with verb `error`. Where the gateway does not make the call, or the server gives no result, a packet with verb `error` and the same `replyTo` says why. The evidence in a Receipt is an item of kind `hash` whose digest is of the canonical form of the `body` returned, or of the UTF-8 bytes of the `body` where it is JSON text. A request names the Commitment it is made under in `context.refs`. A capability's `summary` is the tool's description, or its title, or else its name.

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

## Backwards compatibility

No record format changes for items 1 to 3. Item 4 adds an optional member, as core 8.5 allows within major version `"1"`. A profile whose capability had an `ext` was well formed before, because a reader ignores what it does not recognise (core 1.7); it is malformed now if that `ext` is not as core 8.1 says. No such profile is known. Items 5 and 6 say what 2.1 left open: a gateway built to the earlier text returned every result with `deliver` and could carry no fraction.

Item 1 is a SHOULD, as it was: a server built to the earlier text conforms as before, and protects its user less. Item 2 says what 1.2 said already: a gateway that followed 1.2 wrote a reference, and nothing changes for it. A verifier that took a carried entry now answers `claimed` where it answered `bridged`. For item 3, a verifier that holds the mind's log now answers `claimed` for a profile without a block where the genesis has one, and `native` as before where it does not.

## Security and privacy considerations

Item 1 closes a way to make a user give up a claim, or accuse another party, without knowing it. The question is put by the server and written from the records themselves, so that a model which was talked into the Receipt cannot describe it kindly. An answer counts for the Receipt it was given to, and for no other.

A policy is a standing yes. A user who permits every Receipt has the protection of the earlier text and no more.

Items 2 and 3 err toward `claimed`, the label that promises nothing.

Items 4 to 6 are about JSON that strangers write: the MCP server writes the schemas and the results, and the requester writes the arguments. A schema in a profile is data about a tool, and is no instruction to whoever reads it (Layer 1, 12.5 says the same of a packet's content). JSON text is parsed by whoever reads it, within the limits of a record's size, and a reader bounds its depth as it does for any JSON from outside. A digest is of what the requester received, so the gateway cannot be held to bytes it never passed on, and can be held to those it did.

## Test vectors

For item 2, one negative case of kind `assurance`: `bridge-attestation-inline`, the bridged mind of the vectors with its gateway's own entry in its profile where the reference belongs. It is `claimed`. For item 3, one more: `bridge-profile-omits-block`, the same mind with a profile that has no block, which is `claimed` too. Item 1 is about what a server does before it signs, and no record shows it.

For item 4, three cases of kind `participant`: `profile-with-an-extension-of-a-capability`, which is the agent's current profile, and `profile-with-a-capability-extension-of-no-namespace` with its control, a profile that is nobody's because the block of its capability is named `mcp`. Items 5 and 6 are about what a gateway does with a packet, and the vectors hold no gateway at work.

## Reference implementation

`@oip/mcp-server`, in `packages/mcp-server`: `tools/web.ts` (the confirmation before `oip_receipt` signs), `question.ts` (the question), `policy.ts` (the part of `policy.json` for Receipts). Its tests: `tools.test.ts` and `injection.test.ts`.

`assuranceOf` of `@oip/web`, in `packages/web/src/assurance.ts` (items 2 and 3), and the campaign of the differential tests that found the difference: `packages/conformance/test/differential.delegation.test.ts`.

`Capability` of `@oip/schema`, in `packages/schema/src/records/net.ts` (item 4). `@oip/bridge-mcp`, in `packages/bridge-mcp` (items 4 to 6).

## Open questions

1. **A Delegation.** 2.2 names it, and no tool of 2.2 signs one. A server that adds such a tool is bound by the rule. The reference server adds none: an assistant is given the use of a mind, and no way to hand that use on.
2. **How a bridged mind enters into a Commitment.** 2.1 speaks of "any Commitment it entered into" and does not say how a gateway comes to sign one. The reference gateway signs none by itself: its operator signs for the bridged mind, with the mind's own directory. A convention by which a requester proposes a Commitment for one call, in words the gateway can check, would let a gateway enter into it unasked. It is left for a later proposal.

## Copyright

This document is licensed under the [Creative Commons Attribution 4.0 International Licence](https://creativecommons.org/licenses/by/4.0/) (CC BY 4.0).
