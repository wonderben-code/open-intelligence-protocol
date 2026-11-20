---
oep: 6
title: Bridge clarifications found while building the MCP server and the A2A bridge
authors:
  - Claude Code, building the reference implementation for Ekram Alam (@wonderben-code)
status: Review # Draft | Review | Accepted | Rejected | Withdrawn | Final
type: Layer 0 # Core | Layer 0 | Layer 1 | Layer 2 | Process
created: 2026-11-20
requires: [1, 2, 3, 4, 5]
replaces: []
discussion: # the pull requests of milestones M8 and M9
revision: # the specification revision that adopted the change; empty until Final
---

# OEP-0006: Bridge clarifications found while building the MCP server and the A2A bridge

## Summary

Writing the OIP MCP server showed one place where Layer 0 (revision 2026-11-17, with OEP-0001 to OEP-0005) protects the user from one kind of record and not from another that needs it as much. This proposal settles it. More items may follow while the A2A bridge is built.

## Motivation

An OIP MCP server gives a model the use of a mind. The model reads what strangers wrote, and Layer 0, 2.2 says why that matters: a packet cannot grant authority, but its content can still try to persuade a model to use authority the model already holds. So the server should ask the user before it signs a Commitment or a Delegation.

1. **What of a Receipt?** A Receipt binds nobody, and 2.2 does not name it. But a Commitment is fulfilled once a creditor says so (Layer 2, Section 8), and broken or disputed by the word of any party. The debtor of a Commitment can send its creditor a packet that tells the creditor's assistant to publish a `fulfilled` Receipt. An assistant that does as it is told gives up what the user is owed, in the user's name, in public and for good. The prompt-injection suite of the reference server makes this attack, and without a confirmation it succeeds.

## Specification

Each item is a change to `spec/layer-0-bridge.md`, made in the same commits as the code.

1. **A Receipt is confirmed too (2.2).** The server SHOULD require the human user's confirmation before signing a Commitment, a Receipt or a Delegation unless the user has configured a policy that permits it.

## Rationale and alternatives

- **Item 1: confirm only a Receipt that settles a Commitment the user is owed.** That is where the harm is greatest. But a `broken` or `disputed` Receipt is an accusation in the user's name, and a server that must work out which Receipts matter will be wrong about some. One rule for every Receipt is simpler to state, to implement and to explain to the user, and a policy lets the user wave through the kinds they do not want to be asked about, such as `progress`.
- **Item 1: leave it to the MCP host, which asks before a tool is called.** A host shows the arguments the model chose. It does not show what the record is about, and it cannot: only the server holds the Commitment the Receipt names. The server's question shows the outcome, the user's own statement, and the promise the Receipt is about, word for word.
- **Item 1: confirm an Intent, an Offer and a packet as well.** They bind nobody and settle nothing. A user who is asked about every message learns to say yes without reading, and then the question protects nothing.

## Backwards compatibility

No record format changes, and no test vector. The rule is a SHOULD, as it was: a server built to the earlier text conforms as before, and protects its user less.

## Security and privacy considerations

Item 1 closes a way to make a user give up a claim, or accuse another party, without knowing it. The question is put by the server and written from the records themselves, so that a model which was talked into the Receipt cannot describe it kindly. An answer counts for the Receipt it was given to, and for no other.

A policy is a standing yes. A user who permits every Receipt has the protection of the earlier text and no more.

## Test vectors

None. The rule is about what a server does before it signs, and no record shows it.

## Reference implementation

`@oip/mcp-server`, in `packages/mcp-server`: `tools/web.ts` (the confirmation before `oip_receipt` signs), `question.ts` (the question), `policy.ts` (the part of `policy.json` for Receipts). Its tests: `tools.test.ts` and `injection.test.ts`.

## Open questions

1. **A Delegation.** 2.2 names it, and no tool of 2.2 signs one. A server that adds such a tool is bound by the rule. The reference server adds none: an assistant is given the use of a mind, and no way to hand that use on.

## Copyright

This document is licensed under the [Creative Commons Attribution 4.0 International Licence](https://creativecommons.org/licenses/by/4.0/) (CC BY 4.0).
