---
oep: NNNN # the OEP number, written without leading zeros
title: A short, descriptive title
authors:
  - Full Name (@github-handle)
status: Draft # Draft | Review | Accepted | Rejected | Withdrawn | Final
type: Core # Core | Layer 0 | Layer 1 | Layer 2 | Process
created: YYYY-MM-DD
requires: [] # numbers of the OEPs this proposal depends on
replaces: [] # numbers of the OEPs this proposal replaces
discussion: # link to the pull request, and to the issue if there is one
revision: # the specification revision that adopted the change; empty until Final
---

# OEP-NNNN: A short, descriptive title

Replace the guidance under each heading with your own text. Keep every heading. If a section does not apply, write "None" and say why. The process is in [GOVERNANCE.md](../GOVERNANCE.md).

## Summary

One paragraph. Say what changes and who is affected. A reader who stops here should know whether the proposal concerns them.

## Motivation

State the problem. Show a concrete case: a record, an identity log, an attack or an interoperability failure. Say why the current rules, together with the extension mechanism (core 8), do not solve it.

## Specification

Give the normative text, ready to adopt. Use the key words of BCP 14 (MUST, SHOULD, MAY) as [spec/README.md](../spec/README.md) defines them.

- Name the specification revision the proposal is written against, for example 2026-11-17.
- List every clause the proposal changes, by document and number, for example `core 4.4`, `L1 6.4`, `L2 8.3` or `L0 2.2`. For each one, give the current text and the proposed text.
- For a new clause, say where it goes and what number it takes.
- List every new name: record types, members, namespaces, error codes, limits. Appendix B of the technical paper lists the names already reserved.

For an OEP of type Process, give the exact text of the document it changes.

## Rationale and alternatives

Say why this design was chosen. Describe the alternatives you considered and why you set each aside. Include two in every case: doing nothing, and doing it as an extension in a namespace of your own (core 8.1). Name any prior art.

## Backwards compatibility

Say which of these the proposal is, with reference to core, Section 8:

- **An optional member** that an older implementation can safely ignore (core 8.5).
- **An `oip.*` extension** that records list in `critical`, because ignoring it would be unsafe (core 8.3, 8.5).
- **A rule change.** Implementations of the earlier revision reject records that this proposal accepts, or accept records that it rejects.

Then answer each question:

- Does any record or identity log that is valid today become invalid, or the reverse?
- Does any content ID, address or other golden value in the test vectors change?
- What does an implementation of the earlier revision do with a record that uses the change?
- What must existing minds, hosts, resolvers, indexers and gateways do, and by when?

## Security and privacy considerations

Say what the change makes possible for an attacker, and what it prevents. Cover at least:

- signature verification and key validity (core 4.4; Layer 1, Section 6);
- time, which is judged by evidence and never by the signer's own `created` (core 9);
- limits on size, count and depth (Layer 1, Section 19);
- delegated authority and collectives, if the proposal touches them;
- what becomes visible or linkable that was not before;
- new ways to spam or to exhaust a verifier or a server.

If the proposal fixes a vulnerability, do not publish the details here first. Follow [SECURITY.md](../SECURITY.md).

## Test vectors

List the cases the proposal adds or changes in [spec/test-vectors/vectors.json](../spec/test-vectors/vectors.json). The Python generator, `oip_vectors.py`, produces every case; golden values are never written by hand.

- **Positive cases**: the new values an implementation must reproduce.
- **Must-accept cases**: records that look suspicious but are valid.
- **Negative cases**: records or logs that must be rejected, each with its reason.
- **Controls**: for each negative case where one is possible, the same case changed only in the respect its reason names, which must be accepted.

Give each case's kind (`log`, `countsFor`, `sentFor`, `status`, `assurance` or `record`). List every existing case whose value or verdict changes.

## Reference implementation

Link the implementation, or describe the plan for it. Name the packages affected and the tests that cite the new or changed clauses. A proposal can be accepted before code exists. It becomes Final only when the specification text, the CHANGELOG, the generator and vectors, and the technical paper have all changed.

## Open questions

List what is unresolved. Before the review ends, each question is either answered or explicitly deferred.

## Copyright

This document is licensed under the [Creative Commons Attribution 4.0 International Licence](https://creativecommons.org/licenses/by/4.0/) (CC BY 4.0).
