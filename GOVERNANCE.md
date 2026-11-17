# Governance

This document says how the Open Intelligence Protocol (OIP) is run today and how the protocol changes. It follows Section 12 of the [technical architecture paper](papers/02-technical-architecture.md#12-governance-licensing-and-provenance). Where that section is silent, this document adds only what the process needs to work, and Section 11 lists what is still to be decided.

## 1. Principles

- **OIP is owned by no one.** Anyone may implement it, extend it and build on it, commercially or otherwise, without permission.
- **Changes are made in the open.** A change to the protocol is proposed as an **OIP Enhancement Proposal (OEP)** in this repository, discussed in the open, and adopted into a dated specification revision.
- **The specifications are normative.** The documents in [spec/](spec/) define the protocol. The papers explain it. If a paper and a specification disagree, the specification wins and the paper is corrected.
- **Provenance is public.** The history of `main` is timestamped on the Bitcoin blockchain, and the papers are archived on Zenodo with permanent DOIs.

A note on names. Proposals are called OEPs, not "OIPs", because another agent project uses that name for its own proposals. The initials OIP are also used by KServe's Open Inference Protocol, which is unrelated, so documents spell out "Open Intelligence Protocol" wherever the initials alone could be ambiguous.

## 2. Roles today

There are two roles.

- **The maintainer.** Ekram Alam ([@wonderben-code](https://github.com/wonderben-code)) created OIP and maintains this repository. The maintainer reviews and merges pull requests, decides on OEPs, dates specification revisions, publishes releases, and handles security and conduct reports. Some actions are his alone: creating accounts, publishing packages, choosing domains and hosting, spending money and posting publicly ([BUILD.md](BUILD.md), Section 8).
- **Contributors.** Anyone who opens an issue, comments, reviews, submits a pull request or writes an OEP. Contributing needs no permission and no membership.

There is no committee, board or voting body today.

Much of the reference implementation is written by coding agents that work for the maintainer, as [CLAUDE.md](CLAUDE.md) and [BUILD.md](BUILD.md) describe. Their work passes through the same pull requests, checks and reviews as anyone else's.

## 3. How decisions are made

- **In the open.** Discussion happens in GitHub issues and pull requests in this repository. Security reports are the one exception ([SECURITY.md](SECURITY.md)).
- **By the maintainer, with reasons.** The maintainer looks for agreement among the people taking part, then makes the final decision and writes the reasons on the issue or pull request. This arrangement is interim (Section 11).
- **On the record.** Each kind of decision has a place:

  | Decision                                           | Record                                                                           |
  | -------------------------------------------------- | -------------------------------------------------------------------------------- |
  | A change to the protocol                           | An OEP in [oeps/](oeps/), and an entry in [spec/CHANGELOG.md](spec/CHANGELOG.md) |
  | An implementation decision that is hard to reverse | An architecture decision record (ADR) in `docs/adr/`                             |
  | A milestone review of the reference implementation | A review in `reviews/build/`                                                     |

- **Open to challenge.** Anyone may ask for a decision to be looked at again by opening an issue or an OEP that brings new evidence.

## 4. When an OEP is needed

**An OEP is needed** for any change to:

- a record format: a record type, a member, an encoding, an identifier or a reserved name;
- a verification rule: what a conforming implementation accepts, rejects or counts;
- any other normative specification text, beyond editorial fixes: requirements, limits and conformance profiles;
- the namespaces the specification itself defines: an `oip.*` extension profile or a recognised short name (core 8.1);
- this governance process (an OEP of type Process).

**An OEP is not needed** for:

- **Editorial fixes** to the specifications, the papers or this document: typos, grammar, formatting, broken links, examples, and clearer wording of a rule that stays the same. The test is this: every implementation that conformed before still conforms, and every record gets the same verdict.
- **New test vectors for existing rules.** They go through the Python generator, in a pull request.
- **Implementation-only changes**: code, tests, tooling, CI and documentation of the reference implementation. If such a change is hard to reverse, it needs an ADR in `docs/adr/`.
- **Extensions in your own namespace.** Anyone may define an extension under a reverse-DNS name they control (core 8.1). That needs no permission and no OEP.

Settling an ambiguity is not editorial. If the text allows two readings and a fix chooses one, an implementation that chose the other stops conforming, so the fix needs an OEP.

An OEP is as long as its change needs. A correction to one clause can take a page, and it can share a pull request with the specification change it proposes.

If you are not sure which case applies, open an issue with the **Specification question** form.

## 5. The OEP lifecycle

```
Draft ──> Review ──> Accepted ──> Final
  │          ├─────> Rejected
  └──────────┴─────> Withdrawn
```

| Status        | Meaning                                                                                                                                        | Who sets it                           |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| **Draft**     | The proposal is being written and discussed. It may change freely.                                                                             | The author, by opening a pull request |
| **Review**    | The author considers the proposal complete, and every section of the template is filled in. Changes are limited to those the review calls for. | The maintainer, when the author asks  |
| **Accepted**  | The change will be adopted into the specification.                                                                                             | The maintainer                        |
| **Rejected**  | The change will not be adopted.                                                                                                                | The maintainer                        |
| **Withdrawn** | The author has stopped pursuing the proposal before a decision. Anyone may take the idea up in a new OEP.                                      | The author                            |
| **Final**     | The change is part of a dated specification revision (Section 8).                                                                              | The maintainer                        |

The steps:

1. **Test the idea (optional).** Open an issue with the **OEP proposal** form.
2. **Draft.** Copy [oeps/oep-0000-template.md](oeps/oep-0000-template.md), fill it in and open a pull request. [oeps/README.md](oeps/README.md) says how.
3. **Discuss.** Discussion happens on the pull request. The author revises the proposal in response.
4. **Review.** When the proposal is complete, the author asks for review. The maintainer checks that every section is filled in and sets the status to Review. There is no fixed review period yet. The maintainer keeps the review open long enough for the people affected to respond, and says on the pull request when it will close.
5. **Decide.** The maintainer accepts or rejects the proposal and writes the reasons on the pull request. The author may instead withdraw the proposal at any point before the decision. In each case the pull request is merged with the status the proposal ended on. So `oeps/` holds every proposal, whatever its outcome, and the `discussion` link in each one leads to the reasons.
6. **Adopt.** An accepted change is made as one change with four parts: the specification text, an entry in `spec/CHANGELOG.md` that names the OEP, the Python generator and the vectors, and the technical paper ([CONTRIBUTING.md](CONTRIBUTING.md), Section 5).
7. **Final.** When those four parts are in a dated specification revision, the maintainer sets the status to Final and records the revision in the OEP's `revision` field.

A Final OEP is a historical record. It is changed only by editorial fixes. To change what it specifies, write a new OEP that names it under `replaces`.

A change that fixes a vulnerability may be prepared in private under [SECURITY.md](SECURITY.md). Its OEP is published with the fix.

## 6. Numbering and files

- An OEP is one Markdown file: `oeps/oep-NNNN-short-title.md`.
- `NNNN` is a four-digit number, padded with zeros. Take the next unused number, counting open OEP pull requests as used. If two proposals choose the same number, the one opened later changes.
- `short-title` is a few lower-case words joined by hyphens.
- A number is never reused, whatever the OEP's outcome.
- `oep-0000-template.md` is the template.
- Each OEP has one type: Core, Layer 0, Layer 1, Layer 2 or Process. The first four name the specification document the proposal mainly changes. Process is for changes to how the project runs, including this document.

## 7. Compatibility rules

Every OEP that touches the specification says what happens to existing records and to existing implementations. The rules it must respect are in core, Section 8, with core 1.7 and core 7.

- **The version.** Every record carries `"oip": "1"`, the major protocol version. A record with any other value is rejected (core 7).
- **Unknown members.** An implementation preserves the members it does not recognise when it stores or forwards a record, and otherwise ignores them (core 1.7). A proposal must not rely on older implementations doing anything else.
- **Optional members.** Within major version `"1"`, a later revision may add OPTIONAL members (core 8.5).
- **Members that are unsafe to ignore.** A member whose being ignored by an older implementation would be unsafe must be introduced as an `oip.*` extension that records list in `critical` (core 8.5).
- **`critical`.** An implementation that does not understand a namespace listed in `critical` may store and forward the record, but must not act on it or treat it as valid for any decision (core 8.3). An extension must not change the validity of a record unless it is listed in `critical` (core 8.4).
- **Namespaces.** A reverse-DNS namespace belongs to whoever controls the name and needs no OEP. Short names are only those the specification lists, and names beginning `oip.` are reserved for profiles published by the OIP project (core 8.1). Adding either needs an OEP.
- **Rule changes.** Some changes make verifiers of the earlier revision reject new records: a new key type (core 4.3), a new hash function (core 3.2), merges, recovery keys. An OEP that does this says so plainly in its "Backwards compatibility" section and is marked as a rule change in the CHANGELOG.
- **While the specification is a Draft.** A revision may change details incompatibly ([spec/README.md](spec/README.md), "Versioning"). Such a change still needs an OEP, which names the records, verdicts and golden values that change.

## 8. Specification revisions

- The specification is identified by dated revisions, for example 2026-11-17. Every revision has an entry in [spec/CHANGELOG.md](spec/CHANGELOG.md).
- A revision is complete only when its four parts agree: the specification text, the CHANGELOG, the Python generator with its vectors, and the technical paper.
- The maintainer dates a revision. Publishing a new version of the paper on Zenodo is also the maintainer's action.

## 9. Provenance

- Every push to `main` is timestamped on the Bitcoin blockchain through OpenTimestamps. A bot commits each proof to [timestamps/](timestamps/). The heads of the other branches are stamped every six hours.
- For that reason `main` is never force-pushed or rewritten, and pull requests are merged with merge commits.
- The papers are archived on Zenodo with permanent DOIs.
- OEPs, decisions and specification revisions live in this repository, so they carry the same timestamps.

Provenance is the only thing the protocol's origin keeps.

## 10. Licensing

- The papers, the specifications and OEPs are licensed under [Creative Commons Attribution 4.0](LICENSE-DOCS.md).
- Code is licensed under the [Apache License 2.0](LICENSE).
- Contributions are accepted under these licences, with a Developer Certificate of Origin sign-off ([CONTRIBUTING.md](CONTRIBUTING.md), Sections 11 and 12).

## 11. What is decided, and what is not

**Decided now:**

- changes to the protocol go through the OEP process above;
- the maintainer makes the final decisions for the time being;
- the licences and the provenance record are as Sections 9 and 10 describe;
- OIP is owned by no one. As a community of implementers forms, stewardship will move to a neutral, multi-stakeholder home.

**Not decided yet:**

- which home that will be, what form it takes and when the move happens;
- how further maintainers are added;
- any voting rule or formal consensus rule;
- a fixed review period for OEPs;
- the criteria for marking the specification stable.

Each of these will be proposed and discussed in the open, as an OEP of type Process, before it is settled.

## 12. Conduct and security

- Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).
- Vulnerabilities are reported privately, as [SECURITY.md](SECURITY.md) describes.
