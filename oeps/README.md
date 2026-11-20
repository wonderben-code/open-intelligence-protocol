# OIP Enhancement Proposals (OEPs)

An OEP proposes a change to the Open Intelligence Protocol: to a record format, to a verification rule, to other normative text in [spec/](../spec/), or to how the project runs. [GOVERNANCE.md](../GOVERNANCE.md) defines the process. This page is the index, and it says how to submit a proposal.

## Index

| OEP                                                        | Title                                                                                    | Type    | Status |
| ---------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ------- | ------ |
| [0000](oep-0000-template.md)                               | The OEP template                                                                         |         |        |
| [0001](oep-0001-core-clarifications.md)                    | Core clarifications found while building the reference implementation                    | Core    | Review |
| [0002](oep-0002-identity-clarifications.md)                | Identity clarifications found while building the reference implementation                | Layer 1 | Review |
| [0003](oep-0003-delegation-and-mind-web-clarifications.md) | Delegation and Mind Web clarifications found while building the reference implementation | Layer 2 | Review |
| [0004](oep-0004-mind-network-clarifications.md)            | Mind Network clarifications found while building the reference implementation            | Layer 1 | Review |
| [0005](oep-0005-service-clarifications.md)                 | Service clarifications found while building the reference servers                        | Layer 1 | Review |
| [0006](oep-0006-bridge-clarifications.md)                  | Bridge clarifications found while building the MCP server and the A2A bridge             | Layer 0 | Review |

## Do you need an OEP?

You need one for any change to a record format, a verification rule or other normative specification text, beyond editorial fixes. You do not need one for an editorial fix, for a new test vector that checks an existing rule, for an implementation-only change, or for an extension in your own reverse-DNS namespace (core 8.1). The full list is in [GOVERNANCE.md](../GOVERNANCE.md), Section 4.

## How to submit

1. **Test the idea (optional).** Open an issue with the **OEP proposal** form.
2. **Copy the template.** Copy [oep-0000-template.md](oep-0000-template.md) to `oep-NNNN-short-title.md`. `NNNN` is the next unused four-digit number, counting open OEP pull requests as used. `short-title` is a few lower-case words joined by hyphens.
3. **Fill in every section.** Keep every heading. If a section does not apply, write "None" and say why.
4. **Add a row to the index** above.
5. **Open a pull request** with the status Draft. Put the pull request's link in the `discussion` field. Sign off your commits, as [CONTRIBUTING.md](../CONTRIBUTING.md) describes.
6. **Ask for review** when the proposal is complete.

A small correction can carry its OEP and its specification change in one pull request. For a larger change, agree the OEP first.

## Statuses

`Draft` → `Review` → `Accepted` → `Final`, or `Rejected`, or `Withdrawn`. [GOVERNANCE.md](../GOVERNANCE.md), Section 5, says what each means and who sets it.

## Licence

OEPs are licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
