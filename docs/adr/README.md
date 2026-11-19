# Architecture decision records

An ADR records a decision that is hard to reverse: what was decided, why, and what follows from it. [BUILD.md](../../BUILD.md), Section 7, asks for one for every such decision, and for one that justifies each dependency.

| ADR                                               | Decision                                             |
| ------------------------------------------------- | ---------------------------------------------------- |
| [0001](0001-tooling.md)                           | The workspace, the build and the checks              |
| [0002](0002-cryptography-libraries.md)            | Cryptography libraries                               |
| [0003](0003-evidence-model.md)                    | The evidence model in code                           |
| [0004](0004-error-model.md)                       | The error model and problem types                    |
| [0005](0005-cryptography-libraries-as-adopted.md) | The cryptography libraries as adopted in `@oip/core` |
| [0006](0006-performance-budgets.md)               | Performance budgets, as measured in M1               |
| [0007](0007-programming-errors.md)                | A wrong argument is a `TypeError`                    |

## Writing one

- Name the file `NNNN-short-title.md`, with the next unused number.
- Use the sections **Status**, **Context**, **Decision**, **Consequences**. Add **Alternatives** when a reader would ask "why not X?".
- State the decision in the present tense. Keep it short enough to read in five minutes.
- An ADR is not edited after it is accepted, except to mark it superseded. A new ADR replaces it.
- A change to the protocol itself is not an ADR. It is an OEP ([GOVERNANCE.md](../../GOVERNANCE.md)).
