# Architecture decision records

An ADR records a decision that is hard to reverse: what was decided, why, and what follows from it. [BUILD.md](../../BUILD.md), Section 7, asks for one for every such decision, and for one that justifies each dependency.

| ADR                                               | Decision                                                                      |
| ------------------------------------------------- | ----------------------------------------------------------------------------- |
| [0001](0001-tooling.md)                           | The workspace, the build and the checks                                       |
| [0002](0002-cryptography-libraries.md)            | Cryptography libraries                                                        |
| [0003](0003-evidence-model.md)                    | The evidence model in code                                                    |
| [0004](0004-error-model.md)                       | The error model and problem types                                             |
| [0005](0005-cryptography-libraries-as-adopted.md) | The cryptography libraries as adopted in `@oip/core`                          |
| [0006](0006-performance-budgets.md)               | Performance budgets, as measured in M1                                        |
| [0007](0007-programming-errors.md)                | A wrong argument is a `TypeError`                                             |
| [0008](0008-holding-logs.md)                      | The log book, and the time a log is known up to                               |
| [0009](0009-signing-for-a-party.md)               | Signing for a party: two packages, one view of records, and no search         |
| [0010](0010-checks-cut-short.md)                  | A check that could not be made is refused, and never kept                     |
| [0011](0011-hpke.md)                              | HPKE as adopted in `@oip/core`                                                |
| [0012](0012-service-stack.md)                     | The service stack: what is taken, and what is written here instead            |
| [0013](0013-the-server-package.md)                | A package the three services share                                            |
| [0014](0014-containers.md)                        | The service images                                                            |
| [0015](0015-server-budgets.md)                    | The servers' budgets, as measured in M5, and signatures that are checked once |
| [0016](0016-native-ed25519.md)                    | Ed25519 by OpenSSL in the services                                            |
| [0017](0017-the-keystore.md)                      | The keystore                                                                  |
| [0018](0018-the-keystore-in-a-browser.md)         | The keystore in a browser                                                     |
| [0019](0019-the-system-keychain.md)               | The keychain of the operating system                                          |
| [0020](0020-ratios-turn-about.md)                 | Benchmark ratios are measured turn about                                      |
| [0021](0021-the-client.md)                        | The client                                                                    |
| [0022](0022-the-client-in-a-browser.md)           | The client's test in a browser                                                |
| [0023](0023-sessions-in-the-client.md)            | Sessions in the client                                                        |
| [0024](0024-the-clients-socket.md)                | The client's socket to its host                                               |
| [0025](0025-the-clients-outbox.md)                | The client's outbox                                                           |
| [0026](0026-the-command.md)                       | The `oip` command                                                             |

## Writing one

- Name the file `NNNN-short-title.md`, with the next unused number.
- Use the sections **Status**, **Context**, **Decision**, **Consequences**. Add **Alternatives** when a reader would ask "why not X?".
- State the decision in the present tense. Keep it short enough to read in five minutes.
- An ADR is not edited after it is accepted, except to mark it superseded. A new ADR replaces it.
- A change to the protocol itself is not an ADR. It is an OEP ([GOVERNANCE.md](../../GOVERNANCE.md)).
