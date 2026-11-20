---
"@oip/cli": minor
---

First version: the `oip` command.

- A mind from a terminal: `init`, `show`, `rotate`, `add-key`, `revoke-key`, `fork`; `publish profile`, `publish location`, `publish record`; `resolve`, `find`; `send`, `inbox`; `intent`, `offer`, `commit`, `receipt`, `status`; `delegate`, `revoke`; `collective create`, `collective sign`; `verify`; `keys backup`, `keys restore`; `doctor`; `demo`; `completions`.
- Every command answers for a person and, with `--json`, for a program. `--get <member>` prints one member of the answer for a shell to take. `--help` shows a command's options and an example.
- `verify` says why of every verdict, with the clause of the specification it rests on, for a record, an identity log, a bundle or a mind by its address.
- `demo` runs a resolver, a host and an indexer on this machine, and `--local` makes a mind that uses them. The README's five-minute path, from nothing to an accepted Commitment between two minds, is run as it stands by `scripts/newcomer.ts`.
- No private key is printed, and no passphrase is an option. Everything printed has its control characters shown as escapes, so a stranger's text cannot act on the terminal.
- A record the mind holds is kept in its directory with when its proofs first came, and held again by the next command with that (core 9.4).
