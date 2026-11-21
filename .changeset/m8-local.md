---
"@oip/local": minor
"@oip/cli": patch
---

`@oip/local`: a mind on one machine. The mind's directory, the lock of its keys, opening the mind for one piece of work, and what the directory keeps between runs (records, each with when its proofs first came, and received packets) are taken out of the `oip` command into a package of their own, so that the MCP server can use the same directory without loading the command. `@oip/cli` no longer exports `Config`, `NetworkFile`, `routed` and `routedSocket`: they are `@oip/local`'s.
