---
"@oip/schema": minor
---

A capability carries `ext` (Layer 1, 16.2; OEP-0006, item 4).

- `Capability.ext`: extension blocks about one capability, named as core 8.1 names those of a record. A gateway puts the input schema of an MCP server's tool there (Layer 0, 2.1).
- A profile whose capability has an `ext` that is not an object of namespaces, each with an object, is now malformed. Before, the member was one a reader did not recognise, and ignored.
