---
"@oip/delegation": minor
---

`checkPolicy`: whether a value is a policy at all (Layer 1, 11.3), asked of the policy alone. `evaluatePolicy` makes the same check first, and a policy that is none holds for no record. This is for whoever is given a policy and should say at once if it is none: `oip delegate --policy` now does, and so does the MCP server when it reads what may be signed unasked.
