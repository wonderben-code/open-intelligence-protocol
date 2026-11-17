---
"@oip/conformance": minor
---

- The adapter gains `jsonIsWithinProfile`, `contentId`, `keyHash`, `createProof` and `proofVerifies`.
- A new kind of case, `json`: texts a parser of the JSON profile must read or refuse.
- New positive checks: content IDs and addresses reproduce; every revealed control key was committed to by its hash; every `proofValue` reproduces from its test key; every proof verifies, and the signatures that break core 4.4 do not.
- `referenceAdapter` answers all of them through `@oip/core`, and judges a record of a type an extension defines as core 7 says.
- Cases of kind `record` are now also must-accept cases and controls.
