---
"@oip/delegation": minor
---

First version: delegation (Layer 1, Section 11).

- `isCommand`, `isDelegableCommand`, `covers`, `signCommand`, `DELEGABLE_TYPES`, `SEND_COMMAND`: commands (Layer 1, 11.2). Every command whose first segment is `oip`, other than the four that sign and the one that sends, is reserved, so no grant is a blanket.
- `evaluatePolicy`, `policyHolds`, `select`: the policy language (Layer 1, 11.3). Ordering compares integers and decimal strings only; every statement is evaluated in full; an error anywhere fails the policy, so `not` and `or` never turn a missing or malformed value into a pass. One policy is evaluated for at most `MAX_POLICY_STEPS` statements.
