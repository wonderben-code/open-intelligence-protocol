---
"@oip/delegation": minor
---

First version: delegation (Layer 1, Section 11).

- `isCommand`, `isDelegableCommand`, `covers`, `signCommand`, `DELEGABLE_TYPES`, `SEND_COMMAND`: commands (Layer 1, 11.2). Every command whose first segment is `oip`, other than the four that sign and the one that sends, is reserved, so no grant is a blanket.
- `evaluatePolicy`, `policyHolds`, `select`: the policy language (Layer 1, 11.3). Ordering compares integers and decimal strings only; every statement is evaluated in full; an error anywhere fails the policy, so `not` and `or` never turn a missing or malformed value into a pass. One policy is evaluated for at most `MAX_POLICY_STEPS` statements.
- `delegatedProofTime`, `delegatedTime`: whether a proof counts for another mind through the delegation chain its `authority` lists (Layer 1, 11.4, 11.6). The list is checked exactly as given, root first, and never searched. Each refusal names the entry of `authority` at fault and the item of 11.4 it breaks.
- `revokedTime`: a revocation takes effect from its own evaluation time, and only its delegation's author can make one (Layer 1, 11.5).
- `RecordSet`, `RecordView`: the records a verifier holds. A record keeps every proof it was shown with that verified, from whichever copy: no copy takes a proof away.
- `sentFor`: whether a packet counts as sent on another mind's behalf (Layer 1, 11.2): it names the subject, and a proof by its own sender lists a chain from the subject that covers `/oip/send`.
