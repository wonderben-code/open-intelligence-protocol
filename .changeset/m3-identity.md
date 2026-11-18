---
"@oip/identity": minor
---

`disregardingCompromise(view)`: a view of the same logs and evidence with every compromise declaration (Layer 1, 6.2) disregarded. It answers one question, that of Layer 2, 8.3: whether a Commitment would be accepted had no party declared a key compromised, and so is `disputed`.

`operationalProofEvaluation`: `operationalProofTime` with the evidence the time rests on, for a caller that goes on to ask another log about the proof and must know up to when that log has to be known (core 9.4).

`operationalProofEvaluation` refuses for itself where a check was cut short, as `operationalProofTime` does ([ADR-0010](../docs/adr/0010-checks-cut-short.md)).
