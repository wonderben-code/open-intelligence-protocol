---
"@oip/core": minor
---

First version: the rules of OIP Core, Sections 1 to 8 and 10.

- `parseRecord`, `parseExtensionRecord`, `parseJson`: a strict parser for the JSON profile (no duplicate member names, valid Unicode with no noncharacters, safe integers judged by value, nesting of at most 64), the schema of the record's type, and the limits on size and depth, applied to a container part by part.
- `canonicalize`, `contentId`, `keyHash`: canonical form (RFC 8785), content IDs in their one spelling, and key hashes.
- `verifyProofs`, `verifyProof`, `createProof`, `createProofSync`, `withProofs`, `proofDigest`: `eddsa-jcs-2022` proofs, each judged on its own. `verifyProofs` answers with the proofs that verified, the entries that were rejected, and why none was judged if none was. `createProof` checks the record, as it will stand with the proof, before the signer is asked to sign.
- `verifyEd25519`: Ed25519 under the one rule of core 4.4, which rejects a signature whose `S` is not reduced, and any key or `R` that is not a point of order L.
- Multikey, references, timestamps as nanosecond instants, durations, exact decimal comparison, critical extensions, and the problem types with `OipError`.
- Everything judged is a plain copy read once: no getter and no proxy trap for a member is ever called, and a value cannot be validated as one thing and hashed as another.
