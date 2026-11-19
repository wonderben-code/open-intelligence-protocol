# ADR-0007: A wrong argument is a `TypeError`

**Status:** Accepted, 17 November 2026 (M1). It adds one case to [ADR-0004](0004-error-model.md) and changes nothing else in it.

## Context

ADR-0004 separates results (for judging input) from `OipError` (for the caller or the environment being at fault), and gives `OipError` one of the eleven problem codes of core 10.2. Writing `@oip/core` showed a kind of failure with no fitting code: a function called with an argument of the wrong JavaScript type or length, such as a private key of 31 bytes, a digest that is not 32 bytes, or a content ID given to a function that builds an address.

No problem code describes these, because they never reach the wire: they are mistakes in the calling program.

## Decision

- **A wrong argument throws `TypeError` (or `RangeError` for a number out of range), as the platform itself does.** It has no problem code. Its message is a constant: it says what the function needs and never repeats the value, which may be a secret.
- **`OipError` is for data.** A value that should have been a record, a proof or JSON within the profile, and is not, throws `OipError` with `invalid-record` or `invalid-proof`, the clause, and the issues. `canonicalize`, `contentId`, `createProof` and `withProofs` are the examples in `@oip/core`.
- **Judging still never throws.** `parseJson`, `parseRecord`, `verifyProof`, `verifyProofs`, `verifyEd25519` and every `decode…`, `parse…` and `is…` function return a result for any input whatever.

## Consequences

- A service that catches `OipError` to build a problem response does not turn a programming mistake into a `400`: a `TypeError` propagates, is logged, and becomes a generic `500` (ADR-0004).
- Each function's documentation says which of the two it throws.
