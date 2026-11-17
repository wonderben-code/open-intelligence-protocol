# ADR-0004: The error model and problem types

**Status:** Accepted, 17 November 2026 (M0). `Issue` and `Validation` exist in `@oip/schema`; `OipError` and the problem types arrive in M1, and the HTTP mapping in M5.

## Context

OIP code rejects input for many reasons, at several layers. [BUILD.md](../../BUILD.md), Section 3.5, asks for typed errors that carry the specification clause they enforce, never contain key material, and say what was wrong and what to do. core 10.2 fixes the problem types that HTTP APIs return.

Three kinds of failure need to be told apart:

1. **A value is malformed.** It is not a record of the expected type.
2. **A verification does not succeed.** The record is well formed, but a proof does not count, a log does not verify, or a rule about time fails.
3. **Something else went wrong.** A network request failed, storage is unavailable, the caller passed a wrong argument.

## Decision

### Expected outcomes are values, not exceptions

Rejecting hostile input is the normal work of a verifier, not an exceptional event. Functions that judge input return a result:

```ts
type Validation<T> = { ok: true; value: T } | { ok: false; issues: readonly [Issue, ...Issue[]] };

interface Issue {
  path: string; // JSON Pointer to the value at fault
  message: string; // what is wrong, in words
  clause: string; // the clause it breaks, for example "L1 11.1"
}
```

- Validation in `@oip/schema` returns `Validation`.
- Verification in the packages above returns a verdict of the same shape, with reasons that cite clauses. `oip verify` (M7) and the Explorer's "why" view (M11) show them.
- A verifier never throws on input it was asked to judge, whatever the input: a value that did not come from JSON text, a proxy, an object that throws when read. Each package has a property test that gives it arbitrary values and requires a result, and tests for the hostile inputs that once broke it.
- An answer is bounded. A validation reports at most `MAX_ISSUES` issues (32), with paths of at most 256 characters, however many faults the input has: hostile input must not buy megabytes of output.

### Exceptions are for the third kind

`OipError` (M1, in `@oip/core`) is thrown when the caller or the environment is at fault:

```ts
class OipError extends Error {
  readonly code: ProblemCode; // one of the codes of core 10.2
  readonly clause?: string; // the clause enforced, when there is one
  readonly detail: string; // for a person: what went wrong and what to do
}
```

- `code` is one of the eleven codes of core 10.2. The mapping from code to HTTP status is a table in `@oip/core`, tested against the specification's table.
- A convenience function turns a failed `Validation` or verdict into an `OipError` (`invalid-record`, `invalid-proof`, …) for callers who prefer to throw.

### HTTP

Services return RFC 9457 problem details (`application/problem+json`) with `type` set to `urn:oip:error:<code>`, `status`, a `title` fixed per code, and `detail`. The issues are included as an extension member, so that a client can show which member was wrong. Internal errors return a generic 500 with no detail from the exception.

### Nothing secret, nothing untrusted, in an error

- No private key, seed, passphrase or decrypted content appears in a message, a `detail`, a log line or an `Issue`. Functions that hold secrets build their messages from constants.
- Messages may quote public values from the input (a key, an address, a member name). They are truncated, because input is hostile and messages are logged and displayed.
- Content from a packet is never copied into a message that reaches a model's context as an instruction (Layer 1, 12.5).

### Messages

A message says what is wrong and, where there is a remedy, what to do: `"the number 1.5 is not an integer between -(2^53-1) and 2^53-1; write decimal quantities as strings"`. Messages are reviewed like code. `clause` is always present, so that a reader can check the rule; an implementation limit that the specification does not set says so (`"implementation limit"`).

## Consequences

- Callers handle rejection in the type system: a result must be checked before its value can be used.
- "Why was this rejected?" always has an answer that names a clause.
- Two shapes exist (results and exceptions). The rule for choosing is simple: judging input returns a result; everything else throws.
