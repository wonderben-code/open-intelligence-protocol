# ADR-0002: Cryptography libraries

**Status:** Accepted, 17 November 2026 (M0). The libraries are adopted in M1, M4 and M6; each adoption re-checks the facts below.

## Context

OIP never implements a cryptographic primitive ([CLAUDE.md](../../CLAUDE.md)). It needs Ed25519 signatures under the strict rule of core 4.4, SHA-256, base58btc and base32, RFC 8785 canonical JSON, X25519 with HPKE (RFC 9180) for sealing, and scrypt with XChaCha20-Poly1305 for the keystore. The pure packages must run in Node.js, browsers, Deno and Bun, so the libraries must be plain JavaScript with no native code and no Node.js built-ins.

[BUILD.md](../../BUILD.md), Section 4, proposes the libraries. This record confirms them against the registry as it stood on 17 November 2026.

## Decision

| Need                                  | Library                                                      | Version              | Licence    | Dependencies    | Last release      | Used from |
| ------------------------------------- | ------------------------------------------------------------ | -------------------- | ---------- | --------------- | ----------------- | --------- |
| Ed25519, X25519                       | `@noble/curves`                                              | 2.4.0                | MIT        | `@noble/hashes` | 27 August 2026    | M1        |
| SHA-256, HKDF, scrypt                 | `@noble/hashes`                                              | 2.4.0                | MIT        | none            | 27 August 2026    | M1        |
| XChaCha20-Poly1305, ChaCha20-Poly1305 | `@noble/ciphers`                                             | 2.4.0                | MIT        | none            | 27 August 2026    | M4, M6    |
| base58btc, base32, base64url          | `@scure/base`                                                | 2.4.0                | MIT        | none            | 28 August 2026    | M1        |
| Canonical JSON (RFC 8785)             | `canonicalize`                                               | 5.1.0                | Apache-2.0 | none            | 18 September 2026 | M1        |
| HPKE (RFC 9180)                       | `@hpke/core`, `@hpke/dhkem-x25519`, `@hpke/chacha20poly1305` | 1.10.1, 1.8.1, 1.8.1 | MIT        | `@hpke/common`  | 8 November 2026   | M4        |

The noble and scure libraries share one author, have no dependencies outside their own family, are written for auditability and have been audited by independent firms. They are the usual choice where JavaScript must do cryptography without native code. Their audit reports are to be read, and their versions matched against the audited ones, when M1 adopts them.

### Rules for using them

1. **Strict Ed25519 is our rule, applied on top of the library.** core 4.4 requires `S < L`, canonical encodings, and `A` and `R` of order exactly L. A library's default is not assumed to match. M1 wraps verification so that:
   - the library is called in its strict mode (`zip215: false`, or its equivalent in the version adopted);
   - the public key and `R` are decoded and checked for order exactly L, which rejects the identity point and every small-order and mixed-order point;
   - the order check of a public key is cached, because keys repeat and the check costs a scalar multiplication.

   The test vectors have keys and signatures on each side of the rule, and the Python checker applies the same rule independently.

2. **Every library is checked against published vectors before it is trusted**: RFC 8032 for Ed25519, RFC 8785's examples and the OIP vectors for canonical JSON, RFC 9180's vectors for the one HPKE suite OIP uses (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305), and RFC 7914 for scrypt.
3. **Only `@oip/core` imports the signature and hash libraries.** Every other package asks `@oip/core`. One place applies core 4.4, and one place changes if a library is replaced.
4. **Secrets never leave the functions that need them.** No private key or seed is logged, put in an error, or returned from a function that does not exist to return it.
5. **Canonical JSON is checked, not assumed.** core 1.2 restricts numbers to safe integers, so JCS number formatting reduces to the shortest decimal form. M1 tests `canonicalize` against that and against the vectors. If it differs anywhere in OIP's profile, a small serialiser over the already-parsed, already-validated value replaces it; that is formatting, not a cryptographic primitive.

## Alternatives

- **WebCrypto.** It is built in, but it does not expose the checks core 4.4 needs, its Ed25519 behaviour differs between runtimes on exactly the edge cases that rule exists for, and it is asynchronous, which would make every verification function asynchronous. It may be used later for the keystore's key derivation where it is faster.
- **Native bindings (libsodium, OpenSSL through `node:crypto`).** They are fast but do not run in browsers, and OpenSSL accepts small-order and mixed-order points by default. The Python checker shows the wrapping that needs.
- **The `hpke-js` umbrella package.** It pulls in suites OIP does not use. The three scoped packages give the one suite needed.

## Consequences

- Verification is synchronous and runs anywhere.
- OIP depends on a small number of maintainers. The mitigations are pinned versions, the seven-day release delay ([ADR-0001](0001-tooling.md)), the published vectors in our own tests, and differential testing against the Python checker, which uses a different library.
- A future key type (P-256, for passkeys) is a change to the verification rules and needs an OEP, not only a library.
