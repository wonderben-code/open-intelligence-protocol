---
"@oip/core": minor
---

- `concatBytes` is exported: several byte strings as one.
- `hpkeSeal`, `hpkeOpen` and `HPKE_SUITE`: HPKE (RFC 9180) in base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305, one message for each encapsulation, as a `Sealed` record uses it (Layer 1, 12.6). The sender's randomness is a parameter. Checked against RFC 9180, Appendix A.2.1 ([ADR-0011](../docs/adr/0011-hpke.md)). New dependencies: `@hpke/core`, `@hpke/dhkem-x25519`, `@hpke/chacha20poly1305`.
- `x25519PublicKey`: the public key of an agreement key.
- `bytesToBase64url`, `base64urlToBytes`: base64url without padding, read strictly: one text for each sequence of bytes.
- `bytesToBase64`, `base64ToBytes`: base64 with padding, read as strictly.
