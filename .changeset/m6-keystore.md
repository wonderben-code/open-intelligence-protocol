---
"@oip/keystore": minor
---

First version: the private keys of a mind, sealed and kept apart by role ([ADR-0017](../docs/adr/0017-the-keystore.md)).

- `Keystore`: four roles, each a sealed document of its own, unlocked by itself and under a lock of its own if its owner wants one. Control keys can be kept in another storage.
- `passphrase`, `keychainLock`: a lock that is a passphrase, stretched with scrypt, and one that is a random key a keychain keeps. A sealed document is XChaCha20-Poly1305 over canonical JSON, with its whole header authenticated.
- `ControlKeys`: a control key is bound, in storage, to the identity event it signs before it signs, signs no other, and is destroyed by `published` (Layer 1, 3.11 and 7.4). `pending` gives back an event that was signed and not yet published.
- `InvocationKeys`: remembers the event signed for each position of each collective's log, and signs no other for it.
- `OperationalKeys`, `AgreementKeys`: a signer over an operational key; opening what was sealed to an agreement key.
- `Keystore.backup`, `Keystore.restore`, `backupDue`: the one form in which private keys leave a keystore, and which roles have keys no saved backup holds.
- `KeyStorage`, `memoryStorage`, `indexedDbStorage` for browsers, and `fileStorage` from `@oip/keystore/node`: storages in which every write names the version it replaces, so that two writers cannot both change a role.
