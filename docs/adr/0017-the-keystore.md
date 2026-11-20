# ADR-0017: The keystore

**Status:** Accepted, 20 November 2026 (M6).

## Context

[BUILD.md](../../BUILD.md), Section 3.4, asks for a keystore that keeps each role of a mind's keys apart, stores the next control key separately, destroys a control key once the event it signed is published, and never exports a private key except in an encrypted backup. M6 asks for scrypt with XChaCha20-Poly1305, backup and restore, an adapter for the operating system's keychain and one for browsers.

The protocol says what the keys are and what must become of them:

- A mind has control keys, operational keys, invocation keys and agreement keys (Layer 1, 3.4 and 3.5).
- A control key signs one identity event. Its private part MUST be destroyed once that event is published, so that it cannot sign an alternative (Layer 1, 3.11 and 7.4).
- Two valid events at one position of a log are duplicity, which names a key or a member that signed both (Layer 1, 3.4 and Section 7).

It says nothing of how keys are stored. That is this record.

[ADR-0002](0002-cryptography-libraries.md) chose the libraries: scrypt from `@noble/hashes`, XChaCha20-Poly1305 from `@noble/ciphers`. Each adoption re-checks the facts.

## Decision

### One sealed document for each role

1. **A keystore is five documents** in a storage: `control`, `operational`, `invocation` and `agreement`, each sealed, and `meta`, in the clear, which says that a keystore is there and which one.

2. **Each role is unlocked by itself**, under a lock of its own if its owner gives it one. A process that signs everyday records unlocks the operational keys and never holds a control key. The control keys can also be kept in another storage altogether (`controlStorage`).

3. **A sealed document is canonical JSON**: a header in the clear, a nonce and a ciphertext.

   ```
   { "format": "oip-keystore/1", "keystore": <16 bytes>, "role": <role>, "generation": <count>,
     "lock": <how the key is found again>, "nonce": <24 bytes>, "ciphertext": <bytes> }
   ```

   - **The cipher is XChaCha20-Poly1305** under a 32-byte key. Its nonce is 24 random bytes, long enough to be drawn afresh for every sealing under one key, so a role is sealed again at every change without a new key.
   - **The header is the associated data.** A document whose header was changed, to another role, another keystore, another generation or other parameters, does not open. A document of one keystore put in the place of another's is refused before any lock is asked for a key.
   - **The plaintext is the keys of the role**, as canonical JSON. What comes out is checked member by member all the same, and each public key is worked out again from its private key.

### Locks

4. **A lock yields the key of the cipher.** There are two kinds.

   - **A passphrase**, stretched with scrypt (RFC 7914) under a salt of 32 random bytes for each thing sealed. The work factor N is 2^17, with r = 8 and p = 1: 128 MiB and most of a second in JavaScript. It is the least that is still comfortable in a browser, and what OWASP gives as scrypt's minimum.
   - **A random key that a keychain keeps**, one for each role of each keystore. Nobody chooses or types it.

5. **What a stored document may ask of scrypt is bounded before anything is derived**: N a power of two from 2^14 to 2^20, r = 8, p = 1. A document that asks for more is refused. Otherwise a file an attacker wrote could take a gigabyte and a minute from whoever opens it.

6. **A passphrase is normalised (NFKC)** before it is stretched, and has at least eight characters. A keyboard that composes `é` from two code points and one that sends one must open the same keystore. The keystore judges a passphrase no further.

### Control keys

7. **A control key is bound to the event it signs before it signs.** `ControlKeys.sign` takes the event, writes into the sealed document which event each revealing key signs, and only then signs. A key so bound signs that event again as often as it is asked, and no other. A process that stops between signing and publishing finds the event again in the keystore (`pending`).

8. **`published` destroys the keys that signed an event**: they are taken out of the document, the document is written, and then their bytes in memory are zeroed. If the write fails, the keys stay, in memory as in storage.

9. **The keystore signs the event itself.** A handle gives no signer over a control key or an invocation key. A signer takes bytes, and nothing would tie the bytes it is given to the event the key was bound to.

10. **An invocation key remembers what it signed** for each position of each collective's log, and signs no other event for that position. A member that signs two events for one position is named by them.

### Storage

11. **Every write names the version it replaces**, and a storage refuses a write that names another. Two keystore objects over one storage, in one process or in two, cannot both change a role. Without this a writer that read the control keys before one was destroyed would write it back.

12. **A directory storage never changes a file.** A write puts the whole document in a temporary file, makes it durable and links it to the name of the next version. A link is made whole or not at all, and fails if the name is taken. The version before is removed only then. The directory is for its owner alone, and one that others can read is refused.

### Backups

13. **A backup is one sealed document** that holds the keys of every role, with what the control and invocation keys remember. It is the one form in which a private key leaves a keystore. It is sealed under a lock of its own.

14. **Each role counts the changes to its set of keys** (`generation`, in the header, authenticated). `backupDue` compares the counts with those of the last backup its owner said was saved, and needs no lock. An identity event makes a control key that the event commits to: a keystore lost before a backup holds that key leaves a mind whose identity can never change again.

### What it is not

15. **No clock.** A keystore records no times.

16. **Its errors are its own.** `KeystoreError` has a code from a short list. The codes of core 10.2 are for what a service answers, and none of them means a wrong passphrase. No error holds a key, a passphrase or a plaintext.

### What is still to come

17. **The keychain of the operating system and a storage for browsers** are built on the two interfaces here, `Keychain` and `KeyStorage`. Each brings a dependency or a platform of its own, and has its own record when it is built.

## What was checked

### Versions and audits

The audit facts are as the libraries' own READMEs state them at the versions installed, on 20 November 2026.

| Library          | Installed | Audits the library reports                                                                                                                                                            |
| ---------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `@noble/ciphers` | 2.4.0     | Cure53 at 1.0.0 (September 2024, scope: everything). The authors report regular self-audits since April 2026. It is the latest release, of 27 August 2026, MIT, with no dependencies. |
| `@noble/hashes`  | 2.4.0     | Cure53 at 1.0.0 (January 2022; scrypt is in scope). As in [ADR-0005](0005-cryptography-libraries-as-adopted.md): the installed version is well after the independent audit.           |

### Against published vectors

- **scrypt.** The first three vectors of RFC 7914, Section 12, reproduce, with the synchronous and the asynchronous function. The fourth, with N = 2^20, was reproduced once for this record and is not run with the tests: it takes a gigabyte. With the parameters the keystore uses, the library agrees with the scrypt of OpenSSL on generated passphrases and salts.
- **XChaCha20-Poly1305.** The vector of draft-irtf-cfrg-xchacha-03, Appendix A.3.1, reproduces: ciphertext and tag. A changed bit in the ciphertext, the tag, the nonce, the associated data or the key opens nothing.

## Consequences

- **A key that is destroyed is destroyed as far as the keystore can reach.** It is out of what is stored, and its bytes in memory are zeroed. JavaScript cannot erase a string, and a file system may keep old blocks. Someone who holds an older copy of the storage and the passphrase holds the older keys. The [threat model](../threat-models/keystore.md) says what follows.
- **An old backup holds control keys that have since signed.** A mind that restores one must learn what it has published before it signs an identity event. The client does that (M6).
- **A passphrase costs 128 MiB and most of a second** each time a role is unlocked. A service that starts often uses the keychain lock, or keeps the operational keys unlocked.
- **The keystore knows the shape of an identity event**: it reads the control keys an event reveals, and the position of a collective's event. It depends on `@oip/identity` for that and for the signing.
- **Unlocked keys are in the memory of the process.** Code in the same process can ask a handle to sign. A signer in hardware, or in another process, fits behind the same `Signer` interface later.

## Alternatives

- **One sealed document for the whole keystore.** Simpler, and every unlock would put the control keys in memory.
- **One document for each key.** Destroying a key would be removing a file. Two keys of one role could then be changed by two writers at once, and a role would have no one place where its count of changes is authenticated.
- **Argon2id.** It is the stronger function for the same cost. `@noble/hashes` has it, outside the scope of its audit, and BUILD.md names scrypt. The lock header says which function made the key, so another can be added without a new format.
- **WebCrypto for the cipher.** It has no XChaCha20-Poly1305. With AES-GCM a nonce is 12 bytes, too short to draw at random for every sealing under one key, and the keystore would have to count.
- **A signer for control keys, as for operational keys.** Decision 9: the binding of a key to its event would then be a promise of the caller's.
- **A lock file for the directory storage.** A process that stops while it holds one leaves it behind, and something must then decide when a lock is stale. A link to a name that is taken needs no such decision.
