# Threat model: the keystore

For `@oip/keystore` as built in M6: [README](../../packages/keystore/README.md), [ADR-0017](../adr/0017-the-keystore.md), Layer 1, 3.4, 3.5, 3.11 and 7.4.

## Assets

1. **The control keys.** Whoever holds the next control key can change the mind's identity: its keys, its homes, its end. A control key that has signed and still exists can sign a second event for the same position, which is duplicity (Layer 1, Section 7).
2. **The operational keys.** They sign the mind's everyday records: what it says, offers and commits to.
3. **The invocation keys.** They sign the identity events of collectives the mind is a member of.
4. **The agreement keys.** They open what was sealed to the mind, old packets included.
5. **What the keys remember.** The event a control key is bound to, and the positions an invocation key has signed for. Lost, a key can be made to sign twice.
6. **The passphrase**, while a lock holds it.

## Who can reach it

| Entry point                                  | Caller                                    | Trusted with                                               |
| -------------------------------------------- | ----------------------------------------- | ---------------------------------------------------------- |
| The keystore's interface                     | The application in the same process       | Everything it unlocks. It is asked to sign, and signs      |
| The storage: a directory, or a browser's own | Whoever can read or write it              | Nothing. What is read from it is checked before it is used |
| A backup                                     | Whoever is given the file                 | Nothing without its lock                                   |
| The keychain                                 | The operating system, and what it lets in | The keys it keeps                                          |
| The memory of the process                    | Whoever can read it                       | Everything unlocked                                        |

## Threats

### Spoofing

| Threat                                                                       | What stops it                                                                                                                                                                                              | Left                                                     |
| ---------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| A document of another keystore, or of another role, is put in a role's place | The header names the keystore and the role, and is authenticated. The keystore refuses a document that names another before it asks a lock for a key (`keystore.test.ts`: "is not read as another role's") | None                                                     |
| A stored header sends a keychain lock to another secret                      | The lock asks only for the account of its own keystore and role, under its own service, whatever the header says (`lock.test.ts`: "is not sent by a stored header")                                        | None                                                     |
| A keystore signs with a key whose public half is not the one it says         | Each public key is worked out again from its private key when a role is unlocked (`content.test.ts`)                                                                                                       | None                                                     |
| The note of which mind the keys are of is changed                            | Nothing: it is in the clear and is evidence of nothing. What a key may sign is decided by the mind's identity log                                                                                          | An application that trusts the note. The client does not |

### Tampering

| Threat                                                                                | What stops it                                                                                                                                                                           | Left                                                                                                            |
| ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| A sealed document is edited                                                           | XChaCha20-Poly1305 authenticates the ciphertext and the whole header. Any change opens nothing (`keystore.test.ts`: "does not open once any part of it was changed"; `hostile.test.ts`) | None                                                                                                            |
| An older copy of a role is put back, with a control key that has since been destroyed | Nothing in the keystore: an old document is a genuine one. The client checks the mind's published log before an identity event is signed, and destroys what was used                    | A mind that signs an identity event without looking at its own log. The keystore cannot know what was published |
| Two writers change one role, and one writes back what the other destroyed             | Every write names the version it replaces, and the storage refuses a write that names another (`keystore.test.ts`: "cannot both change a role"; `storage.test.ts`)                      | A storage that does not keep that promise. The storages this package ships do                                   |
| A write is cut short and leaves half a document                                       | The directory storage writes a whole file and links it. What is found is the old document or the new one (`file.faults.test.ts`)                                                        | None on a file system whose links are atomic                                                                    |

### Repudiation

| Threat                                    | What stops it                                                                                                                            | Left |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ---- |
| A mind denies an identity event it signed | Not the keystore's to stop: the event is signed, and resolvers witness it. The keystore keeps the event until it is told it is published | None |

### Information disclosure

| Threat                                                             | What stops it                                                                                                                                                                                                                                                | Left                                                                                                                                                                               |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Someone copies the storage                                         | Every private key in it is sealed. A passphrase is stretched with scrypt at 2^17, under a salt of its own for each document                                                                                                                                  | A weak passphrase is guessed, at about a second and 128 MiB a guess on the owner's machine and less on an attacker's. The keystore asks for eight characters and judges no further |
| Others on the machine read the directory                           | It is made with mode 700 and its files with 600. A directory that others can read or enter is refused (`storage.test.ts`)                                                                                                                                    | Windows, where no modes are checked. An administrator anywhere                                                                                                                     |
| A script in the page reads the browser's storage                   | Nothing keeps it from the database: IndexedDB belongs to the origin, and so to every script that runs in it. The documents are sealed (`indexeddb.test.ts`; [ADR-0018](../adr/0018-the-keystore-in-a-browser.md))                                            | A script that can also watch the passphrase being typed, or use a handle that is unlocked. A page that holds keys loads no script it does not control                              |
| A private key is in an error, a log line or a return value         | A handle returns public keys, signatures and plaintexts sealed to the mind. Errors are built from constants (`errors.ts`). A test looks for each private key in everything a handle answers and everything stored (`keystore.test.ts`)                       | None                                                                                                                                                                               |
| A key is read from memory after it was locked or destroyed         | `lock()` and `published` zero the bytes of each private key and of the cipher's key                                                                                                                                                                          | JavaScript cannot erase a string: the passphrase a lock holds, and the base64url of a key while a document is being sealed, last until the collector takes them                    |
| A destroyed control key is recovered from the disk                 | The key is out of the document, and the version before is removed                                                                                                                                                                                            | A file system keeps old blocks, and a backup tool keeps old files. With the passphrase, an old copy is the old keys. Keep the control keys in a storage of their own               |
| A backup is found                                                  | It is sealed under its own lock, as a role is                                                                                                                                                                                                                | A backup under the same passphrase as the keystore protects against loss and against nothing else                                                                                  |
| Another program of the user asks the keychain for a keystore's key | Nothing: a keychain gives what it keeps to the user's programs while it is unlocked. macOS may ask the user when another program reads an entry, and a script run by the same `node` is not another program ([ADR-0019](../adr/0019-the-system-keychain.md)) | A keystore under the keychain is protected from a copy of the disk and from other users, and from nothing that runs as its owner                                                   |
| The control keys are in memory while everyday records are signed   | Each role is unlocked by itself (`keystore.test.ts`: "are sealed apart")                                                                                                                                                                                     | An application that unlocks everything and locks nothing                                                                                                                           |

### Denial of service

| Threat                                                     | What stops it                                                                                                                                           | Left                                                                              |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| A stored document asks scrypt for gigabytes                | The work factor is checked before any key is derived: at most 2^20, with r = 8 and p = 1 (`keystore.test.ts`: "asks for no more work than is accepted") | 1 GiB and some seconds, for a document that says 2^20                             |
| A stored document is enormous                              | Nothing larger than 4 MiB is parsed                                                                                                                     | None                                                                              |
| The storage is deleted or damaged                          | A backup                                                                                                                                                | A mind whose next control key is in no backup can never change its identity again |
| A control key is bound to an event that is never published | `pending` gives the event back to be published. `unsent` frees the key, for an event no copy of which has left                                          | An owner who calls `unsent` for an event that did leave makes duplicity           |

### Elevation of privilege

| Threat                                               | What stops it                                                                                                                                                                  | Left                                                                           |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------ |
| A control key signs a second event for its position  | It is bound, in storage, to the first event before it signs, and signs no other (`keystore.test.ts`: "signs one event"; "remembers the event in storage before it signs")      | None while the stored document is the latest. See the older copy, above        |
| An invocation key signs two events for one position  | It remembers the event it signed for each position (`keystore.test.ts`: "remembers the position it signed for")                                                                | None, as above. A key remembers 10,000 positions and then signs for no new one |
| An operational key is made to sign an identity event | The keystore cannot tell what the bytes it signs mean. The protocol does: an operational key never signs an identity event, and a verifier counts no such proof (Layer 1, 3.5) | None                                                                           |
| Code in the process uses an unlocked handle          | Nothing. A handle signs what it is asked to                                                                                                                                    | Everything, for as long as a role is unlocked. Unlock late and lock early      |

## What an owner should do

1. Choose a long passphrase. Give the control keys one of their own, or a storage of their own.
2. Back up after every identity event, under a lock kept apart from the keystore's.
3. Unlock the control keys only to change the mind's identity, and lock them at once.
4. After restoring a backup, let the client compare the keys with the mind's published log before anything is signed.
