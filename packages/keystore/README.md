# @oip/keystore

The private keys of a mind of the [Open Intelligence Protocol](../../README.md), sealed and kept apart by role ([BUILD.md](../../BUILD.md), Section 3.4).

A mind has keys of four roles (Layer 1, 3.4 and 3.5). A keystore seals each role as a document of its own, under a lock of its own if its owner wants one, and unlocks each by itself. A process that signs everyday records never holds a control key.

- **Nothing secret leaves it** but in a backup, which is sealed. A handle gives public keys, signatures, and what was sealed to the mind.
- **A control key signs one identity event**, and is destroyed once that event is published (Layer 1, 3.11 and 7.4). The keystore remembers the event before the key signs it, so a process that stops in between cannot sign another.
- **It implements no cryptography.** Keys are stretched with scrypt (`@noble/hashes`) and sealed with XChaCha20-Poly1305 (`@noble/ciphers`), each checked against its published vectors ([ADR-0017](../../docs/adr/0017-the-keystore.md)).

The package has two entries. `@oip/keystore` runs anywhere. `@oip/keystore/node` adds a storage that is a directory.

## An example

[`examples/new-mind.ts`](examples/new-mind.ts) makes the keys of a new mind, signs its genesis and destroys the control key that signed it:

```ts
import { keyHash, utf8 } from "@oip/core";
import { draftGenesis } from "@oip/identity";
import { Keystore, type KeyStorage, type Lock } from "@oip/keystore";

/**
 * The keys of a new mind: made in a keystore, its genesis signed by a control
 * key, and that key destroyed once the genesis is published.
 *
 * @param publish - Sends the genesis to the mind's resolvers.
 */
export async function example(
  storage: KeyStorage,
  lock: Lock,
  created: string,
  publish: (genesis: object) => Promise<void>,
): Promise<string[]> {
  const output: string[] = [];
  const keystore = await Keystore.create({ storage, locks: lock });

  // Each role is unlocked by itself. A new mind needs these three once.
  const control = await keystore.unlock("control", lock);
  const operational = await keystore.unlock("operational", lock);
  const agreement = await keystore.unlock("agreement", lock);

  const first = await control.generate();
  const next = await control.generate();
  const everyday = await operational.generate({ label: "everyday" });
  const sealing = await agreement.generate();

  // The genesis reveals the first control key and commits to the next (Layer 1, 3.4).
  const genesis = await control.sign(
    draftGenesis(created, {
      kind: "agent",
      controller: { keys: [first.publicKey], next: [keyHash(next.publicKey)] },
      keys: [{ key: everyday.publicKey, label: "everyday" }],
      agreement: [{ key: sealing.publicKey }],
    }),
  );
  output.push(`signed: ${String(control.pending().length)} event awaits publication`);

  await publish(genesis);
  // Layer 1, 3.11: a control key is destroyed once the event it signed is published.
  const destroyed = await control.published(genesis);
  output.push(`published: ${String(destroyed)} control key destroyed`);
  output.push(`kept for the next event: ${String(control.keys().length)} control key`);
  control.lock();

  // Everyday signing needs the operational keys, and no others.
  const signer = operational.signer(everyday.publicKey);
  output.push(`a signature of ${String(signer.sign(utf8("hello")).length)} bytes`);
  output.push(`a backup is due for: ${(await keystore.backupDue()).join(", ")}`);
  return output;
}
```

It gives:

```
signed: 1 event awaits publication
published: 1 control key destroyed
kept for the next event: 1 control key
a signature of 64 bytes
a backup is due for: control, operational, agreement
```

## What it exports

| Export                                                                                                                                        | What it does                                                                                                                                                                                                                  |
| --------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Keystore`, `KeystoreOptions`, `CreateOptions`, `Locks`                                                                                       | A keystore in a storage: `create` makes one where there is none, `open` finds the one that is stored, `unlock` gives the keys of a role, `changeLock` seals a role under another lock                                         |
| `KEY_ROLES`, `KeyRole`                                                                                                                        | The four roles: `control`, `operational`, `invocation`, `agreement`                                                                                                                                                           |
| `RoleKeys`, `KeyInfo`, `GenerateOptions`                                                                                                      | What the unlocked keys of every role do: `keys`, `has`, `generate`, `remove`, `lock`                                                                                                                                          |
| `OperationalKeys`                                                                                                                             | The operational keys, unlocked: `signer` gives a signer over one, for the mind's everyday records                                                                                                                             |
| `ControlKeys`, `ControlKeyInfo`                                                                                                               | The control keys, unlocked: `sign` signs the identity event that reveals them, `pending` gives the events that await publication, `published` destroys the keys that signed one, `unsent` frees them from one that never left |
| `InvocationKeys`, `MemberSigning`                                                                                                             | The invocation keys, unlocked: `sign` signs a collective's identity event as its member, once for each position of its log                                                                                                    |
| `AgreementKeys`, `SealedToKey`                                                                                                                | The agreement keys, unlocked: `open` opens what was sealed to one (RFC 9180)                                                                                                                                                  |
| `Backup`, `AllKeys`, `RestoreOptions`                                                                                                         | `Keystore.backup` seals the keys of every role in one document; `Keystore.restore` makes a keystore from one; `backupDue` names the roles whose keys no saved backup holds                                                    |
| `passphrase`, `PassphraseOptions`, `Lock`, `LockContext`                                                                                      | A lock that is a passphrase, stretched with scrypt; and what a lock is                                                                                                                                                        |
| `keychainLock`, `Keychain`                                                                                                                    | A lock that is a random key kept by a keychain, and what a keychain is                                                                                                                                                        |
| `LockHeader`, `ScryptHeader`, `KeychainHeader`                                                                                                | How the key of a sealed document is found again, as the document says it in the clear                                                                                                                                         |
| `KeyStorage`, `Stored`, `memoryStorage`, `STORAGE_NAME`                                                                                       | Where sealed documents are kept: named byte strings, each write naming the version it replaces. `memoryStorage` is gone with the process                                                                                      |
| `fileStorage`, `FileStorageOptions`                                                                                                           | From `@oip/keystore/node`: a storage that is a directory, for its owner alone                                                                                                                                                 |
| `Randomness`, `systemRandomness`                                                                                                              | Where keys, salts and nonces come from: the platform's generator, unless a test gives another                                                                                                                                 |
| `KeystoreError`, `KeystoreErrorCode`, `KEYSTORE_ERRORS`                                                                                       | The one exception the keystore throws, and its reasons. Nothing secret is ever in one                                                                                                                                         |
| `SealedHeader`, `SealedKind`, `SEALED_KINDS`, `FORMAT`                                                                                        | What a sealed document says of itself in the clear, all of it authenticated                                                                                                                                                   |
| `SCRYPT_N`, `SCRYPT_MIN_N`, `SCRYPT_MAX_N`, `SCRYPT_R`, `SCRYPT_P`, `SALT_LENGTH`, `KEY_LENGTH`, `MIN_PASSPHRASE_LENGTH`, `MAX_KEYCHAIN_NAME` | The parameters of a lock                                                                                                                                                                                                      |
| `NONCE_LENGTH`, `TAG_LENGTH`, `KEYSTORE_ID_LENGTH`, `MAX_DOCUMENT_BYTES`, `MAX_KEYS`, `MAX_LABEL_LENGTH`, `MAX_POSITIONS`                     | The sizes and limits of what is sealed                                                                                                                                                                                        |

## What to know

### Roles and locks

- **Unlock what the work needs, and lock it when the work is done.** `unlock` reads one role into memory. `lock()` zeroes its private keys and the key of the cipher, and the handle and every signer it gave do nothing more. Control keys are needed only when the mind's identity changes: unlock them for that, and lock them at once.
- **One lock for every role, or one for each.** `Keystore.create({ storage, locks })` takes either. A separate passphrase for the control keys means that whoever learns the everyday one cannot change the mind's identity.
- **Control keys can be kept elsewhere.** Give `controlStorage`, and nothing of them is with the rest: a directory on a disk that is plugged in when it is needed, for instance.
- **A passphrase is normalised** (NFKC) before it is stretched, so it is the same passphrase however a keyboard composed its characters. It has at least eight characters. The keystore does not judge it further: choose a long one.
- **A lock keeps what it was given.** A `passphrase` lock holds the passphrase while it lives. Let go of it once the keys are unlocked.

### Control keys

A key-controlled mind's identity event reveals the control keys that sign it and commits to the hashes of the next ones (Layer 1, 3.4). So between two events a keystore holds the keys the next event will reveal, and nothing else of that role.

1. Make the next key with `generate`, and draft the event with `@oip/identity`: it reveals the keys held and commits to the new one.
2. `sign` it. The keystore first writes down, sealed, which event each key signs. A key so marked signs that event again as often as it is asked, and never another: a second event for one position is duplicity (Layer 1, Section 7).
3. Publish it. Then call `published`: the keys that signed are destroyed.

If the process stops between 2 and 3, `pending()` has the event when the keys are next unlocked. Sign it again, which gives the same event, and publish it.

`unsent` is for an event that turned out to be wrong before any copy of it left the process. If a copy has left, another event from the same keys is duplicity, and no verifier forgives it.

### Invocation keys

A member signs a collective's identity events with an invocation key (Layer 1, 9.4), many times over the life of the key. `InvocationKeys.sign` remembers which event the key signed for each position of each collective's log, and signs no other for that position: two valid events at one position name the member that signed both. A key remembers 10,000 positions. Replace it before then.

### Storage

- **Every write names the version it replaces.** Two keystore objects over one storage, in one process or in two, cannot both change a role: the second is told `changed`. Without that, a writer that had read the control keys before one was destroyed could write it back. After `changed`, lock the handle and unlock afresh.
- **`fileStorage` never changes a file.** It writes the whole document to a temporary file, makes it durable, and links it to the name of the next version, which fails if another writer got there first. A process that stops at any point leaves the old document or the new one.
- **The directory is its owner's alone.** `fileStorage` makes it with mode 700 and refuses one that others can read or enter. What is in it is sealed, and a passphrase can be guessed at leisure by whoever has a copy.
- **A storage is not trusted.** Every document read from it is checked before anything is derived from it: its format, its role, its keystore, and the work its lock asks for. A document that asks for more than scrypt at 2^20 is refused before any key is derived.

### Backups

- **A backup is the one form in which private keys leave a keystore.** It is one sealed document, under a lock of its own. Keep that lock apart from the keystore's.
- **Back up after every identity event.** The event commits to a control key that was made for it. If the keystore is lost before a backup holds that key, the mind's identity can never change again. `backupDue()` names the roles that have changed since the last backup that was said to be `saved()`, and needs no lock to ask.
- **A backup holds the keys as they were.** A control key that has signed and been destroyed since is in an older backup still. Before any identity event is signed from a restored keystore, find out what the mind has published and call `published` for it.

### What it does not do

- **It cannot erase.** JavaScript gives no way to clear a string, and a file system may keep old blocks. "Destroyed" means that the keystore no longer has the key and that nothing it stores holds it. Someone who holds an old copy of the directory and the passphrase holds the old keys.
- **It does not defend against the process it runs in.** Code in the same process can ask an unlocked handle to sign.
- **It does not know what the mind has published.** The mind's identity log decides what a key may sign. The note a keystore keeps of its mind's address is in the clear and is evidence of nothing.

The [threat model](../../docs/threat-models/keystore.md) says more.

### Limits

| What                                            | Limit                                |
| ----------------------------------------------- | ------------------------------------ |
| Work factor of scrypt for a new passphrase lock | 2^17 (128 MiB), with r = 8 and p = 1 |
| Work factor accepted                            | 2^14 to 2^20                         |
| Characters in a passphrase, at least            | 8                                    |
| Keys in one role                                | 256                                  |
| Positions an invocation key remembers           | 10,000                               |
| Bytes of a sealed document                      | 4 MiB                                |
