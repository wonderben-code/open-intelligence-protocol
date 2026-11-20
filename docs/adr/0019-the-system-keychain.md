# ADR-0019: The keychain of the operating system

**Status:** Accepted, 20 November 2026 (M6).

## Context

[ADR-0017](0017-the-keystore.md) gave the keystore a second kind of lock: a random key that a keychain keeps, behind the interface `Keychain` (`get`, `set`, `delete`). M6 asks for an adapter for the operating system's own: the Keychain of macOS, the Credential Manager of Windows, the Secret Service of a Linux desktop.

Node.js has no interface to any of them. Each is reached through native code, or through a command of the platform.

## Decision

1. **`systemKeychain`, in `@oip/keystore/node`, reaches the keychain through `@napi-rs/keyring`.**

   | Library            | Version | Licence | Last release    | What it is                                                                                                    |
   | ------------------ | ------- | ------- | --------------- | ------------------------------------------------------------------------------------------------------------- |
   | `@napi-rs/keyring` | 2.1.2   | MIT     | 19 October 2026 | A binding, built ahead for twelve platforms, to the Rust crate `keyring`. No dependencies but those binaries. |

   It does no cryptography of ours: it hands a string to the platform and asks for it back.

2. **It is an optional peer.** A keystore under a passphrase needs none of it, and neither does a browser. It is loaded when `systemKeychain` is called, and a keystore that never calls it never loads native code. An application that wants the keychain installs the package.

3. **What it keeps is a key, not a passphrase**: 32 random bytes for each role of each keystore, under the account `<keystore>/<role>` of a service the application names. Nobody chooses it or types it.

4. **A failure says nothing of what the platform said.** A call that fails throws `KeystoreError` `no-keychain`, with words of its own. The platform's message is dropped: a secret was an argument of the call that failed.

5. **It is tested for real, on the three platforms, in CI.** The `keychain` job runs `test/keychain.real.test.ts` on Linux, macOS and Windows runners: a secret kept, given back, replaced and removed, and a keystore locked and opened again by a process that starts afresh. On Linux the job starts a Secret Service (GNOME Keyring, under `dbus-run-session`). A last step fails the job if the tests were skipped. The other tests use a stand-in, since the machines most tests run on have no keychain.

## What was checked

- **On Linux**, against GNOME Keyring 46 on Ubuntu 24.04: the two tests pass, three runs out of three from a machine with no keyring yet.
- **On macOS and Windows**, nothing yet. The job is written and has not run: it runs when the branch reaches GitHub. Until it has passed there, the adapter is untried on those two platforms, and the README says so.

## Consequences

- **A keystore under the keychain opens without a passphrase**, for whatever runs as the user while the keychain is unlocked. That is what a service wants, and it is all the protection there is: the keychain keeps keys from a copy of the disk and from other users, not from the user's own programs.
- **A server without a desktop session has no keychain.** `systemKeychain` loads, and its first call fails with `no-keychain`. Such a machine uses a passphrase from its secret store, or a key the platform injects.
- **A backup is not under the keychain.** It is sealed under a lock of its own (ADR-0017), which should be a passphrase: a key that only one machine's keychain holds is lost with the machine.
- **Native code runs in the process** of an application that chooses this lock. It comes from the registry as binaries built by the library's own CI.

## Alternatives

- **The platform's commands**: `security` on macOS, `secret-tool` on Linux, PowerShell on Windows. No dependency. A secret then passes through a command line or a pipe on its way, three programs must be found and trusted on the path, and each has its own way to fail.
- **`keytar`.** It was the usual choice, and its repository is archived.
- **No adapter, only the interface.** Every application would write the same forty lines, and none would be tested on three platforms.
