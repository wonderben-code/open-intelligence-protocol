# ADR-0018: The keystore in a browser

**Status:** Accepted, 20 November 2026 (M6).

## Context

[ADR-0017](0017-the-keystore.md) left the storage for browsers to its own record. M6 asks for an IndexedDB adapter, and its acceptance runs the SDK in a browser.

A browser gives a page two places to keep bytes for good: `localStorage`, which holds strings and has no transactions, and IndexedDB. It also has WebCrypto, which can make a key that script cannot read out, and keep it in IndexedDB.

What a browser keeps for an origin, every script that runs in that origin can reach.

## Decision

1. **`indexedDbStorage` is a `KeyStorage` like the others.** It holds the same sealed documents as a directory does, under the same names, and a keystore over it is the same keystore. Nothing about a browser is known above the storage.

2. **A write is one transaction: read, compare, write.** IndexedDB runs the read-write transactions of one object store one after another, across every tab and worker of the origin. That is the promise a storage must keep (ADR-0017, decision 11): of two writers that read one version, the second finds the first's and is told `changed`.

3. **A write is reported when its transaction has completed**, not when its request succeeded. A browser may still abort the transaction after the last request, for want of room.

4. **Versions come from one count for the whole database**, kept in the same store and raised in the same transaction. A version is never given twice, to any document, so a writer that read a document before it was removed cannot write over one made later under the same name.

5. **What is read from the database is checked**, as what is read from a file is. Something kept under a document's name that is no document is `damaged`.

6. **The package is typed without the browser's library.** It writes out the six interfaces of IndexedDB it uses. With the library, a keystore's `Lock` would share its name with a type of the Web Locks API in every declaration, and the package would mean something else where there is no browser.

7. **The keys are sealed with the same cipher and the same locks as anywhere.** No WebCrypto key is used.

8. **It is tested against `fake-indexeddb`** (6.2.8, Apache-2.0, a development dependency of `@oip/keystore`), an implementation of IndexedDB in JavaScript that its authors run against the web platform tests. The tests every storage passes run against it, with two storages over one database as two tabs. A browser that fails is a stand-in written for the tests. The run in a real browser belongs to the acceptance of M6, with the SDK.

## Consequences

- **A keystore in a browser is as safe as its lock and its page.** A script that gets into the page can copy the sealed documents and guess at the passphrase elsewhere, at about a second and 128 MiB a guess on the owner's machine. It can also wait for the passphrase to be typed, or use a handle that is unlocked. A page that holds keys loads no script it does not control, and sets a content security policy that says so.
- **A browser may clear what an origin stored**, when it runs short of room or when its owner asks it to. A mind whose only keystore is in a browser needs a backup more than any other. `navigator.storage.persist()` asks the browser not to, and is the application's to call.
- **A private window keeps nothing** once it is closed.

## Alternatives

- **A WebCrypto key that script cannot read out, to wrap the documents.** A script in the page could not copy the keys and guess elsewhere. It could still use them, for as long as it runs in the page, and the documents would open on that browser profile alone: a backup would be the only way to another device. The protocol's own keys cannot be WebCrypto keys ([ADR-0002](0002-cryptography-libraries.md)), so they would be in the page's memory whenever they sign. It can be a kind of lock later: the header of a sealed document says which kind made its key.
- **`localStorage`.** It has no transactions: two tabs could both write, and one would write back a control key the other had destroyed.
- **The origin private file system.** It is newer and has files, and no transactions either.
