# @oip/local

A mind of the [Open Intelligence Protocol](../../README.md) on one machine: its directory, the lock of its keys, and what it keeps between the runs of a program.

[`@oip/client`](../client/README.md) holds a mind while its process lives. A program that runs for a moment and stops needs the mind to be somewhere in between. The `oip` command ([`@oip/cli`](../cli/README.md)) is such a program, and so is a server that a host starts when it wants one. This package is what they share ([ADR-0027](../../docs/adr/0027-a-mind-on-one-machine.md)).

- **One directory is one mind.** It holds `config.json`, the sealed keys, the client's memory, the records the mind holds and the packets it has received, each readable by its owner alone.
- **A record is kept with when its proofs first came.** That is the mind's own evidence that a proof existed then (core 9.4), and for most proofs the only evidence there is. A program that holds a record again without it would judge the record as if it had only then arrived.
- **A passphrase is read from the environment or typed, and never taken as an argument.**
- **It adds no dependency.**

## An example

```ts
import { directoryOf, type Machine, withMind } from "@oip/local";

/** Says what the mind of this machine wants, and keeps the Intent it signed. */
export async function want(machine: Machine, what: string): Promise<string> {
  // `~/.oip`, or what `OIP_DIR` names.
  const where = { edges: machine, dir: directoryOf(undefined, machine) };
  // The keys are unlocked for the work, the records the mind holds are held again before it,
  // and written down after it with when each proof first came. Then the keys are locked.
  return withMind(where, async ({ mind }) => {
    const intent = await mind.intent({ want: what });
    return intent.want;
  });
}
```

## What it exports

| Export                                                                                                 |                                                                                                                                                                               |
| ------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Machine`, `Where`                                                                                     | What a program reaches outside itself, and where it works: the environment, the keychain, the network, the clock, and the directory of a mind                                 |
| `Home`, `Config`, `directoryOf`                                                                        | A mind's directory, what `config.json` holds, and which directory a program works in                                                                                          |
| `openMind`, `withMind`, `Opened`, `keepRecords`, `optionsOf`, `lookupOptions`, `fetchOf`, `servicesOf` | Opens the mind of a directory, for one piece of work or until it is closed, and how its services are asked                                                                    |
| `lockOf`, `backupLockOf`, `passphraseOf`                                                               | What opens the keys: a passphrase from `OIP_PASSPHRASE` or typed, or a key in the keychain. A backup has a passphrase of its own                                              |
| `Kept`, `KeptRecords`, `KeptRecord`                                                                    | What the directory keeps, in files named by content ID: records, each with when its proofs first came                                                                         |
| `KeptPacket`, `keptOf`, `keptFrom`                                                                     | A packet that was received, as the directory keeps it                                                                                                                         |
| `recordOf`, `refOf`, `statusOf`                                                                        | A record named by the ID of one the mind holds or by a file, how another record refers to it, and how it stands                                                               |
| `readJson`, `readObject`, `MAX_FILE_BYTES`                                                             | A file of JSON, read under the profile of core Section 1                                                                                                                      |
| `readNetwork`, `NetworkFile`, `NETWORK_FILE`, `isLocal`, `routed`, `routedSocket`                      | The network `oip demo` runs on this machine: what it says of itself, and how a client reaches it                                                                              |
| `guardedReach`                                                                                         | How a mind that runs unattended asks: under a guard against requests to this machine and the network behind it, but for what a route carried                                  |
| `printable`, `printableJson`, `quoted`, `counted`                                                      | Text made safe to show: every character a terminal would act on is printed as its escape                                                                                      |
| `recordText`, `jsonText`, `asciiJson`                                                                  | A stranger's text made what a record holds (core 1.1), a value as JSON text that a record holds, and a stranger's words quoted in ASCII to set inside a sentence of one's own |
| `UsageError`                                                                                           | What was asked cannot be done as it was asked. The message says what to do                                                                                                    |
| `Store`, `fileNameOf`                                                                                  | What a program remembers between its runs: small JSON files by key, each named by a digest of its key, since a key may be any text                                            |
| `Arrivals`                                                                                             | The packets that wait for a mind: each is written down before the client notes that it arrived, and waits until the program is done with it                                   |
| `hold`, `Hold`, `HOLD_BEAT_MS`, `HOLD_STALE_MS`                                                        | One process at a time for a piece of work in a directory: a file that its holder touches, and that another takes over once it is left behind                                  |
| `withBridged`, `Custody`, `BridgeBlock`, `BridgedSystem`                                               | The mind a gateway makes for a system outside the network (Layer 0, 1.2): made once, named by an entry of the gateway's feed                                                  |

## Notes

- **Keep the directory where nobody else can write.** Whoever can write `records/` can date a proof before a revocation, and whoever can write `config.json` chooses the resolvers the mind believes. The command's [threat model](../../docs/threat-models/cli.md) covers the directory.
- **A file in `records/` that is no record is passed over**, and a time there that is later than the present is not believed.
- **A route leads to `127.0.0.1` and nowhere else.** `readNetwork` refuses a file that says otherwise, whoever wrote it. A mind whose services are real ones has no route.
- **Records are written when `withMind` ends**, whether the work came to an end or failed part of the way: what the mind signed, it signed. A program that keeps a mind open (`openMind`) calls `keepRecords` when it has something to keep.
