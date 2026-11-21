# Threat model: the `oip` command

`@oip/cli` is a mind at a terminal. It is a thin layer over the client ([client.md](client.md)) and the keystore ([keystore.md](keystore.md)), and everything in those models holds here. This model is about what the command adds: a directory, a terminal, a shell, and a network on the user's own machine. It follows STRIDE. [ADR-0026](../adr/0026-the-command.md) records the design.

## Assets

- **The mind's keys**, sealed in its directory.
- **The mind's own evidence**: the records it holds, and its record of when it first obtained each proof. A verdict on an old record rests on it (core 9.4).
- **What the person at the terminal is told**: who sent a packet, whether a record verifies, whom a Commitment binds.
- **The passphrases**: of the keys, and of a backup.
- **The choice of whom to believe**: the resolvers and indexers in `config.json`.

## Who can reach it

| Entry point                            | Caller                                    | Trusted with                                                                                             |
| -------------------------------------- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| The command line                       | The user, and the user's scripts          | Everything the mind can do, once its keys are unlocked                                                   |
| The environment                        | Whatever started the process              | `OIP_PASSPHRASE`, `OIP_BACKUP_PASSPHRASE`, `OIP_DIR`: it is as trusted as the user                       |
| The mind's directory                   | Whoever can write it                      | The mind's evidence and its choice of services. The keys are sealed, and cannot be read without the lock |
| A file named on the command line       | Anyone who wrote it                       | Nothing. It is parsed under the JSON profile and validated as anything from outside is                   |
| A packet, a profile, an indexer's word | Anyone                                    | Nothing. It is verified by the client, and shown as data                                                 |
| `network.json` of a local network      | Whoever can write the network's directory | Where three origins are reached on this machine, and nothing else                                        |
| The services of `oip demo`             | Any process on this machine               | Nothing more than any service: what they serve is verified                                               |

## Threats

### Spoofing

| Threat                                                                                    | What stops it                                                                                                                                                                          |
| ----------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A packet's text writes a line that looks like the command's own: another sender, a status | Every line printed has its control characters shown as escapes, so text cannot move the cursor or overwrite a line. A stranger's text is indented under the label that says what it is |
| Text hides what it says with the controls of bidirectional text                           | Those are escaped too, in lines and in JSON                                                                                                                                            |
| A record in a file claims a signer                                                        | `verify` checks each proof, fetches the signer's log from the resolvers, and says whose key made it and whether that key was the mind's then                                           |
| A service answers for an origin of the local network                                      | A route is `http://127.0.0.1:<port>` for an HTTPS origin, or it is refused. What a service there serves is verified like any other                                                     |
| `network.json` is written to send the mind's requests elsewhere                           | A route that does not lead to `127.0.0.1` is refused, whoever wrote it. The requests of a mind that names real origins have no route                                                   |

### Tampering

| Threat                                                                               | What stops it                                                                                                                                            |
| ------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A file in `records/` is changed                                                      | A record is validated and its proofs verified each time it is held again. One that is no record is passed over                                           |
| A time in `records/` is moved earlier, so that a proof seems to predate a revocation | Not stopped: see below. The directory is the user's alone (mode 0700), and the times are the mind's own evidence, as its memory is                       |
| A time in `records/` is set in the future                                            | The client does not believe a time later than the present: the proof is first seen now                                                                   |
| A file in `inbox/` is changed                                                        | A packet read back is validated, and must be the packet its name says. It is shown as what was kept, and is evidence of nothing by being there           |
| A file given to a command names a file to read or write elsewhere                    | A file holds JSON and nothing the command acts on. Records are kept under their content IDs, which are checked to be content IDs before they name a file |
| A backup file is changed                                                             | A backup is sealed and authenticated by the keystore. One that does not open is refused, and the directory that was to take it is left as it was         |

### Repudiation

| Threat                                    | What stops it                                                                                                                 |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| A mind denies what a command signed       | Every record is signed by the mind's key and kept in `records/`. A Commitment the other party signed is kept with both proofs |
| A person does not know what a command did | Each command says what it signed, by its content ID, where it went, and which services took it                                |

### Information disclosure

| Threat                                                                 | What stops it                                                                                                                                                            |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| A passphrase is seen in the process list or the shell's history        | No option takes one. It is read from the environment or typed, and what is typed is not shown                                                                            |
| A passphrase or a private key is printed, logged or put in an error    | The command never holds a private key: the keystore signs. A passphrase goes to the keystore's lock and nowhere else. Tests look for it in everything the command writes |
| Another user of the machine reads the keys, the records or the packets | The directory and its files are the owner's alone. `doctor` warns when the directory is open to others                                                                   |
| A backup is read                                                       | It is sealed under a passphrase of its own, and written for its owner alone                                                                                              |
| `--json` or `--get` gives a script more than the lines show            | Both print the same answer, which holds nothing secret                                                                                                                   |
| The services of `oip demo` are reached from another machine            | They listen on `127.0.0.1` alone                                                                                                                                         |

### Denial of service

| Threat                                                  | What stops it                                                                                                                                   |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| A file given to a command is enormous, or deeply nested | A file is read up to 16 MiB, and parsed under the limits of core Section 1                                                                      |
| A packet's text fills the terminal                      | A text is shown up to 40 lines, and `--json` has the rest                                                                                       |
| A service does not answer                               | The client bounds every answer in size and in time. `doctor` says which services do not answer                                                  |
| Two commands run at once for one mind                   | Every write to the keystore and the memory names the version it replaces. The second command is told, and nothing is signed twice for one place |

### Elevation of privilege

| Threat                                        | What stops it                                                                                                                                                |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| What a packet says is taken as an instruction | Nothing a packet carries is acted on (Layer 1, 12.5). Its records are held, to be judged when asked. No command signs, sends or pays because of what arrived |
| A record held from a stranger binds the mind  | A record binds whoever signed it. The mind signs only what a command was told to sign: `commit <id>` names the Commitment, and the person has read it        |
| A delegate signs beyond what it was granted   | `status` and `verify` judge a chain of delegations as the client does, and say for whom a record counts                                                      |
| The shell completions run something           | They are a list of words, written from the commands' own names and options, and never from anything that came from outside                                   |

## Left open

- **Whoever can write the mind's directory can date a proof.** The times in `records/` are the mind's own evidence that a proof existed before a delegation expired or was revoked. Moved earlier by someone else, they would make a late signature count. The directory is the user's alone, as the keystore and the client's memory are. Evidence that needs no trust in a file is an anchored feed (Layer 1, Section 10), which a later milestone carries.
- **A packet can be lost between the mailbox and `inbox/`**, if the process is killed between reading and keeping. Its sender still holds it, and keeps it to send again if it never arrived. Closing this needs the client to confirm a packet to the mailbox only once the application has kept it.
- **`OIP_PASSPHRASE` in the environment is readable by the user's other processes.** Typing the passphrase, or the keychain, avoids it.
- **The local network is for trying and testing.** Its services are generous with requests and keep what they are given in a directory of the user's.
- **A person reads what they sign.** The command shows a Commitment before it is signed only if asked (`status`, `verify`). It cannot make anyone read.
