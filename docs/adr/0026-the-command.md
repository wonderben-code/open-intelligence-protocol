# ADR-0026: The `oip` command

**Status:** Accepted, 20 November 2026 (M7).

## Context

M7 puts a mind in a terminal ([BUILD.md](../../BUILD.md), M7). The command is the first thing a newcomer runs, and the five-minute promise (BUILD.md, Section 1.2) is measured through it. It has to work before anyone has chosen a resolver, be safe for a person who pastes what they are shown, and be testable without a network or a terminal.

A command is one short run. The client it is built on was written for a process that stays up: it holds records, and its own record of when it first saw them, in the process.

## Decision

1. **Arguments are read with Node's `parseArgs`.** There is no dependency for it. A command is a value: its name, its options, its notes, an example, and what it does. The help, the shell completions and the README's table are written from those values, and tests hold them together.

2. **Everything the command reaches outside itself is behind one interface**, `Edges`: the environment, the terminal, the network, the clock, the keychain, and the signal to stop. `run(argv, edges)` is the whole command. A test gives its own edges and runs a command in its own process, against real services on ports of the machine. One test runs the command as a process of its own, for its terminal, its signals and its exit.

3. **A command answers twice**: lines for a person, and a value for `--json`. `--get <member>` prints one member of that value alone, so that a shell can take an address or an ID without a JSON tool. An answer of no, such as a record that does not verify, is an answer and ends the run with 1, as what could not be done does. What was asked wrongly ends it with 2.

4. **One directory is one mind**: `~/.oip`, or what `--dir` or `OIP_DIR` names. It holds `config.json`, the keystore, the client's memory, the records the mind holds and the packets it has received, each readable by its owner alone.

5. **A passphrase is never an option.** It is read from `OIP_PASSPHRASE` or typed where there is a terminal, since what is typed on a command line is shown to every user of the machine and kept in the shell's history. A backup has a passphrase of its own, from `OIP_BACKUP_PASSPHRASE` or typed. `--keychain` seals the keys with a key the machine's keychain keeps, and asks for nothing.

6. **A record is kept with when its proofs first came.** At the end of every command that opens the mind, each record it holds is written to `records/` with the client's own record of when it first obtained each proof (`Mind.sightings`). The next command holds it again with that (`Mind.hold`). That record is evidence under core 9.4, and for most proofs the only evidence. Without it every proof would be first seen when each command ran, and a signature made under a delegation that has since expired or been revoked would stop counting from one command to the next. Writing the directory needed the client to give that record out and take it back, which it did not until now.

7. **A packet is kept before it is shown.** A mailbox gives a packet once. `oip inbox` writes each to `inbox/`, with its sender and the evaluation time of the sender's signature, and then prints it.

8. **Everything printed passes one filter.** Much of what a command shows is a stranger's words. A terminal obeys control characters, so every C0 and C1 control, DEL, the line and paragraph separators and the controls of bidirectional text are printed as their escapes, in lines and in JSON alike. In JSON the escape is the same string to a parser. A command cannot print past the filter: it returns its lines, and `run` prints them.

9. **`oip demo` runs a network on this machine**: a resolver, an open host and an indexer with a mind of its own, each started through the service's own `start` on a port the system gives. The services have the origins `https://resolver.oip.localhost`, `https://host.oip.localhost` and `https://indexer.oip.localhost`, and every record and signed request names them as it would a real origin. The command carries a request for one of those origins to `http://127.0.0.1:<port>`, as `network.json` in the network's directory says. The client is unchanged: it is given a `fetch` and a socket that do the carrying.

10. **A route is the user's own setting and leads to this machine alone.** `config.json` names the directory of a network, and the routes are read from there each time, since the ports change when the network starts again. A route that is not `http://127.0.0.1:<port>` for an HTTPS origin is refused. Nothing a service or a record says is ever made a route.

11. **`verify` explains.** It prints one line for each thing it checked, with the clause the verdict rests on, in one of four states: it holds, it fails, the answer is no with nothing wrong (a party that has not signed), or it could not be judged (nobody to ask). Only a failure ends the run with 1.

12. **The newcomer run follows the README.** `scripts/newcomer.ts` installs and builds the repository, starts `oip demo`, and runs the lines between the README's markers in a shell, in a home directory that holds nothing. CI fails if a line fails, if the Commitment is not accepted and verified, or if all of it takes five minutes.

## Consequences

- **A mind can be tried with nothing chosen and nothing deployed.** The path of the README needs Node.js and the repository.
- **The local network is not the protocol over plain HTTP.** Records name HTTPS origins, and the routes exist only in the command. A client that is not the command cannot reach the network without being given the same carrying.
- **The directory is the mind.** Whoever can write `records/` can date a proof, and whoever can write `config.json` chooses the resolvers the mind believes. The threat model says so ([cli.md](../threat-models/cli.md)).
- **A packet can be lost between the mailbox and `inbox/`** if the process is killed between the two. Its sender still holds it. Closing this needs the client to confirm a packet to the mailbox only after the application has kept it.
- **Sessions, retiring a mind and drafting a change to a collective are not in the command.** The client does them, and a later command can.
- **The client gained three things the command needed**: `Mind.sightings` and a second argument of `Mind.hold`; `NewMind.parents`, so that `oip fork` makes a child that names its parent; and the submission of a mind's own Offers and Intents to its indexers, without which `oip find --kind offer` found nothing published through the client.

## Alternatives

- **An argument-parsing library** would give subcommands and help for free. The command needs little of it, and each dependency is one more thing to audit (BUILD.md, Section 2).
- **Plain HTTP origins for the local network** would need the client to accept them. The client speaks HTTPS and refuses anything else, and an exception for `localhost` in the library is an exception every application inherits.
- **A self-signed certificate for the local network** keeps HTTPS all the way, at the price of a certificate authority on the newcomer's machine. That is too much to ask for a first five minutes, and a habit not to teach.
- **Keeping the mind open in a daemon** would keep the client's evidence in one process. It adds a second program to start, stop and secure. Writing the evidence down is what any application that restarts must do.
