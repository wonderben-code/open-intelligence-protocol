# @oip/cli

`oip`: a mind of the [Open Intelligence Protocol](../../README.md) from a terminal. It makes a mind, publishes what it is, finds others, writes to them, and signs what binds it. Every command is a thin layer over [`@oip/client`](../client/README.md), which does the verifying.

- **Every command says what it did for a person, and with `--json` for a program.** `--help` shows a command's options and an example.
- **No private key is ever printed.** Keys are sealed in the mind's directory, under a passphrase or the keychain of the machine. They leave it in one way: a backup, which is sealed too.
- **What a stranger wrote is shown as data.** A packet's text, a profile's name and an indexer's reason are printed with every control character made visible, so that nothing in them can move the cursor or rewrite a line of the terminal (Layer 1, 12.5).
- **It adds one dependency to none.** Arguments are read with Node's own `parseArgs` ([ADR-0026](../../docs/adr/0026-the-command.md)).

## Five minutes: two minds and a promise

You need Node.js 24 or later. Until the package is on npm, build it from the repository:

```sh
git clone https://github.com/wonderben-code/open-intelligence-protocol
cd open-intelligence-protocol
pnpm install
pnpm build
alias oip="node $PWD/packages/cli/dist/bin.js"
```

A mind needs a resolver to publish its identity to, a host to take its packets, and an indexer to be found at. Until you have chosen yours, `oip demo` runs one of each on this machine. Leave it running in a terminal of its own:

<!-- newcomer: the network -->

```sh
oip demo
```

In another terminal, make a mind, say what it can do, and let a second mind find it and make a promise with it:

<!-- newcomer: the path -->

```sh
export OIP_PASSPHRASE="correct horse battery staple"

# A mind, and what it can do.
oip init --local
oip publish profile --name Ada --capability translate="Translates legal texts" --tag domain:legal

# A second mind, in a directory of its own, finds the first by what it can do.
oip init --local --kind human --dir ~/.oip-amina
WHO=$(oip find --tag domain:legal --dir ~/.oip-amina --get found.0.mind)

# It writes a promise between them, signs it, and sends it.
DEAL=$(oip commit --dir ~/.oip-amina --debtor "$WHO" --creditor me \
  --promise "Ada will translate the lease by Friday." --send-to "$WHO" --get id)

# The first mind reads its mailbox, signs the promise too, and sends it back.
oip inbox
oip commit "$DEAL" --send-to "$(oip show --dir ~/.oip-amina --get mind)"

# Both have signed: it is accepted, and anyone who holds it can check that.
oip inbox --dir ~/.oip-amina
oip status "$DEAL" --dir ~/.oip-amina
oip verify "$DEAL" --dir ~/.oip-amina
```

<!-- newcomer: end -->

The last two commands print `accepted`, and one line for every check that was made, each with the clause of the specification it rests on.

`OIP_PASSPHRASE` is there so that the lines can be pasted. Leave it unset and `oip` asks for the passphrase, without showing it. [`scripts/newcomer.ts`](../../scripts/newcomer.ts) runs these lines as they stand, in a fresh home directory, and CI holds the whole of it, from `pnpm install`, to five minutes.

## Commands

| Command                        | What it does                                                                            |
| ------------------------------ | --------------------------------------------------------------------------------------- |
| `oip init`                     | Makes a mind: its keys, sealed in its directory, and its first event with its resolvers |
| `oip show`                     | Shows the mind of this directory, as its resolvers have it                              |
| `oip rotate`                   | Rotates the mind's control keys: the next are revealed, and new ones committed to       |
| `oip add-key`                  | Makes a new key of everyday work, and adds it to the mind's keys                        |
| `oip revoke-key <key>`         | Takes a key of everyday work from the mind's keys for good, and destroys it here        |
| `oip fork [directory]`         | Makes a child of this mind in a directory of its own, and acknowledges it               |
| `oip publish profile`          | Publishes what the mind is and can do: its profile, which others find it by             |
| `oip publish location`         | Publishes where the mind takes packets, and whether it takes them now                   |
| `oip publish record <file>`    | Puts a record on the mind's public feed, at its hosts                                   |
| `oip resolve <address>`        | Resolves any mind by its address: fetches its log from the resolvers, and verifies it   |
| `oip find`                     | Finds minds by what they can do: asks the indexers, and verifies what they name         |
| `oip send <address>...`        | Sends a packet to one mind or several: signed, and sealed to each                       |
| `oip inbox`                    | Reads the mind's mailboxes: the packets that arrived, each verified, and kept           |
| `oip intent`                   | Says what the mind wants: signs an Intent                                               |
| `oip offer`                    | Says what the mind provides, and on what terms: signs an Offer                          |
| `oip commit [commitment]`      | Makes a promise between minds: writes a Commitment, or signs one another wrote          |
| `oip receipt <record>`         | Says what became of a record, usually a Commitment: signs a Receipt                     |
| `oip status <record>`          | Says where a record stands: its status, and whom it binds                               |
| `oip delegate <delegate>`      | Lets another mind sign for this one, within limits: signs a Delegation                  |
| `oip revoke <delegation>`      | Takes a delegation back: signs a Revocation, and puts it on the mind's feed             |
| `oip collective create`        | Founds a collective with other minds: drafts its first event, and signs it as a member  |
| `oip collective sign <record>` | Signs, as a member of a collective, one of its identity events or a record in its name  |
| `oip verify <what>`            | Verifies a record, a log, a bundle or a mind, and says why of every verdict             |
| `oip keys backup <file>`       | Writes the mind's keys to a file, sealed with a passphrase of its own                   |
| `oip keys restore <file>`      | Makes the mind's directory again from a backup of its keys                              |
| `oip doctor`                   | Looks at the mind's directory and its services, and says what is well and what is not   |
| `oip demo`                     | Runs a network on this machine: a resolver, a host and an indexer, until it is stopped  |
| `oip completions <shell>`      | Prints a script that teaches a shell the commands and their options                     |

`oip <command> --help` shows the options of each, and an example.

## What every command takes

| Option           |                                                                                                       |
| ---------------- | ----------------------------------------------------------------------------------------------------- |
| `--dir <path>`   | The mind's directory. Default: `OIP_DIR`, or `.oip` in your home directory. One directory is one mind |
| `--json`         | Print the answer as JSON                                                                              |
| `--get <member>` | Print one member of that JSON alone, as `mind` or `found.0.mind`: for a script                        |
| `--help`         | Show the command's options and an example                                                             |
| `--version`      | Print the version                                                                                     |

A command ends with `0` if it did what was asked, `1` if it could not or the answer is no (a record that does not verify, a mind that cannot do its work), and `2` if it was asked wrongly. An error is one line on standard error, or with `--json` an object `{ "error": { "code", "message" } }` on standard output, where `code` is the problem's code (core 10.2), the transport's failure, or the keystore's reason.

A record is named by the content ID of one the mind holds, or by a file that holds it as JSON. `me` stands for the mind of the directory wherever an address is asked for.

## A mind's directory

|               |                                                                                                                           |
| ------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `config.json` | The resolvers the mind trusts, the indexers it asks, and what seals its keys. Yours to edit                               |
| `keys/`       | The keystore: every key, sealed ([`@oip/keystore`](../keystore/README.md))                                                |
| `memory/`     | What the client remembers of its own work: the position of its feed, the packets that wait to be sent again, its sessions |
| `records/`    | The records the mind holds, each with when its proofs first came                                                          |
| `inbox/`      | The packets it has received                                                                                               |

The directory and everything in it is readable by its owner alone.

- **A command is one short run, so what the mind holds is written down.** A record held at the end of one command is held again at the start of the next. With each is kept when the mind first obtained each of its proofs. That is evidence the proof existed then (core 9.4), and for most proofs the only evidence there is: a Commitment signed under a delegation that has since expired or been revoked still counts, because the mind can show it came before.
- **A mailbox gives a packet once.** `oip inbox` keeps each packet it reads under `inbox/` before it shows it, and `--all` shows them again.
- **Keep the directory where nobody else can write.** Whoever can write `records/` can date a proof before a revocation, and whoever can write `config.json` chooses the resolvers the mind believes.

## Passphrases and keys

- **The keys are sealed with a passphrase**, read from `OIP_PASSPHRASE` or typed where there is a terminal. It is never an option: what is typed on a command line is shown to every user of the machine, and kept in the shell's history.
- **Or with a key the machine's keychain keeps**: `oip init --keychain`. No passphrase is asked for then.
- **A backup has a passphrase of its own**, from `OIP_BACKUP_PASSPHRASE` or typed. `oip keys backup <file>` writes every key to one sealed file. Back up again after every change of the mind's identity (`rotate`, `add-key`, `revoke-key`, `fork`): each makes a control key the change after it will need, and if that key is lost the mind's identity can never change again. `oip doctor` says when no backup holds the keys as they are.
- **Reading asks for nothing.** `show`, `resolve`, `find`, `verify` and `doctor` unlock no key.

## The network on this machine

`oip demo` starts a resolver, a host that takes on any mind, and an indexer, each on a port of its own at `127.0.0.1`, and writes where they are to `network.json` in its directory (`~/.oip-demo`). A mind made with `--local` uses them.

The protocol speaks HTTPS, and names each service by its origin. The three have the origins `https://resolver.oip.localhost`, `https://host.oip.localhost` and `https://indexer.oip.localhost`, which every record and every signed request names as they would a real one. Only the last step differs: `oip` carries a request for one of these origins to the port `network.json` gives, over plain HTTP, and a request for any other origin goes where it says. A route leads to `127.0.0.1` and nowhere else, and is the user's own setting: nothing a service or a record says is ever made one.

It is for trying the protocol and for tests. Its services keep what they are given in its directory, and take it up again when it is started again. They are generous with requests, and reachable from this machine alone.

## What it does not do

- **Sessions** (Layer 1, Section 14) are not opened or sent in from the command. A packet of a session that arrives is shown, with its place in its sender's chain.
- **Nothing retires a mind**, and nothing drafts a change to a collective's log: `collective sign` signs one that a member drafted with the client.
- **A packet read from a mailbox is kept before it is shown, and not before it is read.** A process that is killed between the two has taken the packet from the mailbox and kept nothing of it. Its sender still holds it.
- **One command at a time works for a mind.** Two that change the same thing at once do not both succeed: the second says that what is stored was changed, and is run again.

## From another program

The package is a program first. What it exports is for running the same command inside another process, as its own tests do:

```ts
import { run, systemEdges } from "@oip/cli";

// The same as `oip show --json`, with this process's terminal, environment and home directory.
process.exitCode = await run(["show", "--json"], systemEdges(process));
```

| Export                                                                         |                                                                                                                                       |
| ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| `run`, `ExitCode`                                                              | Runs `oip` once, with the edges it is given, and answers with what the process should exit with                                       |
| `Edges`, `systemEdges`, `Process`                                              | What the command reaches outside itself: the environment, the terminal, the network, the clock and the keychain. A test gives its own |
| `COMMANDS`, `Command`, `Flag`, `Arguments`, `Context`, `Result`, `UsageError`  | The commands, and what one is: its name, its options, its help, and what it does                                                      |
| `GLOBAL_FLAGS`, `overview`, `helpOf`, `VERSION`                                | The options every command takes, the help, and the version                                                                            |
| `startNetwork`, `Network`, `NetworkOptions`, `LOCAL`, `routed`, `routedSocket` | The network `oip demo` runs, and how a client reaches it                                                                              |
| `Config`, `NetworkFile`                                                        | What `config.json` and `network.json` hold                                                                                            |
