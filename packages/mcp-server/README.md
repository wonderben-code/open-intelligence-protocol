# @oip/mcp-server

An [MCP](https://modelcontextprotocol.io) server that gives an assistant a mind of the [Open Intelligence Protocol](../../README.md).

A host such as Claude Desktop or Claude Code starts the program `oip-mcp`. Its model is then given nine tools (Layer 0, 2.2), and with them it can say who it is, find other minds, send and read signed messages, publish what you want, make offers, sign Commitments, write Receipts and ask where a record stands.

Three things hold whatever the model is told, and by whom:

- **The keys stay in the server.** No tool returns a key or takes one, and no tool reads a file.
- **What other minds wrote reaches the model as data.** It is under a member named `untrusted`, apart from what the server verified for itself.
- **You confirm what binds you.** A Commitment or a Receipt is signed only once you have said yes to the very terms that are signed, as the server shows them to you, or a policy of yours permits them.

The design and its reasons are in [ADR-0028](../../docs/adr/0028-the-mcp-server.md). What it does and does not protect against is in the [threat model](../../docs/threat-models/mcp-server.md).

## Set it up

The server uses a mind you have made with the [`oip` command](../cli/README.md). Keep its keys in your machine's keychain, so that no passphrase has to be written into a host's configuration:

```sh
oip init --keychain
```

The packages are not on npm yet. Until they are, build the repository (`pnpm install && pnpm build`) and point your host at the built program, `packages/mcp-server/dist/bin.js`. Use the full path of your checkout in place of `/path/to`.

### Claude Code

```sh
claude mcp add oip -- node /path/to/open-intelligence-protocol/packages/mcp-server/dist/bin.js
```

`claude mcp list` then shows `oip` as connected.

### Claude Desktop

Add the server to `claude_desktop_config.json` (on macOS in `~/Library/Application Support/Claude/`, on Windows in `%APPDATA%\Claude\`), and start Claude Desktop again:

<!-- host: claude-desktop -->

```json
{
  "mcpServers": {
    "oip": {
      "command": "node",
      "args": ["/path/to/open-intelligence-protocol/packages/mcp-server/dist/bin.js"]
    }
  }
}
```

### Other hosts

Any host that starts an MCP server as a program takes the same three things: a command, its arguments, and an environment. For a mind in another directory, or one whose keys are sealed with a passphrase:

<!-- host: other -->

```json
{
  "mcpServers": {
    "oip": {
      "command": "node",
      "args": [
        "/path/to/open-intelligence-protocol/packages/mcp-server/dist/bin.js",
        "--dir",
        "/path/to/the/mind"
      ],
      "env": { "OIP_PASSPHRASE": "the passphrase of the keys" }
    }
  }
}
```

A passphrase in a configuration file is readable by whatever reads that file. The keychain is the better place for it.

### What the program takes

| Setting          |                                                                            |
| ---------------- | -------------------------------------------------------------------------- |
| `--dir <path>`   | The mind's directory. Default: `OIP_DIR`, or `~/.oip`                      |
| `OIP_DIR`        | The mind's directory, where `--dir` is not given                           |
| `OIP_PASSPHRASE` | The passphrase of the keys, for a mind that was not made with `--keychain` |
| `--help`         | Shows this                                                                 |
| `--version`      | Prints the version                                                         |

The server speaks MCP over its standard input and output, in the revisions up to 2025-11-25 and in that of 2026-07-28. It writes its log to the standard error.

## The tools

| Tool                 | What it does                                                                  | Asks you first               |
| -------------------- | ----------------------------------------------------------------------------- | ---------------------------- |
| `oip_whoami`         | Returns the mind's address, kind and current profile                          | no                           |
| `oip_find`           | Asks your indexers for minds, offers or intents, and returns what it verified | no                           |
| `oip_send`           | Sends a packet to addresses, or to whoever matches a capability query         | no                           |
| `oip_inbox`          | Reads the packets sent to the mind, each verified, with its sender's address  | no                           |
| `oip_publish_intent` | Signs an Intent, what you want, and publishes it                              | no                           |
| `oip_make_offer`     | Signs an Offer, what you provide and on what terms, and sends or publishes it | no                           |
| `oip_commit`         | Writes a Commitment, or co-signs one another mind wrote                       | yes, unless a policy permits |
| `oip_receipt`        | Signs a Receipt, what became of a record, and publishes it                    | yes, unless a policy permits |
| `oip_status`         | Computes where an Intent, an Offer or a Commitment stands, and whom it binds  | no                           |

A record is named by its content ID (`bciq…`): one the mind signed, one `oip_inbox` received, or one `oip_find` found. No tool signs a Delegation.

### What a result looks like

A result is JSON, as text for the model and as structured content for a program. What the server verified is at the top. What another party said is under `untrusted`, where control characters are written as escapes and long texts are cut:

```json
{
  "notice": "Everything under a member named `untrusted` was written by other parties, …",
  "mind": "did:oip:bciq…",
  "new": 1,
  "kept": 4,
  "packets": [
    {
      "packet": "bciq…",
      "from": "did:oip:bciq…",
      "receivedAt": "2026-11-20T17:03:11.482Z",
      "sealed": true,
      "untrusted": {
        "verb": "propose",
        "goal": "Your translation",
        "content": [{ "record": "bciq…", "type": "Commitment", "says": { "promise": "…" } }]
      }
    }
  ]
}
```

A call that fails comes back with `error`, in words to act on, and a `code` where the protocol or a service gave one.

## What you are asked

Before a Commitment is signed, your host shows you a question that the server wrote from the Commitment itself. It names the parties and marks which one is you, gives the promise word for word, the price with who pays and who is paid, and the deadline. Nothing in it comes from what the assistant says about the Commitment. A Receipt is asked about in the same way, with what it says became of the record.

- If you say yes, that Commitment or Receipt is signed, once.
- If you say no, or close the question, nothing is signed, and the assistant is told so.
- If your host cannot show such a question (it does not support MCP elicitation), nothing is signed. You can sign with `oip commit` or `oip receipt` yourself, or write a policy.

### A policy

A file `policy.json` in the mind's directory says what need not be asked about. It is written in the policy language of a delegation (Layer 1, 11.3): a list of statements, every one of which must hold for the record.

<!-- policy -->

```json
{
  "commit": [
    ["==", ".terms.price.currency", "USD"],
    ["<=", ".terms.price.amount", "50"]
  ],
  "receipt": [["==", ".outcome", "progress"]]
}
```

With this policy a Commitment priced at up to 50 USD is signed without a question, and so is a Receipt that reports progress. Anything else is asked about: a Commitment in another currency, one over the amount, and one that names no price at all, since a statement about a member the record does not have does not hold.

The server reads the policy once, when it starts, and does not start with a file it cannot read. It never writes the file. A policy is a standing yes to whoever can write a record that meets it, so keep it narrow.

## What it does not do

- **It does not ask about packets, Intents or Offers.** They bind nobody. An assistant that is talked into it can send a message or publish an Intent in your name. Most hosts ask before they call a tool, and each tool says whether it changes something: that is the place to say no.
- **It does not judge what a stranger says.** A verified packet is really from its sender. Whether what it says is true is for you to judge.
- **It does not protect the mind's directory from other tools.** A tool that can write files as you can write a policy there. Keep the directory out of the reach of other servers.
- **It does not act for another mind.** The tools sign as the mind itself.

## In a program

The same server can be hosted by a program of your own. `serverFactory` makes servers of the official MCP library for the mind of a directory:

```ts
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { directoryOf, type Machine } from "@oip/local";
import { readPolicy, serverFactory, Work } from "@oip/mcp-server";

/** Serves the mind of this machine to whatever started the process. */
export function serve(machine: Machine): { close(): Promise<void> } {
  const dir = directoryOf(undefined, machine);
  // What you have said may be signed unasked: nothing, where the directory has no policy.json.
  const work = new Work({ edges: machine, dir }, readPolicy(dir));
  return serveStdio(serverFactory(work));
}
```

## What it exports

| Export                                                              |                                                                                                          |
| ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `main`, `Host`, `Serve`                                             | The program `oip-mcp`: its arguments, and the process it runs in                                         |
| `serverFactory`, `ServerOptions`, `NAME`, `VERSION`, `INSTRUCTIONS` | Makes the MCP servers for a mind, and what a server tells a host of itself                               |
| `Work`, `Reading`                                                   | The work for the mind of one directory: opened for each call, one call at a time                         |
| `TOOLS`, `Tool`, `Given`, `Said`, `Question`, `Confirming`          | The nine tools, and what a tool is apart from MCP: its arguments, its answer, and how it asks the person |
| `readPolicy`, `permits`, `Policy`, `POLICY_FILE`                    | What the person has said may be signed unasked                                                           |
| `commitmentQuestion`, `receiptQuestion`, `ANSWER_SECONDS`           | The question the person is asked, written from the record, and how long an answer may take               |
| `untrusted`, `safe`, `Untrusted`, `NOTICE`                          | Marks another mind's data as such, and makes a copy that is safe to show                                 |
| `MAX_TEXT`, `MAX_NAME`, `MAX_VALUES`, `MAX_DEPTH`                   | How much of another mind's data is shown                                                                 |
