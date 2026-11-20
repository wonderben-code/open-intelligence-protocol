# ADR-0027: A mind on one machine

**Status:** Accepted, 20 November 2026 (M8).

## Context

The `oip` command ([ADR-0026](0026-the-command.md)) keeps a mind in a directory: its sealed keys, the client's memory, the records it holds with when each proof first came, and the packets it has received. The MCP server of M8 gives an MCP host the same mind, from the same directory: a person makes a mind with `oip init` and then lets an assistant act as it.

The command and the server are both tools, on the top layer of the build ([BUILD.md](../../BUILD.md), Section 3.1), and a package may import only packages below it. The command also brings the three services with it, for `oip demo`. A server that holds a mind's keys under a host should load no more than it needs.

## Decision

1. **What both need is a package of its own, `@oip/local`, one layer above the client.** It holds the mind's directory and its configuration, the lock of its keys, opening the mind for one piece of work, the records and packets the directory keeps, reading a record from a file, the client's side of a network that runs on this machine, and text made safe to show.

2. **It was taken out of the command as it stood.** No behaviour of the command changed, and its tests are the same tests. What is a function of its inputs has tests of its own in the package, and the rest is tested there against real services on ports of the machine, started as `oip demo` starts them.

3. **The command keeps what is the command's**: its arguments, its help, what it prints, the commands themselves, and the starting of the local network's services.

4. **It is owed by M7** in the conformance plan, since it is the command's own code.

## Consequences

- **The MCP server depends on the client, the keystore and this package**, and on none of the services.
- **A third program of the same kind has nothing to copy.** The A2A bridge of M9 will need the same directory.
- **The package's interface is public**, and has an API report and a place in the API reference like any other.

## Alternatives

- **Let the MCP server import the command.** It would load the services with it, and put one tool beneath another on a layer where neither is beneath the other.
- **Make the MCP server a subcommand of `oip`.** One program is simpler to install. A host starts an MCP server unattended and gives it a mind's keys: that process should be small enough to read, and the package boundary is what keeps it so. The command can still start it later, as a convenience.
- **Put the directory in the client.** The client runs in a browser and does no I/O of its own choosing: where a mind is kept is the application's to say.
