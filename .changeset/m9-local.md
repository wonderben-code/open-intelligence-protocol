---
"@oip/local": minor
---

What every gateway does, in one place (Layer 0, Section 1).

- `withBridged(where, dir, system, work)` makes the mind a gateway holds for a system outside the network, or goes on with one an earlier run made: its `Genesis` names the gateway, an entry of the gateway's feed names that `Genesis`, and the work is given the `oip.bridge` block for the mind's profile (1.2).
- `Arrivals` gives the packets that wait for a mind. A packet is written down as soon as it is read from the mailbox, and waits until the program says it is done with it.
- `Store` keeps small JSON values by key, in files named by a digest of the key, and `fileNameOf` gives such a name for any text.
- `hold(dir, name, what)` lets one process at a time do a piece of work in a directory. A hold is a file its holder touches every few seconds, and one that nobody has touched for 30 seconds is taken over.
- `guardedReach(guarded)` is how a gateway's minds ask: under a guard, but for a network on this machine, which is reached by its routes.
- `recordText` makes a stranger's text one that a record holds, and cuts it between characters. `asciiJson` quotes a stranger's words as a string of JSON in ASCII, for a sentence of the program's own. `jsonText` writes a value as JSON text that a record holds.
- `Store.put` has what it wrote on the disk when it returns. `Store.has` says whether a file is kept under a key, readable or not. A `.partial` file that a stop left behind is cleared.
- `Arrivals` writes a packet down before the client notes that it has it, and `Arrivals.has` says whether a packet waits though it could not be read just now.
- `withBridged` refuses a directory whose `Genesis` names another gateway, protocol or endpoint than it was asked for.

The A2A gateway had the first three, and the gateway for MCP servers needs them all.
