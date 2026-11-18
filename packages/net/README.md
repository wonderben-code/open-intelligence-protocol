# @oip/net

The Mind Network of the [Open Intelligence Protocol](../../README.md): feeds and checkpoints, locations and profiles, packets, sessions and sealing (Layer 1, Sections 10 and 12 to 16).

The package is pure. It does no I/O and never reads the clock: the time and the evidence are parameters.

It is being built in milestone M4, one part at a time. What is here is finished and tested; the rest of the list in [BUILD.md](../../BUILD.md) follows.

## What it exports

| Export                             | What it does                                                                                                                                  |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `merkleTreeHash`, `checkpointRoot` | The Merkle Tree Hash of RFC 9162, 2.1.1, and the `root` a checkpoint signs over the entries of a feed, from their content IDs (Layer 1, 10.5) |
