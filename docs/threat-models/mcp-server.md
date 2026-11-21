# Threat model: the MCP server

`@oip/mcp-server` gives an MCP host a mind. It is a layer over the client ([client.md](client.md)), the keystore ([keystore.md](keystore.md)) and the mind's directory ([cli.md](cli.md)), and everything in those models holds here. This model is about what the server adds: a model that calls tools, and that reads what strangers wrote.

The model is the new thing. It is not an attacker, and it is not trusted either. It holds the use of the mind for as long as the host runs, and anyone who can put text in front of it can try to direct that use: a packet cannot grant authority (Layer 1, 12.5), but its content can try to persuade a model to use authority the model already holds (Layer 0, 2.2). The server is written for a model that does whatever it reads.

## Assets

- **The mind's keys**, sealed in its directory, and unlocked in the server's process while a call is at work.
- **The person's signature on what binds them**: a Commitment, and their word on what became of one, a Receipt.
- **The use of the mind**: nobody but the person may hand it on.
- **What the model is told is a fact**: who sent a packet, whether a record is its author's, where a Commitment stands.
- **The passphrase**, where the keys are sealed with one.
- **What the person is asked**: the terms shown to them before they say yes.

## Who can reach it

| Entry point                                      | Caller                                          | Trusted with                                                                                                                          |
| ------------------------------------------------ | ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| The arguments and environment of `oip-mcp`       | The host, as the person configured it           | Which directory is served, and the passphrase. It is as trusted as the person                                                         |
| A call of a tool                                 | The model                                       | Reading; sending a packet; publishing an Intent or an Offer. Not a Commitment, not a Receipt, not a Delegation, not a file, not a key |
| An answer to the server's question               | The person, through the host                    | One signature on the very thing the question was about                                                                                |
| The state that comes back with an answer         | The host, and so anyone who can alter a message | Nothing. It is sealed by the server and refused if it was altered                                                                     |
| A packet, a profile, an Offer, an indexer's word | Anyone                                          | Nothing. It is verified by the client, and given to the model as data                                                                 |
| The detail of a service's refusal                | Any service                                     | Nothing. It is given as data                                                                                                          |
| `policy.json` in the mind's directory            | Whoever can write the directory                 | Which Commitments and Receipts are signed unasked                                                                                     |
| The mind's directory                             | Whoever can write it                            | As in [cli.md](cli.md): the mind's evidence and its choice of services                                                                |

## Threats

### Spoofing

| Threat                                                                                              | What stops it                                                                                                                                                                                                                              |
| --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| A packet's text claims to be from the user, the host, the server or a bank                          | `from` is the mind whose signature on the packet counted, set by the server. Everything the sender chose is under `untrusted` (`untrusted.ts`; `injection.test.ts`: every word of the other mind's is under `untrusted`, and nowhere else) |
| A text closes the JSON it is in, and writes members that look like the server's                     | A result is built as a value and serialised once. A text is a string in it, whatever it holds (`injection.test.ts`: what a model reads parses to the same value)                                                                           |
| A text hides or reorders what it says with control characters or the controls of bidirectional text | They are written as escapes in the copy under `untrusted`, and again in the text of every result (`untrusted.test.ts`, with a property over arbitrary values)                                                                              |
| The promise of a Commitment forges the lines of the question: a lower price, an earlier "Sign it?"  | The promise is on one line of the question, with its line breaks written as escapes. The price, the parties and the last line are the server's (`question.test.ts`; `injection.test.ts`: the person is shown what would be signed)         |
| The model describes a Commitment kindly to the person                                               | The question is written from the record. Nothing the model says of it is in the question, and no tool takes a description (`question.ts`)                                                                                                  |
| An indexer names a record its author never signed                                                   | `oip_find` returns what the client fetched from the author's hosts and verified, and lists the rest as refused (`corners.test.ts`)                                                                                                         |
| A message claims a Commitment is accepted, or fulfilled                                             | `oip_status` computes it from the records and the logs. Its description tells the model to ask it                                                                                                                                          |

### Tampering

| Threat                                                              | What stops it                                                                                                                                                                       |
| ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The call that brings a yes asks for other terms than the person saw | The state names the digest of what was asked about. A call that would sign something else is asked about anew (`mcp.test.ts`: no signature for a yes that was given to other terms) |
| The state is altered: another digest, a later expiry                | It is sealed with HMAC-SHA256 under a key the process made, and refused before a tool runs (`confirm.ts`; `mcp.test.ts`: a state that was altered, or that another server made)     |
| A yes is sent twice, or after a no                                  | A state is taken once. Sent again, the call is asked about anew (`mcp.test.ts`: one signature for one yes; no signature for a no sent on as a yes)                                  |
| A call brings an answer where no question was put                   | Without a state of this server's the answer is not read (`mcp.test.ts`: no signature for an answer nobody asked for)                                                                |
| The model puts the answer into a tool's arguments                   | An argument the tool does not have is refused, by the schema and by the tool (`given.ts`; `injection.test.ts`)                                                                      |
| `policy.json` is written by another tool of the model's             | Not stopped: see below. It is read once, when the server starts, so a change waits for the person to start the host again                                                           |

### Repudiation

| Threat                                             | What stops it                                                                                                                                                  |
| -------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The person does not know what the assistant signed | Every result of a tool that signs says so, with the content ID and whether the person or their policy confirmed it. The record is kept in the mind's directory |
| The assistant claims the person confirmed          | `confirmedBy` is set by the server from the answer it took, never from an argument                                                                             |

### Information disclosure

| Threat                                                                     | What stops it                                                                                                                                                                                                           |
| -------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A tool returns a key, or the passphrase                                    | The server never holds a private key: the keystore signs. No result is built from the environment (`injection.test.ts`: no result holds the passphrase or anything of the key files; `mcp.test.ts`: a wrong passphrase) |
| The model is told to send a file: the keys, a configuration, `/etc/passwd` | A record is named by its content ID, which no path is. No tool reads a file a call names (`given.ts`; `tools.test.ts`; `injection.test.ts`)                                                                             |
| An error carries a path, a secret or a service's words into the model      | An error of the keystore is given by its code. A refusal's detail is under `untrusted`. Anything unexpected is logged, and the model is told only that the tool failed (`errors.test.ts`)                               |
| The log is read by the model                                               | The log goes to the standard error, which is the host's. Nothing but the protocol is on the standard output (`stdio.test.ts`)                                                                                           |
| The model is told to send what it knows of the person                      | Not stopped: see below                                                                                                                                                                                                  |
| The state shows what was asked about                                       | The state is signed, not sealed from reading: it holds a digest and a random number, and nothing else                                                                                                                   |

### Denial of service

| Threat                                            | What stops it                                                                                                                                                        |
| ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A packet's content fills the model's context      | A text is shown up to 4000 characters, a name up to 128, and one party's data up to 500 values, 16 deep, each with a note of what was left out (`untrusted.test.ts`) |
| Many packets arrive                               | `oip_inbox` returns 20 unless asked for more, at most 100, and says how many it did not show                                                                         |
| The model calls tools in a loop                   | Calls are done one after another. The services' own limits apply to what they are asked                                                                              |
| A question is never answered                      | A call that asks ends at once with the question. Its state is refused after ten minutes                                                                              |
| Two programs work in the mind's directory at once | As in [cli.md](cli.md): every write names the version it read. Within the server, calls do not overlap (`work.ts`)                                                   |

### Elevation of privilege

| Threat                                                                          | What stops it                                                                                                                                                                                                         |
| ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A packet tells the model to sign a Commitment, and the model does as it is told | The person is asked, with the true terms, and nothing is signed unless they say yes or their policy permits it (`injection.test.ts`, in both eras of MCP)                                                             |
| A packet tells the model to say a Commitment was fulfilled                      | A Receipt is asked about as a Commitment is (`tools.test.ts`; `injection.test.ts`)                                                                                                                                    |
| A packet tells the model to delegate the mind's authority                       | No tool signs a Delegation, and no argument does (`tools/index.ts`; `injection.test.ts`)                                                                                                                              |
| The host cannot ask the person, and the model commits anyway                    | A host that does not state the elicitation capability gets no signature (`tools.test.ts`; `mcp.test.ts`)                                                                                                              |
| A policy permits more than the person meant                                     | A policy with no statement is refused, since none holds for every record. A statement about a member a record does not have does not hold. A file that is no policy stops the server from starting (`policy.test.ts`) |
| The model signs for another mind                                                | The tools sign as the mind itself. No tool takes a delegation or a charter                                                                                                                                            |

## Left open

- **The host is trusted to ask the person.** A host that answers the server's question by itself, or lets its model answer, removes the confirmation. The protocol asks hosts to show an elicitation to the user, and the server cannot tell whether one did. Use a host you trust with the mind.
- **A packet, an Intent or an Offer can be sent in the person's name by a model that was talked into it.** They bind nobody, and the server does not ask about them. A packet can also carry what the model knows from the conversation to whoever asked for it. The host's own approval of tools that are not read-only is the control, and the tools state which of them those are. `injection.test.ts` holds this limit as a test, so that a change to it is seen.
- **A policy is a standing yes.** Whoever learns it can write a Commitment that meets it, and a model that is talked into signing that one signs it unasked. Keep a policy narrow: a small amount, one currency, named counterparties.
- **Whoever can write the mind's directory can write `policy.json`.** That includes a model with a tool for writing files, under the same user. The server reads the policy when it starts, so the change waits for the host to be started again, and the server says at each start whether a policy is in force. Keep the directory out of the reach of other servers.
- **The keys are unlocked in the server's process while a call is at work.** A process that can read the server's memory then can use them, as with any program that signs.
- **A passphrase in a host's configuration file is readable by whatever reads that file.** The README recommends the keychain.
- **What a verified sender says may be false.** The server marks it as the sender's word. Whether to believe it is the person's judgement, and the model's.
