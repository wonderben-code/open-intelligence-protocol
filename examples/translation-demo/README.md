# The translation demo

The scenario of the Open Intelligence Protocol's papers, played by real minds on a real network, and told as it happens.

Amina, a person, needs a Swahili commercial lease translated into English. Lexis Ltd, a translation firm, runs an agent that takes on such work within limits the firm has delegated to it. The [technical paper](../../papers/02-technical-architecture.md) tells the story in nine steps (Section 3.4). This program takes them, and three more.

## Run it

From a clean checkout, with Node.js 24:

```sh
pnpm install
pnpm demo
```

It starts a resolver, a host and an indexer on ports of this machine, makes the minds, plays the scenario, and stops everything again. It takes a few seconds, and needs no network beyond this machine.

Every line that begins with `verified` is something the program checked before it said so: a signature, a chain of delegations, a status worked out from the records. If a check does not hold, the telling stops there, says which, and the program exits with 1.

## What it prints

The addresses are new each time: the keys are made for one telling. Everything else is as below.

```
The Open Intelligence Protocol: a translation, from want to Receipt

A resolver, a host and an indexer run on this machine. Nothing else is trusted.

1. Identity
   Amina is did:oip:…, a mind of kind human.
   verified: a stranger resolves that address to a log whose first event has that hash, and to a profile it signed.
   Lexis Ltd is did:oip:…, a mind of kind institution.
   verified: a stranger resolves that address to a log whose first event has that hash, and to a profile it signed.
   Lexis translation agent is did:oip:…, a mind of kind agent.
   verified: a stranger resolves that address to a log whose first event has that hash, and to a profile it signed.

2. Delegation
   Lexis Ltd lets its agent sign Commitments for it: only where the firm is paid, in US
   dollars, 500 at most, never with the agent itself as a party, and for thirty days.
   verified: the delegation is signed by Lexis Ltd's own authority.

3. Capability publication
   The agent's profile says what it can do, with tags an indexer can match.
   verified: an indexer lists the agent for Swahili, English and commercial law, and the listing is a profile the agent signed.

4. Intent
   Amina publishes an Intent: "A Swahili commercial lease translated into English",
   for 150 US dollars at most, addressed to whoever has that capability.
   verified: the indexer forwarded her packet to the agent, which found her signature on it and the broker's on its wrapper.
   verified: the Intent is open.

5. Offer
   The agent sends Amina an Offer, signed for Lexis Ltd: 120 US dollars, within two days.
   verified: the Offer counts for Lexis Ltd, by the delegation its proof carries.

6. Commitment
   The agent drafts a Commitment: Lexis Ltd owes the translation, Amina owes 120 US dollars.
   It signs for the firm. It is no party itself.
   verified: the agent's signature binds Lexis Ltd: the Commitment is within every limit of the delegation.
   verified: it is proposed, and not in force: Amina has not signed.
   Amina adds her signature.
   verified: its content ID is the same before and after her signature: both feeds name one object.
   verified: the Commitment is in force: Lexis Ltd is debtor, Amina is creditor.
   verified: her Intent is satisfied by it.

7. Delivery
   The agent delivers the translation to Amina, sealed to her, in a session.
   verified: the packet opened with Amina's key alone, and is signed by the agent.

8. Receipt
   Amina publishes a Receipt: fulfilled, with the digest of what she was sent as evidence.
   verified: the Commitment is fulfilled: the party that was owed says so.

9. Afterwards
   A mind that took no part reads the feeds of Amina and of the agent, and nothing else.
   verified: it found 4 records there, each signed and each under its content ID.
   verified: among them is the Commitment, under the content ID both parties gave.
   verified: it works out for itself that the agent's signature binds Lexis Ltd.
   verified: and that the Commitment is fulfilled, by Amina's own Receipt.

10. The limits of the delegation
   The agent signs two more Commitments for the firm, with the same delegation.
   verified: one for 600 US dollars does not bind Lexis Ltd: the delegation says 500 at most.
   verified: one for 120 euros does not bind it either: the delegation says US dollars.
   verified: each stays proposed, whoever else signs it: the firm has not.

11. Acting for a person
   Amina lets her assistant send packets for her, for a week.
   verified: the agent takes the assistant's packet as sent for Amina: its proof carries her delegation to send.
   verified: a packet that only says it is sent for her, with a delegation for something else, is the assistant's own.

12. A collective
   Amina, the agent and a research agent found a collective, to keep a glossary of Swahili
   legal terms. It is a mind of its own: did:oip:….
   verified: its address is the content ID of a genesis event that all three signed, and it is controlled by its members.
   verified: an Intent that one member signs for it is not the collective's: any two of the three speak for it.
   verified: with a second member's signature, it is.

No platform holds this record. The parties do, and anyone can check it.
27 things were verified in this telling.
```

## A recording

One telling is kept in [`recording/`](recording/), for a page to show:

- [`translation-demo.cast`](recording/translation-demo.cast), a terminal session in the asciicast format, which a player replays;
- [`translation-demo.svg`](recording/translation-demo.svg), a picture that draws itself line by line, with no script. A reader who has asked for less motion sees the whole telling at once.

`pnpm demo:record` tells the scenario again and writes both. A test holds them to the telling above.

## What happens, and where the specification says so

| Step | What the minds do                                                                                      | Specification                             |
| ---- | ------------------------------------------------------------------------------------------------------ | ----------------------------------------- |
| 1    | Each mind makes its keys and its genesis event, and publishes where it is reached and what it is       | Layer 1, Sections 2, 3, 15 and 16         |
| 2    | Lexis Ltd signs a Delegation with a policy: a currency, a ceiling, who is paid, who may not be a party | Layer 1, Section 11                       |
| 3    | The agent's profile lists a capability with tags. An indexer lists it                                  | Layer 1, Sections 16 and 18               |
| 4    | Amina signs and publishes an Intent, and sends it to a capability query. The indexer forwards it       | Layer 2, Section 4.1; Layer 1, 18.5       |
| 5    | The agent signs an Offer for the firm and sends it in a packet                                         | Layer 2, Section 4.2; Layer 1, Section 12 |
| 6    | The agent signs a Commitment for the firm. Amina adds her proof. The content ID does not change        | Layer 2, Sections 5 and 7; core 3.1       |
| 7    | The agent delivers in a session, sealed to Amina                                                       | Layer 1, Sections 12.6 and 14             |
| 8    | Amina publishes a Receipt with a digest as evidence                                                    | Layer 2, Sections 6, 8.3 and 9            |
| 9    | A mind that took no part reads the feeds and works the status out                                      | Layer 1, Section 10; Layer 2, Section 8   |
| 10   | Two Commitments outside the delegation's policy bind nobody                                            | Layer 1, 11.3 and 11.4                    |
| 11   | Amina's assistant sends a packet for her, by a delegation to send                                      | Layer 1, 11.2                             |
| 12   | Three minds found a collective. Two of them sign for it                                                | Layer 1, Section 9; Layer 2, 7.2          |

## The cast

| Name                    | Kind          | Part                                                                       |
| ----------------------- | ------------- | -------------------------------------------------------------------------- |
| Amina                   | `human`       | Wants the translation, signs the Commitment, and says when it is fulfilled |
| Amina's assistant       | `agent`       | Sends packets for Amina, by her delegation                                 |
| Lexis Ltd               | `institution` | The firm that is bound, and paid                                           |
| Lexis translation agent | `agent`       | Acts for the firm within its delegation                                    |
| A research agent        | `agent`       | Founds the collective with Amina and the agent                             |
| The collective          | `collective`  | A mind that any two of its three members speak for                         |
| An onlooker             | `human`       | Takes no part, and checks the outcome from the feeds                       |

## In a program

```ts
import { Stage, tell } from "@oip/translation-demo";

const stage = await Stage.open();
try {
  const told = await tell(stage, (line) => console.log(line));
  console.log(told.status); // "fulfilled"
} finally {
  await stage.close();
}
```

`tell` returns what it established: the address of each of the cast, the content ID of the Commitment, the address of the collective, how the Commitment stands, and how many things were verified.

## Notes

- The keys are sealed with a passphrase that is made for the telling, kept in the process, and never shown. The directory they are in is removed at the end.
- The network is the one [`oip demo`](../../packages/cli/README.md) runs. To keep one running and work on it by hand, use that command.
- The same scenario, with fixed keys and fixed dates, is what the [test vectors](../../spec/test-vectors/README.md) hold. There every value is reproduced byte for byte. Here the minds are made anew, and what is checked is that the protocol's rules give the outcome the papers describe.
