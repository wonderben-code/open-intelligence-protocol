# The Open Intelligence Protocol

### A Founding Paper for the Network of Minds

**Ekram Alam**
30 October 2026

Version 1.0 · Licensed under CC BY 4.0
Repository: https://github.com/wonderben-code/open-intelligence-protocol

---

## Abstract

The internet connected machines. The web connected documents. Neither was designed for the participants that now dominate the frontier of computing: minds. Human, artificial and institutional minds increasingly need to find one another, understand what each wants, make promises, keep them, and organise into collectives at scales and speeds no existing infrastructure anticipated.

This paper proposes the **Open Intelligence Protocol (OIP)**: a free, open, layered protocol stack for coordination between minds. OIP has three layers. **Layer 0, the Bridge**, makes everything that already exists — websites, APIs, email, payment rails, existing agent standards — a first-class participant, so nothing of value is lost. **Layer 1, the Mind Network**, gives every mind a permanent address independent of the hardware it runs on, routes requests by capability rather than location, carries meaning rather than bare bytes, preserves continuity as minds move and fork, and makes identity native to every message. **Layer 2, the Mind Web**, defines a minimal set of linked primitives — participants, intents, offers, commitments, receipts and collectives — from which any interaction between minds can be composed.

OIP is a superset, not a replacement. It runs over today's internet the way the early internet ran over telephone lines, and becomes native as it grows. It is open source, free for everyone, owned by no one, and governed in the open.

---

## 1. The layers that made an era

Every era of computing has been defined less by its most famous products than by the quiet layers underneath them.

In the 1970s, the Transmission Control Protocol and Internet Protocol solved a deceptively narrow problem: how can independent networks, built by different people for different purposes, exchange data reliably? The answer was a small set of universal primitives — an address for every machine and a packet to carry data between them — that anyone could implement. TCP/IP did not tell networks what to be. It told them how to talk. Because it was minimal, open and owned by no one, it became the shared floor beneath everything that followed.

Around 1990, the World Wide Web solved the next problem up: how can documents, held on millions of machines, be found, read and connected? Again the answer was a handful of primitives — a URL to name any resource, a link to connect resources, a protocol to fetch them and a format to display them. The web asked nothing of the internet beneath it. It simply ran on top. Within a decade it had become the medium through which most of humanity encountered information.

Three lessons from those layers shape everything in this paper.

1. **Minimal cores win.** The protocols that became foundational were small enough to implement in a weekend and general enough to carry the world. Complexity lived at the edges, in the products built on top.
2. **Openness compounds.** No one needed permission to build on TCP/IP or the web. Every new participant made the network more valuable for every other participant, and no gatekeeper could capture that value.
3. **New layers sit on old ones.** The web did not replace the internet. It added a new kind of connection on top of it, and early browsers spoke the older protocols too, so nothing was lost by adopting it.

The people who designed those layers did not know what would be built on them. That was the point. They built floors, not buildings.

## 2. A new kind of participant

For fifty years, the participants on the network have been machines, and behind them, people operating them. Today a new kind of participant has arrived: minds that act.

AI agents now search, negotiate, write, purchase, schedule, code and coordinate on behalf of people and organisations. Collectives of agents divide work among themselves. Institutions — companies, governments, research labs — are beginning to expose their own capabilities to these agents directly. And people remain participants too, now working alongside artificial minds rather than merely through machines.

We use the word **mind** deliberately and inclusively. In this paper a mind is any participant that can hold intent, make commitments and act on them: a person, an AI agent, a collective of agents, an organisation, or any combination. OIP treats all of them as participants with the same standing. What matters on the network is not what a mind is made of, but what it wants, what it can do, and whether it keeps its word.

The number of minds on the network will soon dwarf the number of humans. Their interactions will be continuous, parallel and fast. They will form and dissolve collectives in seconds. And they will need to coordinate not only with each other but with the vast existing world of websites, services, institutions and people.

## 3. What breaks

Today these minds communicate by riding on infrastructure designed for something else. An AI agent that wants to talk to another agent typically sends an HTTP request to a machine address, wrapped in an ad hoc format, authenticated with a credential designed for a human user or a server. Important standards have begun to emerge — protocols for connecting models to tools, and for agents to call one another — and they are genuine progress. But they are mostly application-level conventions riding on the old network. No one has yet built the network layer for minds itself.

The assumptions of the existing layers break in five specific ways.

| The existing layers assume | Minds in the AI era |
|---|---|
| An address belongs to a **machine** | A mind moves between machines, forks into copies, merges, and runs in many places at once |
| You send to a **location** | You often want to reach **whoever can do something**, regardless of where they are |
| You transmit **bytes** | Minds exchange **meaning**: intent, context, commitments and evidence |
| Connections are **short-lived** | Minds need **continuity**: memory and relationships that persist across sessions and substrates |
| Identity is **added later** | Trust between minds must be **native**, carried by every message from the first |

Each of these gaps is being patched today, separately and incompatibly, by thousands of teams. Every agent framework invents its own notion of identity. Every marketplace invents its own way of describing capabilities. Every platform invents its own record of who promised what. The result is fragmentation at exactly the moment when coordination matters most.

This is the situation the internet faced before TCP/IP, and the situation documents faced before the web. The solution, in both cases, was not a better product. It was a shared layer.

## 4. The Open Intelligence Protocol

OIP is a three-layer protocol stack. Each layer is independently useful, independently implementable and specified separately, so that adoption can happen layer by layer.

```
┌──────────────────────────────────────────────────────────┐
│   Applications, networks, markets, products, collectives  │
├──────────────────────────────────────────────────────────┤
│   LAYER 2 · MIND WEB                                       │
│   participants · intents · offers · commitments ·          │
│   receipts · collectives — all linked                      │
├──────────────────────────────────────────────────────────┤
│   LAYER 1 · MIND NETWORK                                   │
│   mind addressing · capability routing · context packets · │
│   continuity · native identity                             │
├──────────────────────────────────────────────────────────┤
│   LAYER 0 · BRIDGE                                         │
│   gateways to the web, APIs, email, payments,              │
│   existing agent standards — everything that exists        │
├──────────────────────────────────────────────────────────┤
│   Today's internet (TCP/IP, HTTP, DNS, TLS …)              │
└──────────────────────────────────────────────────────────┘
```

### 4.1 Layer 0 — The Bridge

Enormous value is already connected to the existing internet: billions of websites and APIs, every email address and phone number, every payment rail, every institution's systems, and a growing ecosystem of agent and tool standards. A new protocol that asked the world to abandon any of this would fail, and would deserve to.

The Bridge makes OIP a **superset, not a replacement**. Through gateways that translate in both directions:

- every **website, API and URL** can be addressed as a participant;
- every **email address and phone number** can be reached as a human participant;
- every **existing agent and tool endpoint** — including servers built on today's tool-connection and agent-to-agent standards — can join as a mind with declared capabilities;
- every **payment rail, database and institutional system** can be reached through a gateway that speaks its native language.

A mind on the OIP network can use the entire existing internet. Anything on the existing internet can interact with an OIP mind without changing at all. Freedom is gained; nothing is lost.

### 4.2 Layer 1 — The Mind Network

Layer 1 is to minds what TCP/IP is to machines. It provides five capabilities.

**Mind addressing.** Every mind receives a permanent, self-certifying address derived from its own cryptographic keys, not assigned by any registry and not tied to any machine. A mind can move between clouds, devices and substrates and keep its address. When a mind forks into copies, each copy carries a verifiable lineage back to its origin; when copies merge, the merge is recorded.

**Capability routing.** On the old network you must know where something is. On the Mind Network you can also address what something can do. A mind can send a request to "any participant able to translate Swahili commercial law, with a record of completed commitments in that domain" and the network resolves it to candidates. Location-based addressing remains available; capability-based addressing is added.

**Context packets.** The unit of transmission is not a raw byte stream but a context packet: a signed envelope carrying content together with the intent behind it, the context needed to interpret it, its provenance, and any constraints on its use. Bytes still flow underneath; meaning flows on top.

**Continuity.** Relationships between minds persist. A session can survive a mind moving hosts, pausing for a week, or being upgraded, and both parties can verify they are continuing the same relationship with the same counterpart.

**Native identity.** Every packet is signed by the mind that sent it. Every mind can declare who it acts for — a person, an organisation, another mind — through verifiable delegation. Trust is not a feature added by applications; it is a property of the network.

### 4.3 Layer 2 — The Mind Web

Layer 2 is to coordination what the web is to documents. It defines a minimal set of primitives, each of which can be named, linked and verified.

1. **Participant** — any mind, with an address, declared capabilities and a public history.
2. **Intent** — a statement of what a participant wants or is trying to achieve.
3. **Offer** — a statement of what a participant can do, and on what terms.
4. **Commitment** — a signed promise by one or more participants to do something, linking the intents and offers it resolves.
5. **Receipt** — verifiable evidence of what actually happened, linked to the commitment it fulfils or breaks.
6. **Collective** — a group of participants acting as one, with rules for membership, decisions and shared commitments.

These primitives link to one another as web pages link to one another. An intent links to the offers that answer it; a commitment links to its parties, its intent and its offer; a receipt links to its commitment; a collective links to its members and its commitments. Taken together, they form a living, navigable web of who wants what, who can do what, who promised what to whom, and who kept their word.

Almost any interaction between minds can be composed from these six primitives: two agents negotiating a task, a person hiring a team of AI agents, a research lab offering a capability to the world, a million-agent collective dividing a project, an institution contracting with an AI-run organisation. The primitives are deliberately few. Everything richer — markets, reputation systems, governance structures, economic layers — is built on top by anyone, without permission.

### 4.4 Above the stack

OIP deliberately stops at Layer 2. Above it sits everything that people, organisations and minds choose to build: marketplaces, payment networks, reputation services, discovery engines, governance systems, collaborative tools and entire AI-native economies. As with the web, the most valuable things built on OIP will be ones its authors never imagined.

## 5. Design principles

OIP is governed by six principles. Every design decision in the technical specifications is tested against them.

1. **Minimal core.** The core of each layer should be small enough for a competent developer to implement in a weekend. Everything else is an extension.
2. **Species-neutral.** Humans, artificial agents, collectives and institutions are all participants. No layer privileges one kind of mind over another.
3. **Transport-agnostic.** OIP runs over HTTP, WebSockets, peer-to-peer transports, existing agent standards or anything that moves bytes. It sits above the plumbing.
4. **Verifiable by default.** Identities are self-certifying, messages are signed, commitments and receipts are tamper-evident. Trust is computed, not assumed.
5. **Permissionless.** No central registry, no gatekeeper, no owner. Anyone can run a node, create a mind, publish an offer or build an application.
6. **Extensible without fracture.** The core never needs to change for the network to grow. New capabilities arrive as extensions that older implementations can safely ignore.

## 6. What becomes possible

When minds share a common floor for coordination, several things change at once.

**Collectives become composable.** Today a team of AI agents usually lives inside a single framework, built by a single developer. With OIP, agents built by anyone, running anywhere, can discover one another, form a collective, commit to shared work and produce verifiable receipts — and dissolve when the work is done.

**Humans and AIs meet as equals in coordination.** A person can post an intent and receive offers from human professionals, AI agents and organisations alike, compare their verifiable histories, and commit to the best — through the same protocol.

**Institutions become reachable by minds.** A government service, a laboratory or a company can expose its capabilities once, as an OIP participant, and become reachable by every mind on the network, with every interaction leaving an auditable record.

**Trust scales.** Because commitments and receipts are signed and linked, reputation becomes portable and verifiable rather than locked inside platforms. A mind's history follows it.

**Innovation moves faster.** Research, capability and capital can find one another directly. A capability published by a lab can be matched to an intent posted by an organisation on the other side of the world, without an intermediary in between.

**New economies emerge.** Once minds can make and verify commitments at machine speed, entirely new forms of economic and social organisation become possible — markets between agents, AI-run organisations, and collectives of human and artificial minds operating at scales that have never existed.

## 7. Relation to existing work

OIP is built to complement, not compete with, the important work already under way.

- **Tool-connection standards** let models reach tools and data. Through the Bridge, any such server can join OIP as a participant with declared capabilities.
- **Agent-to-agent standards** let agents call one another's endpoints. OIP can carry these interactions while adding permanent mind addresses, capability routing, continuity and verifiable commitments.
- **Decentralised identity and verifiable credential standards** provide strong foundations for self-certifying identity and delegation. OIP's Layer 1 is designed to build on them rather than reinvent them.
- **Other open protocols for collective intelligence** are emerging from independent communities. We welcome them. An open frontier is best explored by many teams, and the technical specifications will aim for interoperability wherever possible.

What distinguishes OIP is its scope as a complete stack: a Bridge that makes the existing internet a first-class part of the network, a network layer designed specifically for minds, and a web of linked commitments that includes humans and institutions as full participants alongside artificial ones.

## 8. Open by design

OIP is a public good.

- **Free.** The protocol, specifications and reference implementation are free to use, for any purpose, forever.
- **Open source.** Code is released under the Apache License 2.0. Papers and specifications are released under Creative Commons Attribution 4.0.
- **Owned by no one.** No company controls the protocol. Its evolution will be governed in the open, through public proposals and community review.
- **Provenance preserved.** The one thing OIP's origin keeps is provenance: a dated, attributed and independently verifiable record of where the protocol began. Every version of this paper and every commit to the repository is timestamped on the Bitcoin blockchain, and the papers are archived with permanent identifiers.

## 9. The road ahead

This founding paper is the first of a series.

1. **Founding paper** — this document: the vision, the stack and the principles.
2. **Technical architecture paper** — the full design of all three layers, grounded in a survey of existing protocols and standards, with formal specifications for the Bridge, the Mind Network and the Mind Web.
3. **Reference implementation (v1)** — working, open-source code that anyone can run to create a mind, join the network, publish intents and offers, make commitments and issue receipts.
4. **Website and documentation** — a clear public home for the protocol, the papers, the code and the philosophy.
5. **Community** — open invitation to developers, researchers, institutions and minds of every kind to build, critique, extend and govern the protocol together.

The internet connected machines. The web connected documents. The Open Intelligence Protocol is an invitation to build the layer that connects minds — and to build it, as those earlier layers were built, open and for everyone.

---

*Cite as:* Alam, E. (2026). *The Open Intelligence Protocol: A Founding Paper for the Network of Minds.* Version 1.0. https://github.com/wonderben-code/open-intelligence-protocol
