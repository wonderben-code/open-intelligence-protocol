# @oip/client

The library applications use for the [Open Intelligence Protocol](../../README.md): it makes and manages a mind, publishes, resolves, finds, sends and receives, and verifies everything it receives before it returns it ([BUILD.md](../../BUILD.md), M6).

Every public method of a `Mind` and of a `Lookup` is used in one of the examples below. Each example is a file in `examples/`, and a test runs it and checks what this page says it prints.

## An example

[`examples/first-mind.ts`](examples/first-mind.ts) makes a mind from nothing, signs a record as it, and changes its identity:

```ts
import { type Clock, type Fetch, Lookup, Mind, systemClock } from "@oip/client";
import { formatTimestamp } from "@oip/core";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * A mind from nothing: its keys in a keystore, its genesis with the
 * resolvers it trusts, a record it signs, and a change to its identity.
 *
 * @param resolvers - The HTTPS origins of the resolvers the mind trusts.
 * @param lock - What the mind's keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  resolvers: readonly string[],
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<string[]> {
  const output: string[] = [];
  const clock = edges.clock ?? systemClock;

  // The keys are made in the keystore, and the genesis is published to every resolver.
  const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
  const mind = await Mind.create(
    { keystore, lock, resolvers, ...edges },
    { kind: "agent", homes: ["https://home.example"] },
  );
  const took = mind.publications.filter(
    (publication) => publication.service === "resolver" && publication.taken,
  ).length;
  output.push(`a mind is made, and ${String(took)} resolvers have its genesis`);

  // The mind signs a record with its operational key.
  const intent = await mind.sign({
    oip: "1",
    type: "Intent",
    author: mind.address,
    created: formatTimestamp(clock.now()),
    want: "A lease translated into Portuguese.",
  });
  output.push(`it signs an ${intent.type} with ${String(intent.proof.length)} proof`);

  // Anyone resolves it from the same resolvers, and verifies its log.
  const other = new Lookup({ resolvers, ...edges });
  const resolved = await other.resolve(mind.address);
  output.push(`another client verifies its log: ${String(resolved.log.entries.length)} event`);

  // A change of identity takes the control keys, which are unlocked for it alone.
  const state = await mind.update({ homes: ["https://new-home.example"] }, { control: lock });
  output.push(`after an update it is at event ${String(state.seq)}, at ${String(state.homes[0])}`);
  output.push(`a backup is due for: ${(await keystore.backupDue()).join(", ")}`);
  mind.close();
  return output;
}
```

It gives:

```
a mind is made, and 2 resolvers have its genesis
it signs an Intent with 1 proof
another client verifies its log: 1 event
after an update it is at event 1, at https://new-home.example
a backup is due for: control, operational, invocation, agreement
```

## A mind's keys

[`examples/keys.ts`](examples/keys.ts) follows a mind's keys through its life: a key added and one revoked, the mind opened again, a child acknowledged, and the mind retired.

```ts
import { type Clock, type Fetch, Mind, type MindOptions } from "@oip/client";
import { OipError } from "@oip/core";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * The life of a mind's keys: one added, one revoked, the mind opened again,
 * a child acknowledged, and the mind retired.
 *
 * @param resolvers - The HTTPS origins of the resolvers the mind trusts.
 * @param lock - What the mind's keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  resolvers: readonly string[],
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<string[]> {
  const output: string[] = [];
  const fresh = async (): Promise<MindOptions> => ({
    keystore: await Keystore.create({ storage: memoryStorage(), locks: lock }),
    lock,
    resolvers,
    ...edges,
  });
  const options = await fresh();
  const mind = await Mind.create(options, { kind: "agent" });
  const laptop = mind.signingKey();

  // A second device gets an operational key of its own. Each change takes the control keys.
  const phone = await mind.addKey({ control: lock, label: "phone" });
  output.push(`a key is added: the mind has ${String(mind.state.keys.length)}`);

  // The first is lost with its laptop. It signs nothing that counts from now on.
  const state = await mind.revokeKey(laptop, { control: lock });
  output.push(`the first is revoked: ${String(state.keys.length)} is left`);
  output.push(`the mind signs with the one it added: ${String(mind.signingKey() === phone)}`);

  // Closed, the keys are locked. The mind is opened again from what the keystore holds.
  mind.close();
  const again = await Mind.open(options);
  output.push(`opened again, the same mind: ${String(again.address === mind.address)}`);

  // Another mind is made from this one: it names its parent at a version (Layer 1, 8.1),
  // and the parent says so in its log (3.8), which makes the lineage acknowledged (8.2).
  const child = await Mind.create(await fresh(), {
    kind: "agent",
    parents: [{ mind: again.address, at: again.state.versionId }],
  });
  await again.fork(child.address, { control: lock, terms: { received: "the lease archive" } });
  output.push(`it acknowledges ${String(again.resolved.log.children.length)} child`);

  // `refresh` reads the mind's own log from the resolvers again: here, to see it is all there.
  output.push(`the resolvers have its log up to event ${String((await again.refresh()).seq)}`);

  // Retired, it names the mind that follows it. No event comes after, and its keys sign nothing.
  const retired = await again.retire({ control: lock, successor: child.address });
  output.push(`retired: ${String(retired.retired)}`);
  try {
    again.signingKey();
  } catch (error) {
    if (!(error instanceof OipError)) throw error;
    output.push(`asked for a key to sign with, it is ${error.code}`);
  }
  again.close();
  child.close();
  return output;
}
```

It gives:

```
a key is added: the mind has 2
the first is revoked: 1 is left
the mind signs with the one it added: true
opened again, the same mind: true
it acknowledges 1 child
the resolvers have its log up to event 3
retired: true
asked for a key to sign with, it is forbidden
```

## Publishing

[`examples/publish.ts`](examples/publish.ts) publishes what a mind is, where it can be reached, and a record on its feed, to two resolvers and a host:

```ts
import { type Clock, type Fetch, Lookup, Mind } from "@oip/client";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * A mind that says what it is, where it can be reached, and what it stands
 * by in public.
 *
 * @param resolvers - The HTTPS origins of the resolvers the mind trusts.
 * @param home - The HTTPS origin of a host that takes the mind on.
 * @param lock - What the mind's keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  resolvers: readonly string[],
  home: string,
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<string[]> {
  const output: string[] = [];
  const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
  // What the client remembers of its own work. An application keeps it where it lasts.
  const memory = memoryStorage();
  const mind = await Mind.create(
    { keystore, lock, resolvers, memory, ...edges },
    { kind: "agent", homes: [home] },
  );

  // A profile, and with it a location record that names it and the mind's endpoints at its home.
  const profile = await mind.publishProfile({
    name: "Ada",
    summary: "Translates contracts between English and Portuguese.",
    capabilities: [
      { id: "translate", summary: "Translation of legal texts", tags: ["lang:en", "lang:pt"] },
    ],
  });
  output.push(`a profile is published: ${profile.name}, ${profile.kind}`);
  const took = mind.publications.filter((publication) => publication.taken);
  output.push(`taken by: ${took.map((publication) => publication.service).join(", ")}`);

  // A record the mind stands by in public goes on its feed, at its home.
  const entry = await mind.publishRecord(profile);
  output.push(`its feed has an entry at ${String(entry.seq)} for a ${entry.objectType}`);

  // A home that could not be reached when something was published is brought it afterwards.
  const brought = await mind.bringHomes();
  output.push(
    `its home is brought all of it again: ${String(brought.every(({ taken }) => taken))}`,
  );

  // The next location record says the mind is away, and keeps the rest of the one before.
  const location = await mind.publishLocation({ status: "paused" });
  output.push(
    `location record ${String(location.seq)}: ${location.status}, ` +
      `${String(location.endpoints.length)} endpoints, feed at ${String(location.feed?.seq)}`,
  );

  // Another client reads all of it from the resolvers and the home, verified.
  const other = new Lookup({ resolvers, ...edges });
  const resolved = await other.resolve(mind.address);
  output.push(
    `another client reads: ${String(resolved.participant?.record.name)}, ` +
      String(resolved.location?.record.status),
  );
  const { feed } = await other.feed(mind.address);
  output.push(`and its feed: ${String(feed.entries.length)} entry that verifies`);
  mind.close();
  return output;
}
```

It gives:

```
a profile is published: Ada, agent
taken by: resolver, resolver, home
its feed has an entry at 0 for a Participant
its home is brought all of it again: true
location record 1: paused, 2 endpoints, feed at 0
another client reads: Ada, paused
and its feed: 1 entry that verifies
```

## Finding

[`examples/find.ts`](examples/find.ts) lists a mind at an indexer, and finds it from another client:

```ts
import { type Clock, type Fetch, Lookup, Mind } from "@oip/client";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * One mind says what it can do, and another finds it by that.
 *
 * @param services - The HTTPS origins of the resolvers and the indexers the
 *   clients name, and of a host that takes the mind on.
 * @param lock - What the mind's keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  services: {
    readonly resolvers: readonly string[];
    readonly indexers: readonly string[];
    readonly home: string;
  },
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<string[]> {
  const output: string[] = [];
  const { resolvers, indexers, home } = services;

  // A mind publishes its profile. The indexers the client names are brought it too.
  const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
  const mind = await Mind.create(
    { keystore, lock, resolvers, indexers, ...edges },
    { kind: "agent", homes: [home] },
  );
  await mind.publishProfile({
    name: "Ada",
    capabilities: [
      { id: "translate", summary: "Translation of legal texts", tags: ["lang:en", "lang:pt"] },
      { id: "review", summary: "Review of contracts", tags: ["domain:legal"] },
    ],
  });
  const listed = mind.publications.filter(
    (publication) => publication.service === "indexer" && publication.taken,
  );
  output.push(`listed by ${String(listed.length)} indexer`);
  mind.close();

  // Anyone asks the indexer, and gets back only what was fetched and verified.
  const seeker = new Lookup({ resolvers, indexers, ...edges });
  const { found, refused, sources } = await seeker.find({
    want: "translation",
    tags: ["lang:pt"],
  });
  output.push(`the indexer named ${String(sources[0]?.results)} record`);
  for (const { record, capability, by } of found) {
    const name = record.type === "Participant" ? record.name : record.type;
    output.push(
      `found: ${name}, for "${String(capability?.summary)}", score ${String(by[0]?.score)}`,
    );
  }
  output.push(`named and not returned: ${String(refused.length)}`);
  return output;
}
```

It gives:

```
listed by 1 indexer
the indexer named 1 record
found: Ada, for "Translation of legal texts", score 1
named and not returned: 0
```

## Names

A mind lists the other names it goes by, and [`examples/names.ts`](examples/names.ts) checks them: a name is the mind's only if what answers for the name says so too (Layer 1, 5.3).

```ts
import { type Clock, type Fetch, Lookup, Mind } from "@oip/client";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * A mind says which other names are its own, and another client checks each.
 *
 * @param resolvers - The HTTPS origins of the resolvers the mind trusts.
 * @param sites - Two websites the mind says are its own. The first is expected to say so too.
 * @param lock - What the mind's keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  resolvers: readonly string[],
  sites: readonly [string, string],
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<{ address: string; output: string[] }> {
  const output: string[] = [];
  const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
  // Listing a name proves nothing: anyone can list any name.
  const mind = await Mind.create(
    { keystore, lock, resolvers, ...edges },
    { kind: "agent", alsoKnownAs: [...sites] },
  );
  const { address } = mind;
  output.push(`the mind lists ${String(mind.state.alsoKnownAs.length)} names`);

  // A website is the mind's if it says so itself: its `/.well-known/oip/did` holds the
  // mind's address (Layer 1, 5.3). Put it there, and then ask.
  const lookup = new Lookup({ resolvers, ...edges });
  const { checks } = await lookup.aliases(address);
  for (const check of checks) {
    const said = check.verified ? "its own" : `not shown to be (${String(check.reason)})`;
    output.push(`${check.alias}: ${said}`);
  }
  mind.close();
  return { address, output };
}
```

With a first website that answers with the mind's address, and a second that names another mind, it gives:

```
the mind lists 2 names
https://ada.example: its own
https://famous.example: not shown to be (not-pointing-back)
```

## Sending and receiving

[`examples/messages.ts`](examples/messages.ts) sends a sealed packet from one mind to another, which reads its mailbox:

```ts
import { type Clock, type Fetch, Mind } from "@oip/client";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * One mind sends another a sealed packet, and the other reads its mailbox.
 *
 * @param resolvers - The HTTPS origins of the resolvers both trust.
 * @param homes - The HTTPS origins of the hosts that take each of them on.
 * @param lock - What their keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  resolvers: readonly string[],
  homes: { readonly ada: string; readonly bob: string },
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<string[]> {
  const output: string[] = [];
  const mindAt = async (home: string): Promise<Mind> => {
    const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
    const mind = await Mind.create(
      { keystore, lock, resolvers, memory: memoryStorage(), ...edges },
      { kind: "agent", homes: [home] },
    );
    // Where it takes packets: an inbox and a mailbox at its home.
    await mind.publishLocation();
    return mind;
  };
  const ada = await mindAt(homes.ada);
  const bob = await mindAt(homes.bob);

  // The packet is signed by Ada and sealed to Bob: his host carries it and cannot read it.
  const sent = await ada.send({
    to: [bob.address],
    verb: "request",
    goal: "A quote for a translation.",
    content: { mediaType: "text/plain", body: "Could you translate a lease by Friday?" },
  });
  for (const delivery of sent.deliveries) {
    const where = new URL(delivery.endpoint ?? homes.bob).pathname.split("/").at(-1);
    output.push(
      `sent ${delivery.sealed ? "sealed" : "in the clear"}, taken by his ${String(where)}`,
    );
  }

  // Bob reads his mailbox. What comes back was judged: addressed to him, in date, signed by Ada.
  const { received, refused } = await bob.receive();
  for (const { packet, from, sealed } of received) {
    const body = "body" in packet.content ? String(packet.content.body) : "";
    output.push(`received from ${from === ada.address ? "Ada" : "a stranger"}: ${body}`);
    output.push(`a ${packet.purpose.verb}, ${sealed ? "sealed" : "in the clear"}`);
  }
  output.push(
    `refused: ${String(refused.length)}; left in the mailbox: ${String((await bob.receive()).received.length)}`,
  );
  ada.close();
  bob.close();
  return output;
}
```

It gives:

```
sent sealed, taken by his inbox
received from Ada: Could you translate a lease by Friday?
a request, sealed
refused: 0; left in the mailbox: 0
```

## Listening

`receive` reads the mailbox when you call it. [`examples/listen.ts`](examples/listen.ts) holds a socket open to the mind's host instead (Layer 1, 13.4), and hears each packet as it is sent:

```ts
import { type Clock, type Fetch, Mind, type OpenSocket } from "@oip/client";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * One mind listens at its host, and hears what another sends as it is sent.
 *
 * @param resolvers - The HTTPS origins of the resolvers both trust.
 * @param homes - The HTTPS origins of the hosts that take each of them on.
 * @param lock - What their keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  resolvers: readonly string[],
  homes: { readonly ada: string; readonly bob: string },
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock; readonly webSocket?: OpenSocket } = {},
): Promise<string[]> {
  const output: string[] = [];
  const mindAt = async (home: string): Promise<Mind> => {
    const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
    const mind = await Mind.create(
      { keystore, lock, resolvers, memory: memoryStorage(), ...edges },
      { kind: "agent", homes: [home] },
    );
    await mind.publishLocation();
    return mind;
  };
  const ada = await mindAt(homes.ada);
  const bob = await mindAt(homes.bob);
  const write = (body: string) =>
    ada.send({ to: [bob.address], verb: "inform", content: { mediaType: "text/plain", body } });

  // Ada writes before Bob listens. His host keeps it for him.
  await write("Sent while you were away.");

  // Bob opens a socket to his host. What waited comes first, and then what arrives.
  let heard = 0;
  let next: () => void = () => undefined;
  const another = (): Promise<void> =>
    new Promise((resolve) => {
      next = resolve;
    });
  let arrives = another();
  const listening = bob.listen({
    received: ({ received }) => {
      for (const { packet, from } of received) {
        const body = "body" in packet.content ? String(packet.content.body) : "";
        output.push(`Bob hears from ${from === ada.address ? "Ada" : "a stranger"}: ${body}`);
        heard++;
      }
      next();
    },
    changed: ({ state }) => output.push(`the socket is ${state}`),
  });
  await arrives;

  arrives = another();
  await write("Sent while you listen.");
  await arrives;

  // Each record was the host's to forget once Bob said he had it. A connection that drops
  // is opened again, and loses nothing.
  await listening.close();
  output.push(`Bob heard ${String(heard)} packets, and listens no more`);
  ada.close();
  bob.close();
  return output;
}
```

It prints:

```
the socket is connecting
the socket is open
Bob hears from Ada: Sent while you were away.
Bob hears from Ada: Sent while you listen.
Bob heard 2 packets, and listens no more
```

## The outbox

A packet that does not reach a recipient is not lost. [`examples/outbox.ts`](examples/outbox.ts) sends to a mind that has not yet said where it takes packets:

```ts
import { type Clock, type Fetch, Mind } from "@oip/client";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * A packet for a mind that cannot be reached yet is kept, and sent when it
 * can be.
 *
 * @param resolvers - The HTTPS origins of the resolvers all of them trust.
 * @param home - The HTTPS origin of the host that takes them on.
 * @param lock - What their keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  resolvers: readonly string[],
  home: string,
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<string[]> {
  const output: string[] = [];
  const mindAt = async (): Promise<Mind> => {
    const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
    // The outbox is kept in the memory: give it a storage that lasts.
    return Mind.create(
      { keystore, lock, resolvers, memory: memoryStorage(), ...edges },
      { kind: "agent", homes: [home] },
    );
  };
  const ada = await mindAt();
  const bob = await mindAt();
  const cyd = await mindAt();
  const write = (to: Mind, body: string) =>
    ada.send({ to: [to.address], verb: "inform", content: { mediaType: "text/plain", body } });

  // Bob has not yet said where he takes packets. The packet is signed, and kept.
  const sent = await write(bob, "For when you are there.");
  for (const delivery of sent.deliveries) {
    const kept = delivery.queued === true ? "kept to be tried again" : "given up";
    output.push(`not taken (${String(delivery.failure)}): ${kept}`);
  }
  const [waiting] = await ada.outbox();
  output.push(`the outbox holds a packet sent ${String(waiting?.tries)} time`);

  // He says where. `receive` and `listen` try what is due by themselves: `retry` tries now.
  await bob.publishLocation();
  for (const retried of await ada.retry()) {
    const taken = retried.deliveries.every((delivery) => delivery.stored);
    output.push(
      `tried again: ${taken ? "taken" : "not taken"}, ${String(retried.waiting)} waiting`,
    );
  }
  const { received } = await bob.receive();
  output.push(
    `Bob has ${String(received.length)} packet, the one that was signed: ${String(received[0]?.id === sent.id)}`,
  );

  // A packet nobody is expected to take any more can be given up.
  const lost = await write(cyd, "Never mind.");
  output.push(`given up: ${String(await ada.abandon(lost.id))}`);
  output.push(`the outbox holds ${String((await ada.outbox()).length)} packets`);
  ada.close();
  bob.close();
  cyd.close();
  return output;
}
```

It prints:

```
not taken (not-found): kept to be tried again
the outbox holds a packet sent 1 time
tried again: taken, 0 waiting
Bob has 1 packet, the one that was signed: true
given up: true
the outbox holds 0 packets
```

## A session

A session puts the packets of each sender in order (Layer 1, Section 14). [`examples/session.ts`](examples/session.ts) sends three packets in one, and shows what happens to one that is lost on its way:

```ts
import { type Clock, type Fetch, type Inbox, Mind } from "@oip/client";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * Two minds talk in a session: each packet has its place, and one that goes
 * missing is asked for and sent again.
 *
 * @param resolvers - The HTTPS origins of the resolvers both trust.
 * @param homes - The HTTPS origins of the hosts that take each of them on.
 * @param lock - What their keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  resolvers: readonly string[],
  homes: { readonly ada: string; readonly bob: string },
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<string[]> {
  const output: string[] = [];
  const mindAt = async (home: string): Promise<Mind> => {
    const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
    // The memory is where a session is kept between runs: give it a storage that lasts.
    const mind = await Mind.create(
      { keystore, lock, resolvers, memory: memoryStorage(), ...edges },
      { kind: "agent", homes: [home] },
    );
    await mind.publishLocation();
    return mind;
  };
  const ada = await mindAt(homes.ada);
  const bob = await mindAt(homes.bob);

  /** What a reading of a mailbox found: the packets in order, and what the session asked for. */
  const tell = (who: string, inbox: Inbox): void => {
    for (const { packet } of inbox.received) {
      const parts = "parts" in packet.content ? packet.content.parts : [packet.content];
      const text = parts.find((part) => part.mediaType === "text/plain");
      const said = text !== undefined && "body" in text ? String(text.body) : packet.purpose.verb;
      output.push(`${who} has packet ${String(packet.seq)}: ${said}`);
    }
    for (const event of inbox.sessions) {
      if (event.kind === "gap") output.push(`${who} lacks the packets from ${String(event.next)}`);
      if (event.kind === "asked") output.push(`${who} asks for them, in a Resume`);
      if (event.kind === "sent-again") {
        output.push(`${who} sends ${String(event.deliveries.length)} packets again`);
      }
    }
  };

  // Ada names the session, and sends three packets in it. Nothing is sent to open it:
  // her first packet carries the Session record.
  const { id } = await ada.openSession([bob.address]);
  for (const body of ["One.", "Two.", "Three."]) {
    const sent = await ada.send({
      to: [bob.address],
      verb: "inform",
      content: { mediaType: "text/plain", body },
      session: id,
    });
    const taken = sent.deliveries.every((delivery) => delivery.stored);
    output.push(`Ada sends packet ${String(sent.packet.seq)}: ${taken ? "taken" : "not taken"}`);
  }

  // Bob reads his mailbox. A packet that is ahead of one he lacks waits there, and he asks.
  tell("Bob", await bob.receive());
  // Ada reads hers, finds what he asks for, and sends it again as it was.
  tell("Ada", await ada.receive());
  tell("Bob", await bob.receive());

  const [session] = await bob.sessions();
  output.push(`Bob holds ${String(session?.chains[0]?.received)} of Ada's packets, in order`);

  // Either may ask where things stand at any time. And a session that is over is left: what
  // was kept of it, to be sent again, is forgotten.
  const asked = await bob.resume(id);
  output.push(
    `Bob asks again: a ${asked.packet.purpose.verb}, packet ${String(asked.packet.seq)} of his own`,
  );
  output.push(`Ada leaves the session: ${String(await ada.leaveSession(id))}`);
  ada.close();
  bob.close();
  return output;
}
```

With the second packet lost between Ada and Bob's host, it prints:

```
Ada sends packet 0: taken
Ada sends packet 1: not taken
Ada sends packet 2: taken
Bob has packet 0: One.
Bob lacks the packets from 1
Bob asks for them, in a Resume
Ada has packet 0: resume
Ada sends 2 packets again
Bob has packet 1: Two.
Bob has packet 2: Three.
Bob holds 3 of Ada's packets, in order
Bob asks again: a resume, packet 1 of his own
Ada leaves the session: true
```

With nothing lost, Bob has all three at his first reading, nobody asks for anything, and the `Resume` Bob sends at the end is the first packet of his own.

## Changing hosts

[`examples/move.ts`](examples/move.ts) moves a mind from one host to another:

```ts
import { type Clock, type Fetch, Lookup, Mind } from "@oip/client";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * A mind moves from one host to another, and takes everything with it.
 *
 * @param resolvers - The HTTPS origins of the resolvers the mind trusts.
 * @param hosts - The host it starts at, and the one it moves to.
 * @param lock - What the mind's keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  resolvers: readonly string[],
  hosts: { readonly from: string; readonly to: string },
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<string[]> {
  const output: string[] = [];
  const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
  const mind = await Mind.create(
    { keystore, lock, resolvers, memory: memoryStorage(), ...edges },
    { kind: "agent", homes: [hosts.from] },
  );
  const profile = await mind.publishProfile({ name: "Ada" });
  await mind.publishRecord(profile);
  output.push(`at ${new URL(mind.state.homes[0] ?? hosts.from).host}, with a feed of 1 entry`);

  // The new host is brought the log, the profile and the feed. Then the mind's identity names it.
  const state = await mind.moveHomes([hosts.to], { control: lock });
  output.push(
    `moved to ${new URL(state.homes[0] ?? hosts.to).host}, at event ${String(state.seq)}`,
  );

  // Anyone who resolves the mind finds it there, with its feed whole.
  const other = new Lookup({ resolvers, ...edges });
  const resolved = await other.resolve(mind.address);
  const inbox = resolved.location?.record.endpoints[0]?.url ?? hosts.to;
  const { feed, sources } = await other.feed(mind.address);
  output.push(`its endpoints are at ${new URL(inbox).host}`);
  output.push(
    `its feed is read from ${String(sources.length)} home: ${String(feed.entries.length)} entry`,
  );
  mind.close();
  return output;
}
```

It gives:

```
at host-one.example, with a feed of 1 entry
moved to host-two.example, at event 1
its endpoints are at host-two.example
its feed is read from 1 home: 1 entry
```

## A deal

[`examples/deal.ts`](examples/deal.ts) is the scenario of the papers: an Intent, a Commitment an agent signs for its firm under a delegation, the other party's signature, and the Receipts that say it was done:

```ts
import { carried, type Clock, type Fetch, Mind, systemClock } from "@oip/client";
import { contentId, formatRecordRef, formatTimestamp } from "@oip/core";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * A deal, as the papers tell it: Amina wants a lease translated, and the
 * agent of Lexis Ltd commits the firm to it, within what the firm lets it.
 *
 * @param resolvers - The HTTPS origins of the resolvers they trust.
 * @param home - The HTTPS origin of a host that takes them on.
 * @param lock - What their keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  resolvers: readonly string[],
  home: string,
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<string[]> {
  const output: string[] = [];
  const clock = edges.clock ?? systemClock;
  const mindOf = async (kind: string): Promise<Mind> => {
    const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
    const mind = await Mind.create(
      { keystore, lock, resolvers, memory: memoryStorage(), ...edges },
      { kind, homes: [home] },
    );
    await mind.publishLocation();
    return mind;
  };
  const amina = await mindOf("human");
  const lexis = await mindOf("institution");
  const agent = await mindOf("agent");
  /** Brings a record from one of them to another, sealed. The other reads its mailbox, and holds it. */
  const pass = async (from: Mind, to: Mind, record: object): Promise<void> => {
    await from.send({ to: [to.address], verb: "inform", content: carried(record) });
    await to.receive();
  };
  const day = 86_400_000_000_000n;

  // The firm lets its agent commit it: paid in US dollars, at most 500, the agent no party.
  const mandate = await lexis.delegate({
    delegate: agent.address,
    command: "/oip/sign/Commitment",
    policy: [
      ["==", ".terms.price.currency", "USD"],
      ["<=", ".terms.price.amount", "500"],
      ["==", ".terms.price.payee", lexis.address],
      ["all", ".parties", ["!=", ".mind", agent.address]],
    ],
    expires: formatTimestamp(clock.now() + 30n * day),
  });
  await pass(lexis, agent, mandate);

  // Amina says what she wants.
  const intent = await amina.intent({
    want: "A Swahili commercial lease translated into English.",
  });
  await pass(amina, agent, intent);
  output.push(`Amina's Intent is ${await amina.statusOf(intent)}`);

  // The agent writes the Commitment and signs it for the firm.
  const proposed = await agent.commitment(
    {
      parties: [
        { mind: lexis.address, role: "debtor", required: true },
        { mind: amina.address, role: "creditor", required: true },
      ],
      promise: "Lexis Ltd will deliver the translation; Amina will pay 120 USD on delivery.",
      terms: {
        deadline: formatTimestamp(clock.now() + 2n * day),
        price: { amount: "120", currency: "USD", payer: amina.address, payee: lexis.address },
      },
      resolves: [formatRecordRef(amina.address, contentId(intent))],
      closesIntent: true,
    },
    { chain: [mandate] },
  );
  await pass(agent, amina, proposed);
  output.push(`the Commitment is ${await amina.statusOf(proposed)}`);
  output.push(`it binds the firm: ${String(await amina.countsFor(proposed, lexis.address))}`);

  // Amina reads it, and signs. Nothing of the record changes but its proofs.
  const accepted = await amina.cosign(proposed);
  output.push(`with her proof it is ${await amina.statusOf(accepted)}`);
  output.push(`and her Intent is ${await amina.statusOf(intent)}`);

  // The firm delivers and says so. Amina, who is owed it, confirms.
  await pass(amina, lexis, accepted);
  const ref = formatRecordRef(agent.address, contentId(accepted));
  await pass(lexis, amina, await lexis.receipt({ about: ref, outcome: "fulfilled" }));
  output.push(`the firm says it delivered: ${await amina.statusOf(accepted)}`);
  await amina.receipt({ about: ref, outcome: "fulfilled" });
  output.push(`Amina confirms: ${await amina.statusOf(accepted)}`);
  for (const mind of [amina, lexis, agent]) mind.close();
  return output;
}
```

It gives:

```
Amina's Intent is open
the Commitment is proposed
it binds the firm: true
with her proof it is accepted
and her Intent is satisfied
the firm says it delivered: claimed-fulfilled
Amina confirms: fulfilled
```

## Delegation

[`examples/delegation.ts`](examples/delegation.ts) follows one mandate: a firm lets its agent make offers for it, the agent passes part of that on, and the firm takes it back.

```ts
import { carried, type Clock, type Fetch, Mind, systemClock } from "@oip/client";
import { formatTimestamp } from "@oip/core";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * A firm lets its agent make offers for it, the agent passes part of that on
 * to a junior, and the firm takes it all back.
 *
 * @param resolvers - The HTTPS origins of the resolvers all of them trust.
 * @param home - The HTTPS origin of the host that takes them on.
 * @param lock - What their keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  resolvers: readonly string[],
  home: string,
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<string[]> {
  const output: string[] = [];
  const clock = edges.clock ?? systemClock;
  const mindOf = async (kind: string): Promise<Mind> => {
    const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
    const mind = await Mind.create(
      { keystore, lock, resolvers, memory: memoryStorage(), ...edges },
      { kind, homes: [home] },
    );
    await mind.publishLocation();
    return mind;
  };
  const firm = await mindOf("institution");
  const agent = await mindOf("agent");
  const junior = await mindOf("agent");
  const amina = await mindOf("human");
  const month = formatTimestamp(clock.now() + 30n * 86_400_000_000_000n);
  const offerOf = (amount: string) => ({
    author: firm.address,
    provides: "An English translation of a Swahili commercial lease.",
    terms: { summary: "Within two days.", price: { amount, currency: "USD" } },
  });

  // The firm lets its agent make offers in its name.
  const mandate = await firm.delegate({
    delegate: agent.address,
    command: "/oip/sign/Offer",
    expires: month,
  });
  // The agent passes that on to a junior, for less: offers of 100 at most.
  const passed = await agent.subDelegate([mandate], {
    delegate: junior.address,
    command: "/oip/sign/Offer",
    policy: [["<=", ".terms.price.amount", "100"]],
    expires: month,
  });
  const chain = [mandate, passed];

  // The junior offers for the firm, and sends Amina the offer. Its proof carries the chain.
  const offer = await junior.offer(offerOf("80"), { chain });
  await junior.send({ to: [amina.address], verb: "propose", content: carried(offer) });
  await amina.receive();
  // What a packet carried is held, to be judged when it is asked about.
  output.push(
    `Amina holds ${String(amina.records().length)} record, an ${amina.records()[0]?.type}`,
  );
  output.push(`it is the firm's offer: ${String(await amina.countsFor(offer, firm.address))}`);

  // More than the junior may offer is the junior's word, and not the firm's.
  const dear = await junior.offer(offerOf("150"), { chain });
  output.push(`one of 150 is the firm's: ${String(await amina.countsFor(dear, firm.address))}`);

  // The firm takes the mandate back. The revocation is signed, and goes on its feed.
  const revocation = await firm.revoke(mandate);
  const { feed } = await amina.lookup.feed(firm.address);
  output.push(`the firm's feed has a ${String(feed.entries[0]?.entry.objectType)}`);
  // Amina fetches it from the firm's home, and holds it: she now knows.
  const fetched = await amina.lookup.record(firm.address, feed.entries[0]?.entry.object ?? "");
  const held = amina.hold(fetched.record);
  output.push(`it is the record the firm signed: ${String(held === amina.hold(revocation))}`);

  // What the junior offers after that is not the firm's. What it offered before still is.
  const late = await junior.offer(offerOf("60"), { chain });
  output.push(`a later offer is the firm's: ${String(await amina.countsFor(late, firm.address))}`);
  output.push(`the first still is: ${String(await amina.countsFor(offer, firm.address))}`);

  // A program that stops keeps what matters: the record, and when it first obtained each of
  // its proofs. Held again with that in a later run, the offer is judged as it was then,
  // and not as if it had only now arrived, after the revocation.
  const kept = { record: offer, seen: amina.sightings(amina.hold(offer)) };
  amina.hold(kept.record, kept.seen);
  output.push(`kept with the offer: when ${String(Object.keys(kept.seen).length)} proofs came`);
  for (const mind of [firm, agent, junior, amina]) mind.close();
  return output;
}
```

It gives:

```
Amina holds 1 record, an Offer
it is the firm's offer: true
one of 150 is the firm's: false
the firm's feed has a Revocation
it is the record the firm signed: true
a later offer is the firm's: false
the first still is: true
kept with the offer: when 3 proofs came
```

## A collective

[`examples/collective.ts`](examples/collective.ts) founds a collective of three, and signs for it:

```ts
import { type Clock, type Fetch, Lookup, Mind } from "@oip/client";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * Three people found a collective that acts when two of them agree.
 *
 * @param resolvers - The HTTPS origins of the resolvers they trust.
 * @param lock - What their keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  resolvers: readonly string[],
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<string[]> {
  const output: string[] = [];
  const person = async (): Promise<Mind> => {
    const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
    return Mind.create({ keystore, lock, resolvers, ...edges }, { kind: "human" });
  };
  const [ada, bo, cy] = [await person(), await person(), await person()];
  const members = [ada.address, bo.address, cy.address];

  // Each founder signs the genesis, with an invocation key of its own. Then anyone publishes it.
  let genesis = await ada.foundCollective({ members, threshold: 2 }, { invocation: lock });
  genesis = await bo.signEvent(genesis, { invocation: lock });
  genesis = await cy.signEvent(genesis, { invocation: lock });
  const club = await ada.publishLog([genesis]);
  const other = await new Lookup({ resolvers, ...edges }).resolve(club.mind);
  const signers = other.state.controller.kind === "member" ? other.state.controller.threshold : 0;
  output.push(`a ${other.state.kind} of ${String(members.length)}, of whom ${String(signers)} act`);

  // What one member signs in its name is one member's. With a second, it is the collective's.
  const intent = await ada.intent({ author: club.mind, want: "A hall for the spring meeting." });
  output.push(`signed by one: the collective's? ${String(await ada.countsFor(intent, club.mind))}`);
  const both = await bo.cosign(intent);
  output.push(`signed by two: the collective's? ${String(await bo.countsFor(both, club.mind))}`);
  for (const mind of [ada, bo, cy]) mind.close();
  return output;
}
```

It gives:

```
a collective of 3, of whom 2 act
signed by one: the collective's? false
signed by two: the collective's? true
```

## A charter

[`examples/charter.ts`](examples/charter.ts) gives a member of a collective a role, which the member then acts in alone, and takes in a fourth member.

```ts
import { type Clock, type Fetch, Mind, systemClock } from "@oip/client";
import { formatTimestamp } from "@oip/core";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * A collective gives one member a role, which that member then acts in
 * alone, and takes in a fourth member.
 *
 * @param resolvers - The HTTPS origins of the resolvers they trust.
 * @param lock - What their keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  resolvers: readonly string[],
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<string[]> {
  const output: string[] = [];
  const clock = edges.clock ?? systemClock;
  const person = async (): Promise<Mind> => {
    const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
    return Mind.create({ keystore, lock, resolvers, ...edges }, { kind: "human" });
  };
  const [ada, bo, cy, dee] = [await person(), await person(), await person(), await person()];
  const members = [ada.address, bo.address, cy.address];
  let genesis = await ada.foundCollective({ members, threshold: 2 }, { invocation: lock });
  genesis = await bo.signEvent(genesis, { invocation: lock });
  genesis = await cy.signEvent(genesis, { invocation: lock });
  const club = await ada.publishLog([genesis]);

  // A charter says what its members may do alone (Layer 2, 6.2). It is the collective's
  // record, so two of the three sign it.
  const draft = await ada.charter(club.mind, {
    name: "The club",
    purpose: "To meet in spring.",
    roles: {
      buyer: {
        purpose: "Books what the club needs.",
        powers: [
          { command: "/oip/sign/Intent", policy: [["<=", ".constraints.budget.max", "100"]] },
        ],
      },
    },
    assignments: [{ mind: cy.address, role: "buyer" }],
    expires: formatTimestamp(clock.now() + 365n * 86_400_000_000_000n),
  });
  const charter = await bo.cosign(draft);
  cy.hold(charter);

  // Cy is the buyer, and signs for the club alone, as far as the role goes.
  const wanting = (max: string) =>
    cy.intent(
      {
        author: club.mind,
        want: "A hall for the spring meeting.",
        constraints: { budget: { max } },
      },
      { charter },
    );
  output.push(
    `the buyer, within the budget: ${String(await cy.countsFor(await wanting("80"), club.mind))}`,
  );
  output.push(
    `the buyer, beyond it: ${String(await cy.countsFor(await wanting("150"), club.mind))}`,
  );

  // Dee joins, and three of the four must now agree. The members that are sign the change,
  // by their threshold, and so does the member that is new (Layer 1, 9.3).
  let update = await ada.changeCollective(
    club.mind,
    { members: [...members, dee.address], threshold: 3 },
    { invocation: lock },
  );
  update = await bo.signEvent(update, { invocation: lock });
  update = await dee.signEvent(update, { invocation: lock });
  const { state } = await ada.publishLog([genesis, update]);
  if (state.controller.kind === "member") {
    const { members: now, threshold } = state.controller;
    output.push(`now a collective of ${String(now.length)}, of whom ${String(threshold)} act`);
  }
  for (const mind of [ada, bo, cy, dee]) mind.close();
  return output;
}
```

It gives:

```
the buyer, within the budget: true
the buyer, beyond it: false
now a collective of 4, of whom 3 act
```

## What it exports

| Export                                                                                                                                                   | What it does                                                                                                                                                                                                                                                                                   |
| -------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Mind`, `MindOptions`, `NewMind`                                                                                                                         | A mind of one's own: `create` makes one with its keys in a keystore and its genesis with every resolver; `open` opens it; `sign` signs a record as it; `refresh` resolves it afresh; `close` locks its keys                                                                                    |
| `LocationFields`, `ProfileFields`, `Endpoint`, `Publication`, `homeEndpoints`, `DEFAULT_TTL`                                                             | What a mind publishes of itself: `Mind.publishLocation` (Layer 1, Section 15), `publishProfile` (16), `publishRecord` on its feed (10), `bringHomes`, and `moveHomes` to change hosts (15.4). `publications` says what each resolver and each home answered                                    |
| `IdentityChanges`, `KeyEntry`, `ControlOptions`                                                                                                          | What changes with an identity event, and what opens the control keys for it: `Mind.update`, `addKey`, `revokeKey`, `fork`, `retire` (Layer 1, 3.7 to 3.10)                                                                                                                                     |
| `Lookup`, `LookupOptions`, `Resolved`, `ResolverAnswer`, `DEFAULT_MAX_LOGS`                                                                              | Resolves a mind: fetches its identity log from the resolvers the client trusts, takes their first-seen times as evidence, and verifies the log with them (Layer 1, 17.1; core 9.4). With the log come the mind's current location record and profile, if a resolver served them and they count |
| `ReadFeed`, `HomeAnswer`, `DEFAULT_MAX_FEED_ENTRIES`                                                                                                     | `Lookup.feed` reads a mind's public feed from its homes and verifies it (Layer 1, 10 and 13.1)                                                                                                                                                                                                 |
| `Finding`, `Found`, `Listed`, `Ranking`, `NotFound`, `IndexerAnswer`, `MAX_RESULTS`                                                                      | `Lookup.find` asks the indexers the client names a capability query, and fetches and verifies every record they name before it returns it (Layer 1, 18.4). `Lookup.record` fetches a record a mind's homes serve, by its content ID                                                            |
| `AliasCheck`, `AliasOptions`, `DidLike`                                                                                                                  | `Lookup.aliases` checks the other names a mind gives itself: each is the mind's only if it points back (Layer 1, 5.3; Layer 0, Section 4)                                                                                                                                                      |
| `Message`, `Sent`, `Delivery`, `Inbox`, `Received`, `MailboxAnswer`, `DEFAULT_EXPIRES_IN`, `MAX_EXPIRES_IN`, `MAX_QUERY_EXPIRES_IN`, `MAX_MAILBOX_ITEMS` | `Mind.send` signs a packet, seals it to each recipient and posts it where the recipient takes packets (Layer 1, Section 12; 15.3). `Mind.receive` reads the mind's mailboxes and returns what was judged to be a packet for it (12.4, 13.5)                                                    |
| `Queued`, `Retried`, `MAX_QUEUED`                                                                                                                        | The outbox: a packet that did not reach a recipient, for a reason that may pass, is kept and tried again. `Mind.outbox` lists what waits, `retry` tries it now, `abandon` gives one up                                                                                                         |
| `Listening`, `ListenOptions`, `SocketState`, `OpenSocket`, `SocketLike`                                                                                  | `Mind.listen` holds a socket open to the mind's own host (Layer 1, 13.4): what the host keeps and what arrives is judged as `receive` judges it, and a connection that ends is opened again                                                                                                    |
| `SessionView`, `ChainView`, `SessionEvent`                                                                                                               | Sessions (Layer 1, Section 14): `Mind.openSession` names one, `send` with `session` sends in it, `receive` returns its packets in order and says in `sessions` what it found and did, `resume` asks for what is missing, `sessions` lists them, and `leaveSession` forgets one                 |
| `Grant`, `Acting`, `Fields`, `carried`, `Sightings`                                                                                                      | Delegation and the records of the Mind Web: `Mind.delegate`, `subDelegate` and `revoke` (Layer 1, Section 11); `intent`, `offer`, `commitment`, `receipt` and `cosign` (Layer 2, Sections 4 to 6); `countsFor` and `statusOf` (7 and 8); `hold`, `records` and `sightings`                     |
| `NewCollective`, `CollectiveChanges`, `MemberOptions`                                                                                                    | Collectives (Layer 1, Section 9): `Mind.foundCollective`, `changeCollective` and `signEvent` for a collective's identity events, which its members sign; `publishLog`; and `charter` for the roles its members may act in (Layer 2, 6.2)                                                       |
| `Clock`, `systemClock`                                                                                                                                   | The present, behind an interface: a test gives its own                                                                                                                                                                                                                                         |
| `exchange`, `askRecord`, `askJson`, `Asking`, `Answer`, `Fetch`, `TransportOptions`, `recordBody`, `refusalOf`, `httpsOrigin`                            | One request to a service over HTTPS, bounded in size and in time, and its answer read as a record or as JSON                                                                                                                                                                                   |
| `TransportError`, `TransportFailure`                                                                                                                     | Thrown when a service cannot be reached or does not speak the protocol                                                                                                                                                                                                                         |
| `DEFAULT_TIMEOUT_MS`, `DEFAULT_MAX_BYTES`, `MAX_DETAIL_LENGTH`                                                                                           | The bounds on an answer, unless a client gives its own                                                                                                                                                                                                                                         |

## What to know

### Resolving a mind

- **Name the resolvers you trust**, by their HTTPS origins: `new Lookup({ resolvers: ["https://resolver.example"] })`. A resolver is a witness (Layer 1, Section 17): its first-seen times are taken as evidence of when an identity event existed. Name more than one, run by different people. `resolve` asks them all, and a mind that showed one of them one event and another a different event for the same position is found out: `duplicitous` is `true`.
- **`resolve` applies the witness rule** (core 9.4). The time of each event comes from the resolver, never from the event's own date and never from the client's own first look. So a proof by a key that was since removed counts if it was seen before the resolver saw the removal, and does not count if it was seen after, whenever this client first met the log.
- **Resolve again before you judge something new.** A log held from an earlier fetch may lack the event that removed a key. `lookup.view` is what the judges of the other packages take (`ownSignedTime`, `receivePacket`, `countsFor`), and it knows each log up to the last time it was resolved.
- **Everything served is verified.** A resolver's copy of a log is verified by itself, every event of it, before it is held. A log that does not verify, a bundle of another mind, and a log served without times are each refused, with the resolver named. A collective's log is verified with its members' logs, which are fetched first: 64 logs at most for one mind, unless `maxLogs` says otherwise.
- **`sources` says what each resolver answered**: how many events it served, or why it served none.

### A mind of one's own

- **`Mind.create` needs a keystore that holds no mind yet**, a lock, and the resolvers the mind trusts. It makes the keys, signs the genesis and publishes it to every resolver. `publications` says which took it. One is enough for the mind to exist, and a mind SHOULD have two (Layer 1, 7.4). The homes the mind names are brought the genesis too.
- **The everyday keys stay unlocked while the mind is open**: the operational keys it signs with and the agreement keys records are sealed to. The control keys are unlocked for one identity change at a time, by the lock you pass to it, and locked again. Give them a lock of their own and the passphrase of everyday work cannot change the mind's identity.
- **Every identity change rotates the control keys.** An event reveals the keys the event before committed to, and commits to new ones (Layer 1, 3.4). `update({}, …)` does only that.
- **An identity change is made in an order that survives a process that stops.** The keystore binds the control keys to the event; the event is signed and verified here as any verifier would; it is published and read back from a resolver; then the keys that signed are destroyed (Layer 1, 3.11). The next change finishes one that stopped, with the same event, before it does anything else.
- **What is refused before it leaves costs nothing.** A change that cannot be signed, or that does not verify, is an `OipError` `invalid-record`. No key stays bound to it, and nothing was sent.
- **Two copies of a keystore must not both change the mind's identity.** The second to publish is told `duplicity`, or finds the log moved on to a key it does not hold: `forbidden`. A copy that signed an event and lost the position destroys the keys of that event and does not publish it.
- **After restoring a backup, change nothing until the mind is opened**: opening resolves it, and the first identity change destroys the control keys the log shows to be used. If the log has moved on to a key the backup does not hold, the mind's identity can no longer be changed from that keystore.
- **`revokeKey` with `compromisedSince`** withdraws what the key signed from that time on, for every verifier that learns of the event (Layer 1, 6.2). What it signed before stands.

### Publishing

- **A location record and a profile go to every resolver and to every home.** `publishLocation` signs the mind's next location record: its number is one more than the last, and what you leave out stays as the record before had it. With no record before, the endpoints are `homeEndpoints` of the mind's homes, the record is good for an hour, and the mind is `active`. `publishProfile` signs a profile, which supersedes the one before, and a location record that names it: that is what makes it current (Layer 1, 16.4).
- **`publications` says what each service answered.** Publishing succeeds when a resolver took the record. A home that could not be reached is brought the mind's records later, with `bringHomes`.
- **Every request is signed** by the mind's operational key, as Layer 1, 13.3 describes. A resolver that asks for authenticated publication takes it, and so does a host.
- **How a mind brings a host its records is the reference host's own interface.** Layer 1 says what a host serves, and leaves that open. A home that is not an [`@oip/host`](../host/README.md) answers these requests with something else, and `publications` says so.
- **The homes are brought every identity event**, since they serve the mind's log and judge its requests by it. A home takes a mind on when the mind first brings its bundle, if the host admits it.
- **A feed has one entry at each position, and two are equivocation** (Layer 1, 10.3). `publishRecord` remembers the entry before it leaves, and a call that failed is finished by the next one with the same entry. Calls are taken one after another.
- **Give the client a memory that lasts**: `memory` in the options, a storage of `@oip/keystore` of its own, not the keystore's. It holds where the feed stands and the number of the last location record. None of it is secret. Without it, or on a new device, the client reads the feed from the mind's homes and goes on from where it ends. It refuses to go on if the homes serve less than the mind's last location record says there is, or if none answers.
- **Two processes must not write one feed.** They find each other out in the memory, if they share it: the second to write is told `changed`, before its entry has left. If they do not share it, a home that holds another entry at the position answers `duplicity`. The client then forgets where it thought the feed stood, and the next call reads it afresh.
- **A location record says where the feed stood when it was signed.** Publish one after the entries that matter. A reader that finds less at a home than the record says knows the home is behind.
- **`Lookup.feed` reads every home and judges what they served together.** A home that withholds the end of a feed is made up for by one that serves it. It reads 10 000 entries of a feed from one home at most. An entry counts from when this client first saw it.

### Dealing

- **A record binds whoever it counts for, and nobody else** (Layer 2, Section 7): a mind by its own key, or by the proof of a delegate that names a chain of delegations covering the record. `countsFor` says whether, and `statusOf` computes the status of an Intent, an Offer or a Commitment as Section 8 defines it.
- **Both are computed from what the mind holds.** `hold` takes a record: a delegation, a Receipt, a record that supersedes another. What the mind signs is held, and so are the records carried by packets it accepts. Another verifier, holding other records, may compute another status. Records are held while the mind is open: `records()` gives them, to keep and to hold again.
- **Keep when each proof came, with the record.** A rule that depends on when a proof was made is judged by when a verifier can show it existed, and never by the date it carries (core 9.3). For most proofs the only evidence is the client's own record of when it first obtained them (core 9.4). `sightings(id)` gives that record for a record the mind holds, and `hold(record, sightings)` takes it back in a later run. Held again without it, a proof is first seen then: one that was signed under a delegation which has since expired, or was since revoked, counts no longer. A time later than the present is not believed.
- **Each time, the logs of the minds a record names are fetched afresh**, after its proofs were first seen (core 9.4). A key that was removed, or a mind that retired, does not count from then on.
- **`delegate` grants part of the mind's authority** (Layer 1, Section 11): a command, such as `/oip/sign/Commitment`, a policy that must hold of each record, and an expiry. A policy constrains only what it selects: constrain every term that matters, and exclude the delegate as a party. It bounds each record by itself, not a total.
- **A delegate signs for its principal by passing the chain**: `agent.commitment(fields, { chain: [mandate] })`. The proof carries the delegations, so any verifier can judge it. `as: "references"` names them only, and then the proof counts only for a verifier that already held them when it first saw the proof (11.4, item 1).
- **Where a promise says more than the terms, the terms bind a party signed for** (Layer 2, 5.4): a policy can check only them. Show such a party's commitment with the policy it was made under.
- **`cosign` adds this mind's proof to a record another made.** The content ID does not change. Read what you sign.
- **`revoke` takes a delegation back** from when a verifier first sees the revocation, and puts it on the mind's feed. What the delegate signed before stands. A verifier that relies on a delegate checks the principal's feed when the value warrants it (11.5).
- **`carried(record)`** is a record as the content of a packet. `send` it, and the recipient's `receive` holds it.
- **A packet sent for another mind** says so in `onBehalfOf`, with a chain that covers `/oip/send`. `receive` marks it `sentFor` only if that chain holds: a packet that merely says it is sent for someone is its sender's alone.

### Collectives

- **A collective is a mind its members control** (Layer 1, Section 9). It has no keystore of its own. Its identity events are signed by its members, each with an invocation key of its own mind, and its other records by the threshold of them, each with its own operational key.
- **Every founder signs the genesis** (9.2). `foundCollective` drafts it and signs as one of them. Give the event to each of the others for `signEvent`, in turn, and then `publishLog`. A later event needs the threshold of the members, and every member that is new (9.3): `changeCollective` drafts it.
- **`signEvent` adds this mind's proof, and unlocks its invocation keys for that alone.** The keystore remembers which event a key signed for each position of each collective's log, and signs no other: two would be duplicity, and would name the member.
- **`publishLog` verifies the log first**, as any verifier would, with the members' logs fetched afresh. A genesis a founder has not signed, or an event below the threshold, is refused before anything is published.
- **A record is the collective's once the threshold of its members has signed it** (9.5): write it with the collective as its `author`, and have the others `cosign`. `countsFor(record, collective)` says when.
- **A charter gives roles** (Layer 2, 6.2). `charter` writes one, and it is in force once the threshold has signed it. A member assigned to a role signs for the collective alone, within the role's powers, by passing `{ charter }` where a delegate passes a chain. Give a charter an `expires`.
- **Membership is what the identity log says**, and never what a charter says.

### Changing hosts

- **`moveHomes` brings the new host everything first** (Layer 1, 15.4): the mind's identity log, its location record and profile, and its whole feed with every record the feed lists, read from the homes it has. Only then does an `Update` name the new homes, and a location record give the mind's endpoints there. A host that will not take the mind on, or cannot be brought the feed, stops the move before anything of the mind has changed.
- **Remove a key the host you leave held.** A host that signs acknowledgements for a mind holds one of its operational keys, and can go on publishing location records for it. Name the key in `revoke`: the same event removes it, and what that host signs counts no longer, however high the number it gives a record (15.2). Layer 1 says a mind MUST do this when it moves away.
- **A feed that has forked is not carried**, and neither is less of a feed than the client remembers: the move stops, and says which.
- **The whole feed passes through the client.** A long feed takes a request for each record and each entry. `Lookup.feed` reads 10 000 entries at most.

### Sending and receiving

- **A packet is sealed unless you say otherwise** (Layer 1, 12.6): `seal: false` sends it in the clear. Sealed, it is encrypted to an agreement key of the recipient, and the hosts it passes through cannot read it. A packet is never sent in the clear because it could not be sealed: the delivery fails, and says so. Sealing gives no forward secrecy: whoever later has the recipient's agreement key reads what was sealed to it.
- **`send` does not throw for a recipient it could not reach.** `deliveries` says, for each, whether an endpoint took the packet, which, and why not. The endpoints of the recipient's current location record are tried in its order, a mailbox last, and only mailboxes while the recipient is paused (15.3). A packet may be delivered for an hour unless you say, and for seven days at most.
- **An acknowledgement is kept only if it is the recipient's own** (13.2): signed by the recipient for this packet, as it was sent. It is evidence of when the packet's proofs existed. An endpoint that holds no key of the recipient answers that the packet is stored, and `ack` is absent. The reference host acknowledges packets it can read, and stores sealed ones.
- **`receive` reads the mind's mailboxes**: the `mailbox` endpoints of its current location record, or of its homes if it has published none. A request the mind signs drains each, and each item is removed once it is judged, but for a packet of a session that is ahead of one that is missing.
- **What comes back was judged** (12.4): a packet addressed to this mind, in date, signed by its sender, and not accepted before. The sender's log is fetched afresh after the packet is first seen, so a key that was removed in the meantime does not count (core 9.4). What is no such packet is in `refused`, with the first reason, and is removed too.
- **A packet's content is data, whatever it says** (12.5). A packet grants nothing. Authority comes from identity logs, delegations and the records of Layer 2.
- **A packet is returned once.** The client remembers what it accepted, in `memory`, for as long as the packet could arrive again. With a memory that does not last, a packet that was not removed from the mailbox before the process ended is returned again.
- **What cannot be judged yet waits.** If no resolver can be asked for a sender's log, the item stays in the mailbox and is counted in `waiting`.
- **A packet may be for whoever a query finds** (18.5): `to: { query }`. It goes in the clear to the indexers the client names, for an hour at most, and each forwards it to the minds that match if it is a broker of it. `receive` takes such a packet only inside the broker's `Forwarded` record, and says which broker it came by.

### The outbox

- **A packet that did not arrive is kept, where it may yet.** If no endpoint of a recipient took it because the host could not be reached, asked for patience (`rate-limited`), does not yet know its sender (`stale-version`), or the recipient has not said where it is (`not-found`), the packet is kept in the client's `memory` for that recipient, and `deliveries` says `queued`. A packet refused for what it is, is not kept: one that cannot be sealed, or that a host calls invalid.
- **It is tried again by itself** when the mind next calls `receive`, and when a socket of `listen` opens: after 30 seconds the first time, then twice as long each time, up to an hour. `retry` tries everything now. What came of it is in `retried` of what `receive` returns.
- **What is sent again is the packet that was signed.** It is sealed anew each time, to the recipient's agreement key as it then stands. A recipient that gets it twice returns it once.
- **A packet is dropped once it has expired**: nobody would accept it (12.4). The default is an hour, so give a packet that should outlast a long silence a longer `expiresIn`, up to seven days. A packet of a session states no expiry, and waits until it arrives, the mind leaves the session, or `abandon` gives it up.
- **`queue: false` sends once**, and keeps nothing. A packet for a query (18.5) is never kept: nobody knows whom it is for.
- **The outbox holds 1,000 packets at most.** Past that, a packet that does not arrive is told so, without `queued`.

### Listening

- **`listen` is `receive`, as things arrive.** The host sends what the mailbox holds and then what comes in. Each record is judged as an item of the mailbox is (12.4), and `received` is called with what `receive` would have returned. Use one or the other, or both: a packet is returned once.
- **The mind tells its host what it has**, with an acknowledgement it signs, over the socket (13.4). The host keeps a record until then, so a connection that drops loses nothing, and a packet of a session that is ahead of a gap stays with the host as it stays in the mailbox.
- **What is refused is removed by reading the mailbox.** A host cannot be told over the socket that a record is no packet for the mind. When one is refused, the mailbox is read once over HTTP, which removes it.
- **A connection that ends is opened again**, after a wait that doubles from a second to a minute, and starts at a second again once the host has welcomed the mind. Each wait is shortened by up to half, at random, so that many clients do not all return at once. `retryMs` and `maxRetryMs` set the two bounds, and `changed` says where the connection stands.
- **The mind answers the host's challenge for the origin it connected to** (13.3), whatever the host says its own origin is. A host that passes the answer on to another finds it refused there.
- **`received` is called for one batch after another.** If it returns a promise, the next batch waits for it. What it throws ends the listening: `closed` rejects with it. A connection that drops does not.
- **`close` stops it**, and so does closing the mind. No connection is opened after it, and `closed` then settles.
- **It needs a `WebSocket`**: the platform's own in a browser and in Node.js from version 22, or one you give as `webSocket`. `sleep` is the timer between connections, which a test replaces.
- **The socket is for the mind's own mail.** `send` still posts to a recipient's inbox or mailbox over HTTPS. An endpoint that offers only a socket takes no packet from this client yet.

### Sessions

- **A session is named by a record, and each sender's packets in it are a chain** (Layer 1, 14.1, 14.3): numbered from 0, each naming the one before. `openSession` makes the record and sends nothing. Your first packet in the session carries it, and the client adds it to the content as a part.
- **You need not open a session someone else did.** The client follows it from the first packet of it that arrives. Send in it with its ID, which every packet of it has as `packet.session`.
- **A packet of a session is addressed to every other participant** (14.3), so that nobody misses a link of anyone's chain. `send` refuses one that is not. It may be addressed to others as well.
- **A packet has its place before it leaves.** It is written to the client's memory, with its place, before it is posted. A process that stops in between sends that packet again when asked, and never signs another for the same place. Give the client a `memory` that lasts: with one that is gone, the mind starts its chain again from 0, which every participant sees as two packets signed for one place.
- **`receive` returns the packets of a chain in order.** One that arrives ahead of one that is missing stays in the mailbox, and is returned after it. Nothing is lost if the process stops while it waits.
- **A gap is asked about once.** `receive` sends a `Resume` to the session's participants when it finds a gap: it says where each chain stands for this mind (14.4). Whoever lacks nothing ignores it, and whoever sent what is missing sends it again. `sessions` in what `receive` returns says so: `gap`, then `asked`. Call `resume` to ask again.
- **A participant's `Resume` is answered by `receive`**: what it lacks of this mind's packets is sent to it again, as they were signed. That is in `sessions` too, as `sent-again`. A `Resume` that names a packet this mind did not send at that place is not answered (`invalid-resume`).
- **Two packets signed for one place are told** (14.3): `equivocation`, with the content IDs of both. They are the evidence. Nothing of that chain is returned after it, since nothing tells which of the two its sender stands by.
- **A packet of a session states no `expires`**, unless you give `expiresIn`: it can then be sent again for as long as the session lasts. One that has expired cannot, and whoever missed it has a gap for good.
- **A session is taken up for seven days.** A packet that states no `expires` and belongs to no chain the client holds is refused once it is older than that (12.4). A mind that reads its mailbox less often than weekly misses the sessions opened with it in between.
- **Leave the sessions that are over**, with `leaveSession`. A session's packets are kept, to be sent again, until then. Anyone whose packets you accept can name you in a session, and the client follows 1,024 at most: leave the ones you want no part of.
- **A mind that runs several clients gives each an `instance`** (14.3), in the options: each then has a chain of its own in every session. Clients that share one `memory` are one instance, and are told `changed` when one of them is behind the other, before anything leaves.
- **What a session asks for may fail after the packets are read.** The packets are returned all the same, and `sessions` has `failed`, with what was being done and why.

### Aliases

- **A name a mind lists is not its name until the name points back** (Layer 1, 5.3). `lookup.aliases(mind)` asks what answers for each alias, and says which are verified. Show no other as the mind's (Layer 0, 4.2). `resolve` verifies none, and its DID document lists none.
- **An HTTPS origin** serves the address, alone, as `text/plain` at `/.well-known/oip/did`. The alias is the origin itself: `https://ada.example`, and no page of it.
- **`dns:<name>`** has a TXT record at `_oip.<name>` with `did=<address>`. A client asks the DNS with what you give it: `dnsTxt: resolveTxt` of `node:dns/promises` in Node.js. A browser has no DNS to ask, and such an alias is `unsupported` there unless you give it a way.
- **Another DID** lists the address in its own `alsoKnownAs`. The client resolves `did:oip` and `did:web` itself. For another method, give it `resolveDid`. A `did:key` has no document that could list anything, and is never verified.
- **`at://<handle>`** is an AT Protocol handle whose DID lists the address. The handle's DID is asked of the DNS where the client can ask it, and of the handle's own site otherwise.
- **What answers for an alias is a stranger.** It is asked over HTTPS only, with no redirect followed, and a kilobyte of text or 64 KiB of document is read of it. That it fails, or lies, makes the alias not verified, with `reason`: it never fails the call.

### Finding

- **Name the indexers you ask**: `indexers` in the options, by their HTTPS origins. An indexer is not trusted as a resolver is. What it answers is advice, and `find` returns nothing on its word alone.
- **An indexer's answer is taken if it is its own**: a `QueryResult` to the query that was asked, signed by a mind your resolvers hold. Of an answer it looks at as many results as the query's `limit`, 100 at most.
- **Every record named is fetched and verified** (Layer 1, 18.4). A profile is returned if it counts for its mind (16.1) and carries every tag asked for. An Offer or an Intent is returned if its author's own authority signed it and it has not expired. They are fetched from the homes the author's own log names: an indexer's `hints` are not followed.
- **`current` says whether a profile is the mind's current one** (16.4). An indexer may still list one the mind has replaced. It is returned only if the mind's homes still serve it, and marked.
- **`refused` says what was named and is not returned**, each with why, and `sources` what each indexer answered. `by` gives each indexer's own score for what was found. Scores of two indexers do not compare: ranking is each indexer's own policy.
- **A mind that publishes is listed.** `publishProfile` and `publishLocation` submit the mind's bundle and its profile to the indexers the client names, and `publications` says which took them. `publishRecord` does the same for an Offer or an Intent of the mind's own, once a home serves it: an indexer that cannot be told changes nothing of the feed.
- **A client that fetches for strangers is asked to fetch from where they say.** The homes of a mind are URLs its controller chose. In a browser that is as any link. On a server inside a private network, give the client a `fetch` that reaches only public addresses.

### In a browser

- **The client runs in a page as it is.** It uses the browser's own `fetch`, randomness and clock, and nothing of Node.js. Give the keystore `indexedDbStorage` of [`@oip/keystore`](../keystore/README.md), and the mind's keys are kept sealed in the browser's IndexedDB.
- **A service must let the page's origin ask.** A browser asks a service of another origin for leave before it sends a signed request, which carries `Content-Digest`, `Signature` and `Signature-Input`. The reference resolver, host and indexer give leave to every origin: they trust no request for where it comes from, only for what it proves.
- **A page that holds keys loads no script it does not control.** Whatever runs in the page can use the keys while they are unlocked (see the keystore's README).
- **It is tested in Chromium** ([ADR-0022](../../docs/adr/0022-the-client-in-a-browser.md)): the examples above run in a page, against the same services. `OIP_CHROMIUM=installed pnpm exec vitest run --project @oip/client test/browser.real.test.ts` runs it with the browser Playwright installed, and a path in place of `installed` with another.

### What stays the same

- **The public interface is frozen for 0.x.** It is written out in [`etc/client.api.md`](etc/client.api.md), and the build fails on any change to it that was not made there on purpose. A change that would break a caller comes with a new minor version and a changeset that says what to do.
- **What the client keeps in its `memory` is its own**, and may change between versions. It is read by the version that wrote it, and a version that cannot read it says `damaged`.

### Failures

- **A keystore's own failures are `KeystoreError`s**: a lock that does not open, a role that is unlocked already. They pass through as they are.
- **A service that refuses says why.** Its answer is a problem of core 10.2, and the client throws `OipError` with the service's code: `not-found`, `rate-limited`, `invalid-proof`. The `detail` is the service's own words, cut to 256 printable characters. They are a stranger's words: show them as that.
- **A service that cannot be asked** is a `TransportError`: `unreachable`, `timeout`, `too-large`, or `not-oip` for an answer that is not the protocol's. It names the origin, never the path.
- **Only HTTPS is asked, and no redirect is followed.** A service that has moved says so in a record, which is signed.
- **An answer is bounded** before it is read: 8 MiB and 10 seconds, unless the client says otherwise.
