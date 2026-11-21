// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The scenario of the papers (technical paper, Section 3.4), played by
 * real minds on a real network, and told as it happens.
 *
 * Amina, a person, needs a Swahili commercial lease translated into
 * English. Lexis Ltd, a translation firm, runs an agent that takes on such
 * work within limits the firm has delegated to it.
 *
 * Every line that begins with "verified" is something the program checked
 * before it said so: a signature, a chain of delegations, a status worked
 * out from the records. The telling stops at the first that does not hold.
 */

import { LOCAL } from "@oip/cli";
import { carried, type Grant, type Mind } from "@oip/client";
import { contentId, formatRecordRef, sha256Digest, utf8 } from "@oip/core";

import type { Player, Stage } from "./stage.ts";

/** What a telling established, for a program that wants more than the words. */
export interface Told {
  /** The address of each of the cast, by name. */
  readonly cast: Readonly<Record<string, string>>;
  /** The address of the collective that three of them found. */
  readonly collective: string;
  /** The content ID of the Commitment, the same before and after Amina signed it. */
  readonly commitment: string;
  /** How the Commitment stands at the end, as a mind that took no part works it out. */
  readonly status: string;
  /** How many things were verified on the way. */
  readonly verified: number;
}

/** Thrown when something the telling was about to say is not so. */
export class NotSo extends Error {
  override readonly name = "NotSo";
}

const TRANSLATION =
  "LEASE AGREEMENT. This lease is made between the Landlord and the Tenant for the commercial premises at Plot 14, Biashara Street, Nairobi, for a term of five years.";

/** A time some days from now, as a record writes one. */
const inDays = (days: number): string =>
  new Date(Date.now() + days * 86_400_000).toISOString().replace(/\.\d+Z$/u, "Z");

const ref = (author: Mind, record: object): string =>
  formatRecordRef(author.address, contentId(record));

/**
 * How a telling speaks: a step has a number and a title, and a thing is
 * said to be verified only if it is so.
 */
export function teller(say: (line: string) => void): {
  readonly step: (number: number, title: string) => void;
  readonly tellOf: (line: string) => void;
  /** @throws NotSo if it does not hold. Nothing is said then. */
  readonly verify: (holds: boolean, line: string) => void;
  /** How many things were verified so far. */
  readonly count: () => number;
} {
  let verified = 0;
  return {
    step: (number, title) => {
      say("");
      say(`${String(number)}. ${title}`);
    },
    tellOf: (line) => {
      say(`   ${line}`);
    },
    verify: (holds, line) => {
      if (!holds) throw new NotSo(`not so: ${line}`);
      verified += 1;
      say(`   verified: ${line}`);
    },
    count: () => verified,
  };
}

/**
 * Tells the scenario.
 *
 * @param say - Takes each line of the telling.
 * @throws NotSo if a check does not hold. Nothing is said of what was not checked.
 */
export async function tell(stage: Stage, say: (line: string) => void): Promise<Told> {
  const { step, tellOf, verify, count } = teller(say);

  say("The Open Intelligence Protocol: a translation, from want to Receipt");
  say("");
  say("A resolver, a host and an indexer run on this machine. Nothing else is trusted.");

  // 1. Identity.
  step(1, "Identity");
  const amina = await stage.cast("amina", "human", { name: "Amina" });
  const firm = await stage.cast("lexis-ltd", "institution", { name: "Lexis Ltd" });
  const agent = await stage.cast("lexis-agent", "agent", {
    name: "Lexis translation agent",
    summary: "Legal translation between Swahili and English, for Lexis Ltd.",
    capabilities: [
      {
        id: "translate-legal-sw-en",
        summary: "Translate Swahili commercial-law documents to and from English",
        tags: ["domain:legal/commercial", "lang:sw", "lang:en"],
        inputs: ["text/plain"],
        outputs: ["text/plain"],
      },
    ],
  });
  const cast: Player[] = [amina, firm, agent];
  const stranger = stage.stranger();
  for (const { mind, label } of cast) {
    const { state, participant } = await stranger.resolve(mind.address);
    const [first] = (await stranger.resolve(mind.address)).log.entries;
    tellOf(`${label} is ${mind.address}, a mind of kind ${state.kind}.`);
    verify(
      mind.address === `did:oip:${contentId(first.event)}` &&
        (participant?.record as { name?: string } | undefined)?.name === label,
      `a stranger resolves that address to a log whose first event has that hash, and to a profile it signed.`,
    );
  }

  // 2. Delegation.
  step(2, "Delegation");
  const policy: Grant["policy"] = [
    ["==", ".terms.price.currency", "USD"],
    ["<=", ".terms.price.amount", "500"],
    ["==", ".terms.price.payee", firm.mind.address],
    ["all", ".parties", ["!=", ".mind", agent.mind.address]],
  ];
  const mandate = await firm.mind.delegate({
    delegate: agent.mind.address,
    command: "/oip/sign/Commitment",
    policy,
    expires: inDays(30),
  });
  const offering = await firm.mind.delegate({
    delegate: agent.mind.address,
    command: "/oip/sign/Offer",
    expires: inDays(30),
  });
  await firm.mind.send({
    to: [agent.mind.address],
    verb: "inform",
    content: { parts: [carried(mandate), carried(offering)] },
  });
  await agent.mind.receive();
  tellOf("Lexis Ltd lets its agent sign Commitments for it: only where the firm is paid, in US");
  tellOf("dollars, 500 at most, never with the agent itself as a party, and for thirty days.");
  verify(
    await agent.mind.countsFor(mandate, firm.mind.address),
    "the delegation is signed by Lexis Ltd's own authority.",
  );

  // 3. Capability publication.
  step(3, "Capability publication");
  tellOf("The agent's profile says what it can do, with tags an indexer can match.");
  const query = { tags: ["lang:sw", "lang:en", "domain:legal/commercial"] };
  const finding = await stranger.find(query);
  verify(
    finding.found.some(({ mind }) => mind === agent.mind.address),
    "an indexer lists the agent for Swahili, English and commercial law, and the listing is a profile the agent signed.",
  );

  // 4. Intent.
  step(4, "Intent");
  const intent = await amina.mind.intent({
    want: "A Swahili commercial lease translated into English.",
    constraints: { budget: { max: "150", currency: "USD" } },
    audience: { query },
  });
  await amina.mind.publishRecord(intent);
  tellOf('Amina publishes an Intent: "A Swahili commercial lease translated into English",');
  tellOf("for 150 US dollars at most, addressed to whoever has that capability.");
  const asked = await amina.mind.send({
    to: { query },
    verb: "request",
    content: carried(intent),
  });
  const reached = await agent.mind.receive();
  const forwarded = reached.received.find(({ id }) => id === asked.id);
  verify(
    forwarded?.broker !== undefined && forwarded.from === amina.mind.address,
    "the indexer forwarded her packet to the agent, which found her signature on it and the broker's on its wrapper.",
  );
  verify((await agent.mind.statusOf(intent)) === "open", "the Intent is open.");

  // 5. Offer.
  step(5, "Offer");
  const offer = await agent.mind.offer(
    {
      author: firm.mind.address,
      provides: "An English translation of a Swahili commercial lease.",
      terms: { summary: "Within two days.", price: { amount: "120", currency: "USD" } },
      answers: ref(amina.mind, intent),
    },
    { chain: [offering] },
  );
  await agent.mind.send({ to: [amina.mind.address], verb: "propose", content: carried(offer) });
  await amina.mind.receive();
  tellOf("The agent sends Amina an Offer, signed for Lexis Ltd: 120 US dollars, within two days.");
  verify(
    await amina.mind.countsFor(offer, firm.mind.address),
    "the Offer counts for Lexis Ltd, by the delegation its proof carries.",
  );

  // 6. Commitment.
  step(6, "Commitment");
  const proposed = await agent.mind.commitment(
    {
      parties: [
        { mind: firm.mind.address, role: "debtor", required: true },
        { mind: amina.mind.address, role: "creditor", required: true },
      ],
      promise:
        "Lexis Ltd will deliver an English translation of the lease; Amina will pay 120 USD on delivery.",
      terms: {
        deadline: inDays(2),
        price: {
          amount: "120",
          currency: "USD",
          payer: amina.mind.address,
          payee: firm.mind.address,
        },
      },
      resolves: [ref(amina.mind, intent), ref(firm.mind, offer)],
      closesIntent: true,
    },
    { chain: [mandate] },
  );
  await agent.mind.send({ to: [amina.mind.address], verb: "propose", content: carried(proposed) });
  await amina.mind.receive();
  tellOf(
    "The agent drafts a Commitment: Lexis Ltd owes the translation, Amina owes 120 US dollars.",
  );
  tellOf("It signs for the firm. It is no party itself.");
  verify(
    await amina.mind.countsFor(proposed, firm.mind.address),
    "the agent's signature binds Lexis Ltd: the Commitment is within every limit of the delegation.",
  );
  verify(
    (await amina.mind.statusOf(proposed)) === "proposed",
    "it is proposed, and not in force: Amina has not signed.",
  );
  const accepted = await amina.mind.cosign(proposed);
  await amina.mind.publishRecord(accepted);
  await amina.mind.send({ to: [agent.mind.address], verb: "accept", content: carried(accepted) });
  await agent.mind.receive();
  await agent.mind.publishRecord(accepted);
  const commitment = contentId(accepted);
  tellOf("Amina adds her signature.");
  verify(
    contentId(proposed) === commitment,
    "its content ID is the same before and after her signature: both feeds name one object.",
  );
  verify(
    (await agent.mind.statusOf(accepted)) === "accepted",
    "the Commitment is in force: Lexis Ltd is debtor, Amina is creditor.",
  );
  verify((await amina.mind.statusOf(intent)) === "satisfied", "her Intent is satisfied by it.");

  // 7. Delivery.
  step(7, "Delivery");
  const session = await agent.mind.openSession([amina.mind.address]);
  const delivered = await agent.mind.send({
    to: [amina.mind.address],
    verb: "deliver",
    session: session.id,
    content: { mediaType: "text/plain", body: TRANSLATION },
  });
  const arrived = (await amina.mind.receive()).received.find(({ id }) => id === delivered.id);
  tellOf("The agent delivers the translation to Amina, sealed to her, in a session.");
  verify(
    arrived?.sealed === true && arrived.from === agent.mind.address,
    "the packet opened with Amina's key alone, and is signed by the agent.",
  );

  // 8. Receipt.
  step(8, "Receipt");
  const body = (arrived?.packet.content as { body?: unknown } | undefined)?.body;
  const receipt = await amina.mind.receipt({
    about: ref(agent.mind, accepted),
    outcome: "fulfilled",
    statement: "The translation was delivered, and reads well.",
    evidence: [
      {
        kind: "hash",
        ref: formatRecordRef(agent.mind.address, delivered.id),
        digest: sha256Digest(utf8(typeof body === "string" ? body : "")),
        mediaType: "text/plain",
      },
    ],
  });
  await amina.mind.publishRecord(receipt);
  tellOf("Amina publishes a Receipt: fulfilled, with the digest of what she was sent as evidence.");
  verify(
    (await amina.mind.statusOf(accepted)) === "fulfilled",
    "the Commitment is fulfilled: the party that was owed says so.",
  );

  // 9. Afterwards.
  step(9, "Afterwards");
  const onlooker = await stage.cast("onlooker", "human", { name: "An onlooker" });
  tellOf("A mind that took no part reads the feeds of Amina and of the agent, and nothing else.");
  let read = 0;
  for (const author of [amina.mind, agent.mind]) {
    const { feed } = await onlooker.mind.lookup.feed(author.address);
    for (const { entry } of feed.entries) {
      const judged = await onlooker.mind.lookup.record(author.address, entry.object);
      onlooker.mind.hold(judged.record);
      read += 1;
    }
  }
  // The firm's Offer is in nobody's feed: the Commitment names it, and it is fetched by that name.
  verify(
    read >= 4,
    `it found ${String(read)} records there, each signed and each under its content ID.`,
  );
  const held = onlooker.mind.records().find((record) => contentId(record) === commitment);
  verify(
    held !== undefined,
    "among them is the Commitment, under the content ID both parties gave.",
  );
  verify(
    held !== undefined && (await onlooker.mind.countsFor(held, firm.mind.address)),
    "it works out for itself that the agent's signature binds Lexis Ltd.",
  );
  const status = held === undefined ? "" : await onlooker.mind.statusOf(held);
  verify(status === "fulfilled", "and that the Commitment is fulfilled, by Amina's own Receipt.");

  // 10. The limits of the delegation.
  step(10, "The limits of the delegation");
  const deal = (amount: string, currency: string): Parameters<Mind["commitment"]>[0] => ({
    parties: [
      { mind: firm.mind.address, role: "debtor", required: true },
      { mind: amina.mind.address, role: "creditor", required: true },
    ],
    promise: `Lexis Ltd will deliver a second translation; Amina will pay ${amount} ${currency} on delivery.`,
    terms: {
      deadline: inDays(2),
      price: { amount, currency, payer: amina.mind.address, payee: firm.mind.address },
    },
  });
  tellOf("The agent signs two more Commitments for the firm, with the same delegation.");
  const tooMuch = await agent.mind.commitment(deal("600", "USD"), { chain: [mandate] });
  verify(
    !(await amina.mind.countsFor(tooMuch, firm.mind.address)),
    "one for 600 US dollars does not bind Lexis Ltd: the delegation says 500 at most.",
  );
  const inEuros = await agent.mind.commitment(deal("120", "EUR"), { chain: [mandate] });
  verify(
    !(await amina.mind.countsFor(inEuros, firm.mind.address)),
    "one for 120 euros does not bind it either: the delegation says US dollars.",
  );
  verify(
    (await amina.mind.statusOf(tooMuch)) === "proposed",
    "each stays proposed, whoever else signs it: the firm has not.",
  );

  // 11. Acting for a person.
  step(11, "Acting for a person");
  const assistant = await stage.cast("amina-assistant", "agent", { name: "Amina's assistant" });
  const sending = await amina.mind.delegate({
    delegate: assistant.mind.address,
    command: "/oip/send",
    expires: inDays(7),
  });
  const signing = await amina.mind.delegate({
    delegate: assistant.mind.address,
    command: "/oip/sign/Intent",
    expires: inDays(7),
  });
  tellOf("Amina lets her assistant send packets for her, for a week.");
  const thanks = await assistant.mind.send({
    to: [agent.mind.address],
    verb: "inform",
    content: { mediaType: "text/plain", body: "Amina thanks you. She will ask again." },
    onBehalfOf: { mind: amina.mind.address, chain: [sending] },
  });
  // The same words, with a delegation that is for something else.
  const claimed = await assistant.mind.send({
    to: [agent.mind.address],
    verb: "inform",
    content: { mediaType: "text/plain", body: "Amina asks for a refund." },
    onBehalfOf: { mind: amina.mind.address, chain: [signing] },
  });
  const heard = (await agent.mind.receive()).received;
  verify(
    heard.find(({ id }) => id === thanks.id)?.sentFor === amina.mind.address,
    "the agent takes the assistant's packet as sent for Amina: its proof carries her delegation to send.",
  );
  verify(
    heard.some(({ id }) => id === claimed.id) &&
      heard.find(({ id }) => id === claimed.id)?.sentFor === undefined,
    "a packet that only says it is sent for her, with a delegation for something else, is the assistant's own.",
  );

  // 12. A collective.
  step(12, "A collective");
  const researcher = await stage.cast("researcher", "agent", {
    name: "A research agent",
    summary: "Finds and checks legal terms.",
  });
  const members = [amina.mind.address, agent.mind.address, researcher.mind.address];
  let founding = await amina.mind.foundCollective(
    { members, threshold: 2, homes: [LOCAL.host] },
    { invocation: amina.lock },
  );
  founding = await agent.mind.signEvent(founding, { invocation: agent.lock });
  founding = await researcher.mind.signEvent(founding, { invocation: researcher.lock });
  const collective = (await amina.mind.publishLog([founding])).mind;
  tellOf("Amina, the agent and a research agent found a collective, to keep a glossary of Swahili");
  tellOf(`legal terms. It is a mind of its own: ${collective}.`);
  const founded = await stranger.resolve(collective);
  verify(
    founded.state.controller.kind === "member" && collective === `did:oip:${contentId(founding)}`,
    "its address is the content ID of a genesis event that all three signed, and it is controlled by its members.",
  );
  const call = await amina.mind.intent({
    author: collective,
    want: "Reviewers for a glossary of Swahili commercial-law terms.",
  });
  verify(
    !(await researcher.mind.countsFor(call, collective)),
    "an Intent that one member signs for it is not the collective's: any two of the three speak for it.",
  );
  const called = await researcher.mind.cosign(call);
  verify(
    await agent.mind.countsFor(called, collective),
    "with a second member's signature, it is.",
  );

  say("");
  say("No platform holds this record. The parties do, and anyone can check it.");
  say(`${String(count())} things were verified in this telling.`);

  return {
    cast: Object.fromEntries(
      [...cast, onlooker, assistant, researcher].map(({ name, mind }) => [name, mind.address]),
    ),
    collective,
    commitment,
    status,
    verified: count(),
  };
}
