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
 *
 * What one mind sends another is judged as it arrived. The copy a mind
 * was sent, and not the copy the sender holds, is what the receiver
 * checks, signs and publishes: a packet that never travelled stops the
 * telling.
 */

import { LOCAL } from "@oip/cli";
import { carried, type Grant, type Mind, Reader, type Received, systemClock } from "@oip/client";
import {
  contentId,
  formatRecordRef,
  type JsonObject,
  MEDIA_TYPE,
  sha256Digest,
  utf8,
} from "@oip/core";

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

/** How long a mind reads its mailbox for a packet that was sent to it, in milliseconds. */
export const ARRIVAL_MS = 10_000;

/**
 * Reads a mind's mailbox until a packet is there, or it has read for so
 * long. An indexer answers its sender before it forwards (Layer 1, 18.5),
 * and a host takes a moment: a packet that was sent is on its way, and not
 * yet there.
 *
 * @returns The packet as the mind accepted it, or `undefined` if it did not come.
 */
async function arrival(mind: Mind, id: string): Promise<Received | undefined> {
  const until = Date.now() + ARRIVAL_MS;
  for (;;) {
    const found = (await mind.receive()).received.find((one) => one.id === id);
    if (found !== undefined || Date.now() > until) return found;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

/** One part of a packet's content. */
interface Part {
  readonly mediaType?: unknown;
  readonly body?: unknown;
}

/** The parts of a packet's content: one, where it has no parts. The first packet of a session has parts. */
const partsOf = (content: unknown): readonly Part[] =>
  typeof content === "object" &&
  content !== null &&
  Array.isArray((content as { parts?: unknown }).parts)
    ? (content as { parts: readonly Part[] }).parts
    : [content as Part];

/** The record of a content ID that a packet carries, as it arrived. */
function carriedBy(received: Received | undefined, id: string): JsonObject | undefined {
  for (const { mediaType, body } of partsOf(received?.packet.content)) {
    if (mediaType !== MEDIA_TYPE || typeof body !== "object" || body === null) continue;
    if (contentId(body) === id) return body as JsonObject;
  }
  return undefined;
}

/** The text a packet carries, as it arrived. */
function textIn(received: Received | undefined): string | undefined {
  const part = partsOf(received?.packet.content).find(
    ({ mediaType }) => mediaType === "text/plain",
  );
  return typeof part?.body === "string" ? part.body : undefined;
}

/**
 * How a telling speaks: a step has a number and a title, and a thing is
 * said to be verified only if it is so.
 */
export function teller(say: (line: string) => void): {
  readonly step: (number: number, title: string) => void;
  readonly tellOf: (line: string) => void;
  /** @throws NotSo if it does not hold. Nothing is said then. */
  readonly verify: (holds: boolean, line: string) => void;
  /**
   * What must be there for the telling to go on: something that arrived.
   *
   * @throws NotSo if it is not there, with what was to arrive.
   */
  readonly need: <T>(value: T | undefined, what: string) => T;
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
    need: (value, what) => {
      if (value === undefined) throw new NotSo(`not so: ${what}`);
      return value;
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
  const { step, tellOf, verify, need, count } = teller(say);

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
  const granted = await firm.mind.send({
    to: [agent.mind.address],
    verb: "inform",
    content: carried(mandate),
  });
  tellOf("Lexis Ltd lets its agent sign Commitments for it: only where the firm is paid, in US");
  tellOf("dollars, 500 at most, never with the agent itself as a party, and for thirty days.");
  const delegation = need(
    carriedBy(await arrival(agent.mind, granted.id), contentId(mandate)),
    "the delegation reached the agent.",
  );
  verify(
    await agent.mind.countsFor(delegation, firm.mind.address),
    "the delegation reached the agent, and is signed by Lexis Ltd's own authority.",
  );

  // 3. Capability publication.
  step(3, "Capability publication");
  tellOf("The agent's profile says what it can do, with tags an indexer can match.");
  const query = { tags: ["lang:sw", "lang:en", "domain:legal/commercial"] };
  // What a query finds is fetched and verified as its author's own before it is returned.
  const listing = (await stranger.find(query)).found.find(
    ({ mind }) => mind === agent.mind.address,
  );
  verify(
    listing?.record.type === "Participant" && listing.current,
    "an indexer lists the agent for Swahili, English and commercial law, and the listing is the agent's current profile, which it signed.",
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
  // The indexer answered her before it forwarded: the agent reads until the packet is there.
  const forwarded = await arrival(agent.mind, asked.id);
  verify(
    forwarded?.broker !== undefined && forwarded.from === amina.mind.address,
    "her packet reached the agent forwarded: it found her signature on the packet, and a broker's on its wrapper.",
  );
  const wanted = need(carriedBy(forwarded, contentId(intent)), "the packet carries her Intent.");
  verify((await agent.mind.statusOf(wanted)) === "open", "the Intent is open.");

  // 5. Offer.
  step(5, "Offer");
  // The agent's own Offer, as in the paper: an Offer binds nobody, and needs no delegation.
  const offer = await agent.mind.offer({
    provides: "An English translation of a Swahili commercial lease.",
    terms: {
      summary: "Within two days.",
      price: { amount: "120", currency: "USD" },
      deliveryBy: inDays(2),
    },
    answers: ref(amina.mind, wanted),
  });
  const offered = await agent.mind.send({
    to: [amina.mind.address],
    verb: "propose",
    content: carried(offer),
  });
  tellOf("The agent sends Amina an Offer of its own: 120 US dollars, delivered within two days.");
  const terms = need(
    carriedBy(await arrival(amina.mind, offered.id), contentId(offer)),
    "the Offer reached Amina.",
  );
  verify(
    (await amina.mind.countsFor(terms, agent.mind.address)) &&
      (await amina.mind.statusOf(terms)) === "open",
    "the Offer reached her, is signed by the agent, and stands open.",
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
      resolves: [ref(amina.mind, wanted), ref(agent.mind, offer)],
      closesIntent: true,
    },
    { chain: [mandate] },
  );
  const drafted = await agent.mind.send({
    to: [amina.mind.address],
    verb: "propose",
    content: carried(proposed),
  });
  tellOf(
    "The agent drafts a Commitment: Lexis Ltd owes the translation, Amina owes 120 US dollars.",
  );
  tellOf("It signs for the firm. It is no party itself.");
  const draft = need(
    carriedBy(await arrival(amina.mind, drafted.id), contentId(proposed)),
    "the Commitment reached Amina.",
  );
  verify(
    await amina.mind.countsFor(draft, firm.mind.address),
    "the agent's signature binds Lexis Ltd: the Commitment is within every limit of the delegation.",
  );
  verify(
    (await amina.mind.statusOf(draft)) === "proposed",
    "it is proposed, and not in force: Amina has not signed.",
  );
  // She signs the copy she was sent, and the agent publishes the copy she sent back.
  const accepted = await amina.mind.cosign(draft);
  await amina.mind.publishRecord(accepted);
  const returned = await amina.mind.send({
    to: [agent.mind.address],
    verb: "accept",
    content: carried(accepted),
  });
  const commitment = contentId(accepted);
  const inForce = need(
    carriedBy(await arrival(agent.mind, returned.id), commitment),
    "the Commitment came back to the agent with Amina's signature.",
  );
  await agent.mind.publishRecord(inForce);
  tellOf("Amina adds her signature.");
  verify(
    contentId(proposed) === commitment && contentId(inForce) === commitment,
    "its content ID is the same before and after her signature: both feeds name one object.",
  );
  verify(
    (await agent.mind.statusOf(inForce)) === "accepted",
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
  const arrived = await arrival(amina.mind, delivered.id);
  tellOf("The agent delivers the translation to Amina, sealed to her, in a session.");
  verify(
    arrived?.sealed === true &&
      arrived.from === agent.mind.address &&
      arrived.packet.session === session.id,
    "the packet came sealed to Amina, in that session, and is signed by the agent.",
  );

  // 8. Receipt.
  step(8, "Receipt");
  // The first packet of a session carries the session's record beside what is said: the text
  // is one part of its content.
  const translation = need(textIn(arrived), "the packet carries the translation as text.");
  const receipt = await amina.mind.receipt({
    about: ref(agent.mind, accepted),
    outcome: "fulfilled",
    statement: "The translation was delivered, and reads well.",
    evidence: [
      {
        kind: "hash",
        ref: formatRecordRef(agent.mind.address, delivered.id),
        digest: sha256Digest(utf8(translation)),
        mediaType: "text/plain",
      },
    ],
  });
  await amina.mind.publishRecord(receipt);
  tellOf("Amina publishes a Receipt: fulfilled, with the digest of what she was sent as evidence.");
  verify(
    receipt.evidence?.[0]?.digest === sha256Digest(utf8(TRANSLATION)),
    "the digest in the Receipt is the digest of the text the agent sent.",
  );
  verify(
    (await amina.mind.statusOf(accepted)) === "fulfilled",
    "the Commitment is fulfilled: the party that was owed says so.",
  );

  // 9. Afterwards.
  step(9, "Afterwards");
  // A stranger: a way to ask for logs and for what a mind published, and no key at all.
  const reader = new Reader({ lookup: stranger, clock: systemClock });
  tellOf("A stranger with no key at all reads the feeds of Amina, of the agent and of Lexis Ltd,");
  tellOf("and nothing else.");
  // The firm's feed too: a delegation's author publishes there what it has taken back (Layer
  // 1, 11.5), and a reader that did not look could not know.
  let listed = 0;
  for (const author of [firm.mind, amina.mind, agent.mind]) {
    const { feed } = await stranger.feed(author.address);
    for (const { entry } of feed.entries) {
      reader.hold((await stranger.record(author.address, entry.object)).record);
      listed += 1;
    }
  }
  const found = reader.held();
  let signed = 0;
  for (const record of found) {
    if (await reader.countsFor(record, (record as { author: string }).author)) signed += 1;
  }
  verify(
    found.length === 3 && listed === 4 && signed === found.length,
    "it found three records in four entries, the Commitment in two feeds, each under its content ID and signed by its author.",
  );
  const held = found.find((record) => contentId(record) === commitment);
  verify(
    held !== undefined,
    "among them is the Commitment, under the content ID both parties gave.",
  );
  verify(
    held !== undefined && (await reader.countsFor(held, firm.mind.address)),
    "it works out for itself that the agent's signature binds Lexis Ltd.",
  );
  const status = held === undefined ? "" : await reader.status(held);
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
  tellOf("The agent signs three more Commitments for the firm, with the same delegation.");
  // Each is the agent's own signature, whatever it does for the firm. What tells them apart
  // is the limit alone: at the limit the firm is bound, and a dollar over it, or in another
  // currency, it is not.
  const atLimit = await agent.mind.commitment(deal("500", "USD"), { chain: [mandate] });
  verify(
    (await amina.mind.countsFor(atLimit, agent.mind.address)) &&
      (await amina.mind.countsFor(atLimit, firm.mind.address)),
    "one for 500 US dollars binds Lexis Ltd: it is within the delegation.",
  );
  const tooMuch = await agent.mind.commitment(deal("600", "USD"), { chain: [mandate] });
  verify(
    (await amina.mind.countsFor(tooMuch, agent.mind.address)) &&
      !(await amina.mind.countsFor(tooMuch, firm.mind.address)),
    "one for 600 US dollars is the agent's signature, and does not bind Lexis Ltd: the delegation says 500 at most.",
  );
  const inEuros = await agent.mind.commitment(deal("120", "EUR"), { chain: [mandate] });
  verify(
    (await amina.mind.countsFor(inEuros, agent.mind.address)) &&
      !(await amina.mind.countsFor(inEuros, firm.mind.address)),
    "one for 120 euros does not bind it either: the delegation says US dollars.",
  );
  const both = [await amina.mind.cosign(tooMuch), await amina.mind.cosign(inEuros)];
  verify(
    (await amina.mind.statusOf(both[0])) === "proposed" &&
      (await amina.mind.statusOf(both[1])) === "proposed",
    "each of the two stays proposed though Amina signs it: the firm has not.",
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
      [...cast, assistant, researcher].map(({ name, mind }) => [name, mind.address]),
    ),
    collective,
    commitment,
    status,
    verified: count(),
  };
}
