// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The commands of the Mind Web (Layer 2): what a mind wants, what it
 * offers, what it promises, and what came of a promise.
 */

import { contentId, type JsonObject } from "@oip/core";
import { validateRecordOfType } from "@oip/schema";

import { withMind } from "@oip/local";

import { type Command, has, many, one, UsageError } from "../command.ts";
import {
  ACTING_FLAGS,
  actingOf,
  recordOf,
  refOf,
  SHARING_FLAGS,
  signed,
  statusOf,
  timeOf,
  who,
} from "./dealing.ts";
import { row } from "./describe.ts";

/** An amount as a command is given one: a decimal, written as text. A record holds no float. */
function amountOf(given: Parameters<typeof one>[0], flag: string): string | undefined {
  const amount = one(given, flag);
  if (amount !== undefined && !/^(0|[1-9][0-9]*)(\.[0-9]+)?$/u.test(amount)) {
    throw new UsageError(`${amount} is no amount: --${flag} is written as 120 or 99.50`);
  }
  return amount;
}

/** Who a record is meant for, as `--audience` says: `public`, or the minds named. */
function audienceOf(given: Parameters<typeof many>[0]): { audience?: "public" | string[] } {
  const named = many(given, "audience");
  if (named.length === 0) return {};
  if (named.includes("public")) {
    if (named.length > 1) throw new UsageError("--audience is public, or the minds it names");
    return { audience: "public" };
  }
  return { audience: [...named] };
}

const AUDIENCE = {
  type: "string",
  multiple: true,
  value: "address",
  describes: "Who it is meant for: public, or a mind. It may be given several times",
} as const;
const EXPIRES = {
  type: "string",
  value: "time",
  describes: "Until when it stands, as 2026-01-31T12:00:00Z",
} as const;

export const intent: Command = {
  name: "intent",
  summary: "Says what the mind wants: signs an Intent",
  flags: {
    want: { type: "string", value: "text", describes: "The outcome wanted, in words" },
    deadline: { type: "string", value: "time", describes: "By when, as 2026-01-31T12:00:00Z" },
    budget: { type: "string", value: "amount", describes: "The most it may cost, as 500 or 99.50" },
    currency: { type: "string", value: "code", describes: "What the budget is counted in: USD" },
    require: {
      type: "string",
      multiple: true,
      value: "text",
      describes: "Something an answer must meet. It may be given several times",
    },
    audience: AUDIENCE,
    expires: EXPIRES,
    ...ACTING_FLAGS,
    ...SHARING_FLAGS,
  },
  notes: [
    "An Intent binds nobody. It is what an Offer answers, and what a Commitment resolves.",
    "With --publish it goes on the mind's feed and to its indexers, for others to find.",
  ],
  example:
    'oip intent --want "A Swahili lease translated into English" --budget 150 --currency USD --publish',
  run: (context, given) => {
    const want = one(given, "want");
    if (want === undefined) throw new UsageError("an Intent says what is wanted: --want");
    const deadline = timeOf(given, "deadline");
    const expires = timeOf(given, "expires");
    const max = amountOf(given, "budget");
    const currency = one(given, "currency");
    if (max === undefined && currency !== undefined) {
      throw new UsageError("--currency is what a --budget is counted in: give the budget");
    }
    const requires = many(given, "require");
    const constraints = {
      ...(deadline === undefined ? {} : { deadline }),
      ...(max === undefined
        ? {}
        : { budget: { max, ...(currency === undefined ? {} : { currency }) } }),
      ...(requires.length === 0 ? {} : { requires: [...requires] }),
    };
    return withMind(context, async (opened) => {
      const { author, acting } = actingOf(opened, given);
      const record = await opened.mind.intent(
        {
          want,
          ...(Object.keys(constraints).length === 0 ? {} : { constraints }),
          ...audienceOf(given),
          ...(expires === undefined ? {} : { expires }),
          ...(author === undefined ? {} : { author }),
        },
        acting,
      );
      return signed(opened, record, given, "request");
    });
  },
};

export const offer: Command = {
  name: "offer",
  summary: "Says what the mind provides, and on what terms: signs an Offer",
  flags: {
    provides: { type: "string", value: "text", describes: "What is provided, in words" },
    summary: {
      type: "string",
      value: "text",
      describes: "The terms in a line. Default: what is provided",
    },
    price: { type: "string", value: "amount", describes: "What it costs, as 120 or 99.50" },
    currency: { type: "string", value: "code", describes: "What the price is counted in: USD" },
    "delivery-by": { type: "string", value: "time", describes: "By when it is delivered" },
    quantity: { type: "string", value: "count", describes: "How many times it can be taken up" },
    condition: {
      type: "string",
      multiple: true,
      value: "text",
      describes: "A condition of the terms. It may be given several times",
    },
    answers: {
      type: "string",
      value: "intent",
      describes: "The Intent it answers: the ID of one the mind holds, or a file",
    },
    capability: {
      type: "string",
      value: "id",
      describes: "The capability of the mind's profile it is an offer of",
    },
    audience: AUDIENCE,
    expires: EXPIRES,
    ...ACTING_FLAGS,
    ...SHARING_FLAGS,
  },
  notes: [
    "An Offer binds nobody until a Commitment takes it up: `oip commit --offer`.",
    "With --publish it goes on the mind's feed and to its indexers, for others to find.",
  ],
  example:
    'oip offer --provides "An English translation of a lease" --price 120 --currency USD --publish',
  run: (context, given) => {
    const provides = one(given, "provides");
    if (provides === undefined) throw new UsageError("an Offer says what is provided: --provides");
    const amount = amountOf(given, "price");
    const currency = one(given, "currency");
    if ((amount === undefined) !== (currency === undefined)) {
      throw new UsageError(
        "a price is an amount and what it is counted in: --price and --currency",
      );
    }
    const deliveryBy = timeOf(given, "delivery-by");
    const expires = timeOf(given, "expires");
    const quantity = one(given, "quantity");
    if (quantity !== undefined && !/^[1-9][0-9]{0,8}$/u.test(quantity)) {
      throw new UsageError(`${quantity} is no number of times an offer can be taken up`);
    }
    const conditions = many(given, "condition");
    const capability = one(given, "capability");
    const answers = one(given, "answers");
    return withMind(context, async (opened) => {
      const { author, acting } = actingOf(opened, given);
      const record = await opened.mind.offer(
        {
          provides,
          terms: {
            summary: one(given, "summary") ?? provides,
            ...(amount === undefined || currency === undefined
              ? {}
              : { price: { amount, currency } }),
            ...(deliveryBy === undefined ? {} : { deliveryBy }),
            ...(quantity === undefined ? {} : { quantity: Number(quantity) }),
            ...(conditions.length === 0 ? {} : { conditions: [...conditions] }),
          },
          ...(answers === undefined
            ? {}
            : { answers: refOf(recordOf(opened, answers, "the intent")) }),
          ...(capability === undefined ? {} : { capability }),
          ...audienceOf(given),
          ...(expires === undefined ? {} : { expires }),
          ...(author === undefined ? {} : { author }),
        },
        acting,
      );
      return signed(opened, record, given, "propose");
    });
  },
};

/**
 * The lines that say whom a Commitment binds now: each party for whom a
 * signature on it counts, its own or that of a mind it lets sign for it.
 */
async function binding(
  mind: Parameters<typeof statusOf>[0],
  record: JsonObject,
): Promise<{ lines: string[]; json: { mind: string; role: string; counts: boolean }[] }> {
  const parties = validateRecordOfType("Commitment", record);
  if (!parties.ok) return { lines: [], json: [] };
  const json: { mind: string; role: string; counts: boolean }[] = [];
  for (const party of parties.value.parties) {
    json.push({
      mind: party.mind,
      role: party.role,
      counts: await mind.countsFor(record, party.mind),
    });
  }
  return {
    lines: json.map(({ mind: party, role, counts }) =>
      row(role, `${party}: ${counts ? "bound" : "not bound"}`),
    ),
    json,
  };
}

export const commit: Command = {
  name: "commit",
  summary: "Makes a promise between minds: writes a Commitment, or signs one another wrote",
  positionals: "[commitment]",
  flags: {
    offer: {
      type: "string",
      value: "offer",
      describes: "Take up this Offer: its author owes, this mind is owed, on the Offer's terms",
    },
    debtor: {
      type: "string",
      multiple: true,
      value: "address",
      describes: "A mind that owes what is promised. `me` is this mind",
    },
    creditor: {
      type: "string",
      multiple: true,
      value: "address",
      describes: "A mind that is owed it. `me` is this mind",
    },
    witness: {
      type: "string",
      multiple: true,
      value: "address",
      describes: "A mind that witnesses it",
    },
    promise: { type: "string", value: "text", describes: "What is promised, in words" },
    deadline: { type: "string", value: "time", describes: "By when, as 2026-01-31T12:00:00Z" },
    price: { type: "string", value: "amount", describes: "What is paid, as 120 or 99.50" },
    currency: { type: "string", value: "code", describes: "What the price is counted in: USD" },
    payer: { type: "string", value: "address", describes: "Who pays. Default: the first creditor" },
    payee: {
      type: "string",
      value: "address",
      describes: "Who is paid. Default: the first debtor",
    },
    resolves: {
      type: "string",
      multiple: true,
      value: "record",
      describes: "An Intent or an Offer it resolves: an ID or a file",
    },
    "closes-intent": {
      type: "boolean",
      describes: "Once accepted, the Intent it resolves is satisfied",
    },
    ...ACTING_FLAGS,
    ...SHARING_FLAGS,
  },
  notes: [
    "A Commitment binds each mind whose signature on it counts, and is accepted once every",
    "debtor and creditor has signed. Read what you sign: it cannot be taken back, only answered",
    "with a Receipt.",
    "Given a Commitment, by the ID of one the mind holds or by a file, this signs it as it is.",
    "Otherwise it writes one, from an Offer or from the options, and signs that.",
  ],
  example: "oip commit --offer bciqexample --send-to did:oip:bciqexample",
  run: (context, given) => {
    const [named, ...more] = given.positionals;
    if (more.length > 0) throw new UsageError("commit takes one Commitment to sign, or none");
    const writing = ["offer", "debtor", "creditor", "witness", "promise", "price", "resolves"];
    if (named !== undefined && writing.some((flag) => given.flags[flag] !== undefined)) {
      throw new UsageError(
        "a Commitment another wrote is signed as it is: the options that write one do not go with it",
      );
    }
    const deadline = timeOf(given, "deadline");
    const amount = amountOf(given, "price");
    return withMind(context, async (opened) => {
      const { mind } = opened;
      const { author, acting } = actingOf(opened, given, true);
      if (named !== undefined) {
        const theirs = recordOf(opened, named, "the commitment");
        if (theirs["type"] !== "Commitment") throw new UsageError(`${named} is no Commitment`);
        const cosigned = await mind.cosign(theirs, acting);
        const bound = await binding(mind, cosigned);
        const said = await signed(opened, cosigned, given, "accept", bound.lines);
        return { lines: said.lines, json: { ...(said.json as object), parties: bound.json } };
      }
      const taken = one(given, "offer");
      const offered =
        taken === undefined
          ? undefined
          : validateRecordOfType("Offer", recordOf(opened, taken, "the offer"));
      if (offered !== undefined && !offered.ok)
        throw new UsageError(`${String(taken)} is no Offer`);
      const terms = offered?.value.terms;
      const debtors = many(given, "debtor").map((address) => who(mind, address));
      const creditors = many(given, "creditor").map((address) => who(mind, address));
      if (offered !== undefined) {
        // Who made the Offer owes what it provides, and who takes it up is owed it.
        if (debtors.length === 0) debtors.push(offered.value.author);
        if (creditors.length === 0) creditors.push(author ?? mind.address);
      }
      const [debtor] = debtors;
      const [creditor] = creditors;
      const promise = one(given, "promise") ?? offered?.value.provides;
      if (debtor === undefined || creditor === undefined || promise === undefined) {
        throw new UsageError(
          "a Commitment names who owes, who is owed, and what: --debtor, --creditor and --promise, or --offer",
        );
      }
      const price = amount ?? terms?.price?.amount;
      const currency = one(given, "currency") ?? terms?.price?.currency;
      if ((price === undefined) !== (currency === undefined)) {
        throw new UsageError(
          "a price is an amount and what it is counted in: --price and --currency",
        );
      }
      const due = deadline ?? terms?.deliveryBy;
      const resolves = [
        ...(offered === undefined ? [] : [refOf(offered.value as unknown as JsonObject)]),
        ...many(given, "resolves").map((ref) => refOf(recordOf(opened, ref, "the record"))),
      ];
      const record = await mind.commitment(
        {
          parties: [
            ...debtors.map((party) => ({ mind: party, role: "debtor" as const, required: true })),
            ...creditors.map((party) => ({
              mind: party,
              role: "creditor" as const,
              required: true,
            })),
            ...many(given, "witness").map((party) => ({
              mind: who(mind, party),
              role: "witness" as const,
            })),
          ],
          promise,
          terms: {
            ...(due === undefined ? {} : { deadline: due }),
            ...(price === undefined || currency === undefined
              ? {}
              : {
                  price: {
                    amount: price,
                    currency,
                    payer: who(mind, one(given, "payer") ?? creditor),
                    payee: who(mind, one(given, "payee") ?? debtor),
                  },
                }),
          },
          ...(resolves.length === 0 ? {} : { resolves }),
          ...(has(given, "closes-intent") ? { closesIntent: true } : {}),
          ...(author === undefined ? {} : { author }),
        },
        acting,
      );
      const bound = await binding(mind, record as unknown as JsonObject);
      const said = await signed(opened, record, given, "propose", bound.lines);
      return { lines: said.lines, json: { ...(said.json as object), parties: bound.json } };
    });
  },
};

const OUTCOMES = ["accepted", "progress", "fulfilled", "broken", "cancelled", "disputed"];

export const receipt: Command = {
  name: "receipt",
  summary: "Says what became of a record, usually a Commitment: signs a Receipt",
  positionals: "<record>",
  flags: {
    outcome: {
      type: "string",
      value: "outcome",
      describes: `What became of it: ${OUTCOMES.join(", ")}, or one of a namespace`,
    },
    statement: { type: "string", value: "text", describes: "More of it, in words" },
    score: { type: "string", value: "decimal", describes: "A rating from 0 to 1, as 0.9" },
    ...ACTING_FLAGS,
    ...SHARING_FLAGS,
  },
  notes: [
    "The record is named by the ID of one the mind holds, or by a file.",
    "A Commitment is fulfilled once a mind that is owed it says so, and broken or disputed",
    "by the word of any party. A Receipt is a statement by its author, and no more.",
  ],
  example: "oip receipt bciqexample --outcome fulfilled --score 1 --send-to did:oip:bciqexample",
  run: (context, given) => {
    const [named, ...more] = given.positionals;
    if (named === undefined || more.length > 0) {
      throw new UsageError("receipt takes one record it is about: an ID or a file");
    }
    const outcome = one(given, "outcome");
    if (outcome === undefined) {
      throw new UsageError(
        `a Receipt says what became of the record: --outcome ${OUTCOMES.join(", ")}`,
      );
    }
    const statement = one(given, "statement");
    const score = one(given, "score");
    if (score !== undefined && !/^(0(\.[0-9]+)?|1(\.0+)?)$/u.test(score)) {
      throw new UsageError(`${score} is no rating: --score is from 0 to 1, as 0.9`);
    }
    return withMind(context, async (opened) => {
      const { author, acting } = actingOf(opened, given);
      const about = recordOf(opened, named, "the record");
      const record = await opened.mind.receipt(
        {
          about: refOf(about),
          outcome: outcome,
          ...(statement === undefined ? {} : { statement }),
          ...(score === undefined ? {} : { rating: { score } }),
          ...(author === undefined ? {} : { author }),
        },
        acting,
      );
      const status = await statusOf(opened.mind, about);
      return signed(
        opened,
        record,
        given,
        "inform",
        status === undefined ? [] : [row("about", `${contentId(about)}, which is now ${status}`)],
      );
    });
  },
};

export const status: Command = {
  name: "status",
  summary: "Says where a record stands: its status, and whom it binds",
  positionals: "<record>",
  flags: {},
  notes: [
    "The record is named by the ID of one the mind holds, or by a file.",
    "A status is computed from the records this mind holds, and from the logs of the minds they",
    "name, fetched now. Another verifier, holding other records, may compute another.",
  ],
  example: "oip status bciqexample",
  run: (context, given) => {
    const [named, ...more] = given.positionals;
    if (named === undefined || more.length > 0) {
      throw new UsageError("status takes one record: an ID or a file");
    }
    return withMind(context, async (opened) => {
      const { mind } = opened;
      const record = recordOf(opened, named, "the record");
      const id = mind.hold(record);
      const stands = await statusOf(mind, record);
      const bound = await binding(mind, record);
      const { type, author } = record;
      const own =
        typeof author === "string" && bound.json.length === 0
          ? [{ mind: author, role: "author", counts: await mind.countsFor(record, author) }]
          : bound.json;
      return {
        lines: [
          id,
          row("type", typeof type === "string" ? type : "none"),
          ...(stands === undefined ? [] : [row("status", stands)]),
          ...(bound.lines.length > 0
            ? bound.lines
            : own.map((party) =>
                row(
                  "author",
                  `${party.mind}: ${party.counts ? "its own" : "not shown to be its own"}`,
                ),
              )),
        ],
        json: {
          mind: mind.address,
          id,
          type,
          ...(stands === undefined ? {} : { status: stands }),
          parties: own,
        },
      };
    });
  },
};
