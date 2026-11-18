// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Differential testing of delegation and of the Mind Web against the
 * independent Python checker (M3): generated policies, generated delegation
 * chains with a record signed under them, and generated sets of Layer 2
 * records whose status is asked.
 *
 * A case starts from something a test mind did rightly, and then something
 * is done to it: a link moved, dropped or given twice, a subject or a
 * delegate changed, a command widened, a statement of the policy lost, a
 * date moved across a limit, a revocation seen before or after the proof.
 * Both implementations decide every case completely, so the rule is "same".
 */

import { contentId, formatRecordRef, formatTimestamp, proofDigest } from "@oip/core";
import { policyHolds } from "@oip/delegation";
import { at, intentBy, KeyMind, type Mind, rawSign, T } from "@oip/testkit/minds";
import fc from "fast-check";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  claimHolds,
  type JsonObject,
  loadVectors,
  PythonJudge,
  pythonJudgeUnavailable,
  referenceAdapter,
  type VectorCase,
  viewFor,
} from "../src/index.ts";

const unavailable = pythonJudgeUnavailable();
const required = process.env["OIP_REQUIRE_PYTHON"] !== undefined;
// A short campaign with the ordinary tests; `pnpm run ci` and the nightly job set more.
const RUNS = Number(process.env["OIP_DIFFERENTIAL_DELEGATION"] ?? 150);
const TIMEOUT = Math.max(120_000, RUNS * 600);
const measured = process.env["OIP_MUTATION"] !== undefined;

const vectors = loadVectors();

type Signed = JsonObject & { proof: JsonObject[] };
type Events = readonly JsonObject[];

// ---------------------------------------------------------------- policies

/** Strings that are decimals, that nearly are, and that are not. */
const TEXTS = [
  "0",
  "1",
  "5",
  "5.0",
  "5.00",
  "-1",
  "-0",
  "0.1",
  "499.99",
  "500",
  "500.01",
  "1000000000000000000000",
  "0.000000000000000000001",
  "05",
  "+5",
  ".5",
  "5.",
  "1e3",
  "",
  " 5",
  "USD",
  "EUR",
  "did:oip:somebody",
] as const;

const scalar: fc.Arbitrary<unknown> = fc.oneof(
  fc.constantFrom<unknown>(...TEXTS),
  fc.integer({ min: -3, max: 600 }),
  fc.constantFrom<unknown>(true, false, null),
);

const NAMES = ["a", "b", "amount", "list", "x y", "proof"] as const;

/** A value as a record might hold: scalars, arrays and objects, a few deep. */
const { value: held } = fc.letrec<{ value: unknown }>((tie) => ({
  value: fc.oneof(
    { depthSize: "small", withCrossShrink: true },
    scalar,
    fc.array(tie("value"), { maxLength: 3 }),
    fc.dictionary(fc.constantFrom(...NAMES), tie("value"), { maxKeys: 3 }),
  ),
}));

const policyRecord: fc.Arbitrary<JsonObject> = fc.dictionary(fc.constantFrom(...NAMES), held, {
  maxKeys: 5,
});

/** Selectors that resolve in some records, that never do, and that are no selectors. */
const selector = fc.constantFrom(
  ".",
  ".a",
  ".b",
  ".amount",
  ".list",
  ".a.b",
  ".a.amount",
  ".list[0]",
  ".list[1].a",
  ".a[0]",
  ".a[2]",
  '.["x y"]',
  '["x y"]',
  '.a["x y"]',
  ".proof",
  ".a.proof",
  ".missing",
  ".a.missing.b",
  ".list[9]",
  // Not selectors (Layer 1, 11.3).
  "",
  "a",
  "..a",
  ".a[",
  ".a[-1]",
  ".a[01]",
  ".[0]",
  '.a["x]',
);

const comparison = fc.tuple(
  fc.constantFrom("==", "!=", "<", "<=", ">", ">="),
  selector,
  fc.oneof(scalar, fc.constantFrom<unknown>([], {}, ["USD"], { a: "5" })),
);

const { statement } = fc.letrec<{ statement: unknown }>((tie) => ({
  statement: fc.oneof(
    { depthSize: "small", withCrossShrink: true },
    comparison,
    comparison,
    fc.tuple(fc.constant("not"), tie("statement")),
    fc.tuple(fc.constantFrom("and", "or"), fc.array(tie("statement"), { maxLength: 3 })),
    fc.tuple(fc.constantFrom("all", "any"), selector, tie("statement")),
    // Not statements.
    fc.constantFrom<unknown>(
      [],
      ["xor", ".a", "5"],
      ["==", ".a"],
      ["==", ".a", "5", "6"],
      ["not"],
      ["and", []],
      ["and", ["==", ".a", "5"]],
      ["all", ".list"],
      "==",
      null,
    ),
  ),
}));

/** A statement nested `depth` deep in `not`: eight is the most a policy may nest (11.3). */
const nested = (depth: number): unknown => {
  let made: unknown = ["==", ".a", "5"];
  for (let i = 0; i < depth; i++) made = ["not", made];
  return made;
};

const policy: fc.Arbitrary<unknown> = fc.oneof(
  { weight: 12, arbitrary: fc.array(statement, { maxLength: 4 }) },
  { weight: 1, arbitrary: fc.constantFrom<unknown>([nested(7)], [nested(8)], [nested(9)]) },
  {
    weight: 1,
    arbitrary: fc.constantFrom<unknown>(
      Array.from({ length: 64 }, () => ["==", ".a", ".a"]),
      Array.from({ length: 65 }, () => ["==", ".a", ".a"]),
      {},
      "policy",
      null,
    ),
  },
);

/**
 * Policies made by hand, each with the record it is asked of and whether it
 * holds (Layer 1, 11.3). What a generator reaches only by chance is here on
 * purpose: decimals that are equal and spelt otherwise, the limits, every
 * kind of error under every connective.
 */
function policiesByHand(): [name: string, holds: boolean, policy: unknown, record: unknown][] {
  const deal = {
    terms: { price: { amount: "500.00", currency: "USD" }, quantity: 3 },
    parties: [
      { mind: "did:oip:a", role: "debtor" },
      { mind: "did:oip:b", role: "creditor" },
    ],
    tags: [],
    "x y": { "a.b": "5" },
    note: null,
    proof: [{ created: "2026-01-01T00:00:00Z" }],
  };
  const amount = ".terms.price.amount";
  const repeated = (count: number) => Array.from({ length: count }, () => ["==", ".tags", []]);
  return [
    ["no statement", true, [], deal],
    ["decimals equal by value, spelt otherwise", true, [["==", amount, "500"]], deal],
    ["and so not unequal", false, [["!=", amount, "500.0"]], deal],
    ["an integer and a decimal string", true, [["==", ".terms.quantity", "3.0"]], deal],
    ["a decimal string and an integer", true, [["==", amount, 500]], deal],
    ["at most, at the limit", true, [["<=", amount, "500"]], deal],
    ["less than, at the limit", false, [["<", amount, "500"]], deal],
    ["at least, at the limit", true, [[">=", amount, 500]], deal],
    ["more than, at the limit", false, [[">", amount, "500.000"]], deal],
    ["a cent over", false, [["<=", amount, "499.99"]], deal],
    ["a negative bound", true, [[">", amount, "-0.01"]], deal],
    ["text by its canonical form", true, [["==", ".terms.price.currency", "USD"]], deal],
    [
      "text that is no decimal is not ordered",
      false,
      [["<", ".terms.price.currency", "USE"]],
      deal,
    ],
    ["nor under a negation", false, [["not", [">=", ".terms.price.currency", "USE"]]], deal],
    [
      "nor beside a statement that holds",
      false,
      [
        [
          "or",
          [
            ["==", amount, "500"],
            ["<", ".note", 1],
          ],
        ],
      ],
      deal,
    ],
    ["an exponent is no decimal", false, [["<", amount, "1e3"]], deal],
    ["a leading zero is no decimal: unequal as text", true, [["!=", amount, "0500"]], deal],
    ["null by its canonical form", true, [["==", ".note", null]], deal],
    ["an array by its canonical form", true, [["==", ".tags", []]], deal],
    [
      "an object whatever the order of its members",
      true,
      [["==", ".terms.price", { currency: "USD", amount: "500.00" }]],
      deal,
    ],
    [
      "an object is not compared by the value of its decimals",
      false,
      [["==", ".terms.price", { amount: "500", currency: "USD" }]],
      deal,
    ],
    [
      "a boolean is no number",
      false,
      [["==", ".terms.quantity", true]],
      { terms: { quantity: 1 } },
    ],
    ["a member that is absent", false, [["==", ".terms.deadline", "soon"]], deal],
    ["is absent under a negation too", false, [["not", ["==", ".terms.deadline", "soon"]]], deal],
    [
      "and under an or",
      false,
      [
        [
          "or",
          [
            ["==", amount, "500"],
            ["==", ".terms.deadline", "soon"],
          ],
        ],
      ],
      deal,
    ],
    [
      "the proof is not part of the record",
      false,
      [["==", ".proof[0].created", "2026-01-01T00:00:00Z"]],
      deal,
    ],
    ["a proof deeper down is", true, [["==", ".a.proof", 1]], { a: { proof: 1 } }],
    ["a quoted name", true, [["==", '["x y"]["a.b"]', 5]], deal],
    ["a quoted name after a dot is no selector", false, [["==", '.["x y"]["a.b"]', 5]], deal],
    ["an index", true, [["==", ".parties[1].role", "creditor"]], deal],
    ["an index past the end", false, [["==", ".parties[2].role", "creditor"]], deal],
    ["an index into what is no array", false, [["==", ".terms[0]", 1]], deal],
    ["a name in what is no object", false, [["==", ".parties.role", "debtor"]], deal],
    ["the value itself", true, [["all", ".parties", ["!=", ".", null]]], deal],
    ["all, of every element", true, [["all", ".parties", ["!=", ".mind", "did:oip:c"]]], deal],
    ["all, with one that fails", false, [["all", ".parties", ["==", ".role", "debtor"]]], deal],
    ["any, with one that holds", true, [["any", ".parties", ["==", ".role", "debtor"]]], deal],
    ["any, with none", false, [["any", ".parties", ["==", ".mind", "did:oip:c"]]], deal],
    ["all of nothing holds", true, [["all", ".tags", ["==", ".", "x"]]], deal],
    ["any of nothing does not", false, [["any", ".tags", ["==", ".", "x"]]], deal],
    ["nor does its negation fail", true, [["not", ["any", ".tags", ["==", ".", "x"]]]], deal],
    ["a quantifier over what is no array", false, [["all", ".terms", ["==", ".", 1]]], deal],
    ["nor under a negation", false, [["not", ["any", ".terms", ["==", ".", 1]]]], deal],
    [
      "an error in one element only",
      false,
      [
        [
          "any",
          ".parties",
          [
            "or",
            [
              ["==", ".role", "debtor"],
              ["<", ".mind", 1],
            ],
          ],
        ],
      ],
      deal,
    ],
    [
      "and, with both",
      true,
      [
        [
          "and",
          [
            ["==", amount, 500],
            ["==", ".terms.quantity", 3],
          ],
        ],
      ],
      deal,
    ],
    [
      "and, with one",
      false,
      [
        [
          "and",
          [
            ["==", amount, 500],
            ["==", ".terms.quantity", 4],
          ],
        ],
      ],
      deal,
    ],
    [
      "or, with one",
      true,
      [
        [
          "or",
          [
            ["==", amount, 1],
            ["==", ".terms.quantity", 3],
          ],
        ],
      ],
      deal,
    ],
    [
      "or, with none",
      false,
      [
        [
          "or",
          [
            ["==", amount, 1],
            ["==", ".terms.quantity", 4],
          ],
        ],
      ],
      deal,
    ],
    [
      "every statement of the policy",
      false,
      [
        ["==", amount, 500],
        ["==", ".terms.quantity", 4],
      ],
      deal,
    ],
    ["nested as deep as a policy may: eight negations", true, [nested(8)], { a: 5 }],
    ["and one level less: seven", false, [nested(7)], { a: 5 }],
    ["and one level more", false, [nested(9)], { a: 5 }],
    ["one level more is no policy, whatever it says", false, [nested(10)], { a: 5 }],
    ["64 statements", true, repeated(64), deal],
    ["65 statements", false, repeated(65), deal],
    ["an and of nothing", false, [["and", []]], deal],
    ["a statement that is none", false, [["like", amount, "5*"]], deal],
    ["a selector that is none", false, [["==", "terms", 1]], { terms: 1 }],
    [
      "a selector with an index written with a zero before it",
      false,
      [["==", ".parties[01].role", "creditor"]],
      deal,
    ],
    [
      "a statement that is none, where no record reaches it",
      false,
      [["all", ".tags", ["==", "tags", 1]]],
      deal,
    ],
    ["nor under a negation", false, [["not", ["any", ".tags", ["like", ".", "a*"]]]], deal],
    ["a policy that is no list", false, { "0": ["==", amount, 500] }, deal],
    ["a record that is no object", true, [["==", ".", 5]], "5.0"],
  ];
}

// ---------------------------------------------------------------- chains

/** Pia delegates; the agents pass it on, one to the next; Sly is nobody's delegate. */
const pia = new KeyMind("pia");
const agents = Array.from({ length: 9 }, (_, n) => new KeyMind(`agent-${n}`));
const sly = new KeyMind("sly");
const everyone: Mind[] = [pia, ...agents, sly];
const LOGS = everyone.map((mind) => mind.events as unknown as Events);

/**
 * A record signed with a mind's first operational key, well formed or not,
 * as an attacker with the key could sign it.
 */
function signRaw(mind: Mind, record: object, authority?: readonly unknown[]): Signed {
  return rawSign(
    record,
    [{ member: mind.address, versionId: mind.versionId(0), invocation: mind.operational() }],
    {
      // core 5.3: a Delegation is signed for the purpose of delegating.
      purpose:
        (record as { type?: unknown }).type === "Delegation"
          ? "capabilityDelegation"
          : "assertionMethod",
      ...(authority === undefined ? {} : { authority: authority as string[] }),
    },
  );
}

/** When the record is signed. Links are made from 10 on, one every second. */
const SIGNED = 1000;
const LIMIT = ["<=", ".constraints.budget.max", "500"];
const FLOOR = [">=", ".constraints.budget.max", "1"];
const DOLLARS = ["==", ".constraints.budget.currency", "USD"];

const TWISTS = [
  "nothing",
  "nothing",
  "swap",
  "drop",
  "twice",
  "other subject",
  "in the author's name",
  "another delegate",
  "to itself",
  "another type",
  "a reserved command",
  "an extension's command",
  "statement lost",
  "statement added",
  "outlives its parent",
  "not yet",
  "at its start",
  "expired",
  "at its end",
  "made after the proof",
  "revoked before",
  "revoked just then",
  "revoked after",
  "revoked by another",
  "not held",
  "no policy",
  "a policy that is none",
] as const;
type Twist = (typeof TWISTS)[number];

interface ChainPlan {
  readonly length: number;
  readonly twists: readonly Twist[];
  /** Which link a twist is done to, and which other link it involves. */
  readonly picks: readonly number[];
  /** For each link, whether the proof names it by reference; otherwise it carries it whole. */
  readonly byReference: readonly boolean[];
  readonly amount: string | undefined;
  readonly currency: string;
  /** How long after the record's own date its proof was first seen. */
  readonly seenAfter: number;
  readonly signer: "the last delegate" | "the principal" | "an outsider";
  readonly asked: "the principal" | "the signer" | "the first delegate" | "an outsider";
  readonly type: "Intent" | "Offer";
}

const chainPlan: fc.Arbitrary<ChainPlan> = fc.record({
  length: fc.constantFrom(1, 1, 1, 2, 2, 3, 4, 8, 9),
  twists: fc.array(fc.constantFrom(...TWISTS), { minLength: 1, maxLength: 2 }),
  picks: fc.array(fc.nat(8), { minLength: 4, maxLength: 4 }),
  byReference: fc.array(fc.boolean(), { minLength: 9, maxLength: 9 }),
  amount: fc.constantFrom("120", "120", "500", "500.0", "500.01", "900", "0.5", "USD", undefined),
  currency: fc.constantFrom("USD", "USD", "USD", "EUR"),
  seenAfter: fc.constantFrom(0, 0, 0, 1, 299, 300, 301, 5000),
  signer: fc.constantFrom(
    "the last delegate",
    "the last delegate",
    "the last delegate",
    "the last delegate",
    "the principal",
    "an outsider",
  ),
  asked: fc.constantFrom(
    "the principal",
    "the principal",
    "the principal",
    "the signer",
    "the first delegate",
    "an outsider",
  ),
  type: fc.constantFrom("Intent", "Intent", "Intent", "Offer"),
});

function chainCase(plan: ChainPlan): VectorCase {
  {
    const seen: Record<string, string> = {};
    const extraRecords: JsonObject[] = [];
    const length = plan.length;
    const pick = (n: number): number => (plan.picks[n] ?? 0) % length;
    /** A link that has a parent, where the chain has one. */
    const child = (n: number): number =>
      length === 1 ? 0 : 1 + ((plan.picks[n] ?? 0) % (length - 1));
    const does = (twist: Twist, link: number, n = 0): boolean =>
      plan.twists.includes(twist) && pick(n) === link;
    const doesToChild = (twist: Twist, link: number): boolean =>
      plan.twists.includes(twist) && child(0) === link;

    const links: Signed[] = [];
    // What each link takes from its parent, as 11.4 requires of a valid chain: every
    // statement of the parent's policy, and an expiry no later than the parent's.
    let carried: unknown[] = [];
    let limit = 100_000;
    for (let i = 0; i < length; i++) {
      const author = i === 0 ? pia : agents[i - 1]!;
      const delegate = does("to itself", i)
        ? author
        : does("another delegate", i)
          ? sly
          : agents[i]!;
      // The first three links each add a statement of their own.
      let statements: unknown[] = [...carried, ...[LIMIT, FLOOR, DOLLARS].slice(i, i + 1)];
      if (doesToChild("statement lost", i) && i > 0) statements = statements.slice(1);
      if (does("statement added", i)) statements = [...statements, ["!=", ".want", ""]];
      if (does("no policy", i)) statements = [];
      carried = statements;
      const made = does("made after the proof", i) ? SIGNED + 400 : 10 + i;
      // The proof is evaluated at SIGNED and its evidence, with 300 seconds of grace (11.4).
      if (does("expired", i)) limit = Math.min(limit, SIGNED - 301);
      if (does("at its end", i)) limit = Math.min(limit, SIGNED - 300);
      const expires = doesToChild("outlives its parent", i) && i > 0 ? limit + 1 : limit;
      const command = does("another type", i)
        ? "/oip/sign/Receipt"
        : does("a reserved command", i)
          ? "/oip/sign"
          : does("an extension's command", i)
            ? "/com.example/translate"
            : `/oip/sign/${plan.type}`;
      const draft: JsonObject = {
        oip: "1",
        type: "Delegation",
        author: author.address,
        delegate: delegate.address,
        subject: does("other subject", i) ? sly.address : pia.address,
        command,
        ...(does("no policy", i)
          ? {}
          : { policy: does("a policy that is none", i) ? [["==", "a", "5"]] : statements }),
        ...(does("not yet", i) ? { notBefore: T(SIGNED + 301) } : {}),
        ...(does("at its start", i) ? { notBefore: T(SIGNED + 300) } : {}),
        expires: T(expires),
        nonce: `link-${String(i).padStart(4, "0")}`,
        created: T(made),
      };
      const signer = does("in the author's name", i) ? sly : author;
      links.push(signRaw(signer, draft));
    }
    for (const [i, link] of links.entries()) {
      for (const twist of [
        "revoked before",
        "revoked just then",
        "revoked after",
        "revoked by another",
      ] as const) {
        if (!does(twist, i, 1)) continue;
        const author = i === 0 ? pia : agents[i - 1]!;
        const by = twist === "revoked by another" ? sly : author;
        const revocation = signRaw(by, {
          oip: "1",
          type: "Revocation",
          author: by.address,
          revokes: formatRecordRef(String(link["author"]), contentId(link)),
          created: T(500),
        });
        // Seen a second before the proof is evaluated, at that very time, or a second after.
        const when =
          SIGNED +
          plan.seenAfter +
          (twist === "revoked after" ? 1 : twist === "revoked just then" ? 0 : -1);
        for (const proof of revocation.proof) seen[proofDigest(proof)] = formatTimestamp(at(when));
        extraRecords.push(revocation);
      }
    }
    let authority: unknown[] = links.map((link, i) => {
      if (plan.byReference[i] !== true) return link;
      if (!does("not held", i)) extraRecords.push(link);
      return formatRecordRef(String(link["author"]), contentId(link));
    });
    if (plan.twists.includes("swap") && length > 1) {
      const [a, b] = [pick(0), pick(2) === pick(0) ? (pick(0) + 1) % length : pick(2)];
      const turned = [...authority];
      [turned[a], turned[b]] = [turned[b], turned[a]];
      authority = turned;
    }
    if (plan.twists.includes("drop")) authority = authority.filter((_, i) => i !== pick(0));
    if (plan.twists.includes("twice")) {
      authority = [...authority.slice(0, pick(0) + 1), ...authority.slice(pick(0))];
    }

    const last = agents[length - 1]!;
    const signer =
      plan.signer === "the principal" ? pia : plan.signer === "an outsider" ? sly : last;
    const budget =
      plan.amount === undefined ? {} : { budget: { max: plan.amount, currency: plan.currency } };
    const content =
      plan.type === "Intent"
        ? intentBy(pia, SIGNED, { constraints: budget })
        : {
            oip: "1",
            type: "Offer",
            author: pia.address,
            created: T(SIGNED),
            provides: "Translation of leases.",
            terms: { summary: "One lease." },
            constraints: budget,
          };
    const record = signRaw(signer, content, authority);
    if (plan.seenAfter !== 0) {
      for (const proof of record.proof) {
        seen[proofDigest(proof)] = formatTimestamp(at(SIGNED + plan.seenAfter));
      }
    }
    const asked =
      plan.asked === "the principal"
        ? pia
        : plan.asked === "the signer"
          ? signer
          : plan.asked === "the first delegate"
            ? agents[0]!
            : sly;
    return {
      kind: "countsFor",
      name: "generated",
      record,
      mind: asked.address,
      extraLogs: LOGS,
      extraRecords,
      seen,
    };
  }
}

/**
 * Layer 1, 11.4 to 11.6: whether a chain that counts still does, with one
 * thing done to one of its links.
 *
 * @param link - The link it is done to. A twist that needs a parent is done to a link that has one.
 */
function stillCounts(twist: Twist, length: number, link: number, byReference: boolean): boolean {
  // A chain of one has nothing to swap, and no parent to take less from.
  if (twist === "swap" || twist === "statement lost" || twist === "outlives its parent") {
    return length === 1;
  }
  // Only the principal's own delegation may come without the statements of another.
  if (twist === "no policy") return link === 0;
  // A delegation the proof names and the verifier does not hold.
  if (twist === "not held") return !byReference;
  return HARMLESS.includes(twist);
}

/** What leaves a chain as good as it was. */
const HARMLESS: readonly Twist[] = [
  "nothing",
  // A statement more only narrows what is granted.
  "statement added",
  // The tolerance of core 9.1, either way, reaches exactly this far.
  "at its start",
  "at its end",
  // A revocation takes effect from its own evaluation time, and is its author's to make.
  "revoked after",
  "revoked by another",
];

// ---------------------------------------------------------------- status

/** Ann asks and is owed, Bo provides and owes, Cy is an outsider. */
const [ann, bo, cy] = ["ann", "bo", "cy"].map((name) => new KeyMind(name)) as [
  KeyMind,
  KeyMind,
  KeyMind,
];
const PARTIES: Mind[] = [ann, bo, cy];
const PARTY_LOGS = PARTIES.map((mind) => mind.events as unknown as Events);
const refOf = (record: JsonObject) => formatRecordRef(String(record["author"]), contentId(record));
const signedBy = (record: JsonObject, signers: readonly number[]): Signed => {
  let signed: object = record;
  for (const n of signers) signed = PARTIES[n]!.sign(signed, { position: 0 });
  return signed as Signed;
};

const who = fc.constantFrom(0, 0, 0, 1, 1, 2);
const signers = fc.subarray([0, 1, 2], { minLength: 1 });

interface StatusPlan {
  readonly of: "Intent" | "Offer" | "Commitment";
  readonly expires: number | undefined;
  readonly at: number;
  /** Records that supersede the one asked about. */
  readonly superseding: readonly {
    readonly author: number;
    readonly signer: number;
    readonly status: string | undefined;
    readonly ofAnotherType: boolean;
  }[];
  /** Commitments that list the Intent or the Offer in `resolves`. */
  readonly resolving: readonly {
    readonly signers: readonly number[];
    readonly closes: boolean | undefined;
    readonly creditor: number;
    readonly author: number;
  }[];
  readonly quantity: number | undefined;
  /** For a Commitment: who signed it, and what its terms say. */
  readonly signers: readonly number[];
  readonly watched: boolean;
  readonly deadline: number | undefined;
  readonly selfReport: boolean | undefined;
  readonly receipts: readonly {
    readonly author: number;
    readonly signers: readonly number[];
    readonly outcome: string;
    /** Which earlier Receipt it supersedes, if any. */
    readonly supersedes: number | undefined;
    readonly aboutAnother: boolean;
  }[];
}

const statusPlan: fc.Arbitrary<StatusPlan> = fc.record({
  of: fc.constantFrom("Intent", "Offer", "Commitment", "Commitment"),
  expires: fc.constantFrom(undefined, undefined, 2000),
  at: fc.constantFrom(500, 1999, 2000, 2001, 5000),
  superseding: fc.array(
    fc.record({
      author: fc.constantFrom(0, 0, 0, 1, 2),
      signer: fc.constantFrom(0, 0, 0, 1, 2),
      status: fc.constantFrom(undefined, "withdrawn", "satisfied", "exhausted"),
      ofAnotherType: fc.constantFrom(false, false, false, false, true),
    }),
    { maxLength: 3 },
  ),
  resolving: fc.array(
    fc.record({
      // Both parties, both and an outsider, or one alone.
      signers: fc.constantFrom([0, 1], [1, 2], [0, 1, 2], [1, 2], [0, 1], [1], [0], [2]),
      closes: fc.constantFrom(true, true, true, false, undefined),
      // Ann, whose Intent or Offer it is, or Cy: then the two commit between themselves.
      creditor: fc.constantFrom(0, 0, 2, 2),
      author: fc.constantFrom(1, 1, 1, 2),
    }),
    { maxLength: 3 },
  ),
  quantity: fc.constantFrom(undefined, 1, 1, 2),
  signers,
  watched: fc.constantFrom(false, false, true),
  deadline: fc.constantFrom(undefined, 2000),
  selfReport: fc.constantFrom(undefined, undefined, true, false),
  receipts: fc.array(
    fc.record({
      author: who,
      signers,
      outcome: fc.constantFrom(
        "accepted",
        "progress",
        "fulfilled",
        "fulfilled",
        "broken",
        "cancelled",
        "cancelled",
        "disputed",
        "revoked",
        "com.example:paused",
      ),
      supersedes: fc.constantFrom(undefined, undefined, 0, 1),
      aboutAnother: fc.constantFrom(false, false, false, false, true),
    }),
    { maxLength: 4 },
  ),
});

function commitmentBetween(
  seconds: number,
  debtor: number,
  creditor: number,
  more: JsonObject = {},
): JsonObject {
  return {
    oip: "1",
    type: "Commitment",
    author: PARTIES[debtor]!.address,
    created: T(seconds),
    parties: [
      { mind: PARTIES[debtor]!.address, role: "debtor", required: true },
      { mind: PARTIES[creditor]!.address, role: "creditor", required: true },
    ],
    promise: "Translate the lease.",
    terms: {},
    ...more,
  };
}

interface StatusQuestion {
  readonly kind: "status";
  readonly name: string;
  readonly of: JsonObject;
  readonly records: readonly JsonObject[];
  readonly at: string;
  readonly extraLogs: readonly Events[];
}

function statusQuestion(plan: StatusPlan): StatusQuestion {
  {
    const expires = plan.expires === undefined ? {} : { expires: T(plan.expires) };
    const records: JsonObject[] = [];
    let of: Signed;
    if (plan.of === "Commitment") {
      const terms = {
        ...(plan.deadline === undefined ? {} : { deadline: T(plan.deadline) }),
        ...(plan.selfReport === undefined ? {} : { selfReport: plan.selfReport }),
      };
      const draft = commitmentBetween(100, 1, 0, { terms });
      if (plan.watched) {
        (draft["parties"] as JsonObject[]).push({ mind: cy.address, role: "witness" });
      }
      of = signedBy(draft, plan.signers);
      const other = signedBy(commitmentBetween(101, 1, 0), [1, 0]);
      const made: Signed[] = [];
      plan.receipts.forEach((receipt, i) => {
        const earlier = receipt.supersedes === undefined ? undefined : made[receipt.supersedes];
        // A `revoked` Receipt supersedes an earlier one (Layer 2, 6.1).
        if (receipt.outcome === "revoked" && earlier === undefined) return;
        made.push(
          signedBy(
            {
              oip: "1",
              type: "Receipt",
              author: PARTIES[receipt.author]!.address,
              created: T(300 + i),
              about: refOf(receipt.aboutAnother ? other : of),
              outcome: receipt.outcome,
              ...(earlier === undefined ? {} : { supersedes: refOf(earlier) }),
            },
            receipt.signers,
          ),
        );
      });
      records.push(...made);
    } else {
      const base: JsonObject =
        plan.of === "Intent"
          ? { ...intentBy(ann, 100), ...expires }
          : {
              oip: "1",
              type: "Offer",
              author: ann.address,
              created: T(100),
              provides: "Translation of leases.",
              terms: {
                summary: "Leases.",
                ...(plan.quantity === undefined ? {} : { quantity: plan.quantity }),
              },
              ...expires,
            };
      of = signedBy(base, [0]);
      plan.superseding.forEach((later, i) => {
        const type = later.ofAnotherType ? (plan.of === "Intent" ? "Offer" : "Intent") : plan.of;
        const content: JsonObject =
          type === "Intent"
            ? intentBy(PARTIES[later.author]!, 200 + i)
            : {
                oip: "1",
                type: "Offer",
                author: PARTIES[later.author]!.address,
                created: T(200 + i),
                provides: "Translation of leases and deeds.",
                terms: { summary: "Leases and deeds." },
              };
        records.push(
          signedBy(
            {
              ...content,
              supersedes: refOf(of),
              ...(later.status === undefined ? {} : { status: later.status }),
            },
            [later.signer],
          ),
        );
      });
      plan.resolving.forEach((commitment, i) => {
        records.push(
          signedBy(
            commitmentBetween(
              400 + i,
              commitment.author,
              // A mind is a party once (Layer 2, 5.1).
              commitment.creditor === commitment.author ? 0 : commitment.creditor,
              {
                resolves: [refOf(of)],
                ...(commitment.closes === undefined ? {} : { closesIntent: commitment.closes }),
              },
            ),
            commitment.signers,
          ),
        );
      });
    }
    return {
      kind: "status",
      name: "generated",
      of,
      records: [of, ...records],
      at: T(plan.at),
      extraLogs: PARTY_LOGS,
    };
  }
}

describe.skipIf((unavailable !== undefined && !required) || measured)(
  "differential: delegation and status",
  () => {
    let judge: PythonJudge;
    const tally = new Map<string, Map<string, number>>();
    const count = (campaign: string, answer: string): void => {
      const answers = tally.get(campaign) ?? new Map<string, number>();
      tally.set(campaign, answers);
      answers.set(answer, (answers.get(answer) ?? 0) + 1);
    };

    beforeAll(() => {
      if (unavailable !== undefined) throw new Error(unavailable);
      judge = new PythonJudge();
    });

    afterAll(async () => {
      await judge.close();
      for (const [campaign, answers] of tally) {
        const listed = [...answers]
          .sort(([a], [b]) => (a < b ? -1 : 1))
          .map(([answer, times]) => `${answer} ${times}`)
          .join(", ");
        // For the log of the run: what both implementations answered, and how often.
        process.stdout.write(`differential, ${campaign}: ${listed}\n`);
      }
    });

    const shown = (value: unknown): string => JSON.stringify(value).slice(0, 6000);

    it(
      `agrees with the Python checker on ${RUNS * 4} generated policies`,
      async () => {
        await fc.assert(
          fc.asyncProperty(policy, policyRecord, async (statements, record) => {
            const question = { kind: "policy", name: "generated", policy: statements, record };
            const ours = policyHolds(statements, record as never);
            const theirs = await judge.judge(question);
            expect(
              { implementation: ours, judge: theirs.holds, judgeError: theirs.error },
              shown(question),
            ).toMatchObject({ implementation: theirs.holds });
            count("policies", ours ? "hold" : "do not hold");
          }),
          { numRuns: RUNS * 4 },
        );
        const answers = tally.get("policies");
        if (RUNS >= 100) expect(answers?.get("hold")).toBeGreaterThan(10);
      },
      TIMEOUT,
    );

    it("agrees with it, and with the rule, on policies made by hand", async () => {
      const made = policiesByHand();
      for (const [name, holds, statements, record] of made) {
        const question = { kind: "policy", name, policy: statements, record };
        const theirs = await judge.judge(question);
        expect(
          {
            implementation: policyHolds(statements, record as never),
            judge: theirs.holds,
            judgeError: theirs.error,
          },
          name,
        ).toStrictEqual({ implementation: holds, judge: holds, judgeError: undefined });
      }
      count("policies made by hand", `compared ${made.length}`);
      expect(made.length).toBeGreaterThan(55);
    });

    it("generates chains that count and chains that do not, for each thing done to them", () => {
      const sample = fc.sample(chainPlan, { numRuns: 300, seed: 5 });
      const counted = new Map<Twist, [counts: number, not: number]>();
      for (const plan of sample) {
        const holds = claimHolds(referenceAdapter, vectors, chainCase(plan)) === true;
        for (const twist of plan.twists) {
          const tallied = counted.get(twist) ?? [0, 0];
          counted.set(twist, tallied);
          tallied[holds ? 0 : 1]++;
        }
      }
      // An untouched chain counts and does not, by the amount and by who is asked.
      expect(counted.get("nothing")?.[0]).toBeGreaterThan(3);
      expect(counted.get("nothing")?.[1]).toBeGreaterThan(3);
      // Every twist is reached, and those that leave a chain valid leave some counting.
      for (const twist of TWISTS) expect(counted.get(twist), twist).toBeDefined();
      for (const twist of [
        "at its start",
        "at its end",
        "revoked after",
        "revoked by another",
      ] as const) {
        expect(counted.get(twist)?.[0], twist).toBeGreaterThan(0);
      }
    });

    it(
      "agrees with it, and with the rule, on each thing done alone to a chain that counts",
      async () => {
        let compared = 0;
        for (const twist of new Set(TWISTS)) {
          for (const length of [1, 2, 3]) {
            for (let link = 0; link < length; link++) {
              for (const byReference of [false, true]) {
                const plan: ChainPlan = {
                  length,
                  twists: [twist],
                  // The link the twist is done to, and for a swap the one after it.
                  picks: [link, link, link + 1, link],
                  byReference: Array.from({ length: 9 }, () => byReference),
                  amount: "120",
                  currency: "USD",
                  seenAfter: 0,
                  signer: "the last delegate",
                  asked: "the principal",
                  type: "Intent",
                };
                const vectorCase = chainCase(plan);
                const ours = claimHolds(referenceAdapter, vectors, vectorCase);
                const theirs = await judge.judge(vectorCase);
                const told = `${twist}, link ${link} of ${length}, ${byReference ? "by reference" : "given whole"}`;
                expect(
                  { implementation: ours, judge: theirs.holds, judgeError: theirs.error },
                  told,
                ).toStrictEqual({
                  implementation: stillCounts(twist, length, link, byReference),
                  judge: stillCounts(twist, length, link, byReference),
                  judgeError: undefined,
                });
                compared++;
              }
            }
          }
        }
        count("things done alone to a chain", `compared ${compared}`);
        expect(compared).toBeGreaterThan(300);
      },
      TIMEOUT,
    );

    it(
      `agrees with it on ${RUNS} generated delegation chains`,
      async () => {
        await fc.assert(
          fc.asyncProperty(chainPlan, async (plan) => {
            const vectorCase = chainCase(plan);
            const ours = claimHolds(referenceAdapter, vectors, vectorCase);
            expect(ours, `not judged: ${shown(plan)}`).toBeDefined();
            const theirs = await judge.judge(vectorCase);
            expect(
              { implementation: ours, judge: theirs.holds, judgeError: theirs.error },
              `${shown(plan)} ${shown(vectorCase)}`,
            ).toMatchObject({ implementation: theirs.holds });
            count("delegation chains", ours === true ? "count" : "do not count");
          }),
          { numRuns: RUNS },
        );
        if (RUNS >= 100) expect(tally.get("delegation chains")?.get("count")).toBeGreaterThan(5);
      },
      TIMEOUT,
    );

    it(
      `agrees with it on the status of ${RUNS} generated Intents, Offers and Commitments`,
      async () => {
        await fc.assert(
          fc.asyncProperty(statusPlan, async (plan) => {
            const question = statusQuestion(plan);
            const view = viewFor(vectors, {
              kind: "countsFor",
              name: "generated",
              record: question.of,
              mind: ann.address,
              extraLogs: question.extraLogs,
            });
            const ours = referenceAdapter.status?.(
              question.of,
              question.records,
              question.at,
              view,
            );
            const theirs = await judge.judge(question);
            expect(
              { implementation: ours, judgeError: theirs.error },
              `${shown(plan)} ${shown(question)}`,
            ).toStrictEqual({ implementation: theirs.value, judgeError: undefined });
            count("statuses", `${plan.of} ${String(ours)}`);
          }),
          { numRuns: RUNS },
        );
        // A campaign of any size reaches more than the status a record starts with.
        if (RUNS >= 100) expect(tally.get("statuses")?.size).toBeGreaterThan(8);
      },
      TIMEOUT,
    );
  },
);
