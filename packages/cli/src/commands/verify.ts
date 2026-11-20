// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `oip verify`: verifies a record, an identity log, a bundle, or a mind by
 * its address, and says why of every verdict, with the clause of the
 * specification the verdict rests on.
 *
 * It signs nothing and unlocks no key. What it is given is as little
 * trusted as what a stranger sent, wherever it came from.
 */

import { Lookup, TransportError } from "@oip/client";
import {
  contentId,
  formatTimestamp,
  type Instant,
  type JsonObject,
  type JsonValue,
  OipError,
  verifyProofs,
} from "@oip/core";
import { delegatedProofTime, witnessProofs } from "@oip/delegation";
import { judgeRecord, operationalProofEvaluation, verifyLog } from "@oip/identity";
import { validateRecord } from "@oip/schema";
import { countsFor, WebRecordSet } from "@oip/web";

import { type Command, type Context, has, one, type Result, UsageError } from "../command.ts";
import { readJson } from "../files.ts";
import { type Config, Home } from "../home.ts";
import { lookupOptions, servicesOf } from "../mind.ts";
import { KeptRecords } from "../records.ts";
import { counted } from "../text.ts";
import { row } from "./describe.ts";
import { networkDirectory } from "./init.ts";

/** One thing that was checked, and what came of it. */
interface Verdict {
  /**
   * `ok`: it holds. `fails`: something is wrong with what was given. `no`:
   * it was judged, and the answer is no, with nothing wrong: a record does
   * not count for a party that has not signed it. `unknown`: it could not
   * be judged, for want of someone to ask.
   */
  readonly verdict: "ok" | "fails" | "no" | "unknown";
  /** What was checked, and what was found. */
  readonly what: string;
  /** The clause the verdict rests on. */
  readonly clause: string;
}

const yes = (what: string, clause: string): Verdict => ({ verdict: "ok", what, clause });
const no = (what: string, clause: string): Verdict => ({ verdict: "fails", what, clause });
const not = (what: string, clause: string): Verdict => ({ verdict: "no", what, clause });
const unknown = (what: string, clause: string): Verdict => ({ verdict: "unknown", what, clause });

/** An address of a mind, wherever it stands in a string. */
const ADDRESS = /did:oip:bciq[a-z2-7]{52}/gu;
const CONTENT_ID = /^bciq[a-z2-7]{52}$/u;
const EVENTS = new Set(["Genesis", "Update", "Fork", "Retire"]);
/** The most minds whose logs are fetched to judge one record. */
const MAX_MINDS = 64;

/** Every address of a mind that a value names, at any depth. */
function mindsIn(value: unknown, into: Set<string>): void {
  if (typeof value === "string") {
    for (const [address] of value.matchAll(ADDRESS)) into.add(address);
  } else if (Array.isArray(value)) {
    for (const item of value) mindsIn(item, into);
  } else if (typeof value === "object" && value !== null) {
    for (const member of Object.values(value)) mindsIn(member, into);
  }
}

/** What a verifier holds while it judges: the logs it fetched, and the records it was given. */
interface Holding {
  readonly lookup: Lookup;
  readonly records: WebRecordSet;
  readonly now: Instant;
}

/** Fetches the logs of the minds a value names, afresh, and says which could not be had. */
async function fetchLogs(
  holding: Holding,
  value: unknown,
): Promise<{ verdicts: Verdict[]; missing: Set<string> }> {
  const minds = new Set<string>();
  mindsIn(value, minds);
  const verdicts: Verdict[] = [];
  const missing = new Set<string>();
  for (const mind of [...minds].slice(0, MAX_MINDS)) {
    try {
      await holding.lookup.resolve(mind);
    } catch (error) {
      if (!(error instanceof OipError || error instanceof TransportError)) throw error;
      const code = error instanceof OipError ? error.code : error.failure;
      missing.add(mind);
      verdicts.push(
        unknown(`the log of ${mind} could not be had from the resolvers (${code})`, "core 9.4"),
      );
    }
  }
  return { verdicts, missing };
}

/** The verdicts on one record: its form, each of its proofs, and for whom it counts. */
async function verdictsOnRecord(
  value: JsonValue,
  holding: Holding | undefined,
): Promise<Verdict[]> {
  const formed = validateRecord(value);
  if (!formed.ok) {
    return formed.issues.map(({ message, clause, path }) =>
      no(`it is no well-formed record: ${message}${path === "" ? "" : ` at ${path}`}`, clause),
    );
  }
  const record = formed.value;
  const verdicts = [yes(`it is a well-formed ${record.type}`, "core 2.1")];
  if (EVENTS.has(record.type)) {
    return [
      ...verdicts,
      unknown(
        "an identity event is judged in its log: verify the log, or the mind by its address",
        "L1 4.1",
      ),
    ];
  }
  const proofs = verifyProofs(record);
  verdicts.push(
    ...proofs.issues.map(({ message, clause }) => no(`its proofs: ${message}`, clause)),
  );
  for (const { index, issues } of proofs.rejected) {
    const [{ message, clause }] = issues;
    verdicts.push(no(`proof ${String(index)} does not verify: ${message}`, clause));
  }
  for (const { index, key } of proofs.verified) {
    verdicts.push(yes(`proof ${String(index)} is a good signature by the key ${key}`, "core 5.4"));
  }
  if (holding === undefined) {
    return [
      ...verdicts,
      unknown("whose keys those are was not asked: there is no resolver to ask", "L1 6.1"),
    ];
  }
  const judged = judgeRecord(record);
  if (!judged.ok) {
    const [{ message, clause }] = judged.issues;
    return [...verdicts, no(`it may not be relied on: ${message}`, clause)];
  }
  holding.records.add(record);
  // Its proofs are first seen now, unless the mind's own record says they came earlier. The
  // logs they are judged by are fetched after that (core 9.4).
  witnessProofs(judged.value, holding.now, holding.lookup.seen);
  const fetched = await fetchLogs(holding, [record, ...judged.value.proofs.map((p) => p.proof)]);
  verdicts.push(...fetched.verdicts);
  const context = { identity: holding.lookup.view, records: holding.records };
  const { author } = record as { author?: unknown };
  const parties = (record as { parties?: readonly { mind?: unknown }[] }).parties ?? [];
  const principals = [
    ...new Set(
      [author, ...parties.map((party) => party.mind)].filter(
        (mind): mind is string => typeof mind === "string",
      ),
    ),
  ];
  for (const proof of judged.value.proofs) {
    const named = `proof ${String(proof.index)}`;
    if (proof.method.kind !== "key") {
      verdicts.push(
        no(`${named} is by a control key, which signs identity events alone`, "core 6.2"),
      );
      continue;
    }
    const signer = proof.method.mind;
    if (fetched.missing.has(signer)) {
      // Nothing is known against it: there is only nobody to say whose key that is.
      verdicts.push(
        unknown(
          `${named} cannot be judged: it names a key of ${signer}, whose log was not had`,
          "L1 6.1",
        ),
      );
      continue;
    }
    const own = operationalProofEvaluation(record.type, proof, context.identity);
    if (!own.ok) {
      const [{ message, clause }] = own.issues;
      verdicts.push(no(`${named} is not by a valid key of ${signer}: ${message}`, clause));
      continue;
    }
    const at = formatTimestamp(own.value.time);
    verdicts.push(yes(`${named} is by a key of ${signer} that was valid at ${at}`, "L1 6.1"));
    if (proof.proof.authority === undefined) continue;
    // It names an authority: it is signed for another, by a chain of delegations or a charter.
    const others = principals.filter((mind) => mind !== signer);
    const through = others.map((principal) => ({
      principal,
      time: delegatedProofTime(judged.value, proof, principal, context),
    }));
    const held = through.find(({ time }) => time.ok);
    if (held !== undefined) {
      verdicts.push(
        yes(`${named} counts for ${held.principal} through the delegations it names`, "L1 11.4"),
      );
    } else {
      for (const { principal, time } of through) {
        if (time.ok) continue;
        const [{ message, clause }] = time.issues;
        verdicts.push(
          no(`${named} does not count for ${principal} through a delegation: ${message}`, clause),
        );
      }
    }
  }
  for (const mind of principals) {
    if (countsFor(judged.value, mind, context)) {
      verdicts.push(yes(`it counts for ${mind}`, "L2 7.1"));
    } else if (fetched.missing.size > 0) {
      verdicts.push(
        unknown(
          `whether it counts for ${mind} cannot be judged without the logs that were not had`,
          "L2 7.1",
        ),
      );
    } else {
      verdicts.push(
        not(
          `it does not count for ${mind}: no signature on it is that mind's, or made for it`,
          "L2 7.1",
        ),
      );
    }
  }
  return verdicts;
}

/** The verdicts on an identity log, as it was given. */
async function verdictsOnLog(
  events: readonly JsonValue[],
  holding: Holding | undefined,
  now: Instant,
): Promise<{ verdicts: Verdict[]; mind?: string }> {
  // The members of a collective sign its events: their logs are needed, and fetched first.
  const fetched = holding === undefined ? [] : (await fetchLogs(holding, events)).verdicts;
  const own = verifyLog(events, {
    // Each event is first seen now at the latest, unless a resolver saw it before.
    evidence: {
      eventSeen: (id) => {
        const witnessed = holding?.lookup.view.evidence.eventSeen(id);
        return witnessed !== undefined && witnessed < now ? witnessed : now;
      },
      proofSeen: () => undefined,
    },
    asOf: now,
    ...(holding === undefined ? {} : { memberLog: (member) => holding.lookup.view.log(member) }),
  });
  if (!own.ok) {
    return {
      verdicts: [
        ...own.issues.map(({ message, clause, path }) =>
          no(`the log does not verify: ${message}${path === "" ? "" : ` at ${path}`}`, clause),
        ),
        ...fetched,
      ],
    };
  }
  const log = own.value;
  const last = log.entries.at(-1);
  const verdicts = [
    yes(
      `the log verifies: ${counted(log.entries.length, "event")} of ${log.mind}${
        last?.state.retired === true ? ", which is retired" : ""
      }`,
      "L1 4.1",
    ),
  ];
  if (holding === undefined) {
    return {
      verdicts: [
        ...verdicts,
        unknown("whether the resolvers hold the same log was not asked", "L1 7.1"),
      ],
      mind: log.mind,
    };
  }
  try {
    const resolved = await holding.lookup.resolve(log.mind);
    const theirs = resolved.log.entries;
    const shared = Math.min(theirs.length, log.entries.length);
    const parted = log.entries
      .slice(0, shared)
      .findIndex(
        (entry, index) => contentId(entry.event) !== contentId(theirs[index]?.event ?? {}),
      );
    if (parted >= 0) {
      verdicts.push(
        no(
          `the resolvers hold another event at position ${String(parted)}: the mind signed two, which is duplicity`,
          "L1 7.1",
        ),
      );
    } else if (theirs.length === log.entries.length) {
      verdicts.push(yes("the resolvers hold the same log", "L1 17.1"));
    } else if (theirs.length > log.entries.length) {
      verdicts.push(
        unknown(
          `the resolvers hold ${counted(theirs.length - log.entries.length, "event")} more: this copy is behind`,
          "L1 17.1",
        ),
      );
    } else {
      verdicts.push(
        unknown(
          `this copy has ${counted(log.entries.length - theirs.length, "event")} the resolvers do not hold yet`,
          "L1 17.1",
        ),
      );
    }
    if (resolved.duplicitous) {
      verdicts.push(no("the resolvers show the mind's duplicity", "L1 7.3"));
    }
  } catch (error) {
    if (!(error instanceof OipError || error instanceof TransportError)) throw error;
    const code = error instanceof OipError ? error.code : error.failure;
    verdicts.push(unknown(`the resolvers do not serve the mind (${code})`, "L1 17.1"));
  }
  return {
    verdicts: [...verdicts, ...fetched.filter(({ what }) => !what.includes(log.mind))],
    mind: log.mind,
  };
}

/** The verdicts on a mind, by its address: what the resolvers serve of it. */
async function verdictsOnMind(address: string, holding: Holding): Promise<Verdict[]> {
  const resolved = await holding.lookup.resolve(address);
  const verdicts = resolved.log.entries.map(({ event, time }, position) =>
    yes(
      `event ${String(position)} (${event.type}) verifies, and takes effect at ${formatTimestamp(time)}`,
      position === 0 ? "L1 3.6" : "L1 4.1",
    ),
  );
  verdicts.push(
    resolved.duplicitous
      ? no("the mind signed two events for one position: nothing after that is relied on", "L1 7.3")
      : yes("no two events were seen for one position", "L1 7.1"),
  );
  if (resolved.state.retired) {
    verdicts.push(unknown("the mind is retired: its keys sign nothing from then on", "L1 3.10"));
  }
  for (const { resolver, events, failure } of resolved.sources) {
    verdicts.push(
      events === undefined
        ? unknown(`${resolver} served nothing (${failure ?? "no reason"})`, "L1 17.1")
        : yes(`${resolver} served ${counted(events, "event")}`, "L1 17.1"),
    );
  }
  return verdicts;
}

/** The services to ask, or `undefined` where the command is to ask nobody, or has nobody to ask. */
function servicesFor(
  context: Context,
  local: string | undefined,
  offline: boolean,
): Config | undefined {
  if (offline) return undefined;
  try {
    return servicesOf(context, local);
  } catch (error) {
    // No mind lives in the directory, and no network was named: there is nobody to ask.
    if (error instanceof UsageError && local === undefined) return undefined;
    throw error;
  }
}

const LABELS = { ok: "ok", fails: "FAILS", no: "no", unknown: "unknown" } as const;

export const verify: Command = {
  name: "verify",
  summary: "Verifies a record, a log, a bundle or a mind, and says why of every verdict",
  positionals: "<what>",
  flags: {
    offline: {
      type: "boolean",
      describes: "Ask no service: check what can be checked without one",
    },
    local: {
      type: "boolean",
      describes: "Ask the network `oip demo` runs on this machine, with no mind of your own",
    },
    network: {
      type: "string",
      value: "path",
      describes: "The directory of that network. Default: ~/.oip-demo",
    },
  },
  notes: [
    "What is verified is named by a file of JSON, by the ID of a record the mind of this",
    "directory holds, or by the address of a mind. A file may hold one record, a bundle, or an",
    "identity log as an array of its events.",
    "Each line is one verdict, with the clause of the specification it rests on. `unknown` is",
    "what could not be judged, and `no` an answer of no with nothing wrong: a party that has",
    "not signed. The command ends with 1 if anything fails.",
    "A signature is judged by its signer's log as the resolvers serve it now, and counts from",
    "when this mind first obtained it, if it holds the record, or else from now.",
    "It unlocks no key: no passphrase is asked for.",
  ],
  example: "oip verify commitment.json",
  async run(context, given): Promise<Result> {
    const [named, ...more] = given.positionals;
    if (named === undefined || more.length > 0) {
      throw new UsageError("verify takes one thing: a file, the ID of a record, or an address");
    }
    const local = has(given, "local")
      ? networkDirectory(context.edges.home, one(given, "network"))
      : undefined;
    const config = servicesFor(context, local, has(given, "offline"));
    const now = context.edges.clock?.now() ?? BigInt(Date.now()) * 1_000_000n;
    const holding: Holding | undefined =
      config === undefined
        ? undefined
        : { lookup: new Lookup(lookupOptions(context, config)), records: new WebRecordSet(), now };
    // What the mind of the directory holds is what the record is judged among: a revocation
    // it knows of, a delegation named by reference. Each with when it first came.
    const kept = new KeptRecords(new Home(context.dir).records);
    if (holding !== undefined) {
      for (const { record, seen } of kept.all()) {
        if (!holding.records.add(record).ok) continue;
        for (const [digest, time] of Object.entries(seen)) {
          if (time < now) holding.lookup.seen.sawProof(digest, time);
        }
      }
    }
    let subject: string;
    let verdicts: Verdict[];
    if (named.startsWith("did:oip:")) {
      if (holding === undefined) {
        throw new UsageError(
          "a mind is verified by what its resolvers serve: run this from a mind's directory, or with --local",
        );
      }
      subject = named;
      verdicts = await verdictsOnMind(named, holding);
    } else {
      let value: JsonValue | undefined;
      if (CONTENT_ID.test(named)) {
        value = kept.get(named);
        if (value === undefined) {
          throw new UsageError(`the mind holds no record ${named}: a file names any other`);
        }
      } else {
        value = readJson(named, "what is verified");
      }
      const bundled =
        (value as JsonObject | null)?.["type"] === "Bundle" ? (value as JsonObject) : undefined;
      const events = Array.isArray(value) ? value : bundled?.["log"];
      if (Array.isArray(events)) {
        const judged = await verdictsOnLog(events as readonly JsonValue[], holding, now);
        subject = judged.mind ?? "an identity log";
        verdicts = judged.verdicts;
        // What a bundle carries besides the log is the mind's own, and is judged as any record.
        for (const member of ["location", "participant"]) {
          const carried = bundled?.[member];
          if (carried === undefined) continue;
          const each = await verdictsOnRecord(carried, holding);
          verdicts.push(
            ...each.map((verdict) => ({ ...verdict, what: `its ${member}: ${verdict.what}` })),
          );
        }
      } else {
        verdicts = await verdictsOnRecord(value, holding);
        const formed = validateRecord(value);
        subject = formed.ok ? `${formed.value.type} ${contentId(formed.value)}` : named;
      }
    }
    const failed = verdicts.some(({ verdict }) => verdict === "fails");
    const open = verdicts.some(({ verdict }) => verdict === "unknown");
    return {
      lines: [
        subject,
        ...verdicts.map(({ verdict, what, clause }) => row(LABELS[verdict], `${what} (${clause})`)),
        failed
          ? "It does not verify."
          : open
            ? "Nothing fails. Not everything could be judged."
            : "It verifies.",
      ],
      json: { subject, verified: !failed && !open, failed, verdicts },
      failed,
    };
  },
};
