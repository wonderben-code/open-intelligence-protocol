// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";

import {
  type CaseKind,
  type CaseResult,
  claimHolds,
  claimMustHold,
  type ConformanceAdapter,
  loadVectors,
  namedLog,
  namedRecord,
  NOT_JUDGED,
  parseVectors,
  POSITIVE_CHECKS,
  positiveRecords,
  referenceAdapter,
  runCase,
  runPositiveCheck,
  runVectors,
  tally,
  type VectorCase,
  viewFor,
} from "../src/index.ts";

const vectors = loadVectors();
/** The result of the one positive check whose name begins so, or `undefined` if there is none. */
const positive = (
  name: string,
  adapter: ConformanceAdapter,
  from = vectors,
): CaseResult | undefined => {
  const found = POSITIVE_CHECKS.find((entry) => entry.name.startsWith(name));
  return found === undefined ? undefined : runPositiveCheck(found, adapter, from);
};
const first = (kind: CaseKind, section: "valid" | "negative" | "controls" = "negative") => {
  const found = vectors[section].find((entry) => entry.kind === kind);
  if (found === undefined) throw new Error(`no ${kind} case in ${section}`);
  return found;
};

/** An adapter that answers every question the same way. */
const always = (answer: boolean, status = "open"): ConformanceAdapter => ({
  name: `always ${String(answer)}`,
  recordIsWellFormed: () => answer,
  jsonIsWithinProfile: () => answer,
  logVerifies: () => answer,
  countsFor: () => answer,
  sentFor: () => answer,
  status: () => status,
  assurance: () => status,
  canonicalize: () => "",
  ...network(() => ({ holds: answer, value: null })),
});

/** The eight methods of the Mind Network, each answering as `say` does. */
function network(say: () => unknown) {
  const method = say as () => never;
  return {
    feed: method,
    checkpoint: method,
    receive: method,
    chain: method,
    hello: method,
    ack: method,
    location: method,
    participant: method,
  } satisfies Partial<ConformanceAdapter>;
}

describe("what a case requires", () => {
  it("requires must-accept cases and controls to hold, and negative cases not to", () => {
    for (const kind of ["log", "countsFor", "sentFor", "record"] as const) {
      expect(claimMustHold("valid", kind)).toBe(true);
      expect(claimMustHold("controls", kind)).toBe(true);
      expect(claimMustHold("negative", kind)).toBe(false);
    }
  });

  it("requires a negative status or assurance case to give the value it expects", () => {
    expect(claimMustHold("negative", "status")).toBe(true);
    expect(claimMustHold("negative", "assurance")).toBe(true);
  });
});

describe("running a case", () => {
  it("reports pending, never pass, when the adapter says it does not judge the case yet", () => {
    const undecided: ConformanceAdapter = { name: "undecided", countsFor: () => NOT_JUDGED };
    for (const section of ["valid", "negative", "controls"] as const) {
      const vectorCase = first("countsFor", section);
      expect(claimHolds(undecided, vectors, vectorCase)).toBeUndefined();
      expect(runCase(undecided, vectors, section, vectorCase).outcome).toBe("pending");
    }
    // The reference implementation judges every such case of the vectors, by a mind's own
    // authority and through a delegation. It still says "not judged" of a collective's
    // record whose proofs name an authority, which may act through a charter role; the
    // vectors have no such case among these.
    const results = runVectors(referenceAdapter, vectors).filter(
      (result) => result.kind === "countsFor",
    );
    expect(results.filter((result) => result.outcome !== "pass")).toEqual([]);
    expect(results.length).toBeGreaterThan(80);
  });

  it("reports pending, never pass, when the adapter lacks the method", () => {
    const none: ConformanceAdapter = { name: "nothing yet" };
    for (const section of ["valid", "negative", "controls"] as const) {
      for (const vectorCase of vectors[section]) {
        expect(runCase(none, vectors, section, vectorCase).outcome).toBe("pending");
      }
    }
    expect(tally(runVectors(none, vectors))).toMatchObject({ pass: 0, fail: 0 });
  });

  it("fails an implementation that accepts everything on every negative case", () => {
    const accepting = always(true, "not a real status");
    for (const vectorCase of vectors.negative) {
      const result = runCase(accepting, vectors, "negative", vectorCase);
      expect(result.outcome, vectorCase.name).toBe("fail");
      expect(result.detail).toContain(vectorCase.reason);
    }
    for (const section of ["valid", "controls"] as const) {
      for (const vectorCase of vectors[section]) {
        // A status is right or wrong in every section: accepting everything does not guess it.
        const named = vectorCase.kind === "status" || vectorCase.kind === "assurance";
        expect(runCase(accepting, vectors, section, vectorCase).outcome, vectorCase.name).toBe(
          named ? "fail" : "pass",
        );
      }
    }
  });

  it("fails an implementation that rejects everything on every must-accept case and control", () => {
    const rejecting = always(false, "not a real status");
    for (const section of ["valid", "controls"] as const) {
      for (const vectorCase of vectors[section]) {
        const result = runCase(rejecting, vectors, section, vectorCase);
        expect(result.outcome, vectorCase.name).toBe("fail");
        expect(result.detail).toMatch(/must be accepted/);
      }
    }
  });

  it("fails every case on which the adapter throws, negative cases included", () => {
    const crash = () => {
      throw new TypeError("cannot read properties of undefined");
    };
    const throwing: ConformanceAdapter = {
      name: "throws",
      recordIsWellFormed: crash,
      jsonIsWithinProfile: crash,
      logVerifies: crash,
      countsFor: crash,
      sentFor: crash,
      status: crash,
      assurance: crash,
      ...network(crash),
    };
    for (const section of ["valid", "negative", "controls"] as const) {
      for (const vectorCase of vectors[section]) {
        const result = runCase(throwing, vectors, section, vectorCase);
        expect(result.outcome, vectorCase.name).toBe("fail");
        expect(result.detail).toMatch(/^the implementation threw: cannot read/);
      }
    }
    expect(tally(runVectors(throwing, vectors)).pass).toBe(0);
    expect(() => claimHolds(throwing, vectors, first("log"))).toThrow(TypeError);
  });

  it("fails every case on which the adapter answers something other than true or false", () => {
    for (const answer of [undefined, null, 1, 0, "yes", {}, []]) {
      const say = () => answer as boolean;
      const loose: ConformanceAdapter = {
        name: "loose",
        recordIsWellFormed: say,
        jsonIsWithinProfile: say,
        logVerifies: say,
        countsFor: say,
        sentFor: say,
        status: () => answer as string,
        assurance: () => answer as string,
        // An answer that is none, and one whose `holds` is none.
        ...network(() => (answer === "yes" ? { holds: answer } : answer)),
      };
      for (const section of ["valid", "negative", "controls"] as const) {
        for (const vectorCase of vectors[section]) {
          const result = runCase(loose, vectors, section, vectorCase);
          const wantsName = vectorCase.kind === "status" || vectorCase.kind === "assurance";
          expect(result.outcome, vectorCase.name).toBe("fail");
          // A string is a proper answer to a status or assurance case; "yes" is simply wrong.
          expect(result.detail).toMatch(
            wantsName && answer === "yes"
              ? /^must be accepted/
              : /^the implementation threw: the adapter answered/,
          );
        }
      }
    }
  });

  it("compares status and assurance with the expected value", () => {
    const status = first("status") as Extract<VectorCase, { kind: "status" }>;
    expect(runCase(always(true, status.expect), vectors, "negative", status).outcome).toBe("pass");
    expect(runCase(always(true, "open-ish"), vectors, "negative", status).outcome).toBe("fail");
    const assurance = first("assurance") as Extract<VectorCase, { kind: "assurance" }>;
    expect(runCase(always(true, assurance.expect), vectors, "negative", assurance).outcome).toBe(
      "pass",
    );
    expect(runCase(always(true, "bridged"), vectors, "negative", assurance).outcome).toBe("fail");
  });

  it("gives the adapter the baseline and what the case adds", () => {
    const withExtras = vectors.negative.find(
      (entry) => entry.extraLogs !== undefined && entry.seen !== undefined,
    );
    if (withExtras === undefined) throw new Error("no case with extraLogs and seen");
    const view = viewFor(vectors, withExtras);
    expect(view.logs).toHaveLength(vectors.baseline.logs.length);
    expect(view.records).toHaveLength(vectors.baseline.records.length);
    expect(view.logs[0]).toBe(namedLog(vectors, vectors.baseline.logs[0] ?? ""));
    expect(view.extraLogs).toBe(withExtras.extraLogs);
    expect(view.seen).toBe(withExtras.seen);
    const plain = viewFor(vectors, first("record"));
    expect(plain).toMatchObject({ extraLogs: [], branches: [], extraRecords: [] });
    expect(plain.seen).toBeUndefined();
  });
});

describe("the positive checks", () => {
  // Every check of the positive part verifies logs and signatures, which a machine busy
  // with other work does several times as slowly: the limit is for a test that hangs.
  vi.setConfig({ testTimeout: 300_000 });

  it("pass the reference implementation where it is built and are pending elsewhere", () => {
    const results = runVectors(referenceAdapter, vectors).filter(
      (result) => result.section === "positive",
    );
    expect(results.filter((result) => result.outcome === "fail")).toEqual([]);
    expect(results.find((result) => result.name.includes("well formed"))?.outcome).toBe("pass");
    // M1: canonical form, content IDs, key hashes and proofs.
    const m1 = [
      "JCS example",
      "content IDs use the canonical spelling and reproduce",
      "key hashes reproduce: every revealed control key was committed to",
      "every proofValue reproduces from its test key",
      "proofs verify, and signatures that break core 4.4 do not",
    ];
    expect(
      POSITIVE_CHECKS.filter((check) => check.milestone === "M1").map((check) => check.name),
    ).toEqual(m1);
    for (const name of m1) {
      expect(
        results.find((result) => result.name === name),
        name,
      ).toMatchObject({ outcome: "pass" });
    }
    // M2: identity logs, key validity, lineage and DID documents.
    const m2 = [
      "identity logs verify; addresses derive from genesis",
      "2-of-3 pre-rotation with distinct keys",
      "lineage acknowledged by a Fork event and by a Lineage record",
      "signatures count for their authors (purpose and key checks)",
      "DID documents, current and versioned",
    ];
    expect(
      POSITIVE_CHECKS.filter((check) => check.milestone === "M2").map((check) => check.name),
    ).toEqual(m2);
    for (const name of m2) {
      expect(
        results.find((result) => result.name === name),
        name,
      ).toMatchObject({ outcome: "pass" });
    }
    // M3: delegation, charter roles and status.
    const m3 = [
      "packet sent on Amina's behalf under a /oip/send delegation",
      "co-signing keeps the content ID; delegated party proof",
      "two agents sign for their principals, in either order",
      "delegation policy enforced (120, 500 ok; 500.01, 900 not)",
      "two-step delegation chain (150 ok; 300 beyond the sub-limit)",
      "collective signs by 2-of-3 threshold and by a charter role",
      "Layer 2 status (every state of Intent, Offer and Commitment)",
    ];
    expect(
      POSITIVE_CHECKS.filter((check) => check.milestone === "M3").map((check) => check.name),
    ).toEqual(m3);
    for (const name of m3) {
      expect(
        results.find((result) => result.name === name),
        name,
      ).toMatchObject({ outcome: "pass" });
    }
    // M4: feeds, checkpoints, packets and sessions.
    const m4 = [
      "feed entries commit to proofs; checkpoint Merkle root",
      "packet opens its session; Ack names the packet",
    ];
    expect(
      POSITIVE_CHECKS.filter((check) => check.milestone === "M4").map((check) => check.name),
    ).toEqual(m4);
    for (const name of m4) {
      expect(
        results.find((result) => result.name === name),
        name,
      ).toMatchObject({ outcome: "pass" });
    }
    // M9: a bridged mind, which Layer 0, 1.3 has a verifier tell from one that only says it is.
    const m9 = ["a bridged mind, attested in its gateway's feed"];
    expect(
      POSITIVE_CHECKS.filter((check) => check.milestone === "M9").map((check) => check.name),
    ).toEqual(m9);
    for (const name of m9) {
      expect(
        results.find((result) => result.name === name),
        name,
      ).toMatchObject({ outcome: "pass" });
    }
    expect(results.filter((result) => result.outcome === "pass")).toHaveLength(
      1 + m1.length + m2.length + m3.length + m4.length + m9.length,
    );
    // Nothing of the positive part is left for a later milestone.
    expect(results.filter((result) => result.outcome === "pending")).toEqual([]);
  });

  describe("of delegation, charter roles and status", () => {
    type Fields = Readonly<Record<string, unknown>>;
    /** What one check finds: nothing if it passes, and `undefined` if it cannot run yet. */
    const check = (adapter: ConformanceAdapter, name: string, from = vectors) => {
      const found = POSITIVE_CHECKS.find((entry) => entry.name.startsWith(name));
      if (found === undefined) throw new Error(`no positive check ${name}`);
      return found.run(adapter, from);
    };
    const mind = (name: string) => vectors.cases[name] as string;
    /** The reference implementation without some of its methods. */
    const without = (...methods: (keyof ConformanceAdapter)[]): ConformanceAdapter =>
      Object.fromEntries(
        Object.entries(referenceAdapter).filter(
          ([name]) => !methods.includes(name as keyof ConformanceAdapter),
        ),
      ) as unknown as ConformanceAdapter;
    const proofsOn = (record: Fields) => record["proof"] as readonly Fields[];
    /** The reference implementation, asked about another record than the one given. */
    const countsAs =
      (
        other: (record: Fields, mind: string) => Fields,
      ): NonNullable<ConformanceAdapter["countsFor"]> =>
      (record, of, view) =>
        referenceAdapter.countsFor?.(other(record, of), of, view) ?? false;

    it("are pending for an implementation that does not judge them yet", () => {
      const own: ConformanceAdapter = { ...referenceAdapter, countsFor: () => NOT_JUDGED };
      for (const name of [
        "co-signing",
        "two agents",
        "delegation policy",
        "two-step",
        "collective signs",
      ]) {
        expect(check(own, name), name).toBeUndefined();
      }
      for (const name of [
        "packet sent",
        "co-signing",
        "delegation policy",
        "two-step",
        "Layer 2 status",
      ]) {
        expect(check(without("status", "sentFor", "createProof"), name), name).toBeUndefined();
      }
      for (const name of ["co-signing", "two agents"]) {
        expect(check(without("contentId"), name), name).toBeUndefined();
      }
    });

    it("pass the reference implementation", () => {
      for (const entry of POSITIVE_CHECKS.filter((found) => found.milestone === "M3")) {
        expect(entry.run(referenceAdapter, vectors), entry.name).toEqual([]);
      }
    });

    it("fail an implementation that takes any packet as sent for anyone, or none", () => {
      expect(check({ ...referenceAdapter, sentFor: () => true }, "packet sent")).toEqual([
        "packet_on_behalf was sent for lexis_ltd, and must not be",
      ]);
      expect(check({ ...referenceAdapter, sentFor: () => false }, "packet sent")).toEqual([
        "packet_on_behalf was not sent for amina",
      ]);
    });

    it("fail an implementation that counts no proof made for another, or every proof for everyone", () => {
      // A proof that names an authority counts for nobody.
      const none: ConformanceAdapter = {
        ...referenceAdapter,
        countsFor: countsAs((record) => ({
          ...record,
          proof: proofsOn(record).filter((proof) => proof["authority"] === undefined),
        })),
      };
      expect(check(none, "co-signing")).toContain(
        "commitment_accepted does not count for lexis_ltd",
      );
      expect(check(none, "two agents")).toContain(
        "commitment_agents as signed does not count for amina",
      );
      expect(check(none, "delegation policy")).toContain(
        "for 120, the commitment does not count for lexis_ltd",
      );
      expect(check(none, "two-step")).toContain(
        "commitment_via_chain does not count for lexis_ltd",
      );
      expect(check(none, "collective signs")).toEqual([
        "commitment_by_steward does not count for the collective",
      ]);
      const all: ConformanceAdapter = { ...referenceAdapter, countsFor: () => true };
      expect(check(all, "co-signing")).toEqual(["commitment_proposed counts for amina"]);
      expect(check(all, "delegation policy")).toEqual([
        "for 500.01, the commitment counts for lexis_ltd",
        "for 900, the commitment counts for lexis_ltd",
      ]);
      expect(check(all, "two-step")).toEqual([
        "for 300, beyond the sub-delegation's limit, the commitment counts for lexis_ltd",
      ]);
      // An agent whose own signature is lost when its principal's limit is passed.
      const strict: ConformanceAdapter = {
        ...referenceAdapter,
        countsFor: (record, of, view) => {
          const terms = record["terms"] as { readonly price?: { readonly amount?: string } };
          if (of === mind("lexis_agent") && terms.price?.amount === "900") return false;
          return referenceAdapter.countsFor?.(record, of, view) ?? false;
        },
      };
      expect(check(strict, "delegation policy")).toEqual([
        "for 900, the commitment does not count for the agent that signed it",
      ]);
    });

    it("fail an implementation for which the order of proofs matters, or a proof changes the content ID", () => {
      // A content ID that covers the proofs.
      const covering: ConformanceAdapter = {
        ...referenceAdapter,
        contentId: (record) => JSON.stringify(record["proof"]),
      };
      expect(check(covering, "co-signing")).toEqual([
        "a second proof changed the content ID of the commitment",
      ]);
      expect(check(covering, "two agents")).toEqual([
        "the order of the proofs changed the content ID",
      ]);
      // Only the first proof on a record is looked at.
      const firstOnly: ConformanceAdapter = {
        ...referenceAdapter,
        countsFor: countsAs((record) => ({ ...record, proof: proofsOn(record).slice(0, 1) })),
      };
      expect(check(firstOnly, "two agents")).toEqual([
        "commitment_agents as signed does not count for amina",
        "commitment_agents with its proofs in the other order does not count for lexis_ltd",
      ]);
    });

    it("fail an implementation that gets a status wrong", () => {
      const open: ConformanceAdapter = { ...referenceAdapter, status: () => "open" };
      expect(check(open, "Layer 2 status")).toContain(
        "intent at 2026-10-30T12:00:00Z with intent, commitment_accepted: open, not satisfied",
      );
      expect(check(open, "co-signing")).toEqual([
        "commitment_accepted is not accepted",
        "commitment_proposed is not proposed",
      ]);
      expect(check(open, "two-step")).toEqual(["commitment_via_chain is not accepted"]);
      // An answer that is no status is no answer.
      expect(() =>
        check({ ...referenceAdapter, status: () => undefined as never }, "Layer 2 status"),
      ).toThrow(TypeError);
      const none = structuredClone(vectors) as unknown as { cases: Record<string, unknown> };
      delete none.cases["status"];
      expect(check(referenceAdapter, "Layer 2 status", none as unknown as typeof vectors)).toEqual([
        "the vectors have no cases.status",
      ]);
    });
  });

  it("fail an implementation that verifies no log, or derives the wrong addresses", () => {
    const name = "identity logs verify; addresses derive from genesis";
    const check = (adapter: ConformanceAdapter) => positive(name, adapter);
    // Both methods are needed.
    expect(check({ name: "half", contentId: () => "" })?.outcome).toBe("pending");
    expect(check({ name: "half", logVerifies: () => true })?.outcome).toBe("pending");
    const refuses = check({ ...referenceAdapter, logVerifies: () => false });
    expect(refuses?.outcome).toBe("fail");
    expect(refuses?.detail).toContain("amina_log did not verify");
    expect(refuses?.detail).toContain("collective_log did not verify");
    const wrong = check({ ...referenceAdapter, contentId: () => `bciqa${"a".repeat(51)}` });
    expect(wrong?.detail).toContain("amina_log: the address is not derived from the genesis");
    expect(wrong?.detail).not.toContain("did not verify");
    // An answer that is not a verdict fails the check; it is never read as a rejection.
    const vague = check({ ...referenceAdapter, logVerifies: () => undefined as never });
    expect(vague).toMatchObject({ outcome: "fail" });
    expect(vague?.detail).toContain("not true or false");
  });

  it("fail an implementation that loses the threshold of a 2-of-3 rotation", () => {
    const name = "2-of-3 pre-rotation with distinct keys";
    const check = (adapter: ConformanceAdapter) => positive(name, adapter);
    for (const answer of [undefined, null, {}, { didDocumentMetadata: { nextThreshold: 2 } }]) {
      const result = check({ name: "wrong", didDocument: () => answer });
      expect(result?.outcome).toBe("fail");
      expect(result?.detail).toBe("after the update, the next threshold should be 1");
    }
    expect(check({ name: "none" })?.outcome).toBe("pending");
    // The check says so if the vectors no longer hold the log it was written for.
    const changed = structuredClone(vectors) as unknown as {
      cases: { multi_log: { controller: { nextThreshold?: number; keys: string[] } }[] };
    };
    const [genesis, update] = changed.cases.multi_log;
    if (genesis === undefined || update === undefined) throw new Error("no multi_log");
    update.controller.keys = [update.controller.keys[0] ?? "", update.controller.keys[0] ?? ""];
    expect(
      positive(name, referenceAdapter, changed as unknown as typeof vectors)?.detail,
    ).toContain("the update does not reveal two distinct keys");
    genesis.controller.nextThreshold = 3;
    expect(
      positive(name, referenceAdapter, changed as unknown as typeof vectors)?.detail,
    ).toContain("multi_log is not the log this check was written for");
  });

  it("fail an implementation that gets lineage wrong", () => {
    const name = "lineage acknowledged by a Fork event and by a Lineage record";
    const check = (adapter: ConformanceAdapter) => positive(name, adapter);
    const parent = vectors.cases["lexis_agent"] as string;
    for (const answer of [
      {},
      { [parent]: "claimed" },
      { [parent]: "acknowledged", other: "claimed" },
    ]) {
      const result = check({ name: "wrong", lineage: () => answer as never });
      expect(result?.outcome).toBe("fail");
      expect(result?.detail).toContain("lexis_fork: its parent should acknowledge it, got");
      expect(result?.detail).toContain("lexis_fork2: its parent should acknowledge it, got");
    }
    // Acknowledged by the Fork event only: the Lineage record is not looked at.
    const forkOnly = check({
      ...referenceAdapter,
      lineage: (child, view) =>
        referenceAdapter.lineage?.(child, { ...view, records: [], extraRecords: [] }) ?? {},
    });
    expect(forkOnly?.outcome).toBe("fail");
    expect(forkOnly?.detail).toMatch(/^lexis_fork2: /);
  });

  it("fail an implementation for which a signature does not count for its author", () => {
    const name = "signatures count for their authors (purpose and key checks)";
    const check = (adapter: ConformanceAdapter) => positive(name, adapter);
    const never = check({ name: "never", countsFor: () => false });
    expect(never?.outcome).toBe("fail");
    expect(never?.detail).toContain("intent does not count for amina");
    expect(never?.detail).toContain("bridged_participant does not count for bridged");
    expect(never?.detail?.split("; ")).toHaveLength(19);
    // An implementation that does not judge one of them yet has not passed the check.
    const intent = vectors.cases["intent"];
    const partly = check({
      ...referenceAdapter,
      countsFor: (record, mind, view) =>
        record === intent
          ? NOT_JUDGED
          : (referenceAdapter.countsFor?.(record, mind, view) ?? false),
    });
    expect(partly?.outcome).toBe("pending");
    // One that gets the others wrong has failed it, whatever it left unjudged.
    const wrongAndPartly = check({
      name: "wrong, and one short",
      countsFor: (record) => (record === intent ? NOT_JUDGED : false),
    });
    expect(wrongAndPartly?.outcome).toBe("fail");
    expect(wrongAndPartly?.detail?.split("; ")).toHaveLength(18);
    expect(wrongAndPartly?.detail).not.toContain("intent does not count for amina");
  });

  it("fail an implementation whose DID documents differ", () => {
    const name = "DID documents, current and versioned";
    const check = (adapter: ConformanceAdapter) => positive(name, adapter);
    expect(check({ name: "half", didDocument: () => ({}) })?.outcome).toBe("pending");
    expect(check({ name: "half", contentId: () => "" })?.outcome).toBe("pending");
    const none = check({ ...referenceAdapter, didDocument: () => undefined });
    expect(none?.detail).toBe(
      "did_document_amina was not reproduced; did_document_amina_at_genesis was not reproduced; did_document_collective was not reproduced; did_document_retired_at_genesis was not reproduced",
    );
    // The versioned document is asked for by the version of the genesis.
    const unversioned = check({
      ...referenceAdapter,
      didDocument: (mind, _versionId, view) =>
        referenceAdapter.didDocument?.(mind, undefined, view),
    });
    expect(unversioned?.detail).toBe(
      "did_document_amina_at_genesis was not reproduced; did_document_retired_at_genesis was not reproduced",
    );
    // An implementation that says of a version what was so at that version: the mind had not
    // retired at its first, and it is deactivated all the same (Layer 1, 5.2).
    const ofTheVersion = check({
      ...referenceAdapter,
      didDocument: (mind, versionId, view) => {
        const resolved = referenceAdapter.didDocument?.(mind, versionId, view) as
          { didDocumentMetadata: Record<string, unknown> } | undefined;
        if (resolved === undefined || versionId === undefined) return resolved;
        return {
          ...resolved,
          didDocumentMetadata: { ...resolved.didDocumentMetadata, deactivated: false },
        };
      },
    });
    expect(ofTheVersion?.detail).toBe("did_document_retired_at_genesis was not reproduced");
  });

  it("leave every check pending for an adapter that has none of the methods", () => {
    const results = runVectors({ name: "nothing yet" }, vectors).filter(
      (result) => result.section === "positive",
    );
    expect(results.every((result) => result.outcome === "pending")).toBe(true);
    expect(results).toHaveLength(POSITIVE_CHECKS.length);
  });

  it("fail an implementation whose content IDs or addresses are wrong", () => {
    const check = (adapter: ConformanceAdapter) => positive("content IDs", adapter);
    const constant = check({ name: "constant", contentId: () => `bciqa${"a".repeat(51)}` });
    expect(constant?.outcome).toBe("fail");
    expect(constant?.detail).toContain("content_ids.amina_genesis: expected bciq");
    expect(constant?.detail).toContain("amina_log: the address should be did:oip:bciqaaaa");
    expect(constant?.detail).toContain(
      "amina_log[1].prev is not the content ID of the event before it",
    );
    // An implementation that lets the proofs into the hash gets every signed record wrong.
    const withProofs = check({
      name: "hashes proof",
      contentId: (record) =>
        referenceAdapter.contentId?.(
          Array.isArray(record["proof"]) ? { ...record, proofs: record["proof"] } : record,
        ) ?? "",
    });
    expect(withProofs?.outcome).toBe("fail");
    expect(withProofs?.detail).toContain("content_ids.intent");
    expect(withProofs?.detail).not.toContain("content_ids.session");
  });

  it("fail when the vectors name a content ID this suite cannot place, or spell one wrongly", () => {
    const changed = structuredClone(vectors) as unknown as {
      cases: { content_ids: Record<string, string>; amina: string };
    };
    changed.cases.content_ids["mystery"] = changed.cases.content_ids["intent"] ?? "";
    changed.cases.amina = `${changed.cases.amina.slice(0, -1)}b`;
    const result = positive("content IDs", referenceAdapter, changed as unknown as typeof vectors);
    expect(result?.outcome).toBe("fail");
    expect(result?.detail).toContain("is not in the canonical spelling");
    expect(result?.detail).toContain(
      "content_ids.mystery: this suite does not know which record it names",
    );
    expect(result?.detail).toContain("amina_log: the address should be");
  });

  it("fail an implementation whose key hashes are wrong", () => {
    const result = positive("key hashes", { name: "constant", keyHash: () => "bciq" });
    expect(result?.outcome).toBe("fail");
    expect(result?.detail).toMatch(
      /amina_log\[1\]: the hash of z6Mk\w+ is not in the event before/,
    );
  });

  it("fail an implementation that does not reproduce a proof", () => {
    const check = (createProof: NonNullable<ConformanceAdapter["createProof"]>) =>
      positive("every proofValue", { name: "signer", createProof });
    const reference = referenceAdapter.createProof?.bind(referenceAdapter);
    if (reference === undefined) throw new Error("the reference adapter creates proofs");
    expect(check(reference)?.outcome).toBe("pass");
    // The wrong signature.
    const wrongValue = check((record, request, key) => ({
      ...reference(record, request, key),
      proofValue: "z1",
    }));
    expect(wrongValue?.detail).toContain("amina_log[0] proof 0 was not reproduced");
    // The right signature in a proof with another member.
    const extra = check((record, request, key) => ({
      ...reference(record, request, key),
      id: "x",
    }));
    expect(extra?.outcome).toBe("fail");
    // A member dropped: the proofs that carry authority no longer match.
    const dropped = check((record, request, key) => {
      const { authority: _authority, ...rest } = reference(record, request, key);
      return rest;
    });
    expect(dropped?.outcome).toBe("fail");
    expect(dropped?.detail).not.toContain("amina_log[0]");
    // Members in another order are the same proof.
    const reordered = check((record, request, key) =>
      Object.fromEntries(Object.entries(reference(record, request, key)).reverse()),
    );
    expect(reordered?.outcome).toBe("pass");
    // A key the vectors do not have.
    const noKeys = structuredClone(vectors) as unknown as { keys: Record<string, unknown> };
    noKeys.keys = {};
    const missing = positive(
      "every proofValue",
      referenceAdapter,
      noKeys as unknown as typeof vectors,
    );
    expect(missing?.detail).toContain("the vectors have no test key for it");
  });

  it("fail an implementation that accepts a signature core 4.4 forbids, or rejects a good one", () => {
    const check = (proofVerifies: NonNullable<ConformanceAdapter["proofVerifies"]>) =>
      positive("proofs verify", { name: "verifier", proofVerifies });
    const lax = check(() => true);
    expect(lax?.outcome).toBe("fail");
    for (const name of ["signature-s-not-reduced", "signature-r-identity", "wrong-proof-purpose"]) {
      expect(lax?.detail).toContain(`${name}: proof 0 verified, and must not`);
    }
    expect(lax?.detail).not.toContain("did not verify");
    const strict = check(() => false);
    expect(strict?.outcome).toBe("fail");
    expect(strict?.detail).toContain("intent proof 0 did not verify");
    expect(strict?.detail).not.toContain("must not");
    // An answer that is not a boolean is not an answer.
    const vague = check(() => "yes" as unknown as boolean);
    expect(vague).toMatchObject({
      outcome: "fail",
      detail: "threw the adapter answered a string, not true or false",
    });
    expect(check(() => undefined as unknown as boolean)?.outcome).toBe("fail");
    const without = structuredClone(vectors) as unknown as { negative: { name: string }[] };
    without.negative = without.negative.filter((entry) => entry.name !== "signature-r-identity");
    const missing = positive(
      "proofs verify",
      referenceAdapter,
      without as unknown as typeof vectors,
    );
    expect(missing?.detail).toBe("the vectors have no negative case signature-r-identity");
  });

  it("fail an implementation that rejects a positive record or canonicalises wrongly", () => {
    const results = runVectors(always(false), vectors).filter(
      (result) => result.section === "positive" && result.outcome === "fail",
    );
    expect(results.map((result) => result.name)).toEqual([
      "every record in the positive vectors is well formed",
      "JCS example",
      "signatures count for their authors (purpose and key checks)",
      "packet sent on Amina's behalf under a /oip/send delegation",
      "collective signs by 2-of-3 threshold and by a charter role",
      "Layer 2 status (every state of Intent, Offer and Commitment)",
      "a bridged mind, attested in its gateway's feed",
    ]);
    expect(results[0]?.detail).toContain("amina_log[0] was rejected");
  });

  it("report a check that throws as a failure", () => {
    const throwing: ConformanceAdapter = {
      name: "throws",
      canonicalize: () => {
        throw new Error("no JCS here");
      },
    };
    const result = positive("JCS example", throwing);
    expect(result).toMatchObject({ outcome: "fail", detail: "threw no JCS here" });
  });
});

describe("reading the vectors", () => {
  const raw = () => structuredClone(vectors) as unknown as Record<string, unknown>;

  it("finds named records and logs, and every positive record", () => {
    expect(namedRecord(vectors, "intent")["type"]).toBe("Intent");
    expect(namedLog(vectors, "amina_log")).toHaveLength(2);
    expect(() => namedRecord(vectors, "amina_log")).toThrow(/not a record/);
    expect(() => namedLog(vectors, "intent")).toThrow(/not a log/);
    expect(() => namedRecord(vectors, "missing")).toThrow(/not a record/);
    expect(positiveRecords(vectors).length).toBeGreaterThan(40);
  });

  it("rejects a file that is not the shape the suite relies on", () => {
    expect(() => parseVectors(null)).toThrow(/not an object/);
    for (const member of [
      "spec_revision",
      "cases",
      "keys",
      "baseline",
      "valid",
      "negative",
      "controls",
    ]) {
      const broken = raw();
      delete broken[member];
      expect(() => parseVectors(broken), member).toThrow(/vectors\.json/);
    }
  });

  it("rejects a baseline that names something the file does not contain", () => {
    const broken = raw();
    broken["baseline"] = { logs: ["amina_log", "nobody_log"], records: [] };
    expect(() => parseVectors(broken)).toThrow(/nobody_log/);
  });

  it("rejects a member it does not know, so that a misspelt one cannot change a case unnoticed", () => {
    const withMember = (section: string, member: string, value: unknown) => {
      const broken = raw();
      const target = section === "" ? broken : (broken[section] as Record<string, unknown>[])[0];
      if (target === undefined) throw new Error(`the vectors have no ${section} cases`);
      target[member] = value;
      return () => parseVectors(broken);
    };
    expect(withMember("negative", "extraLog", [])).toThrow(/unknown member "extraLog"/);
    expect(withMember("valid", "expect", "open")).toThrow(/unknown member "expect"/);
    expect(withMember("", "must_reject", [])).toThrow(/unknown member "must_reject"/);
  });

  it("rejects a case whose members have the wrong shape", () => {
    const withMember = (member: string, value: unknown) => {
      const broken = raw();
      const list = broken["negative"] as Record<string, unknown>[];
      const target = list.find((entry) => entry["kind"] === "countsFor");
      if (target === undefined) throw new Error("no countsFor case");
      target[member] = value;
      return () => parseVectors(broken);
    };
    expect(withMember("seen", { "sha256:00": 1793350800 })).toThrow(
      /seen is not a map of timestamps/,
    );
    expect(withMember("seen", ["2026-10-30T09:00:00Z"])).toThrow(/seen is not/);
    expect(withMember("extraLogs", [{ type: "Genesis" }])).toThrow(
      /extraLogs is not an array of logs/,
    );
    expect(withMember("extraRecords", "none")).toThrow(/extraRecords is not/);
    expect(withMember("mind", 7)).toThrow(/mind is not an address/);
  });

  it("rejects a case with no name, an unknown kind, a missing member or a repeated name", () => {
    const withCase = (
      change: (first: Record<string, unknown>, list: Record<string, unknown>[]) => void,
    ) => {
      const broken = raw();
      const list = broken["negative"] as Record<string, unknown>[];
      const [first] = list;
      if (first === undefined) throw new Error("the vectors have no negative cases");
      change(first, list);
      return () => parseVectors(broken);
    };
    expect(withCase((first) => delete first["name"])).toThrow(/no name/);
    expect(withCase((first) => (first["kind"] = "vibes"))).toThrow(/unknown kind/);
    expect(withCase((first) => delete first["log"])).toThrow(/has no log/);
    expect(withCase((first, list) => list.push({ ...first }))).toThrow(/appears twice/);
    expect(
      withCase((_first, list) => list.push("a string" as unknown as Record<string, unknown>)),
    ).toThrow(/not an object/);
  });
});
