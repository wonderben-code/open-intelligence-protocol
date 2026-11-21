// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, formatVersionId } from "@oip/core";
import { clause, type JsonObject, type VectorCase } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import {
  didDocument,
  judgeRecord,
  latestState,
  lineage,
  ownSignedTime,
  verifyLog,
} from "../src/index.ts";
import {
  ALWAYS,
  type CaseExtras,
  cases,
  controls,
  log,
  mind,
  named,
  negative,
  valid,
  worldFor,
} from "./world.ts";

const MINDS = [
  "amina",
  "lexis_ltd",
  "lexis_agent",
  "lexis_fork",
  "lexis_fork2",
  "researcher",
  "collective",
  "multi",
  "assistant",
  "gateway",
  "bridged",
];

function logVerifies(vectorCase: VectorCase): boolean {
  const world = worldFor(vectorCase as CaseExtras);
  return verifyLog(vectorCase["log"], {
    evidence: world.book.evidence,
    asOf: ALWAYS,
    memberLog: (member) => world.book.log(member),
  }).ok;
}

/** Whether a record counts for a mind by the mind's own authority. Records with `authority` are for M3. */
function countsFor(vectorCase: VectorCase): boolean {
  const world = worldFor(vectorCase as CaseExtras);
  const judged = judgeRecord(vectorCase["record"]);
  return (
    judged.ok && ownSignedTime(judged.value, vectorCase["mind"] as string, world.book) !== undefined
  );
}

const usesAuthority = (vectorCase: VectorCase): boolean =>
  ((vectorCase["record"] as JsonObject | undefined)?.["proof"] as JsonObject[] | undefined)?.some(
    (proof) => "authority" in proof,
  ) === true;

const ofKind = (section: readonly VectorCase[], kind: string) =>
  section.filter((vectorCase) => vectorCase.kind === kind);

describe("the positive vectors", () => {
  const world = worldFor();

  it(`${clause("L1 2.2", "L1 4.1")} every log verifies, and each address derives from its genesis`, () => {
    for (const name of MINDS) {
      const events = log(`${name}_log`);
      expect(mind(name)).toBe(`did:oip:${contentId(events[0])}`);
      const verified = world.book.log(mind(name));
      expect(verified.ok ? verified.value.mind : verified.issues, name).toBe(mind(name));
    }
  });

  it(`${clause("L1 4.7")} the collective of three people has height 1`, () => {
    const collective = world.book.log(mind("collective"));
    expect(collective.ok && collective.value.height).toBe(1);
  });

  it(`${clause("L1 4.3")} 2-of-3 pre-rotation with distinct keys`, () => {
    const multi = world.book.log(mind("multi"));
    expect(multi.ok && latestState(multi.value).controller).toMatchObject({ nextThreshold: 1 });
  });

  it(`${clause("L1 8.2")} lineage is acknowledged by a Fork event and by a Lineage record`, () => {
    for (const child of ["lexis_fork", "lexis_fork2"]) {
      const held = world.book.log(mind(child));
      if (!held.ok) throw new Error(`${child} does not verify`);
      expect(lineage(held.value, world.book, world.records), child).toEqual([
        expect.objectContaining({ mind: mind("lexis_agent"), status: "acknowledged" }),
      ]);
    }
  });

  it(`${clause("L1 6.1")} signatures count for their authors`, () => {
    const signed: [string, string][] = [
      ["intent", "amina"],
      ["offer", "lexis_agent"],
      ["offer_glossary", "lexis_ltd"],
      ["receipt", "amina"],
      ["packet", "lexis_agent"],
      ["ack", "amina"],
      ["hello", "lexis_agent"],
      ["delegation", "lexis_ltd"],
      ["delegation_sub", "lexis_agent"],
      ["delegation_amina", "amina"],
      ["delegation_send", "amina"],
      ["participant", "lexis_agent"],
      ["location", "lexis_agent"],
      ["feed_entry", "lexis_agent"],
      ["feed_entry_1", "lexis_agent"],
      ["checkpoint", "lexis_agent"],
      ["lineage", "lexis_agent"],
      ["gateway_entry", "gateway"],
      ["bridged_participant", "bridged"],
    ];
    for (const [record, author] of signed) {
      const judged = judgeRecord(named(record));
      if (!judged.ok) throw new Error(`${record} is not well formed`);
      expect(ownSignedTime(judged.value, mind(author), world.book), record).toBeDefined();
    }
  });

  it(`${clause("L1 5.2", "L1 2.4")} DID documents, current and versioned`, () => {
    const documents: [string, string, string | undefined][] = [
      ["did_document_amina", "amina", undefined],
      [
        "did_document_amina_at_genesis",
        "amina",
        formatVersionId(0, contentId(log("amina_log")[0])),
      ],
      ["did_document_collective", "collective", undefined],
    ];
    for (const [name, of, versionId] of documents) {
      const held = world.book.log(mind(of));
      if (!held.ok) throw new Error(`${of} does not verify`);
      const resolved = didDocument(held.value, versionId === undefined ? {} : { versionId });
      expect(resolved.ok && resolved.value, name).toEqual(cases[name]);
    }
  });

  it(`${clause("L1 5.2", "L1 3.10")} the document of an earlier version of a mind that has retired says that the mind is deactivated`, () => {
    // The mind is no part of the baseline: a verifier that holds its log is one that was given it.
    const events = log("retired_log");
    expect(mind("retired")).toBe(`did:oip:${contentId(events[0])}`);
    const held = worldFor({ extraLogs: [events] }).book.log(mind("retired"));
    if (!held.ok) throw new Error("the retired mind does not verify");
    const first = formatVersionId(0, contentId(events[0]));
    const resolved = didDocument(held.value, { versionId: first });
    expect(resolved.ok && resolved.value).toEqual(cases["did_document_retired_at_genesis"]);
    // The document is of the first version, with that version's keys, named as a proof pinned
    // to it names them. That the mind is deactivated is said of the mind as its log stands.
    expect(resolved.ok && resolved.value.didDocumentMetadata).toMatchObject({
      versionId: first,
      deactivated: true,
    });
    const latest = didDocument(held.value, {});
    expect(latest.ok && latest.value.didDocumentMetadata.deactivated).toBe(true);
    // A mind that has not retired is deactivated at no version.
    const amina = world.book.log(mind("amina"));
    if (!amina.ok) throw new Error("amina does not verify");
    for (const versionId of [undefined, formatVersionId(0, contentId(log("amina_log")[0]))]) {
      const document = didDocument(amina.value, versionId === undefined ? {} : { versionId });
      expect(document.ok && document.value.didDocumentMetadata.deactivated).toBe(false);
    }
  });
});

describe("the identity cases of the vectors", () => {
  it.each(ofKind(valid, "log").concat(ofKind(controls, "log")))(
    "accepts the log $name",
    (vectorCase) => {
      expect(logVerifies(vectorCase)).toBe(true);
    },
  );

  it.each(ofKind(negative, "log"))("rejects the log $name", (vectorCase) => {
    expect(logVerifies(vectorCase)).toBe(false);
  });

  const own = (section: readonly VectorCase[]) =>
    ofKind(section, "countsFor").filter((vectorCase) => !usesAuthority(vectorCase));

  it.each(own(valid).concat(own(controls)))("counts $name for its mind", (vectorCase) => {
    expect(countsFor(vectorCase)).toBe(true);
  });

  it.each(own(negative))("does not count $name for its mind", (vectorCase) => {
    expect(countsFor(vectorCase)).toBe(false);
  });
});
