// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { keyHash, parseKeyRef } from "@oip/core";
import { clause } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import { didDocument, type DidResolution, latestState, type VerifiedLog } from "../src/index.ts";
import { agreementKey, bookOf, Collective, intentBy, KeyMind, type Mind } from "@oip/testkit/minds";

function logOf(mind: Mind, others: readonly Mind[] = []): VerifiedLog {
  const log = bookOf([mind, ...others]).log(mind.address);
  if (!log.ok) throw new Error(JSON.stringify(log.issues));
  return log.value;
}

function resolve(...given: Parameters<typeof didDocument>): DidResolution {
  const resolved = didDocument(...given);
  if (!resolved.ok) throw new Error(JSON.stringify(resolved.issues));
  return resolved.value;
}

describe(`${clause("L1 5.1")} identity state`, () => {
  it("is everything the replay of a log produces", () => {
    const parent = new KeyMind("parent");
    const child = new KeyMind("child").address;
    const ada = new KeyMind("ada", 0, {
      kind: "human",
      homes: ["https://ada.example"],
      alsoKnownAs: ["dns:ada.example"],
      parents: [{ mind: parent.address, at: parent.versionId() }],
    });
    const revoked = ada.invocation().publicKey;
    ada
      .fork(10, { child })
      .update(20, { revoked: [{ key: revoked }] })
      .retire(30);
    const state = latestState(logOf(ada));
    expect(state).toEqual({
      mind: ada.address,
      kind: "human",
      controller: { kind: "key", next: [], nextThreshold: 0 },
      keys: [ada.operational().publicKey],
      invocation: [],
      agreement: [agreementKey("ada/agreement/0")],
      homes: ["https://ada.example"],
      alsoKnownAs: ["dns:ada.example"],
      parents: [{ mind: parent.address, at: parent.versionId() }],
      children: [child],
      revoked: new Map([[revoked, undefined]]),
      seq: 3,
      head: ada.versionId().slice(2),
      versionId: ada.versionId(),
      created: state.created,
      retired: true,
    });
  });
});

describe(`${clause("L1 5.2")} the DID document`, () => {
  const ada = new KeyMind("ada", 0, { homes: ["https://ada.example", "https://two.example"] });
  const log = logOf(ada);
  const [operational, invocation, agreement] = [
    ada.operational().publicKey,
    ada.invocation().publicKey,
    agreementKey("ada/agreement/0"),
  ];

  it("lists each key once, operational then invocation then agreement, and no control key", () => {
    const { didDocument: document } = resolve(log);
    expect(document.id).toBe(ada.address);
    expect(document.verificationMethod).toEqual(
      [operational, invocation, agreement].map((key) => ({
        id: `${ada.address}#${key}`,
        type: "Multikey",
        controller: ada.address,
        publicKeyMultibase: key,
      })),
    );
    expect(JSON.stringify(document)).not.toContain(ada.control(0).publicKey);
  });

  it("gives each key the relationships of its kind", () => {
    const { didDocument: document } = resolve(log);
    const id = (key: string) => [`${ada.address}#${key}`];
    expect(document.authentication).toEqual(id(operational));
    expect(document.assertionMethod).toEqual(id(operational));
    expect(document.capabilityDelegation).toEqual(id(operational));
    expect(document.capabilityInvocation).toEqual(id(invocation));
    expect(document.keyAgreement).toEqual(id(agreement));
  });

  it("lists the homes as services, then the endpoints of a location record that is known", () => {
    expect(resolve(log).didDocument.service).toEqual([
      { id: `${ada.address}#home-0`, type: "OIPHome", serviceEndpoint: "https://ada.example" },
      { id: `${ada.address}#home-1`, type: "OIPHome", serviceEndpoint: "https://two.example" },
    ]);
    const endpoints = ["https://ada.example/oip", "wss://ada.example/oip/ws"];
    expect(resolve(log, { endpoints }).didDocument.service?.slice(2)).toEqual([
      { id: `${ada.address}#endpoint-0`, type: "OIPEndpoint", serviceEndpoint: endpoints[0] },
      { id: `${ada.address}#endpoint-1`, type: "OIPEndpoint", serviceEndpoint: endpoints[1] },
    ]);
    const bare = new KeyMind("bare");
    expect(resolve(logOf(bare)).didDocument).not.toHaveProperty("service");
    expect(resolve(logOf(bare), { endpoints: [] }).didDocument).not.toHaveProperty("service");
  });

  it("presents an alias only if the caller has verified it, and the log lists it", () => {
    const named = new KeyMind("named", 0, { alsoKnownAs: ["dns:named.example", "at://named"] });
    const held = logOf(named);
    expect(resolve(held).didDocument).not.toHaveProperty("alsoKnownAs");
    expect(resolve(held, { verifiedAliases: [] }).didDocument).not.toHaveProperty("alsoKnownAs");
    const verifiedAliases = ["at://named", "dns:someone-else.example"];
    expect(resolve(held, { verifiedAliases }).didDocument.alsoKnownAs).toEqual(["at://named"]);
  });

  it("says in its metadata what the log holds and the document does not", () => {
    const parent = new KeyMind("parent");
    const child = new KeyMind("child").address;
    const forked = new KeyMind("forked", 0, {
      parents: [{ mind: parent.address, at: parent.versionId() }],
    }).fork(10, { child });
    expect(resolve(logOf(forked)).didDocumentMetadata).toEqual({
      versionId: forked.versionId(),
      deactivated: false,
      parents: [{ mind: parent.address, at: parent.versionId() }],
      children: [child],
      nextKeyHashes: [keyHash(forked.control(2).publicKey)],
      nextThreshold: 1,
    });
    forked.retire(20);
    expect(resolve(logOf(forked)).didDocumentMetadata).toEqual({
      versionId: forked.versionId(),
      deactivated: true,
      parents: [{ mind: parent.address, at: parent.versionId() }],
      children: [child],
      nextKeyHashes: [],
    });
    const members = [new KeyMind("a"), new KeyMind("b"), new KeyMind("c")];
    const club = new Collective("club", members, 2);
    expect(resolve(logOf(club, members)).didDocumentMetadata).toEqual({
      versionId: club.versionId(),
      deactivated: false,
      parents: [],
      children: [],
      members: members.map((member) => member.address),
      threshold: 2,
    });
  });
});

describe(`${clause("L1 2.4")} resolution with versionId`, () => {
  const ada = new KeyMind("ada");
  const later = ada.operational(1).publicKey;
  ada.update(10, { keys: [{ key: later }], homes: ["https://ada.example"] }).retire(20);
  const log = logOf(ada);

  it("produces the document from the log up to and including the event named", () => {
    const keys = [ada.operational().publicKey, later, later];
    [0, 1, 2].forEach((position) => {
      const versionId = ada.versionId(position);
      const { didDocument: document, didDocumentMetadata: metadata } = resolve(log, { versionId });
      expect(document.assertionMethod).toEqual([
        `${ada.address}?versionId=${versionId}#${keys[position]}`,
      ]);
      expect(metadata.versionId).toBe(versionId);
      expect(metadata.deactivated).toBe(position === 2);
      expect("service" in document).toBe(position > 0);
    });
    expect(resolve(log).didDocumentMetadata.versionId).toBe(ada.versionId(2));
  });

  it("gives each key the id that a key reference in a proof carries", () => {
    const signed = ada.sign(intentBy(ada, 15), { key: 1, position: 1 });
    const method = signed.proof[0]?.verificationMethod;
    const { didDocument: document } = resolve(log, { versionId: ada.versionId(1) });
    expect(document.verificationMethod.map((entry) => entry.id)).toContain(method);
    expect(parseKeyRef(method)?.key).toBe(later);
    // Services are not versioned: a home is a home.
    expect(document.service?.[0]?.id).toBe(`${ada.address}#home-0`);
  });

  it("refuses a version the log does not have", () => {
    const other = new KeyMind("other");
    for (const versionId of [other.versionId(), `3-${ada.versionId(2).slice(2)}`, "", "latest"]) {
      expect(didDocument(log, { versionId })).toMatchObject({
        ok: false,
        issues: [{ clause: "L1 2.4" }],
      });
    }
  });
});
