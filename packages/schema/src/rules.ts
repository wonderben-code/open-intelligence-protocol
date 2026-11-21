// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The structural rules JSON Schema cannot express: comparisons between two
 * members, arithmetic on lengths, and limits on recursion. Each rule reads
 * only the record in front of it. Rules that need an identity log, the time or
 * a signature belong to the packages above this one.
 *
 * Every function here takes a value that has already passed its schema.
 */

import { type Issue, pointerToken, quote } from "./issue.ts";
import type { Proof } from "./proof.ts";
import type { OipRecord, RecordOf } from "./registry.ts";
import type { PolicyStatement } from "./records/delegation.ts";
import type { ExtensionRecord } from "./records/extension.ts";
import type { Controller, IdentityEvent } from "./records/identity.ts";
import { parseSelector } from "./selector.ts";

/** Layer 1, 11.3 and Section 19: statements nest at most 8 deep. */
export const MAX_POLICY_DEPTH = 8;

type Report = (path: string, message: string, clause: string) => void;

function checkStatement(
  statement: PolicyStatement,
  depth: number,
  path: string,
  report: Report,
): void {
  if (depth > MAX_POLICY_DEPTH) {
    report(path, `a policy statement nests more than ${MAX_POLICY_DEPTH} deep`, "L1 11.3");
    return;
  }
  const selector = (at: string, value: string) => {
    if (parseSelector(value) === undefined) {
      report(
        at,
        `${quote(value)} is not a selector: use ".", ".name", "[index]" or ["name"]`,
        "L1 11.3",
      );
    }
  };
  switch (statement[0]) {
    case "not":
      checkStatement(statement[1], depth + 1, `${path}/1`, report);
      break;
    case "and":
    case "or":
      statement[1].forEach((inner, i) => {
        checkStatement(inner, depth + 1, `${path}/1/${i}`, report);
      });
      break;
    case "all":
    case "any":
      selector(`${path}/1`, statement[1]);
      checkStatement(statement[2], depth + 1, `${path}/2`, report);
      break;
    default:
      selector(`${path}/1`, statement[1]);
  }
}

function checkPolicy(policy: readonly PolicyStatement[], path: string, report: Report): void {
  policy.forEach((statement, i) => {
    checkStatement(statement, 0, `${path}/${i}`, report);
  });
}

function checkController(
  controller: Controller,
  self: string | undefined,
  path: string,
  report: Report,
): void {
  if ("members" in controller) {
    const count = controller.members.length;
    // A genesis has no address until its content ID is known, so only later
    // events are checked here; @oip/identity checks the genesis.
    const own = self === undefined ? -1 : controller.members.indexOf(self);
    if (own !== -1) {
      report(`${path}/members/${own}`, "a mind is not a member of itself", "L1 3.4");
    }
    if (controller.threshold > count || 2 * controller.threshold <= count) {
      report(
        `${path}/threshold`,
        `threshold ${controller.threshold} is not a majority of ${count} members`,
        "L1 3.4",
      );
    }
    return;
  }
  const count = controller.next.length;
  if (count === 0) {
    if (controller.nextThreshold !== undefined) {
      report(`${path}/nextThreshold`, "nextThreshold must be absent when next is empty", "L1 3.4");
    }
    return;
  }
  const threshold = controller.nextThreshold ?? 1;
  if (threshold > count || 2 * threshold <= count) {
    report(
      `${path}/nextThreshold`,
      `nextThreshold ${threshold} is not a majority of the ${count} keys committed in next`,
      "L1 3.4",
    );
  }
}

function checkKeySets(event: IdentityEvent, path: string, report: Report): void {
  const seenIn = new Map<string, string>();
  for (const set of ["keys", "invocation", "agreement"] as const) {
    const inSet = new Set<string>();
    event[set]?.forEach((entry, i) => {
      const at = `${path}/${set}/${i}/key`;
      if (inSet.has(entry.key)) {
        report(at, `key ${entry.key} appears twice in ${set}`, "L1 3.5");
      }
      inSet.add(entry.key);
      const other = seenIn.get(entry.key);
      if (other !== undefined && other !== set) {
        report(at, `key ${entry.key} is in both ${other} and ${set}`, "L1 3.5");
      }
      seenIn.set(entry.key, set);
    });
  }
}

function checkIdentityEvent(event: IdentityEvent, path: string, report: Report): void {
  const self = event.type === "Genesis" ? undefined : event.mind;
  if (event.controller !== undefined) {
    checkController(event.controller, self, `${path}/controller`, report);
  }
  checkKeySets(event, path, report);
  if (event.type === "Genesis" || event.revoked === undefined) return;
  // 4.5: a revoked key is not in the resulting keys or invocation. Sets the
  // event leaves out are checked against the state, by @oip/identity.
  const revoked = new Set(event.revoked.map((entry) => entry.key));
  for (const set of ["keys", "invocation"] as const) {
    event[set]?.forEach((entry, i) => {
      if (revoked.has(entry.key)) {
        report(`${path}/${set}/${i}/key`, `key ${entry.key} is revoked by this event`, "L1 4.5");
      }
    });
  }
}

function checkCommitment(record: RecordOf<"Commitment">, path: string, report: Report): void {
  const minds = new Set<string>();
  record.parties.forEach((party, i) => {
    if (minds.has(party.mind)) {
      report(`${path}/parties/${i}/mind`, `${party.mind} is a party more than once`, "L2 5.1");
    }
    minds.add(party.mind);
  });
  const price = record.terms.price;
  if (price === undefined) return;
  for (const side of ["payer", "payee"] as const) {
    if (!minds.has(price[side])) {
      report(`${path}/terms/price/${side}`, `the ${side} must be one of the parties`, "L2 5.1");
    }
  }
  if (price.payer === price.payee) {
    report(`${path}/terms/price/payee`, "payer and payee must be two different parties", "L2 5.1");
  }
}

function checkCollective(record: RecordOf<"Collective">, path: string, report: Report): void {
  for (const [name, role] of Object.entries(record.roles ?? {})) {
    role.powers?.forEach((power, i) => {
      if (power.policy !== undefined) {
        checkPolicy(power.policy, `${path}/roles/${pointerToken(name)}/powers/${i}/policy`, report);
      }
    });
  }
}

/** core 8.3: every critical namespace has an extension block. */
function checkCritical(
  record: { readonly critical?: readonly string[]; readonly ext?: object },
  path: string,
  report: Report,
): void {
  record.critical?.forEach((namespace, i) => {
    if (record.ext === undefined || !Object.hasOwn(record.ext, namespace)) {
      report(
        `${path}/critical/${i}`,
        `critical namespace ${quote(namespace)} is not in ext`,
        "core 8.3",
      );
    }
  });
}

function checkRecordAt(record: OipRecord, path: string, report: Report): void {
  checkCritical(record, path, report);

  switch (record.type) {
    case "Genesis":
    case "Update":
    case "Fork":
    case "Retire":
      checkIdentityEvent(record, path, report);
      break;
    case "Delegation":
      if (record.delegate === record.author) {
        report(
          `${path}/delegate`,
          "a delegation's delegate must differ from its author",
          "L1 11.1",
        );
      }
      if (record.policy !== undefined) checkPolicy(record.policy, `${path}/policy`, report);
      break;
    case "Commitment":
      checkCommitment(record, path, report);
      break;
    case "Collective":
      checkCollective(record, path, report);
      break;
    case "Session":
      for (let i = 1; i < record.participants.length; i++) {
        // Addresses are ASCII, so comparing UTF-16 code units is comparing code points.
        if ((record.participants[i - 1] ?? "") >= (record.participants[i] ?? "")) {
          report(
            `${path}/participants/${i}`,
            "participants must be sorted by code point",
            "L1 14.1",
          );
        }
      }
      break;
    case "Participant": {
      const ids = new Set<string>();
      record.capabilities?.forEach((capability, i) => {
        if (ids.has(capability.id)) {
          report(
            `${path}/capabilities/${i}/id`,
            `capability id ${quote(capability.id)} is used more than once`,
            "L1 16.2",
          );
        }
        ids.add(capability.id);
      });
      break;
    }
    case "Forwarded":
      checkRecordAt(record.packet, `${path}/packet`, report);
      break;
    case "Bundle":
      record.log.forEach((event, i) => {
        checkRecordAt(event, `${path}/log/${i}`, report);
      });
      if (record.location !== undefined) checkRecordAt(record.location, `${path}/location`, report);
      if (record.participant !== undefined) {
        checkRecordAt(record.participant, `${path}/participant`, report);
      }
      break;
    case "LogPage":
      record.events.forEach((event, i) => {
        checkRecordAt(event, `${path}/events/${i}`, report);
      });
      break;
    case "FeedPage":
      record.entries.forEach((entry, i) => {
        checkRecordAt(entry, `${path}/entries/${i}`, report);
      });
      break;
    case "DuplicityEvidence":
      record.pairs.forEach((pair, i) => {
        pair.forEach((event, j) => {
          checkRecordAt(event, `${path}/pairs/${i}/${j}`, report);
        });
      });
      break;
    default:
      break;
  }
}

/** More issues than a caller reports (see `MAX_ISSUES` in validate.ts) are not worth gathering. */
const ENOUGH = 64;

function collect(run: (report: Report) => void): Issue[] {
  const issues: Issue[] = [];
  run((path, message, clause) => {
    if (issues.length < ENOUGH) issues.push({ path, message, clause });
  });
  return issues;
}

/** The rule violations in a record of an extension's type that has passed `ExtensionRecord`. */
export function checkExtensionRules(record: ExtensionRecord): Issue[] {
  return collect((report) => {
    checkCritical(record, "", report);
  });
}

/** The rule violations in a record that has passed its schema. Empty when there are none. */
export function checkRecordRules(record: OipRecord): Issue[] {
  return collect((report) => {
    checkRecordAt(record, "", report);
  });
}

/**
 * The rule violations in a proof that has passed the `Proof` schema. Empty
 * when there are none. Inline records in `authority` are not checked here:
 * a bad chain or charter means the proof counts for nobody but its signer,
 * not that it stops being a proof.
 */
export function checkProofRules(proof: Proof): Issue[] {
  return collect((report) => {
    const method = proof.verificationMethod;
    if (method.startsWith("did:key:")) {
      // core 6.2: a control-key-ref names the same key on both sides of "#".
      const [key, fragment] = method.slice("did:key:".length).split("#");
      if (key !== fragment) {
        report(
          "/verificationMethod",
          "both keys of a control-key-ref must be identical",
          "core 6.2",
        );
      }
    }
  });
}
