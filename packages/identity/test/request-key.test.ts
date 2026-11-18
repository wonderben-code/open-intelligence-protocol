// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { formatKeyRef, parseKeyRef, parseVerificationMethod } from "@oip/core";
import { cutShort, noteCutShort } from "@oip/schema";
import { clause } from "@oip/testkit";
import { at, bookOf, Collective, KeyMind, type Mind } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import { requestKeyTime } from "../src/index.ts";

/** The key reference of one of a mind's operational keys, pinned to a version of its log. */
function keyOf(mind: Mind, key = 0, position?: number) {
  const ref = parseKeyRef(
    formatKeyRef(mind.address, mind.versionId(position), mind.operational(key).publicKey),
  );
  if (ref === undefined) throw new Error("no key reference");
  return ref;
}

const refusal = (...args: Parameters<typeof requestKeyTime>) => {
  const result = requestKeyTime(...args);
  if (result.ok) throw new Error("the key counts");
  return result.issues[0].clause;
};

describe(`${clause("L1 13.3", "L1 6.1")} the key of an authenticated request`, () => {
  it("is a valid operational key of its mind, judged at the later of its date and its receipt", () => {
    const ada = new KeyMind("ada");
    const book = bookOf([ada]);
    expect(requestKeyTime(keyOf(ada), at(90), at(100), book)).toStrictEqual({
      ok: true,
      value: at(100),
    });
    // Dated ahead of the receiver's clock, within what clocks may differ by (core 9.3).
    expect(requestKeyTime(keyOf(ada), at(400), at(100), book)).toStrictEqual({
      ok: true,
      value: at(400),
    });
    expect(refusal(keyOf(ada), at(400.000000001), at(100), book)).toBe("core 9.3");
  });

  it("is not judged where the check was cut short: the answer says so (ADR-0010)", () => {
    const ada = new KeyMind("ada");
    const book = bookOf([ada]);
    const cut = { now: true };
    const noting = {
      evidence: book.evidence,
      log: (mind: string) => {
        if (cut.now) noteCutShort(new RangeError("Maximum call stack size exceeded"));
        return book.log(mind);
      },
    };
    expect(requestKeyTime(keyOf(ada), at(90), at(100), noting)).toStrictEqual(cutShort());
    cut.now = false;
    expect(requestKeyTime(keyOf(ada), at(90), at(100), noting)).toStrictEqual({
      ok: true,
      value: at(100),
    });
  });

  it("is a key of the version it names", () => {
    const ada = new KeyMind("ada");
    const bob = new KeyMind("bob");
    const book = bookOf([ada, bob]);
    // Bob's key under Ada's name, and a version Ada's log does not have.
    const borrowed = parseKeyRef(
      formatKeyRef(ada.address, ada.versionId(), bob.operational().publicKey),
    );
    const elsewhere = parseKeyRef(
      formatKeyRef(ada.address, bob.versionId(), ada.operational().publicKey),
    );
    if (borrowed === undefined || elsewhere === undefined) throw new Error("no key reference");
    expect(refusal(borrowed, at(90), at(100), book)).toBe("L1 6.1");
    expect(refusal(elsewhere, at(90), at(100), book)).toBe("L1 6.1");
    // A mind whose log is not held.
    expect(requestKeyTime(keyOf(new KeyMind("stranger")), at(90), at(100), book).ok).toBe(false);
  });

  it("is among the keys of the latest state known: a request describes the present", () => {
    const zed = new KeyMind("zed");
    const old = keyOf(zed);
    zed.update(50, { keys: [{ key: zed.operational(1).publicKey }] });
    const book = bookOf([zed]);
    // Removed at 50: whenever the request says it was made, the key signs no request now.
    expect(refusal(old, at(40), at(100), book)).toBe("L1 6.1");
    expect(refusal(old, at(40), at(45), book)).toBe("L1 6.1");
    expect(requestKeyTime(keyOf(zed, 1), at(90), at(100), book).ok).toBe(true);
    // The new key, pinned to the version before it was a key.
    expect(refusal(keyOf(zed, 1, 0), at(90), at(100), book)).toBe("L1 6.1");
  });

  it("is no key of a mind that has retired, and no key declared compromised", () => {
    const gone = new KeyMind("gone");
    const key = keyOf(gone);
    gone.retire(50);
    expect(requestKeyTime(key, at(90), at(100), bookOf([gone])).ok).toBe(false);
    const leaky = new KeyMind("leaky");
    const leaked = keyOf(leaky);
    leaky.update(50, {
      keys: [{ key: leaky.operational(1).publicKey }],
      revoked: [{ key: leaky.operational().publicKey, compromisedSince: "2026-11-17T09:00:00Z" }],
    });
    expect(requestKeyTime(leaked, at(90), at(100), bookOf([leaky])).ok).toBe(false);
  });

  it("is an operational key: a control key signs identity events and nothing else", () => {
    const ada = new KeyMind("ada");
    const control = parseVerificationMethod(
      `did:key:${ada.control(0).publicKey}#${ada.control(0).publicKey}`,
    );
    if (control === undefined) throw new Error("no control key reference");
    expect(refusal(control as never, at(90), at(100), bookOf([ada]))).toBe("L1 3.11");
  });

  it("is a key of the mind itself: a collective authenticates with a key of its own or not at all", () => {
    const ada = new KeyMind("ada");
    const bob = new KeyMind("bob");
    const club = new Collective("club", [ada, bob], 2, 5);
    const book = bookOf([ada, bob, club]);
    // A member's key under the collective's name is no key of the collective.
    const members = parseKeyRef(
      formatKeyRef(club.address, club.versionId(), ada.operational().publicKey),
    );
    if (members === undefined) throw new Error("no key reference");
    expect(refusal(members, at(90), at(100), book)).toBe("L1 6.1");
  });
});
