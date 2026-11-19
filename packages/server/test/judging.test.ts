// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId } from "@oip/core";
import { cutShortCount, noteCutShort } from "@oip/schema";
import { clause } from "@oip/testkit";
import { bookOf, KeyMind } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import { overlaid, seenAt, standing, Unavailable } from "../src/index.ts";

describe("a judgement a service acts on (ADR-0010)", () => {
  it("is the one that was made, where every check in it was made", () => {
    expect(standing(() => 7)).toBe(7);
    expect(standing(() => undefined)).toBeUndefined();
    expect(() =>
      standing(() => {
        throw new TypeError("its own");
      }),
    ).toThrow(TypeError);
  });

  it("is refused where a check in it was cut short, whatever it answered", () => {
    const before = cutShortCount();
    expect(() =>
      standing(() => {
        noteCutShort(new RangeError("Maximum call stack size exceeded"));
        return { ok: true };
      }),
    ).toThrow(Unavailable);
    expect(cutShortCount()).toBe(before + 1);
    // One that was cut short before this judgement began says nothing of it.
    expect(standing(() => "sound")).toBe("sound");
  });
});

describe(`${clause("core 9.4")} evidence laid over what is held`, () => {
  const ada = new KeyMind("ada");
  const held = bookOf([ada]);

  it("answers for proofs the view knows nothing of, and leaves what is held as it stands", () => {
    const event = contentId(ada.events[0]);
    const view = overlaid(held, (digest) => (digest === "sha256:new" ? 500n : undefined));
    expect(view.evidence.proofSeen("sha256:new")).toBe(500n);
    expect(view.evidence.proofSeen("sha256:other")).toBeUndefined();
    expect(view.log(ada.address)).toStrictEqual(held.log(ada.address));
    expect(view.log("did:oip:nobody").ok).toBe(false);
    // The times of events are the view's own, and nothing is laid over them.
    expect(view.evidence.eventSeen(event)).toBe(held.evidence.eventSeen(event));
    expect(view.evidence.eventSeen(event)).toBeDefined();
    expect(view.evidence.eventSeen("nothing")).toBeUndefined();
    // What the view holds for a proof stands, whatever is laid over it.
    const seen = { ...held.evidence, proofSeen: () => 100n };
    const firm = overlaid({ log: held.log.bind(held), evidence: seen }, () => 900n);
    expect(firm.evidence.proofSeen("sha256:any")).toBe(100n);
  });

  it("may be that some proofs were first seen now, and says nothing of any other", () => {
    const seen = seenAt(new Set(["sha256:one", "sha256:two"]), 700n);
    expect(seen("sha256:one")).toBe(700n);
    expect(seen("sha256:two")).toBe(700n);
    expect(seen("sha256:three")).toBeUndefined();
  });
});
