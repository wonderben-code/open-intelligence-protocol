// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Telling a check that was cut short from a verdict (ADR-0010).
 *
 * The count must move for a failure that says nothing of the value judged,
 * and for no other: a value from outside that could move it would turn its
 * own rejection into a refusal for want of room, for whoever asks.
 */

import { inNode } from "@oip/testkit";
import fc from "fast-check";
import { afterEach, describe, expect, it, vi } from "vitest";

import type * as CutShort from "../src/cut-short.ts";
import {
  CUT_SHORT,
  cutShort,
  cutShortCount,
  finding,
  judging,
  noteCutShort,
  parseSelector,
  UnfitProcess,
  validateJson,
  validateProof,
  validateRecord,
  type Validation,
} from "../src/index.ts";

/** By how much the count moves while `work` runs. */
function moved(work: () => unknown): number {
  const before = cutShortCount();
  work();
  return cutShortCount() - before;
}

const noted = (error: unknown): number => moved(() => noteCutShort(error));

/** The error an engine throws when its call stack is spent, made by spending it. */
function spent(): unknown {
  const descend = (): never => descend();
  try {
    return descend();
  } catch (error) {
    return error;
  }
}

const revoked = (): object => {
  const { proxy, revoke } = Proxy.revocable({}, {});
  revoke();
  return proxy;
};

describe("a failure for want of room, or for the state of the process", () => {
  it("is the engine's own error for a spent call stack, by its message, whole", () => {
    expect(noted(spent())).toBe(1);
    expect(noted(new RangeError("Maximum call stack size exceeded"))).toBe(1);
    // As JavaScriptCore and SpiderMonkey say it.
    expect(noted(new RangeError("Maximum call stack size exceeded."))).toBe(1);
    expect(noted(new Error("too much recursion"))).toBe(1);
    // A regular expression that could not be compiled with the stack spent, as V8 reports it.
    expect(noted(new SyntaxError("Invalid regular expression: /^[a-z]+$/u: Stack overflow"))).toBe(
      1,
    );
    // And one that could not be parsed.
    expect(
      noted(
        new SyntaxError(
          "Invalid regular expression: /^[a-z]+$/u: Maximum call stack size exceeded",
        ),
      ),
    ).toBe(1);
  });

  it("is each thing the engine throws for a regular expression at the end of the stack", () => {
    // Asked of the engine itself, in a process of its own: an expression made there, and
    // one made beforehand and first used there.
    const report = inNode(new URL("./regex-at-depth.node.ts", import.meta.url)) as Readonly<
      Record<"made" | "firstUsed", Readonly<Record<string, number>>>
    >;
    const kinds = [...Object.keys(report.made), ...Object.keys(report.firstUsed)];
    expect(kinds.filter((kind) => !kind.endsWith(", counted"))).toStrictEqual([]);
    // The engine said each of the three things this run. If it has new words for one, the
    // rule must learn them: this is where that shows.
    expect(Object.keys(report.made)).toContain(
      "SyntaxError: Invalid regular expression: /…/: Maximum call stack size exceeded, counted",
    );
    expect(Object.keys(report.firstUsed)).toContain(
      "SyntaxError: Invalid regular expression: /…/: Stack overflow, counted",
    );
    expect(kinds).toContain("RangeError: Maximum call stack size exceeded, counted");
  });

  it("is a process that can serialise nothing", () => {
    expect(noted(new UnfitProcess("nothing can be serialised safely"))).toBe(1);
    expect(new UnfitProcess("x").name).toBe("UnfitProcess");
    expect(new UnfitProcess("x")).toBeInstanceOf(Error);
  });

  it("is no other failure, whatever its class and whatever it quotes", () => {
    for (const error of [
      // A library's error for a value out of range: such a value may come from outside.
      new RangeError("invalid scalar: expected 0 <= sc < curve.n"),
      new RangeError("expected valid point.y: 0 <= n < 57896…, got 57896…"),
      new RangeError("Invalid array length"),
      new RangeError(""),
      // A message that quotes its input, which says the engine's words.
      new SyntaxError(
        "Unexpected token 'M', \"Maximum call stack size exceeded\" is not valid JSON",
      ),
      new SyntaxError("Unexpected token: Stack overflow"),
      new SyntaxError("Invalid regular expression: /(/: Unterminated group"),
      // An expression that says the engine's words: the reason comes after it.
      new SyntaxError("Invalid regular expression: /(: Stack overflow/: Unterminated group"),
      new SyntaxError(
        "Invalid regular expression: /(: Maximum call stack size exceeded/: Unterminated group",
      ),
      // And the reason for a spent stack on an error of another class.
      new Error("Invalid regular expression: /a/: Maximum call stack size exceeded"),
      new Error("Maximum call stack size exceeded, said the record"),
      new Error("the call stack"),
      new TypeError("not a function"),
      new Error("anything else"),
    ]) {
      expect(noted(error), String(error)).toBe(0);
    }
    // What is no error is no engine's error.
    for (const value of [undefined, null, 7, "Maximum call stack size exceeded", {}, []]) {
      expect(noted(value), JSON.stringify(value)).toBe(0);
    }
    expect(noted({ message: "Maximum call stack size exceeded" })).toBe(0);
  });

  it("is told without running any code of what was thrown", () => {
    let ran = 0;
    const sly = new Error("plain");
    Object.defineProperty(sly, "message", {
      get: () => {
        ran++;
        return "Maximum call stack size exceeded";
      },
    });
    Object.defineProperty(sly, "name", {
      get: () => {
        ran++;
        throw new Error("no name");
      },
    });
    expect(noted(sly)).toBe(0);
    expect(ran).toBe(0);
  });

  it("is counted, and never thrown on, where what was thrown cannot be looked at", () => {
    const trapped = new Proxy(
      {},
      {
        getPrototypeOf: () => {
          throw new Error("trap");
        },
      },
    );
    for (const value of [revoked(), trapped]) {
      let counted = 0;
      expect(() => {
        counted = noted(value);
      }).not.toThrow();
      // Nothing shows that it is not a failure for want of room.
      expect(counted).toBe(1);
    }
  });

  it("is never noted for data: no value of JSON, valid or not, moves the count", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        expect(
          moved(() => {
            validateJson(value);
            validateRecord(value);
            validateProof(value);
          }),
        ).toBe(0);
      }),
      { numRuns: 300 },
    );
    fc.assert(
      fc.property(fc.string(), (text) => {
        expect(moved(() => parseSelector(text))).toBe(0);
      }),
      { numRuns: 300 },
    );
    // A selector that quotes the engine's words is a selector that does not parse.
    expect(moved(() => parseSelector('["Maximum call stack size exceeded'))).toBe(0);
    expect(moved(() => parseSelector('["Maximum call stack size exceeded"x]'))).toBe(0);
  });
});

describe("a second copy of this module in one process", () => {
  // Two installed versions, or two bundles: `@oip/core` may note through one copy while
  // `@oip/identity` compares through the other.
  async function secondCopy(): Promise<typeof CutShort> {
    vi.resetModules();
    return import("../src/cut-short.ts");
  }

  it("shares the count: a note made through one is seen through the other", async () => {
    const other = await secondCopy();
    expect(other.noteCutShort).not.toBe(noteCutShort);
    expect(other.cutShortCount()).toBe(cutShortCount());
    expect(moved(() => other.noteCutShort(spent()))).toBe(1);
    const before = other.cutShortCount();
    noteCutShort(spent());
    expect(other.cutShortCount()).toBe(before + 1);
    // So a judge of the one refuses for a check that the other noted.
    expect(
      judging(() => {
        other.noteCutShort(spent());
        return { ok: true, value: 1 };
      }),
    ).toBe(cutShort());
    expect(
      other.finding(() => {
        noteCutShort(spent());
        return 1;
      }),
    ).toBeUndefined();
  });

  it("knows the other's `UnfitProcess`, which is none of its own", async () => {
    const other = await secondCopy();
    const unfit = new other.UnfitProcess("nothing can be serialised safely");
    expect(unfit).not.toBeInstanceOf(UnfitProcess);
    expect(noted(unfit)).toBe(1);
    expect(moved(() => other.noteCutShort(new UnfitProcess("x")))).toBe(1);
    // The mark is the error's own: one on a prototype marks nothing, and no getter is run.
    const marked = Object.create(unfit) as object;
    expect(noted(marked)).toBe(0);
    let ran = 0;
    const sly = Object.defineProperty(
      new Error("plain"),
      Symbol.for("@oip/schema/unfit-process/1"),
      {
        get: () => {
          ran++;
          return true;
        },
      },
    );
    expect(noted(sly)).toBe(0);
    expect(ran).toBe(0);
  });

  it.each([
    ["closed", "undefined"],
    ["taken", "string"],
    ["unsound", "object"],
    ["frozen", "object"],
  ])(
    "keeps a count of its own where the global object cannot hold the one shared: %s",
    (how, shared) => {
      // A global object that takes no new property; one where the place is taken by
      // something else, or by what looks like a count and is none; and a count that other
      // code froze after the module loaded. Each in a process of its own.
      expect(inNode(new URL("./own-count.node.ts", import.meta.url), [how])).toStrictEqual({
        moved: 1,
        refused: true,
        answered: { ok: true, value: 1 },
        shared,
      });
    },
  );
});

describe("a validator, where a check is cut short", () => {
  /** A value that throws when anything is asked of it. */
  const failing = (error: unknown): object => {
    const refuse = (): never => {
      throw error;
    };
    return new Proxy(
      {},
      { ownKeys: refuse, get: refuse, has: refuse, getOwnPropertyDescriptor: refuse },
    );
  };
  const SPENT = { ok: false, issues: [{ path: "", clause: "implementation limit" }] };

  it("refuses for want of room, and does not call the value unreadable", () => {
    for (const validate of [validateJson, validateRecord, validateProof]) {
      expect(validate(failing(spent()))).toMatchObject(SPENT);
      // A value that throws anything else is one that cannot be read as plain data.
      expect(validate(failing(new Error("no")))).toMatchObject({
        ok: false,
        issues: [{ clause: "core 1.2" }],
      });
    }
  });

  it("answers, and does not throw, for a value that throws what cannot be looked at", () => {
    const sly = new Error("plain");
    Object.defineProperty(sly, "name", {
      get: () => {
        // Not an error, and not a thing that can be looked at.
        throw revoked() as Error;
      },
    });
    for (const thrown of [revoked(), sly]) {
      for (const validate of [validateJson, validateRecord, validateProof]) {
        expect(validate(failing(thrown)).ok).toBe(false);
      }
    }
  });
});

describe("the refusal for a check that was cut short", () => {
  it("says nothing of what was judged, and cannot be changed", () => {
    const refusal = cutShort();
    expect(refusal).toStrictEqual({
      ok: false,
      issues: [{ path: "", message: CUT_SHORT, clause: "implementation limit" }],
    });
    expect(Object.isFrozen(refusal)).toBe(true);
    expect(Object.isFrozen(refusal.issues)).toBe(true);
    expect(Object.isFrozen(refusal.issues[0])).toBe(true);
    expect(cutShort()).toBe(refusal);
  });
});

describe("judging for a caller", () => {
  const good: Validation<number> = { ok: true, value: 7 };
  const bad: Validation<number> = {
    ok: false,
    issues: [{ path: "/x", message: "wrong", clause: "core 1.2" }],
  };

  it("gives the answer that was worked out, where no check was cut short", () => {
    expect(judging(() => good)).toBe(good);
    expect(judging(() => bad)).toBe(bad);
    expect(finding(() => 7)).toBe(7);
    expect(finding(() => undefined)).toBeUndefined();
  });

  it("refuses, or finds nothing, where one was: whatever was worked out", () => {
    const cut =
      <T>(answer: T) =>
      () => {
        noteCutShort(spent());
        return answer;
      };
    expect(judging(cut(good))).toBe(cutShort());
    expect(judging(cut(bad))).toBe(cutShort());
    expect(finding(cut(7))).toBeUndefined();
  });

  it("answers for work that fails for want of room, at whatever depth", () => {
    const failing = (): never => {
      throw spent();
    };
    expect(judging(failing)).toBe(cutShort());
    expect(finding(failing)).toBeUndefined();
    expect(moved(() => judging(failing))).toBe(1);
  });

  it("does not hide a failure that is no such thing", () => {
    const broken = (): never => {
      throw new TypeError("a mistake in the calling program");
    };
    expect(() => judging(broken)).toThrow(TypeError);
    expect(() => finding(broken)).toThrow(TypeError);
    // Nor a library's error for a value out of range.
    const outOfRange = (): never => {
      throw new RangeError("invalid scalar");
    };
    expect(() => judging(outOfRange)).toThrow(RangeError);
  });
});

describe("a spent stack inside what this package calls", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("is noted by the reading of a selector, which answers that it is none", () => {
    // The engine's parser is given text, which cannot be made to throw: a spy stands in for
    // the call that found no room.
    vi.spyOn(JSON, "parse").mockImplementationOnce(() => {
      throw new RangeError("Maximum call stack size exceeded");
    });
    const before = cutShortCount();
    expect(parseSelector('["a name"]')).toBeUndefined();
    expect(cutShortCount()).toBe(before + 1);
    expect(parseSelector('["a name"]')).toStrictEqual(["a name"]);
    // A name that is not a JSON string is no selector, and no sign of anything else.
    expect(parseSelector('["\\u00zz"]')).toBeUndefined();
    expect(cutShortCount()).toBe(before + 1);
  });
});
