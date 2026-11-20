// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `inNode` says how a script's process ended. A run that reports one line
 * of a failure must be able to tell a script that failed from one that
 * crashed and from one that was stopped for taking too long.
 */

import { describe, expect, it } from "vitest";

import { inNode } from "../src/index.ts";

const script = new URL("./ends.node.ts", import.meta.url);
const said = (...args: [string, number?]): string => {
  const [how, timeoutMs] = args;
  try {
    inNode(script, [how], timeoutMs);
  } catch (error) {
    return (error as Error).message;
  }
  throw new Error(`the script ended well, asked to end ${how}`);
};

describe("inNode", () => {
  it("returns what the script printed, read as JSON", () => {
    expect(inNode(script, ["well"])).toStrictEqual({ ended: "well" });
  });

  it("says with what code a script ended, and the end of what it wrote to its error, on one line", () => {
    const message = said("badly");
    expect(message).toMatch(/ends\.node\.ts ended with 3\. Its standard error ends: /u);
    expect(message).toContain("the first line of what went wrong | and the last");
    expect(message.split("\n")).toHaveLength(1);
  });

  it("says that a script wrote nothing, where it wrote nothing", () => {
    expect(said("silently")).toMatch(/ended with 1\. It wrote nothing to its standard error$/u);
  });

  it("says by what signal a script was ended", () => {
    expect(said("killed")).toMatch(/was ended by SIGKILL\. /u);
  });

  it("says that a script was stopped for taking too long, and after how long", () => {
    expect(said("never", 500)).toMatch(/was stopped after 0\.5 seconds\. /u);
  });
});
