// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import type { Issue } from "@oip/schema";
import { describe, expect, it } from "vitest";

import { issuesUnder, no, ok, under } from "../src/result.ts";

describe("results", () => {
  const issues: [Issue, ...Issue[]] = [
    { path: "", message: "the first", clause: "core 5.2" },
    { path: "/created", message: "the second", clause: "core 1.4" },
    { path: "/authority/0", message: "the third", clause: "core 5.2" },
  ];

  it("put every reason of a rejection under the path of the thing rejected", () => {
    expect(issuesUnder("/proof/3", { issues })).toEqual([
      { path: "/proof/3", message: "the first", clause: "core 5.2" },
      { path: "/proof/3/created", message: "the second", clause: "core 1.4" },
      { path: "/proof/3/authority/0", message: "the third", clause: "core 5.2" },
    ]);
    expect(under("/a", { issues })).toEqual({
      ok: false,
      issues: issuesUnder("/a", { issues }),
    });
    // The reasons given are not changed.
    expect(issues.map((issue) => issue.path)).toEqual(["", "/created", "/authority/0"]);
  });

  it("are a value or the reasons there is none", () => {
    expect(ok(7)).toEqual({ ok: true, value: 7 });
    expect(no("why", "core 1.1")).toEqual({
      ok: false,
      issues: [{ path: "", message: "why", clause: "core 1.1" }],
    });
    expect(no("why", "core 1.1", "/x")).toEqual({
      ok: false,
      issues: [{ path: "/x", message: "why", clause: "core 1.1" }],
    });
  });
});
