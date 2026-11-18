// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { sha256Digest } from "@oip/core";
import type { Evidence } from "@oip/schema";
import { clause } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import { evidenceIsChecked, evidenceMatches } from "../src/index.ts";

const bytes = new TextEncoder().encode("The lease, translated.\n");
const item = (more: Partial<Evidence> = {}): Evidence => ({
  kind: "uri",
  ref: "https://files.example/lease.txt",
  digest: sha256Digest(bytes),
  ...more,
});

describe(`${clause("L2 9")} an evidence item`, () => {
  it("matches the exact bytes its digest names, and no others", () => {
    expect(evidenceMatches(item(), bytes)).toBe(true);
    expect(evidenceMatches(item(), bytes.slice(0, -1))).toBe(false);
    expect(evidenceMatches(item(), new Uint8Array())).toBe(false);
    const changed = Uint8Array.from(bytes);
    changed[0] = (changed[0] ?? 0) ^ 1;
    expect(evidenceMatches(item(), changed)).toBe(false);
    // The digest is of the bytes, whatever the kind of the item.
    expect(evidenceMatches(item({ kind: "hash", ref: "lease.txt" }), bytes)).toBe(true);
    expect(
      evidenceMatches(item({ digest: sha256Digest(new Uint8Array()) }), new Uint8Array()),
    ).toBe(true);
  });

  it("matches nothing when it names no digest", () => {
    const loose: Evidence = { kind: "log", ref: "https://log.example/entries/5" };
    expect(evidenceMatches(loose, bytes)).toBe(false);
    expect(evidenceMatches(loose, new Uint8Array())).toBe(false);
    expect(evidenceIsChecked(loose)).toBe(false);
    expect(evidenceIsChecked(item())).toBe(true);
  });

  it("is a mistake in the caller to give it what is not bytes", () => {
    expect(() => evidenceMatches(item(), "The lease, translated.\n" as never)).toThrow(TypeError);
  });
});
