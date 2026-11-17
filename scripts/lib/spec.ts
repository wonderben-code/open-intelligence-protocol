// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Reads the specifications as a list of numbered clauses. */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** The specification documents and the prefix of their clause IDs. */
export const SPEC_DOCUMENTS = [
  { prefix: "core", file: "spec/core.md" },
  { prefix: "L0", file: "spec/layer-0-bridge.md" },
  { prefix: "L1", file: "spec/layer-1-mind-network.md" },
  { prefix: "L2", file: "spec/layer-2-mind-web.md" },
] as const;

/** The key words of BCP 14, longest first so that `MUST NOT` is not read as `MUST`. */
export const KEYWORDS = [
  "MUST NOT",
  "SHALL NOT",
  "SHOULD NOT",
  "NOT RECOMMENDED",
  "MUST",
  "REQUIRED",
  "SHALL",
  "SHOULD",
  "RECOMMENDED",
  "MAY",
  "OPTIONAL",
] as const;
export type Keyword = (typeof KEYWORDS)[number];

const ABSOLUTE: readonly Keyword[] = ["MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT"];
const ADVISORY: readonly Keyword[] = ["SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED"];

/** How strongly a clause binds: the strongest key word it contains. */
export type Level = "MUST" | "SHOULD" | "MAY" | "none";

export interface Clause {
  /** For example `core 4.4`, or `L1 19` for a section with no numbered paragraphs. */
  readonly id: string;
  readonly document: string;
  /** The title of the section the clause is in. */
  readonly section: string;
  /** The first words of the clause, to recognise it by. */
  readonly summary: string;
  readonly level: Level;
  /** How often each key word appears, in all capitals. */
  readonly keywords: Readonly<Partial<Record<Keyword, number>>>;
  /** SHA-256 of the clause's text, so that a change to the text is visible in review. */
  readonly digest: string;
}

function countKeywords(text: string): Partial<Record<Keyword, number>> {
  const counts: Partial<Record<Keyword, number>> = {};
  // Key words count only in all capitals, as whole words (spec/README.md, Conventions).
  const pattern = new RegExp(`(?<![A-Za-z])(${KEYWORDS.join("|")})(?![A-Za-z])`, "g");
  for (const match of text.matchAll(pattern)) {
    const keyword = match[1] as Keyword;
    counts[keyword] = (counts[keyword] ?? 0) + 1;
  }
  return counts;
}

function levelOf(counts: Partial<Record<Keyword, number>>): Level {
  if (ABSOLUTE.some((keyword) => counts[keyword] !== undefined)) return "MUST";
  if (ADVISORY.some((keyword) => counts[keyword] !== undefined)) return "SHOULD";
  return Object.keys(counts).length > 0 ? "MAY" : "none";
}

function summarise(text: string, section: string): string {
  // A clause that opens with a table or a list has no sentence to quote.
  const first = text.split("\n").find((line) => line.trim() !== "") ?? "";
  if (/^\s*(\||[-*] )/.test(first))
    return `${section} (${first.trimStart().startsWith("|") ? "table" : "list"})`;
  const plain = text
    // Anchors only: `<seq>` and `<contentId>` in the text are placeholders, not tags.
    .replace(/<\/?a(?:\s[^>]*)?>/g, "")
    .replace(/\*\*/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/^[0-9]+\.[0-9]+\.\s*/, "");
  return plain.length <= 96 ? plain : `${plain.slice(0, 95).trimEnd()}…`;
}

/**
 * Splits one document into clauses. A clause is a paragraph that starts with
 * `N.M.`, together with everything up to the next clause or heading (its
 * tables, lists and code). Text in a numbered section before its first
 * numbered paragraph, or all of a section that has none, is the clause `N`.
 */
export function clausesOf(
  prefix: string,
  markdown: string,
  digest: (text: string) => string,
): Clause[] {
  const clauses: Clause[] = [];
  let section: { number: string; title: string } | undefined;
  let current: { id: string; lines: string[] } | undefined;

  const close = () => {
    if (current === undefined || section === undefined) return;
    const text = current.lines.join("\n").trim();
    if (text !== "") {
      const keywords = countKeywords(text);
      clauses.push({
        id: current.id,
        document: prefix,
        section: section.title,
        summary: summarise(text, section.title),
        level: levelOf(keywords),
        keywords,
        digest: digest(text),
      });
    }
    current = undefined;
  };

  let inCode = false;
  // An anchor on a line of its own belongs to the clause that follows it.
  let anchors: string[] = [];
  for (const line of markdown.split("\n")) {
    if (line.startsWith("```")) inCode = !inCode;
    if (!inCode && /^<a id="[^"]*"><\/a>\s*$/.test(line)) {
      anchors.push(line);
      continue;
    }
    const heading = inCode ? null : /^## (?:([0-9]+)\. )?(.*)$/.exec(line);
    if (heading !== null) {
      current?.lines.push(...anchors);
      anchors = [];
      close();
      const [, number, title] = heading;
      section = number === undefined ? undefined : { number, title: (title ?? "").trim() };
      if (section !== undefined) current = { id: `${prefix} ${section.number}`, lines: [] };
      continue;
    }
    if (section === undefined) {
      anchors = [];
      continue;
    }
    const numbered = inCode ? null : /^([0-9]+)\.([0-9]+)\. /.exec(line);
    if (numbered !== null && numbered[1] === section.number) {
      close();
      current = { id: `${prefix} ${numbered[1]}.${numbered[2] ?? ""}`, lines: [] };
    }
    if (line.trim() !== "" || anchors.length === 0) {
      // The held anchors go with whichever clause this line belongs to.
      current?.lines.push(...anchors);
      anchors = [];
    }
    current?.lines.push(line);
  }
  current?.lines.push(...anchors);
  close();
  return clauses;
}

/** Every clause of every specification document, in document order. */
export function readClauses(digest: (text: string) => string): Clause[] {
  return SPEC_DOCUMENTS.flatMap(({ prefix, file }) =>
    clausesOf(prefix, readFileSync(join(repoRoot, file), "utf8"), digest),
  );
}
