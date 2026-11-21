// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A telling as something to show: a terminal session in the asciicast
 * format, which a player replays, and a picture that draws itself line by
 * line, which a page shows with no player at all.
 *
 * Both are made of the lines of a telling and of nothing else: no clock is
 * read, so the same lines give the same files.
 */

/** How long a line stays alone before the next, in seconds: a title longer, a check shorter. */
function pause(line: string): number {
  if (line === "") return 0.3;
  if (/^\d+\. /u.test(line)) return 1.2;
  return line.startsWith("   verified: ") ? 0.35 : 0.7;
}

/** The widest line, in characters, and at least the width of a narrow terminal. */
const widthOf = (lines: readonly string[]): number =>
  Math.max(80, ...lines.map((line) => Array.from(line).length));

/**
 * The telling as an asciicast, version 2: a header, and one event for each
 * line with the time it appears at.
 *
 * @param title - What a player shows as the name of the session.
 */
export function castOf(lines: readonly string[], title: string): string {
  const header = { version: 2, width: widthOf(lines), height: 40, title };
  let at = 0.5;
  const events = lines.map((line) => {
    const event = JSON.stringify([Number(at.toFixed(2)), "o", `${line}\r\n`]);
    at += pause(line);
    return event;
  });
  return `${[JSON.stringify(header), ...events].join("\n")}\n`;
}

/** The lines an asciicast shows, in order: what `castOf` was given. */
export function linesOf(cast: string): string[] {
  return cast
    .split("\n")
    .slice(1)
    .filter((line) => line !== "")
    .map((line) => {
      const [, , text] = JSON.parse(line) as [number, string, string];
      return text.replace(/\r\n$/u, "");
    });
}

const escaped = (text: string): string =>
  text.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");

/**
 * The telling as a picture that draws itself: each line appears at its
 * time and stays. It is one SVG file with its own style and no script, so
 * a page shows it as it shows any image.
 *
 * A reader who asked for less motion is shown the whole telling at once.
 */
export function svgOf(lines: readonly string[], title: string): string {
  const LINE = 18;
  const CHARACTER = 7.8;
  const width = Math.ceil(widthOf(lines) * CHARACTER) + 32;
  const height = lines.length * LINE + 32;
  let at = 0.5;
  const rows = lines.map((line, index) => {
    const kind = /^\d+\. /u.test(line)
      ? "step"
      : line.startsWith("   verified: ")
        ? "verified"
        : "said";
    const row =
      `<text class="${kind}" x="16" y="${String(32 + index * LINE)}" ` +
      `style="animation-delay:${at.toFixed(2)}s" xml:space="preserve">${escaped(line)}</text>`;
    at += pause(line);
    return row;
  });
  return [
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${String(width)} ${String(height)}" role="img" aria-labelledby="title">`,
    `<title id="title">${escaped(title)}</title>`,
    "<style>",
    "svg { background: #101418; font: 13px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }",
    "text { fill: #d8dee6; opacity: 0; animation: appear 0.2s ease-out forwards; }",
    "text.step { fill: #ffffff; font-weight: 600; }",
    "text.verified { fill: #7fd69b; }",
    "@keyframes appear { to { opacity: 1; } }",
    "@media (prefers-reduced-motion: reduce) { text { animation: none; opacity: 1; } }",
    "</style>",
    ...rows,
    "</svg>",
    "",
  ].join("\n");
}
