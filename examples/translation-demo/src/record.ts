#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Tells the scenario once and keeps the telling as a recording: a terminal
 * session and a picture, in `recording/`, for the website to show.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { castOf, svgOf } from "./recording.ts";
import { Stage } from "./stage.ts";
import { tell } from "./story.ts";

const TITLE = "The Open Intelligence Protocol: a translation, from want to Receipt";
const directory = fileURLToPath(new URL("../recording/", import.meta.url));

const lines: string[] = [];
const stage = await Stage.open();
try {
  await tell(stage, (line) => lines.push(line));
} finally {
  await stage.close();
}
mkdirSync(directory, { recursive: true });
writeFileSync(`${directory}translation-demo.cast`, castOf(lines, TITLE));
writeFileSync(`${directory}translation-demo.svg`, svgOf(lines, TITLE));
process.stdout.write(`${String(lines.length)} lines recorded in ${directory}\n`);
