#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** `oip`, as a program. */

import { run } from "./run.ts";
import { systemEdges } from "./system.ts";

process.exitCode = await run(process.argv.slice(2), systemEdges(process));
