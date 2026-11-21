#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Tells the scenario, as a program. */

import { main } from "./main.ts";

const code = await main(process.argv.slice(2), process);
process.exitCode = code;
// An interrupted telling was still at work somewhere: the process does not wait for it.
if (code === 130) process.exit(code);
