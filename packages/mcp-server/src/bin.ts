#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** `oip-mcp`, as a program. */

import { main } from "./main.ts";

const code = main(process.argv.slice(2), process);
if (code !== undefined) process.exitCode = code;
