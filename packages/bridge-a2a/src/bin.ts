#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** `oip-bridge-a2a`, as a program. */

import { main } from "./main.ts";

const done = await main(process.argv.slice(2), process);
if (typeof done === "number") process.exitCode = done;
else await done.ended;
