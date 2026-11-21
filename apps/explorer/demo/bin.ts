#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Opens the Explorer on the demo network, as a program. */

import { main } from "./main.ts";

process.exitCode = await main(process.argv.slice(2), process);
