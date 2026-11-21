#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The command `oip-conformance`: a profile of the suite, run against an implementation over the wire. */

import { command } from "./wire/run.ts";

process.exitCode = await command(process.argv.slice(2), {
  out: (text) => process.stdout.write(text),
  err: (text) => process.stderr.write(text),
});
