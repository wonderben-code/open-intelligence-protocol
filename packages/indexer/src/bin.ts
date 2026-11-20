#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The indexer, started from the command line with the environment's settings. */

import { ConfigError } from "@oip/server";

import { start } from "./main.ts";

try {
  const running = await start(process.env);
  running.shutdown.listen(process, (code) => {
    process.exitCode = code;
  });
} catch (error) {
  // A configuration that is wrong is said to whoever started the service, and nothing runs.
  process.stderr.write(
    `${error instanceof ConfigError ? error.message : "the indexer could not start"}\n`,
  );
  process.exitCode = 1;
  if (!(error instanceof ConfigError)) throw error;
}
