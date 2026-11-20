#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The indexer, started from the command line with the environment's settings.
 * `oip-indexer init <directory>` makes the indexer's own mind first, once.
 */

import { formatTimestamp } from "@oip/core";
import { ConfigError, systemClock, systemRandomness } from "@oip/server";

import { initCommand } from "./init.ts";
import { start } from "./main.ts";

if (process.argv[2] === "init") {
  process.exitCode = initCommand(process.argv.slice(3), {
    // A genesis is dated to the second: nothing needs it finer.
    created: formatTimestamp(systemClock.now() - (systemClock.now() % 1_000_000_000n)),
    randomness: systemRandomness,
    out: (text) => process.stdout.write(text),
    err: (text) => process.stderr.write(text),
  });
} else {
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
}
