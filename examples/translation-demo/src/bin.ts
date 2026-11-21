#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Tells the scenario, on a network of its own that ends with it. */

import { Stage } from "./stage.ts";
import { NotSo, tell } from "./story.ts";

const stage = await Stage.open();
try {
  await tell(stage, (line) => {
    process.stdout.write(`${line}\n`);
  });
} catch (error) {
  if (!(error instanceof NotSo)) throw error;
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
} finally {
  await stage.close();
}
