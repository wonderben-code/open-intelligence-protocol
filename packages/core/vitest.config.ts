// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { defineProject } from "vitest/config";

import { sourceAliases } from "../../scripts/lib/source-aliases.ts";

export default defineProject({
  // Tests run against each package's source, so nothing needs building first.
  resolve: { alias: sourceAliases },
  test: {
    name: "@oip/core",
    environment: "node",
    include: ["test/**/*.test.ts"],
    // Signatures and megabyte records take real time, more so on a busy CI
    // machine or under mutation testing.
    testTimeout: 60_000,
    benchmark: { include: ["bench/**/*.bench.ts"] },
  },
});
