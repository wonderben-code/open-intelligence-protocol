// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { defineProject } from "vitest/config";

import { sourceAliases } from "../../scripts/lib/source-aliases.ts";

export default defineProject({
  // Tests run against each package's source, so nothing needs building first.
  resolve: { alias: sourceAliases },
  test: {
    name: "@oip/cli",
    environment: "node",
    include: ["test/**/*.test.ts"],
    testTimeout: 120_000,
    // Each file starts a network of three services and makes its minds before its first
    // test: with coverage on, on a machine that is busy, that takes more than the default.
    hookTimeout: 120_000,
    benchmark: { include: ["bench/**/*.bench.ts"] },
  },
});
