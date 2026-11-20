// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { defineProject } from "vitest/config";

import { sourceAliases } from "../../scripts/lib/source-aliases.ts";

export default defineProject({
  // Tests run against each package's source, so nothing needs building first.
  resolve: { alias: sourceAliases },
  test: {
    name: "@oip/conformance",
    environment: "node",
    include: ["test/**/*.test.ts"],
    // The same tests with OpenSSL doing the arithmetic of each signature (ADR-0016).
    setupFiles: process.env["OIP_ED25519"] === "native" ? ["./test/native.setup.ts"] : [],
    // Hostile inputs of a megabyte take real time on a busy CI machine or
    // under mutation testing; the default of five seconds is too tight.
    testTimeout: 60_000,
    benchmark: { include: ["bench/**/*.bench.ts"] },
  },
});
