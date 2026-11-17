// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Mutation testing (BUILD.md, Section 2): the verification code must have a
 * mutation score of at least 85%. Stryker changes the code in small ways and
 * runs the tests that cover each change; a change no test notices is a gap
 * in the tests.
 *
 * `pnpm mutation` runs it for every package below. `pnpm mutation -- --mutate
 * "packages/core/src/proof.ts"` runs it for one file.
 */

// Each mutant runs the tests that cover it. The parser's campaign of a million
// inputs is cut down for those runs; its full size runs with the ordinary tests.
process.env["OIP_PARSER_CAMPAIGN"] ??= "20000";

/** @type {import('@stryker-mutator/api/core').PartialStrykerOptions} */
export default {
  testRunner: "vitest",
  plugins: ["@stryker-mutator/vitest-runner"],
  vitest: { configFile: "vitest.config.ts", related: false },
  mutate: [
    "packages/core/src/**/*.ts",
    "packages/identity/src/**/*.ts",
    "packages/schema/src/**/*.ts",
    // Generated from the schemas, and tested through them.
    "!packages/schema/src/generated/**",
    "!packages/**/*.d.ts",
  ],
  coverageAnalysis: "perTest",
  ignoreStatic: false,
  thresholds: { high: 95, low: 90, break: 85 },
  reporters: ["clear-text", "progress", "json", "html"],
  clearTextReporter: { reportTests: false, logTests: false },
  jsonReporter: { fileName: "reports/mutation/mutation.json" },
  htmlReporter: { fileName: "reports/mutation/mutation.html" },
  tempDirName: ".stryker-tmp",
  // Copies left behind by a run that was interrupted would be linted and
  // measured by the other checks.
  cleanTempDir: "always",
  timeoutMS: 20_000,
  timeoutFactor: 3,
  concurrency: 4,
  // The symbolic links of the workspace are what make "@oip/*" resolve in the sandbox.
  symlinkNodeModules: true,
  ignorePatterns: ["dist", "coverage", "reports", "docs/api", "papers", "timestamps", ".git"],
};
