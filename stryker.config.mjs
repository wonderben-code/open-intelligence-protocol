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

// Each mutant runs the tests that cover it, and a mutant in code that every
// record passes through is covered by nearly all of them. The campaigns (a
// million inputs to the parser, thousands of cases compared with the Python
// checker) are cut down for those runs; their full size runs with the
// ordinary tests.
process.env["OIP_PARSER_CAMPAIGN"] ??= "20000";
process.env["OIP_DIFFERENTIAL_RUNS"] ??= "100";
// The identity campaign is left out altogether: nearly every mutant of
// `@oip/identity` is covered by it, and each would wait for the Python
// checker on every case. The unit tests are what a mutant has to get past.
// The properties of identity logs are tried on a quarter of the logs. So a
// score from here is a lower bound on what the whole suite notices.
process.env["OIP_MUTATION"] ??= "1";

/** @type {import('@stryker-mutator/api/core').PartialStrykerOptions} */
export default {
  testRunner: "vitest",
  plugins: ["@stryker-mutator/vitest-runner"],
  vitest: { configFile: "vitest.config.ts", related: false },
  mutate: [
    "packages/core/src/**/*.ts",
    "packages/identity/src/**/*.ts",
    "packages/delegation/src/**/*.ts",
    "packages/web/src/**/*.ts",
    "packages/net/src/**/*.ts",
    "packages/server/src/**/*.ts",
    "packages/resolver/src/**/*.ts",
    "packages/host/src/**/*.ts",
    "packages/indexer/src/**/*.ts",
    "packages/schema/src/**/*.ts",
    // Generated from the schemas, and tested through them.
    "!packages/schema/src/generated/**",
    "!packages/**/*.d.ts",
    // Each starts its service from the process's environment, and is run by hand and in the containers.
    "!packages/*/src/bin.ts",
  ],
  coverageAnalysis: "perTest",
  // Nothing type-checks the copies, so no file needs a `@ts-nocheck` put at
  // its head. Tests that compare a file with what a README quotes of it read
  // the copy, and would find the line.
  disableTypeChecks: false,
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
