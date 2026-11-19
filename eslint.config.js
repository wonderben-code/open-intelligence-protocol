// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { createRequire } from "node:module";

import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

// Packages that do no I/O and never read the clock (BUILD.md, Section 3.1).
const { PURE: PURE_PACKAGES } = createRequire(import.meta.url)("./scripts/layers.cjs");
const PURE = `packages/{${PURE_PACKAGES.join(",")}}/src/**/*.{ts,mts,cts,tsx}`;

const ambient = (name, instead) => ({
  name,
  message: `Pure packages do no I/O and read no ambient state. ${instead}`,
});

// Everything through which the clock, randomness, the environment or the
// network can be reached. `Date` is forbidden outright: an instant is a
// number of nanoseconds passed in as a parameter (ADR-0003), and a guard
// that lists the dangerous uses of `Date` one by one is easy to walk round.
const AMBIENT = [
  ambient("Date", "Take the current time as a parameter; an instant is a bigint of nanoseconds."),
  ambient("Intl", "Formatting and collation read the locale; compare code points."),
  ambient("performance", "Take the current time as a parameter."),
  ambient("process", "Take configuration as a parameter."),
  ambient("crypto", "Take randomness as a parameter; cryptography goes through @oip/core."),
  ambient("fetch", "Fetching belongs to the client and the services."),
  ambient("XMLHttpRequest", "Fetching belongs to the client and the services."),
  ambient("WebSocket", "Sockets belong to the client and the services."),
  ambient("EventSource", "Streams belong to the client and the services."),
  ambient("localStorage", "Storage belongs to the keystore and the services."),
  ambient("sessionStorage", "Storage belongs to the keystore and the services."),
  ambient("indexedDB", "Storage belongs to the keystore and the services."),
  ambient("navigator", "Read nothing from the environment."),
  ambient("document", "Read nothing from the environment."),
  ambient("location", "Read nothing from the environment."),
  ambient("setTimeout", "Timers belong to the client and the services."),
  ambient("setInterval", "Timers belong to the client and the services."),
  ambient("setImmediate", "Timers belong to the client and the services."),
  ambient("queueMicrotask", "Return a value; do not schedule work."),
  ambient("console", "Return a result or throw a typed error instead of logging."),
  // The ways to reach any of the above under another name.
  ambient("globalThis", "Name what you use, so that these rules can see it."),
  ambient("window", "Name what you use, so that these rules can see it."),
  ambient("self", "Name what you use, so that these rules can see it."),
  ambient("global", "Name what you use, so that these rules can see it."),
  ambient("Reflect", "Call and construct directly, so that these rules can see it."),
  ambient("Function", "Code is not built from strings."),
  ambient("require", "Use static imports, so that the layering rules can see them."),
  ambient("Deno", "Read nothing from the runtime."),
  ambient("Bun", "Read nothing from the runtime."),
];

const PURE_SYNTAX = [
  {
    selector: "ImportExpression",
    message: "Use static imports, so that the layering rules can see what is imported.",
  },
  {
    selector: "CallExpression[callee.property.name=/^(localeCompare|toLocale.*)$/]",
    message: "This reads the locale. Compare code points and format by hand.",
  },
];

// Every rule about time is judged at an evaluation time, which comes from
// evidence (core 9.3 and 9.5, ADR-0003). `created` is the signer's own claim,
// and a comparison with it is how a backdating attack is let back in.
const CREATED_COMPARED = {
  selector: "BinaryExpression[operator=/^(<|<=|>|>=)$/] Identifier[name='created']",
  message:
    "`created` is the signer's claim, never evidence (core 9.2). Compare evaluation times: proofTime and eventTime of @oip/identity.",
};

// The places that may compare a `created`. `evidence.ts` holds the two
// formulas and the rule that a log's dates do not run backwards (Layer 1,
// 4.2); `proof.ts` the rule that a proof is not dated before its record (core
// 5.7). None of them decides whether a key may sign. The file that judges
// members' proofs, `log.ts`, is not among them.
//
// This is a tripwire, not a proof. It catches the spelling a tired author
// writes first, `proof.created < removed`. A renamed local, a subtraction or
// a helper that takes the value pass it; the review of every change to these
// packages is what stands behind it (ADR-0008).
//
// `dates.ts` of `@oip/net` holds the rules about a date a record states of
// itself to say how long it asks to be used for: when a mind's own location
// record goes stale (Layer 1, 15.2).
const MAY_COMPARE_CREATED = [
  "packages/identity/src/evidence.ts",
  "packages/core/src/proof.ts",
  "packages/net/src/dates.ts",
];

export default tseslint.config(
  {
    ignores: [
      "**/dist/**",
      "**/coverage/**",
      "**/node_modules/**",
      // Generated by Ajv from the schemas; checked by tests, not by lint.
      "packages/schema/src/generated/**",
      "docs/api/**",
      // Mutation testing works on copies of the repository and writes reports.
      ".stryker-tmp/**",
      "reports/**",
      // The papers' PDF build is separate from the workspace.
      "papers/**",
      "reviews/**",
      // Files that break the rules on purpose (scripts/check-guards.ts).
      "scripts/fixtures/**",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: "module",
      // Linting with types holds a program for each package: about 4 GB for the workspace,
      // which is more than Node gives itself. The `lint` script in package.json gives it 6.
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    linterOptions: { reportUnusedDisableDirectives: "error" },
    rules: {
      eqeqeq: ["error", "always"],
      "no-console": "error",
      "@typescript-eslint/consistent-type-imports": ["error", { fixStyle: "inline-type-imports" }],
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/explicit-module-boundary-types": "off",
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_", destructuredArrayIgnorePattern: "^_" },
      ],
      // Numbers in messages are deliberate; objects and unknowns are not.
      "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true }],
      // A schema and its static type share one name, as TypeBox intends.
      "@typescript-eslint/no-redeclare": "off",
      "no-redeclare": "off",
    },
  },
  {
    files: [PURE],
    // A comment must not be able to switch these rules off.
    linterOptions: { noInlineConfig: true },
    rules: {
      "no-restricted-globals": ["error", ...AMBIENT],
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-restricted-properties": [
        "error",
        { object: "Math", property: "random", message: "Take randomness as a parameter." },
      ],
      "no-restricted-syntax": ["error", ...PURE_SYNTAX, CREATED_COMPARED],
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            { group: ["node:*"], message: "Pure packages run anywhere: no Node.js built-ins." },
          ],
        },
      ],
    },
  },
  {
    files: MAY_COMPARE_CREATED,
    rules: { "no-restricted-syntax": ["error", ...PURE_SYNTAX] },
  },
  {
    // Command-line scripts report on the console.
    files: ["scripts/**/*.ts", "packages/*/scripts/**/*.ts"],
    languageOptions: { globals: globals.node },
    rules: { "no-console": "off" },
  },
  {
    files: ["**/test/**/*.ts", "**/bench/**/*.ts"],
    rules: {
      // Tests pick values out of loosely typed vectors and build malformed input on purpose.
      "@typescript-eslint/no-non-null-assertion": "off",
      "@typescript-eslint/no-unnecessary-condition": "off",
      "@typescript-eslint/no-dynamic-delete": "off",
      "@typescript-eslint/no-confusing-void-expression": "off",
    },
  },
  {
    // Configuration files are outside every package's TypeScript project.
    files: ["*.js", "*.cjs", "*.mjs", "*.config.ts", ".dependency-cruiser.cjs", "scripts/*.cjs"],
    extends: [tseslint.configs.disableTypeChecked],
    languageOptions: { globals: globals.node },
    // dependency-cruiser loads its configuration as CommonJS.
    rules: { "@typescript-eslint/no-require-imports": "off" },
  },
);
