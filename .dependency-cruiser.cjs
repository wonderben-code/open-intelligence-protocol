// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The layering of BUILD.md, Section 3.1, as rules:
 *
 *   1. a package imports only packages below it;
 *   2. pure packages use no Node.js built-in and only the dependencies an ADR allows;
 *   3. a package's source never imports test code or development dependencies.
 */

// Lowest layer first. Packages on one line are siblings and do not import each other.
const LAYERS = [
  ["schema"],
  ["core"],
  ["identity"],
  ["delegation"],
  ["web"],
  ["net"],
  ["keystore"],
  ["client"],
  ["host", "resolver", "indexer"],
  ["cli", "mcp-server", "bridge-a2a", "did-resolver", "conformance"],
];

const PURE = ["schema", "core", "identity", "delegation", "web", "net"];

// The npm packages a pure package may import, each justified in an ADR (docs/adr/).
const PURE_DEPENDENCIES = ["typebox"];

const group = (names) => `(?:${names.join("|")})`;

const layerRules = LAYERS.flatMap((layer, index) =>
  layer.map((name) => {
    const notBelow = LAYERS.slice(index)
      .flat()
      .filter((other) => other !== name);
    return {
      name: `layer-${name}`,
      comment: `@oip/${name} may import only packages below it (BUILD.md, Section 3.1).`,
      severity: "error",
      from: { path: `^packages/${name}/` },
      to: { path: `^packages/${group(notBelow)}/` },
    };
  }),
);

/** @type {import('dependency-cruiser').IConfiguration} */
module.exports = {
  forbidden: [
    ...layerRules,
    {
      name: "pure-no-node-builtins",
      comment: "Pure packages do no I/O, so they import no Node.js built-in.",
      severity: "error",
      from: { path: `^packages/${group(PURE)}/src/` },
      to: { dependencyTypes: ["core"] },
    },
    {
      name: "pure-dependencies-need-an-adr",
      comment:
        "A pure package imports only the npm packages listed in PURE_DEPENDENCIES. Add one only with an ADR.",
      severity: "error",
      from: { path: `^packages/${group(PURE)}/src/` },
      to: {
        dependencyTypes: [
          "npm",
          "npm-optional",
          "npm-peer",
          "npm-bundled",
          "npm-no-pkg",
          "npm-unknown",
        ],
        pathNot: `node_modules/${group(PURE_DEPENDENCIES)}/`,
      },
    },
    {
      name: "source-not-to-tests",
      comment: "Published source never depends on tests, benchmarks, scripts or the test kit.",
      severity: "error",
      from: { path: "^packages/[^/]+/src/" },
      to: { path: "^packages/(?:[^/]+/(?:test|bench|scripts)|testkit)/" },
    },
    {
      name: "source-not-to-dev-dependencies",
      comment: "Published source imports only what the package declares under dependencies.",
      severity: "error",
      from: { path: "^packages/[^/]+/src/", pathNot: "^packages/testkit/" },
      to: { dependencyTypes: ["npm-dev"], dependencyTypesNot: ["type-only"] },
    },
    {
      name: "no-circular",
      comment: "Modules that import each other at run time load in an order nobody chose.",
      severity: "error",
      from: {},
      to: { circular: true, viaOnly: { dependencyTypesNot: ["type-only"] } },
    },
    {
      name: "no-unresolvable",
      severity: "error",
      from: {},
      to: { couldNotResolve: true },
    },
  ],
  options: {
    doNotFollow: { path: "node_modules" },
    // Only the workspace's own build output. A broader pattern would also hide
    // every dependency whose entry point lives in a "dist" directory.
    // The fixtures break the rules on purpose; scripts/check-guards.ts cruises them separately.
    exclude: { path: "^(?:(?:packages|apps|examples)/[^/]+/(?:dist|coverage)|scripts/fixtures)/" },
    // Read imports before TypeScript erases the type-only ones, so that they are seen too.
    tsPreCompilationDeps: true,
    tsConfig: { fileName: "tsconfig.base.json" },
    enhancedResolveOptions: {
      exportsFields: ["exports"],
      conditionNames: ["@oip/source", "import", "types", "default"],
      extensions: [".ts", ".js", ".mjs", ".cjs", ".json"],
    },
  },
};
