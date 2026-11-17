// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The packages of the workspace and how they may depend on each other
 * (BUILD.md, Section 3.1). The layering rules, the purity rules and the check
 * that the guards hold all read this one list. A package that is not listed
 * here fails `pnpm lint`: nothing is pure, or layered, by default.
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

// Packages that do no I/O and never read the clock.
const PURE = ["schema", "core", "identity", "delegation", "web", "net"];

// The npm packages a pure package may import, each justified in an ADR (docs/adr/).
const PURE_DEPENDENCIES = [
  "typebox",
  // ADR-0002: signatures, hashes, encodings and canonical JSON. Only @oip/core imports these.
  "@noble/curves",
  "@noble/hashes",
  "@scure/base",
  "canonicalize",
];

// Packages used only by tests. No package's source may import them.
const TEST_ONLY = ["testkit"];

module.exports = { LAYERS, PURE, PURE_DEPENDENCIES, TEST_ONLY };
