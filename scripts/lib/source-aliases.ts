// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

/**
 * Each workspace package, by its name, as its source. Tests run against
 * source, so nothing needs building first.
 *
 * The paths are worked out from this file's own place, and not through
 * `node_modules`. A copy of the repository, such as the one mutation testing
 * works on, then resolves a package to the copy's own files. Through
 * `node_modules` it reaches the original's: a mutant in one package would
 * never meet the tests of another, and would be counted as surviving them.
 */
export const sourceAliases = [
  // The test kit's builders of minds and logs, which only some tests need.
  {
    find: /^@oip\/testkit\/minds$/,
    replacement: join(repoRoot, "packages", "testkit", "src", "minds.ts"),
  },
  // What a keystore has in Node.js only: a directory, and the system's keychain.
  {
    find: /^@oip\/keystore\/node$/,
    replacement: join(repoRoot, "packages", "keystore", "src", "node.ts"),
  },
  {
    find: /^@oip\/([a-z0-9-]+)$/,
    replacement: join(repoRoot, "packages", "$1", "src", "index.ts"),
  },
];
