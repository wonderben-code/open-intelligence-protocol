// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from "vite";

import { sourceAliases } from "../../scripts/lib/source-aliases.ts";

export default defineConfig({
  // A static site that can be served from any path: every link in it is relative.
  base: "./",
  // The packages are read from their sources, as the tests read them.
  resolve: { alias: sourceAliases },
  build: { target: "es2023", sourcemap: false },
});
