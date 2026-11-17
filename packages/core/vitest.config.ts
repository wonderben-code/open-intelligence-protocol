// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { defineProject } from "vitest/config";

export default defineProject({
  // Tests run against each package's source, so nothing needs building first.
  resolve: { conditions: ["@oip/source"] },
  ssr: { resolve: { conditions: ["@oip/source"] } },
  test: {
    name: "@oip/core",
    environment: "node",
    include: ["test/**/*.test.ts"],
    benchmark: { include: ["bench/**/*.bench.ts"] },
  },
});
