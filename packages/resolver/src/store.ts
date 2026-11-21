// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The resolver's database: an archive of identity logs, and the nonces of signed requests. */

import { ARCHIVE_SQL, type Migration, NONCES_SQL } from "@oip/server";

/** The migrations of a resolver's database. */
export const RESOLVER_MIGRATIONS: readonly Migration[] = [
  {
    version: 1,
    name: "logs, records, first sight, duplicity, the stream and nonces",
    sql: [ARCHIVE_SQL, NONCES_SQL].join("\n"),
  },
];
