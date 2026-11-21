// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { validateRecord } from "@oip/schema";

/** Says whether a JSON text is a well-formed OIP record and, if it is not, why. */
export function describeRecord(json: string): string {
  const result = validateRecord(JSON.parse(json));
  if (result.ok) {
    // `result.value` is typed: narrowing on `type` gives the record's own members.
    const record = result.value;
    return record.type === "Intent"
      ? `a well-formed Intent: ${record.want}`
      : `a well-formed ${record.type}`;
  }
  return result.issues.map((issue) => `${issue.clause} ${issue.path}: ${issue.message}`).join("\n");
}
