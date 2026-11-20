// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { OipError, type ProblemCode } from "@oip/core";
import type { Validation } from "@oip/schema";

/** The value a judge answered with, or an `OipError` for its refusal. */
export function accepted<T>(judged: Validation<T>, code: ProblemCode, what: string): T {
  if (judged.ok) return judged.value;
  const [first] = judged.issues;
  throw new OipError(code, `${what}: ${first.message}`, {
    clause: first.clause,
    issues: judged.issues,
  });
}
