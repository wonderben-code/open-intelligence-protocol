// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { TransportError } from "@oip/client";
import { OipError } from "@oip/core";

import { type ClauseRef, clauseOf } from "../oip/why.ts";

/** What went wrong, in words for a page, with the clause that was not met if there is one. */
export interface Failure {
  readonly message: string;
  readonly clause?: ClauseRef;
}

/** Says what a failure was. Nothing but its message is shown: no stack, and nothing of the page's inside. */
export function failureOf(error: unknown): Failure {
  if (error instanceof OipError) {
    const clause = error.clause === undefined ? undefined : clauseOf(error.clause);
    return { message: error.detail, ...(clause === undefined ? {} : { clause }) };
  }
  if (error instanceof TransportError) {
    return { message: `${error.origin}: ${error.message}` };
  }
  return {
    message: error instanceof Error ? error.message : "Something failed that gave no reason.",
  };
}
