// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import type { Reason } from "../oip/why.ts";

/** Why a page says what it says: what was checked here, and the clauses that ask for it. */
export function Why({ reason, about }: { reason: Reason; about: string }): React.JSX.Element {
  return (
    <details className="why">
      <summary>Why: {about}</summary>
      <p>{reason.says}</p>
      <ul>
        {reason.clauses.map((clause) => (
          <li key={clause.id}>
            <a href={clause.href} rel="noreferrer">
              {clause.id}
            </a>
            : {clause.section}
          </li>
        ))}
      </ul>
    </details>
  );
}
