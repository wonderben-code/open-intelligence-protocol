// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What the functions of this package that never throw answer with the call
 * stack all but spent. `spent-stack.test.ts` runs it in a process of its own
 * (`inNode` says why) and reads what it prints.
 */

import { tally, withStackSpent } from "@oip/testkit";
import { at, bookOf, intentBy, KeyMind, LATER, witness } from "@oip/testkit/minds";

import { judgeRecord, ownSignedTime, verifyLog } from "../src/index.ts";

function logs(): unknown {
  const ada = new KeyMind("ada").update(10);
  const context = { evidence: witness([ada.events]), asOf: LATER };
  return {
    verified: tally(
      withStackSpent(() => verifyLog(ada.events, context)),
      (answer) => {
        if (answer.ok) return `${answer.value.entries.length} events`;
        return answer.issues[0].message.length > 0 ? "refused with a reason" : "refused";
      },
    ),
    after: verifyLog(ada.events, context).ok,
  };
}

function records(): unknown {
  const ada = new KeyMind("ada");
  const intent = ada.sign(intentBy(ada, 10));
  const book = bookOf([ada], [intent]);
  const signed = (): string => {
    const record = judgeRecord(intent);
    if (!record.ok) return `not judged: ${record.issues[0].clause}`;
    const time = ownSignedTime(record.value, ada.address, book);
    return time === at(10) ? "signed at 10" : `signed at ${String(time)}`;
  };
  const answers = withStackSpent(signed);
  return { signed: tally(answers, (answer) => answer), last: answers.at(-1), after: signed() };
}

process.stdout.write(JSON.stringify({ logs: logs(), records: records() }));
