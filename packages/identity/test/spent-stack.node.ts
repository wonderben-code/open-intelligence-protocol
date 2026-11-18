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

/**
 * A book that has verified nothing yet, asked for the first time with the
 * stack spent. It runs first, while the verifier's code is as cold as the
 * book: a refusal reached with a check cut short was once kept as the log's
 * verdict.
 */
function coldBook(): unknown {
  const ada = new KeyMind("ada");
  const intent = ada.sign(intentBy(ada, 10));
  const record = judgeRecord(intent);
  if (!record.ok) return { error: record.issues[0].message };
  const book = bookOf([ada], [intent]);
  const signed = (): string => {
    const time = ownSignedTime(record.value, ada.address, book);
    return time === at(10) ? "signed at 10" : `signed at ${String(time)}`;
  };
  const answers = withStackSpent(signed);
  const log = book.log(ada.address);
  return { signed: tally(answers, (answer) => answer), after: signed(), log: log.ok };
}

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

// In this order: the first is for code that has never run.
const cold = coldBook();
process.stdout.write(JSON.stringify({ cold, logs: logs(), records: records() }));
