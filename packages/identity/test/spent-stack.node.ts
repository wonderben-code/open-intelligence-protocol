// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What the functions of this package that never throw answer with the call
 * stack all but spent. `spent-stack.test.ts` runs it in a process of its own
 * (`inNode` says why) and reads what it prints.
 */

import { contentId } from "@oip/core";
import { tally, withStackSpent } from "@oip/testkit";
import {
  at,
  bookOf,
  Collective,
  intentBy,
  KeyMind,
  LATER,
  rawSign,
  T,
  witness,
} from "@oip/testkit/minds";

import {
  draftUpdate,
  FirstSeen,
  judgeRecord,
  LogBook,
  ownSignedTime,
  verifyLog,
} from "../src/index.ts";

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
  // Read with room: an address is worked out each time it is asked for, and the stack is
  // to be spent on the function asked, not on its arguments.
  const address = ada.address;
  const signed = (): string => {
    const time = ownSignedTime(record.value, address, book);
    return time === at(10) ? "signed at 10" : `signed at ${String(time)}`;
  };
  const answers = withStackSpent(signed);
  const log = book.log(address);
  return { signed: tally(answers, (answer) => answer), after: signed(), log: log.ok };
}

function logs(): unknown {
  const ada = new KeyMind("ada").update(10);
  const context = { evidence: witness([ada.events]), asOf: LATER };
  return {
    verified: tally(
      withStackSpent(() => verifyLog(ada.events, context)),
      (answer) => {
        // A refusal says why: for want of room, and for nothing else here.
        return answer.ok ? `${answer.value.entries.length} events` : answer.issues[0].clause;
      },
    ),
    after: verifyLog(ada.events, context).ok,
  };
}

function records(): unknown {
  const ada = new KeyMind("ada");
  const intent = ada.sign(intentBy(ada, 10));
  const book = bookOf([ada], [intent]);
  const address = ada.address;
  const signed = (): string => {
    const record = judgeRecord(intent);
    if (!record.ok) return `not judged: ${record.issues[0].clause}`;
    const time = ownSignedTime(record.value, address, book);
    return time === at(10) ? "signed at 10" : `signed at ${String(time)}`;
  };
  const answers = withStackSpent(signed);
  return { signed: tally(answers, (answer) => answer), last: answers.at(-1), after: signed() };
}

/**
 * A book's own operations with the stack spent: a copy taken in, the log
 * asked for, and the two looks. Each answers, and none answers `ok` for a
 * look that recorded nothing of an event that verifies: Ada removes her key
 * in an update, and a look that passes over it unseen would let that key
 * sign until the next look.
 */
function books(): unknown {
  const ada = new KeyMind("ada").update(140, {});
  const removal = contentId(ada.events[1]);
  const address = ada.address;
  const reading = at(150);
  const options = { following: [address] };
  const fresh = () => {
    const seen = new FirstSeen();
    return { seen, book: new LogBook(seen) };
  };
  const look = (how: "witness" | "witnessHeld") => (): string => {
    const { seen, book } = fresh();
    if (how === "witnessHeld") book.hold(ada.events, reading);
    const answer =
      how === "witness"
        ? book.witness(ada.events, reading, seen, options)
        : book.witnessHeld(reading, seen, options);
    const recorded = seen.eventSeen(removal) === undefined ? "not recorded" : "recorded";
    return `${answer.ok ? "ok" : answer.issues[0].clause}, removal ${recorded}`;
  };
  const taken = (): string => {
    const book = new LogBook(witness([ada.events]));
    const held = book.hold(ada.events, reading);
    // A copy is taken whole or not at all.
    const log = book.log(address);
    const events = log.ok
      ? `${log.value.entries.length} events`
      : log.issues[0].clause === "L1 6.3"
        ? "no log is held"
        : log.issues[0].clause;
    return `${held.ok ? "held" : held.issues[0].clause}, ${events}`;
  };
  const { seen, book } = fresh();
  book.witness(ada.events, reading, seen, options);
  const asked = (): string => {
    book.forget();
    const log = book.log(address);
    return log.ok ? `${log.value.entries.length} events` : log.issues[0].clause;
  };
  return {
    witness: tally(withStackSpent(look("witness")), (answer) => answer),
    witnessHeld: tally(withStackSpent(look("witnessHeld")), (answer) => answer),
    hold: tally(withStackSpent(taken), (answer) => answer),
    log: tally(withStackSpent(asked), (answer) => answer),
    after: [look("witness")(), look("witnessHeld")(), taken(), asked()],
  };
}

/**
 * A look that was refused for want of room, made again with room at the
 * same reading of the clock, as a caller is told to make it.
 *
 * A club removes its keys. Its copy with the removal is taken in at 150,
 * where the removal waits on the logs of the members who signed it. The
 * look at 160 follows those logs, and so reaches the removal. A look that
 * is cut short has moved the logs it follows all the same: the look made
 * again must not pass over what waited on them.
 */
function again(): unknown {
  const [a, b, c] = ["a", "b", "c"].map((name) => new KeyMind(name)) as [KeyMind, KeyMind, KeyMind];
  const zed = new KeyMind("zed");
  const club = new Collective("club", [a, b, c], 2, 5);
  const removal = rawSign(draftUpdate(club.head, T(20), { keys: [] }), [
    a.asMember(),
    b.asMember(),
  ]);
  const removed = contentId(removal);
  const copy = [...club.events, removal];
  const options = { following: [a, b, c, club].map((mind) => mind.address) };
  const other = zed.events;
  const reading = at(160);
  const ANSWERS = 200;
  // A book for each look, made with room.
  const books = Array.from({ length: ANSWERS }, () => {
    const seen = new FirstSeen();
    const book = new LogBook(seen);
    for (const mind of [a, b, c, club]) book.witness(mind.events, at(100), seen, options);
    book.witness(copy, at(150), seen);
    return { seen, book };
  });
  let looks = 0;
  const first = withStackSpent(() => {
    const { seen, book } = books[looks]!;
    const answer = book.witness(other, reading, seen, options);
    // Only a look that answered has used its book.
    looks++;
    return answer.ok;
  }, ANSWERS);
  return tally(
    first.map((ok, look) => {
      const { seen, book } = books[look]!;
      const recorded = (): string =>
        seen.eventSeen(removed) === reading ? "removal recorded at 160" : "removal not recorded";
      if (ok) return `ok, ${recorded()}`;
      const second = book.witness(other, reading, seen, options);
      return `refused, then ${second.ok ? "ok" : second.issues[0].clause}, ${recorded()}`;
    }),
    (answer) => answer,
  );
}

// Each of those that ask a book is for code that has never run: a process runs one of them
// first, as it is told to.
if (process.argv[2] === "books") {
  process.stdout.write(JSON.stringify({ books: books() }));
} else if (process.argv[2] === "again") {
  process.stdout.write(JSON.stringify({ again: again() }));
} else {
  const cold = coldBook();
  process.stdout.write(JSON.stringify({ cold, logs: logs(), records: records() }));
}
