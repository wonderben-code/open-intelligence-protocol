// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { clause } from "@oip/testkit";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  Book,
  type Held,
  MAX_IDLE_CONTEXT_SECONDS,
  MAX_KEPT_SECONDS,
  MAX_UNANNOUNCED_SECONDS,
} from "../src/book.ts";

const MINA = "did:oip:bciqmina";
const OTHER = "did:oip:bciqother";

let root: string;
let book: Book;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "oip-bridge-book-"));
  book = new Book(root);
});
afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

/** A time, a number of seconds after the first of 2026, as the gateway writes one. */
const at = (seconds: number): string =>
  new Date(Date.UTC(2026, 0, 1) + seconds * 1000).toISOString();

const task = (id: string, more: Partial<Held> = {}): Held => ({
  id,
  mind: MINA,
  contextId: "ctx-1",
  state: "TASK_STATE_COMPLETED",
  at: at(0),
  artifacts: [],
  history: [],
  session: "bciqsession",
  request: `bciqrequest-${id}`,
  announced: true,
  ...more,
});

const ids = (page: { tasks: readonly Held[] } | undefined): string[] =>
  (page?.tasks ?? []).map(({ id }) => id);

describe("the tasks a gateway holds for a mind", () => {
  it("are kept by the names the gateway gave them, as they were last put", () => {
    expect(book.get(MINA, "t-1")).toBeUndefined();
    book.put(task("t-1", { state: "TASK_STATE_SUBMITTED" }));
    book.put(task("t-1", { state: "TASK_STATE_WORKING" }));
    expect(book.get(MINA, "t-1")).toMatchObject({ id: "t-1", state: "TASK_STATE_WORKING" });
    // Another book on the directory finds them.
    expect(new Book(root).get(MINA, "t-1")).toMatchObject({ id: "t-1" });
    book.drop(MINA, "t-1");
    expect(book.get(MINA, "t-1")).toBeUndefined();
  });

  it("are each mind's own: a task is none to who asks another mind for it, and is counted for its own", () => {
    book.put(task("t-1"));
    book.put(task("t-2"));
    book.put(task("t-3", { mind: OTHER }));
    expect(book.get(OTHER, "t-1")).toBeUndefined();
    expect(book.get(MINA, "t-3")).toBeUndefined();
    expect(book.get(OTHER, "t-3")).toMatchObject({ id: "t-3", mind: OTHER });
    expect([book.count(MINA), book.count(OTHER), book.count("did:oip:bciqnobody")]).toStrictEqual([
      2, 1, 0,
    ]);
    // Forgetting a task of one mind's by the name of another's forgets nothing.
    book.drop(OTHER, "t-1");
    expect(book.get(MINA, "t-1")).toBeDefined();
  });

  it("are found by the packets the gateway sent in them", () => {
    book.sent("bciqpacket-1", "t-1");
    book.sent("bciqpacket-2", "t-1");
    expect(book.taskOf("bciqpacket-1")).toBe("t-1");
    expect(book.taskOf("bciqpacket-2")).toBe("t-1");
    expect(book.taskOf("bciqpacket-3")).toBeUndefined();
  });

  it(`${clause("L0 3.1")} have a session for each context of each mind`, () => {
    expect(book.session(MINA, "ctx-1")).toBeUndefined();
    book.context(MINA, "ctx-1", "bciqsession-1", at(0));
    book.context(MINA, "ctx-2", "bciqsession-2", at(0));
    book.context(OTHER, "ctx-1", "bciqsession-3", at(0));
    expect(book.session(MINA, "ctx-1")).toBe("bciqsession-1");
    expect(book.session(MINA, "ctx-2")).toBe("bciqsession-2");
    // A context is a mind's: two minds that are given one name share nothing.
    expect(book.session(OTHER, "ctx-1")).toBe("bciqsession-3");
  });
});

describe("a listing of a mind's tasks", () => {
  beforeEach(() => {
    book.put(task("t-old", { at: at(1) }));
    book.put(task("t-new", { at: at(3), state: "TASK_STATE_INPUT_REQUIRED" }));
    book.put(task("t-mid", { at: at(2) }));
    book.put(task("t-elsewhere", { at: at(4), contextId: "ctx-2" }));
    book.put(task("t-others", { at: at(5), mind: OTHER }));
    book.put(task("t-untold", { at: at(6), announced: false }));
  });

  it("has the task whose state is newest first, and none of another mind or that no client was told of", () => {
    const page = book.list({ mind: MINA, pageSize: 50 });
    expect(ids(page)).toStrictEqual(["t-elsewhere", "t-new", "t-mid", "t-old"]);
    expect(page).toMatchObject({ next: "", total: 4 });
    expect(ids(book.list({ mind: OTHER, pageSize: 50 }))).toStrictEqual(["t-others"]);
  });

  it("is of one context, of one state, or of what changed since a time, where that is asked", () => {
    expect(ids(book.list({ mind: MINA, pageSize: 50, contextId: "ctx-1" }))).toStrictEqual([
      "t-new",
      "t-mid",
      "t-old",
    ]);
    expect(
      ids(book.list({ mind: MINA, pageSize: 50, state: "TASK_STATE_INPUT_REQUIRED" })),
    ).toStrictEqual(["t-new"]);
    // At the time or later.
    expect(ids(book.list({ mind: MINA, pageSize: 50, since: at(3) }))).toStrictEqual([
      "t-elsewhere",
      "t-new",
    ]);
    expect(book.list({ mind: MINA, pageSize: 50, contextId: "ctx-none" })).toStrictEqual({
      tasks: [],
      next: "",
      total: 0,
    });
  });

  it("comes a page at a time, each page from where the one before ended", () => {
    const first = book.list({ mind: MINA, pageSize: 2 });
    expect(ids(first)).toStrictEqual(["t-elsewhere", "t-new"]);
    expect(first?.total).toBe(4);
    expect(first?.next).not.toBe("");
    const second = book.list({ mind: MINA, pageSize: 2, pageToken: first?.next ?? "" });
    expect(ids(second)).toStrictEqual(["t-mid", "t-old"]);
    // The last page says that it is the last.
    expect(second).toMatchObject({ next: "", total: 4 });
    // A page of one, and the page after the last.
    const one = book.list({ mind: MINA, pageSize: 3 });
    expect(ids(book.list({ mind: MINA, pageSize: 3, pageToken: one?.next ?? "" }))).toStrictEqual([
      "t-old",
    ]);
    const end = Buffer.from(`${at(0)} t-0`).toString("base64url");
    expect(book.list({ mind: MINA, pageSize: 3, pageToken: end })).toMatchObject({ tasks: [] });
  });

  it("gives no task twice for having changed between two pages: it is at the front then, of a new listing", () => {
    const first = book.list({ mind: MINA, pageSize: 2 });
    book.put(task("t-old", { at: at(9) }));
    expect(ids(book.list({ mind: MINA, pageSize: 2, pageToken: first?.next ?? "" }))).toStrictEqual(
      ["t-mid"],
    );
  });

  it("takes tasks of one time in one order", () => {
    book.put(task("t-b", { at: at(7) }));
    book.put(task("t-a", { at: at(7) }));
    book.put(task("t-c", { at: at(7) }));
    const page = book.list({ mind: MINA, pageSize: 2 });
    expect(ids(page)).toStrictEqual(["t-c", "t-b"]);
    expect(ids(book.list({ mind: MINA, pageSize: 2, pageToken: page?.next ?? "" }))).toStrictEqual([
      "t-a",
      "t-elsewhere",
    ]);
  });

  it.each([
    ["no base64url at all", "not a token!"],
    ["base64url of what names no task", Buffer.from("nothing").toString("base64url")],
    ["base64url with padding", `${Buffer.from("2026 t-1").toString("base64url")}=`],
  ])("is none for a page token that is %s", (_, pageToken) => {
    expect(book.list({ mind: MINA, pageSize: 2, pageToken })).toBeUndefined();
  });
});

describe("the packets a gateway brought for others", () => {
  it("are remembered until nobody can accept them any more, so that none is brought twice", () => {
    expect(book.wasPassed("bciqpacket-1")).toBe(false);
    book.pass("bciqpacket-1", at(100));
    book.pass("bciqpacket-2", at(300));
    expect(book.wasPassed("bciqpacket-1")).toBe(true);
    expect(new Book(root).wasPassed("bciqpacket-2")).toBe(true);
    // At a time between the two, the first is forgotten.
    book.sweep((seconds) => at(200 - seconds));
    expect(book.wasPassed("bciqpacket-1")).toBe(false);
    expect(book.wasPassed("bciqpacket-2")).toBe(true);
  });
});

describe("what a gateway keeps no longer", () => {
  it("is a task whose state last changed thirty days ago, and one a day old that no client was told of, with their packets", () => {
    const now = 100 * 86_400;
    const ago = (seconds: number): string => at(now - seconds);
    book.put(task("ended-long-ago", { at: at(now - MAX_KEPT_SECONDS - 1) }));
    book.put(task("ended-lately", { at: at(now - MAX_KEPT_SECONDS + 1) }));
    // A task that has not ended and has not changed in thirty days is one whose mind never
    // answered: it is kept no longer than one that ended. Another mind's is swept with the rest.
    book.put(
      task("open-long-ago", { at: at(now - MAX_KEPT_SECONDS - 1), state: "TASK_STATE_WORKING" }),
    );
    book.put(
      task("open-lately", {
        at: at(now - MAX_KEPT_SECONDS + 1),
        state: "TASK_STATE_WORKING",
        mind: OTHER,
      }),
    );
    book.put(task("untold-old", { at: at(now - MAX_UNANNOUNCED_SECONDS - 1), announced: false }));
    book.put(task("untold-new", { at: at(now - MAX_UNANNOUNCED_SECONDS + 1), announced: false }));
    for (const id of ["ended-long-ago", "ended-lately", "untold-old", "untold-new"]) {
      book.sent(`bciqpacket-${id}`, id);
    }
    expect(book.sweep(ago)).toStrictEqual({ forgotten: 3, sessions: [] });
    expect(book.get(MINA, "ended-long-ago")).toBeUndefined();
    expect(book.get(MINA, "open-long-ago")).toBeUndefined();
    expect(book.get(MINA, "untold-old")).toBeUndefined();
    expect(book.get(MINA, "ended-lately")).toBeDefined();
    expect(book.get(OTHER, "open-lately")).toBeDefined();
    expect(book.get(MINA, "untold-new")).toBeDefined();
    expect(book.taskOf("bciqpacket-ended-long-ago")).toBeUndefined();
    expect(book.taskOf("bciqpacket-untold-old")).toBeUndefined();
    expect(book.taskOf("bciqpacket-ended-lately")).toBe("ended-lately");
    expect(book.taskOf("bciqpacket-untold-new")).toBe("untold-new");
    expect(book.sweep(ago)).toStrictEqual({ forgotten: 0, sessions: [] });
  });

  it("is the session of a context that has no task and was last used a day ago: nothing more is said in it", () => {
    const now = 100 * 86_400;
    const ago = (seconds: number): string => at(now - seconds);
    const long = at(now - MAX_IDLE_CONTEXT_SECONDS - 1);
    // A context that was used long ago and has no task, one that has a task still, one that
    // was used lately, and another mind's of the same name.
    book.context(MINA, "ctx-idle", "bciqsession-idle", long);
    book.context(MINA, "ctx-with-task", "bciqsession-task", long);
    book.put(task("t-1", { contextId: "ctx-with-task", at: at(now) }));
    book.context(MINA, "ctx-lately", "bciqsession-lately", at(now - MAX_IDLE_CONTEXT_SECONDS + 1));
    book.context(OTHER, "ctx-with-task", "bciqsession-other", long);
    expect(book.sweep(ago)).toStrictEqual({
      forgotten: 0,
      sessions: ["bciqsession-idle", "bciqsession-other"].sort(),
    });
    expect(book.session(MINA, "ctx-idle")).toBeUndefined();
    expect(book.session(OTHER, "ctx-with-task")).toBeUndefined();
    expect(book.session(MINA, "ctx-with-task")).toBe("bciqsession-task");
    expect(book.session(MINA, "ctx-lately")).toBe("bciqsession-lately");
    // A context that is used again is kept again.
    book.context(MINA, "ctx-lately", "bciqsession-lately", at(now + MAX_IDLE_CONTEXT_SECONDS));
    expect(
      book.sweep((seconds) => at(now + MAX_IDLE_CONTEXT_SECONDS + 10 - seconds)),
    ).toMatchObject({
      sessions: [],
    });
  });

  it("is nothing where nothing was ever kept", () => {
    expect(book.sweep((seconds) => at(1000 - seconds))).toStrictEqual({
      forgotten: 0,
      sessions: [],
    });
  });
});
