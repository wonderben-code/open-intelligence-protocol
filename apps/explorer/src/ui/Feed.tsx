// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import type { Lookup, Reader } from "@oip/client";
import { useState } from "react";

import { type FeedView, readFeed } from "../oip/feed.ts";
import { shown, shownJson } from "../oip/text.ts";
import { type Reason, WHY } from "../oip/why.ts";
import { type Failure, failureOf } from "./said.ts";
import { Why } from "./Why.tsx";

type Read =
  | { readonly state: "unread" }
  | { readonly state: "reading" }
  | { readonly state: "failed"; readonly failure: Failure }
  | { readonly state: "read"; readonly view: FeedView };

/** The reason for a record's status, by the record's type. */
const statusReason = (type: string): Reason | undefined =>
  type === "Intent" || type === "Offer" || type === "Commitment" ? WHY[type] : undefined;

/**
 * A mind's feed. It is read only when the reader says so: a feed is at the
 * mind's homes, and asking them tells them that somebody looked.
 */
export function Feed({
  lookup,
  reader,
  mind,
  homes,
}: {
  lookup: Lookup;
  reader: Reader;
  mind: string;
  homes: readonly string[];
}): React.JSX.Element {
  const [read, setRead] = useState<Read>({ state: "unread" });
  const ask = (): void => {
    setRead({ state: "reading" });
    readFeed(lookup, reader, mind).then(
      (view) => {
        setRead({ state: "read", view });
      },
      (error: unknown) => {
        setRead({ state: "failed", failure: failureOf(error) });
      },
    );
  };
  return (
    <section aria-labelledby="feed-title">
      <h2 id="feed-title">Feed</h2>
      {homes.length === 0 ? (
        <p>This mind names no home, so it has no feed to read.</p>
      ) : (
        <>
          <p>
            What a mind has said publicly is kept at its homes, which its verified log names:{" "}
            {homes.map((home) => (
              <code key={home}>{shown(home)} </code>
            ))}
            . Reading the feed asks them, and so tells them that somebody looked.
          </p>
          <button type="button" onClick={ask} disabled={read.state === "reading"}>
            {read.state === "read" ? "Read the feed again" : "Read the feed"}
          </button>
        </>
      )}
      <div aria-live="polite">
        {read.state === "reading" && <p>Reading the feed, and verifying each entry.</p>}
        {read.state === "failed" && <p className="failed">{read.failure.message}</p>}
        {read.state === "read" && <Entries view={read.view} />}
      </div>
    </section>
  );
}

function Entries({ view }: { view: FeedView }): React.JSX.Element {
  if (view.entries.length === 0) {
    return <p>The feed is empty: this mind has published nothing.</p>;
  }
  return (
    <>
      <p className="verified">
        {String(view.entries.length)} {view.entries.length === 1 ? "entry" : "entries"}, each signed
        by the mind and each in its place in the chain.
        {view.refused > 0 && ` ${String(view.refused)} that did not verify are not listed.`}
        {view.equivocation > 0 &&
          ` ${String(view.equivocation)} more stand at a place the feed had filled already.`}
      </p>
      <Why reason={WHY.feed} about="the feed" />
      <ol className="entries">
        {view.entries.map((entry) => {
          const reason = statusReason(entry.objectType);
          return (
            <li key={entry.id}>
              <h3>
                {String(entry.seq)}. {shown(entry.objectType)}
                {entry.status !== undefined && <span className="status"> {entry.status}</span>}
              </h3>
              <p>
                <code>{entry.object}</code>, listed {entry.created}
              </p>
              {entry.missing !== undefined && (
                <p className="failed">The record could not be read: {entry.missing}</p>
              )}
              {entry.record !== undefined && (
                <details>
                  <summary>
                    The record <span className="hidden">of entry {String(entry.seq)}</span>
                  </summary>
                  <pre>{shownJson(entry.record)}</pre>
                  <Why reason={WHY.record} about={`the record of entry ${String(entry.seq)}`} />
                </details>
              )}
              {reason !== undefined && entry.status !== undefined && (
                <Why reason={reason} about={`the status of entry ${String(entry.seq)}`} />
              )}
            </li>
          );
        })}
      </ol>
    </>
  );
}
