// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import type { Lookup, Reader } from "@oip/client";
import { useEffect, useState } from "react";

import { type MindView, mindView } from "../oip/mind.ts";
import { shown, shownJson } from "../oip/text.ts";
import { WHY } from "../oip/why.ts";
import { Feed } from "./Feed.tsx";
import { type Failure, failureOf } from "./said.ts";
import { Why } from "./Why.tsx";

type Found =
  | { readonly state: "asking" }
  | { readonly state: "failed"; readonly failure: Failure }
  | { readonly state: "found"; readonly view: MindView };

/** A mind: everything a resolution found, with why each thing is shown as it is. */
export function MindPage({
  lookup,
  reader,
  address,
}: {
  lookup: Lookup;
  reader: Reader;
  address: string;
}): React.JSX.Element {
  const [found, setFound] = useState<Found>({ state: "asking" });
  useEffect(() => {
    let wanted = true;
    setFound({ state: "asking" });
    lookup.resolve(address).then(
      (resolved) => {
        if (wanted) setFound({ state: "found", view: mindView(resolved) });
      },
      (error: unknown) => {
        if (wanted) setFound({ state: "failed", failure: failureOf(error) });
      },
    );
    return () => {
      // An answer for an address the reader has left is not shown.
      wanted = false;
    };
  }, [lookup, address]);

  return (
    <>
      <h1 tabIndex={-1}>A mind</h1>
      <p>
        <code className="address">{address}</code>
      </p>
      <div aria-live="polite">
        {found.state === "asking" && <p>Asking the resolvers, and verifying what they serve.</p>}
        {found.state === "failed" && (
          <div className="failed">
            <p>This mind could not be shown: {found.failure.message}</p>
            {found.failure.clause !== undefined && (
              <p>
                The rule is{" "}
                <a href={found.failure.clause.href} rel="noreferrer">
                  {found.failure.clause.id}
                </a>
                : {found.failure.clause.section}.
              </p>
            )}
          </div>
        )}
      </div>
      {found.state === "found" && (
        <>
          <Summary view={found.view} />
          <Log view={found.view} />
          <Keys view={found.view} />
          <Said view={found.view} />
          <Feed lookup={lookup} reader={reader} mind={address} homes={found.view.homes} />
          <Sources view={found.view} />
        </>
      )}
    </>
  );
}

function Summary({ view }: { view: MindView }): React.JSX.Element {
  const signatures = view.events.reduce((sum, event) => sum + event.proofs, 0);
  return (
    <section aria-labelledby="summary-title">
      <h2 id="summary-title">Verified in this browser</h2>
      <p className="verified">
        {String(view.events.length)} {view.events.length === 1 ? "event" : "events"} of the identity
        log and {String(signatures)} {signatures === 1 ? "signature" : "signatures"} on them were
        checked here. Nothing below is taken on a resolver&apos;s word.
      </p>
      <dl>
        <dt>Kind</dt>
        <dd>{shown(view.kind)}</dd>
        <dt>Controlled by</dt>
        <dd>
          {view.controller === "member" ? "its members: a collective" : "its own control keys"}
        </dd>
        <dt>Standing</dt>
        <dd>
          {view.retired ? "Retired: it signs nothing more." : "Active."}
          {view.duplicitous && " Two valid events were seen at one place of its log."}
        </dd>
        {view.alsoKnownAs.length > 0 && (
          <>
            <dt>Also known as, by its own word</dt>
            <dd>{view.alsoKnownAs.map(shown).join(", ")}</dd>
          </>
        )}
      </dl>
      <Why reason={WHY.address} about="the address" />
      {view.duplicitous && <Why reason={WHY.duplicity} about="the two events at one place" />}
    </section>
  );
}

function Log({ view }: { view: MindView }): React.JSX.Element {
  return (
    <section aria-labelledby="log-title">
      <h2 id="log-title">Identity log</h2>
      <ol className="timeline">
        {view.events.map((event) => (
          <li key={event.id}>
            <h3>
              {String(event.seq)}. {event.type}
            </h3>
            <p>
              Took effect <time dateTime={event.evaluated}>{event.evaluated}</time>. Its author
              dates it <time dateTime={event.created}>{event.created}</time>. {String(event.proofs)}{" "}
              {event.proofs === 1 ? "signature" : "signatures"}.
            </p>
            {event.changes.length > 0 && (
              <ul>
                {event.changes.map((change) => (
                  <li key={change}>{shown(change)}</li>
                ))}
              </ul>
            )}
            <p>
              <code>{event.id}</code>
            </p>
          </li>
        ))}
      </ol>
      <Why reason={WHY.log} about="the identity log" />
      <Why reason={WHY.time} about="when each event took effect" />
    </section>
  );
}

function Keys({ view }: { view: MindView }): React.JSX.Element {
  return (
    <section aria-labelledby="keys-title">
      <h2 id="keys-title">Keys</h2>
      <div className="wide">
        <table>
          <caption>Each key, and the stretch of the log in which it is the mind&apos;s</caption>
          <thead>
            <tr>
              <th scope="col">Key</th>
              <th scope="col">For</th>
              <th scope="col">From</th>
              <th scope="col">Until</th>
            </tr>
          </thead>
          <tbody>
            {view.keys.map((key) => (
              <tr key={`${key.role} ${key.key} ${String(key.since)}`}>
                <th scope="row">
                  <code>{key.key}</code>
                </th>
                <td>{key.role}</td>
                <td>
                  event {String(key.since)}, {key.sinceTime}
                </td>
                <td>
                  {key.until === undefined
                    ? "still the mind's"
                    : `event ${String(key.until)}, ${key.untilTime ?? ""}`}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Why reason={WHY.keys} about="the keys" />
    </section>
  );
}

function Said({ view }: { view: MindView }): React.JSX.Element {
  const profile = view.profile?.record as
    | { name?: string; summary?: string; capabilities?: { id: string; summary: string }[] }
    | undefined;
  return (
    <section aria-labelledby="said-title">
      <h2 id="said-title">What it says of itself</h2>
      {profile === undefined ? (
        <p>It has no profile that counts now.</p>
      ) : (
        <>
          <p>
            These are the mind&apos;s own words, signed by it. Nobody else vouches for them here.
          </p>
          <dl>
            <dt>Name</dt>
            <dd>{shown(profile.name ?? "")}</dd>
            {profile.summary !== undefined && (
              <>
                <dt>Summary</dt>
                <dd>{shown(profile.summary)}</dd>
              </>
            )}
            {(profile.capabilities ?? []).length > 0 && (
              <>
                <dt>Capabilities</dt>
                <dd>
                  <ul>
                    {(profile.capabilities ?? []).map((capability) => (
                      <li key={capability.id}>
                        <code>{shown(capability.id)}</code>: {shown(capability.summary)}
                      </li>
                    ))}
                  </ul>
                </dd>
              </>
            )}
          </dl>
          <details>
            <summary>The profile record</summary>
            <pre>{shownJson(view.profile?.record)}</pre>
          </details>
        </>
      )}
      <Why reason={WHY.profile} about="the profile" />
      <h3>Where it is reached</h3>
      {view.location === undefined ? (
        <p>It has no location record that counts now.</p>
      ) : (
        <details>
          <summary>
            The location record{view.location.stale ? ", which is past its time to live" : ""}
          </summary>
          <pre>{shownJson(view.location.record)}</pre>
        </details>
      )}
      <Why reason={WHY.location} about="the location record" />
      <h3>DID document</h3>
      <details>
        <summary>The DID document, worked out from the log</summary>
        <pre>{shownJson(view.didDocument)}</pre>
      </details>
      <Why reason={WHY.didDocument} about="the DID document" />
    </section>
  );
}

function Sources({ view }: { view: MindView }): React.JSX.Element {
  return (
    <section aria-labelledby="sources-title">
      <h2 id="sources-title">Who was asked</h2>
      <ul>
        {view.sources.map((source) => (
          <li key={source.resolver}>
            <code>{shown(source.resolver)}</code>:{" "}
            {source.failure === undefined
              ? "answered"
              : `did not answer (${shown(source.failure)})`}
          </li>
        ))}
      </ul>
      <Why reason={WHY.resolver} about="the resolvers" />
    </section>
  );
}
