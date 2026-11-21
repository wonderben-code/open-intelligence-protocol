// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import type { Lookup, Reader } from "@oip/client";
import { useEffect, useState } from "react";

import type { Asked } from "../oip/asked.ts";
import { type KeyView, type MindView, mindView, type Said as SaidOf } from "../oip/mind.ts";
import { shown, shownJson, shownName } from "../oip/text.ts";
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
  asked,
  lookup,
  reader,
  address,
}: {
  asked: Asked;
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
      {/* One short line for a reader who does not see the page. What was found stands after it. */}
      <p role="status">
        {found.state === "asking" && "Asking the resolvers, and verifying what they serve."}
        {found.state === "found" &&
          `Found: ${plural(found.view.events.length, "event", "events")} of its identity log verified.`}
        {found.state === "failed" && "This mind could not be shown."}
      </p>
      {found.state === "failed" && (
        <div className="failed">
          <p>{shown(found.failure.message)}</p>
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
      {found.state === "found" && (
        <>
          <Summary view={found.view} />
          <Log view={found.view} />
          <Keys view={found.view} />
          <Said view={found.view} />
          <Feed
            asked={asked}
            lookup={lookup}
            reader={reader}
            mind={address}
            homes={found.view.homes}
          />
          <Sources view={found.view} />
        </>
      )}
    </>
  );
}

const plural = (count: number, one: string, many: string): string =>
  `${String(count)} ${count === 1 ? one : many}`;

/** The page's own words, with the keys, addresses or strangers' text they speak of set apart. */
function Line({ said }: { said: SaidOf }): React.JSX.Element {
  return (
    <>
      {said.says}
      {(said.code ?? []).map((one) => (
        <span key={one}>
          {" "}
          <code>{shown(one)}</code>
        </span>
      ))}
      {said.more !== undefined && shown(said.more)}
    </>
  );
}

function Summary({ view }: { view: MindView }): React.JSX.Element {
  return (
    <section aria-labelledby="summary-title">
      <h2 id="summary-title">Verified in this browser</h2>
      <p className="verified">
        {plural(view.events.length, "event", "events")} of the identity log{" "}
        {view.events.length === 1 ? "was" : "were"} verified here: each is the event that the
        address or the event before it names, and each is signed as the protocol asks of it.
      </p>
      <p>
        When each event took effect is the word of the resolvers you chose, as witnesses. It is the
        one thing here that a signature does not settle.
      </p>
      <dl>
        <dt>Kind, by its own word</dt>
        <dd>{shown(view.kind)}</dd>
        <dt>Controlled by</dt>
        <dd>
          {view.members !== undefined ? (
            <>
              its members, a collective: {String(view.members.threshold)} of{" "}
              {plural(view.members.minds.length, "member", "members")} must sign an event of its log
              <ul>
                {view.members.minds.map((mind) => (
                  <li key={mind}>
                    <code>{mind}</code>
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <>
              its own control keys.{" "}
              {view.next === undefined || view.next.keys === 0
                ? "None is committed to for a next event: its log can never be extended."
                : `${plural(view.next.keys, "is", "are")} committed to for the next event, of which ${String(view.next.threshold)} must sign it.`}
            </>
          )}
        </dd>
        <dt>Standing</dt>
        <dd>
          {view.retired ? "Retired: it signs nothing more." : "Active."}
          {view.duplicitous && " Two valid events were seen at one place of its log."}
        </dd>
      </dl>
      <Why reason={WHY.address} about="the address" />
      {view.retired && <Why reason={WHY.standing} about="its standing" />}
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
              dates it <time dateTime={event.created}>{event.created}</time>.
            </p>
            <p>
              <Line said={event.signed} />
            </p>
            {event.changes.length > 0 && (
              <ul>
                {event.changes.map((change) => (
                  <li key={`${change.says} ${(change.code ?? []).join(" ")}`}>
                    <Line said={change} />
                  </li>
                ))}
              </ul>
            )}
            <p>
              <code>{event.id}</code>
            </p>
          </li>
        ))}
      </ol>
      <Why
        reason={view.controller === "member" ? WHY.collectiveLog : WHY.log}
        about="the identity log"
      />
      <Why reason={WHY.time} about="when each event took effect" />
    </section>
  );
}

const FOR: Readonly<Record<KeyView["role"], string>> = {
  operational: "Signing the mind's records",
  invocation: "Signing the identity events of a collective it is a member of",
  agreement: "Opening packets that are sealed to it",
};

/** How the stretch of a key ended, in words. */
function endOf(key: KeyView): string {
  const { ended } = key;
  if (ended === undefined) return "Still the mind's.";
  if (ended.why === "branch") {
    return `${ended.time}: an event of another branch of its log removed it, or retired the mind.`;
  }
  const event = ended.event === undefined ? "" : `event ${String(ended.event)}, `;
  return ended.why === "retired"
    ? `${event}${ended.time}: the mind retired.`
    : `${event}${ended.time}: removed.`;
}

function Keys({ view }: { view: MindView }): React.JSX.Element {
  return (
    <section aria-labelledby="keys-title">
      <h2 id="keys-title">Keys</h2>
      {view.keys.length === 0 ? (
        <p>
          It has no key of its own for signing records or opening packets.
          {view.controller === "member" && " A collective signs by its members."}
        </p>
      ) : (
        <>
          <p>Each key, and the stretch of the log in which it is the mind&apos;s.</p>
          <ul className="keys">
            {view.keys.map((key) => (
              <li key={`${key.role} ${key.key} ${String(key.since)}`}>
                <code>{key.key}</code>
                <dl>
                  <dt>For</dt>
                  <dd>{FOR[key.role]}</dd>
                  <dt>From</dt>
                  <dd>
                    event {String(key.since)}, {key.sinceTime}
                  </dd>
                  <dt>Until</dt>
                  <dd>{endOf(key)}</dd>
                  {key.compromisedSince !== undefined && (
                    <>
                      <dt>Compromised</dt>
                      <dd className="failed">
                        The mind declares it compromised since {key.compromisedSince}: no signature
                        by it on a record of the mind&apos;s counts from then on.
                        {key.never && " That is before it was the mind's: none counts at all."}
                      </dd>
                    </>
                  )}
                </dl>
              </li>
            ))}
          </ul>
        </>
      )}
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
        <p>It has no profile that its location record names.</p>
      ) : (
        <>
          <p>
            These are the mind&apos;s own words, signed by it. Nobody else vouches for them here.
          </p>
          <dl>
            <dt>Name</dt>
            <dd>{shownName(profile.name ?? "")}</dd>
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
      {view.alsoKnownAs.length > 0 && (
        <>
          <h3>Other names it lists for itself</h3>
          <p>
            Its log lists these. They are its own word, and nobody has checked here that any of them
            is the mind&apos;s:
          </p>
          <ul>
            {view.alsoKnownAs.map((alias) => (
              <li key={alias}>
                <code>{shown(alias)}</code>
              </li>
            ))}
          </ul>
          <Why reason={WHY.aliases} about="the other names" />
        </>
      )}
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
