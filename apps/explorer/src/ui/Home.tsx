// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import type { Lookup } from "@oip/client";
import { isMindAddress } from "@oip/core";
import { useState } from "react";

import type { Asked } from "../oip/asked.ts";
import { browse, type Listing } from "../oip/browse.ts";
import { shown, shownName } from "../oip/text.ts";
import { WHY } from "../oip/why.ts";
import { hashOf } from "../route.ts";
import type { Settings } from "../settings.ts";
import { type Failure, failureOf } from "./said.ts";
import { Why } from "./Why.tsx";

type Listed =
  | { readonly state: "unasked" }
  | { readonly state: "asking" }
  | { readonly state: "failed"; readonly failure: Failure }
  | { readonly state: "listed"; readonly listing: Listing };

/** The tags a reader typed, with spaces or commas between. */
export const tagsIn = (typed: string): string[] =>
  typed.split(/[\s,]+/u).filter((tag) => tag !== "");

/** Where a reader starts: an address to look up, or the minds an indexer lists. */
export function Home({
  network,
  settings,
}: {
  network: { readonly lookup: Lookup; readonly asked: Asked } | undefined;
  settings: Settings;
}): React.JSX.Element {
  const [typed, setTyped] = useState("");
  const [wrong, setWrong] = useState(false);
  const [tags, setTags] = useState("");
  const [listed, setListed] = useState<Listed>({ state: "unasked" });
  const go = (event: React.SyntheticEvent): void => {
    event.preventDefault();
    const address = typed.trim();
    if (!isMindAddress(address)) {
      setWrong(true);
      return;
    }
    window.location.hash = hashOf({ page: "mind", address });
  };
  const list = (event: React.SyntheticEvent): void => {
    event.preventDefault();
    // The button stays where the focus is while the indexers are asked, and does nothing then.
    if (network === undefined || listed.state === "asking") return;
    setListed({ state: "asking" });
    browse(network.lookup, network.asked, tagsIn(tags)).then(
      (listing) => {
        setListed({ state: "listed", listing });
      },
      (error: unknown) => {
        setListed({ state: "failed", failure: failureOf(error) });
      },
    );
  };
  return (
    <>
      <h1 tabIndex={-1}>OIP Explorer</h1>
      <p>
        Look up any mind of the Open Intelligence Protocol: a person, an agent, an institution or a
        collective. Its identity log, its keys and what it has published are fetched from the
        services you choose, and every signature is verified here, in your browser.
      </p>
      {network === undefined ? (
        <p className="notice">
          No resolver is chosen yet. <a href={hashOf({ page: "settings" })}>Choose the services</a>{" "}
          the Explorer may ask.
        </p>
      ) : (
        <>
          <form onSubmit={go} noValidate>
            <label htmlFor="address">The address of a mind</label>
            <input
              id="address"
              name="address"
              type="text"
              inputMode="url"
              autoComplete="off"
              spellCheck={false}
              placeholder="did:oip:…"
              value={typed}
              aria-invalid={wrong}
              aria-describedby={wrong ? "address-wrong" : undefined}
              onChange={(event) => {
                setTyped(event.target.value);
                setWrong(false);
              }}
            />
            {wrong && (
              <p id="address-wrong" className="failed" role="alert">
                That is no address of a mind. An address is <code>did:oip:</code> and 56 letters and
                digits.
              </p>
            )}
            <button type="submit">Look it up</button>
          </form>
          <section aria-labelledby="browse-title">
            <h2 id="browse-title">Browse</h2>
            {settings.indexers.length === 0 ? (
              <p>
                No indexer is chosen. <a href={hashOf({ page: "settings" })}>Choose one</a> to see
                the minds it lists.
              </p>
            ) : (
              <form onSubmit={list} noValidate>
                <label htmlFor="tags">Only minds that can do what these tags say (optional)</label>
                <input
                  id="tags"
                  name="tags"
                  type="text"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="lang:sw domain:legal"
                  value={tags}
                  onChange={(event) => {
                    setTags(event.target.value);
                  }}
                />
                <button type="submit" aria-disabled={listed.state === "asking"}>
                  List the minds the indexers know
                </button>
              </form>
            )}
            {/* One short line for a reader who does not see the page. What was found stands after it. */}
            <p role="status" className={listed.state === "failed" ? "failed" : undefined}>
              {listed.state === "asking" && "Asking the indexers, and verifying each profile."}
              {listed.state === "failed" && shown(listed.failure.message)}
              {listed.state === "listed" && toldOf(listed.listing)}
            </p>
            {listed.state === "listed" && <Minds listing={listed.listing} />}
          </section>
        </>
      )}
    </>
  );
}

/** What a listing came to, in one line. */
export function toldOf(listing: Listing): string {
  if (!listing.answered) return "No indexer answered.";
  const count = listing.minds.length;
  if (count === 0) return "The indexers that answered list no such mind.";
  return `${String(count)} ${count === 1 ? "mind" : "minds"} listed, each with a profile it signed.`;
}

function Minds({ listing }: { listing: Listing }): React.JSX.Element {
  return (
    <>
      {listing.minds.length > 0 && (
        <ul className="minds">
          {listing.minds.map((mind) => (
            <li key={mind.address}>
              <a href={hashOf({ page: "mind", address: mind.address })}>{shownName(mind.name)}</a>,{" "}
              {shown(mind.kind)}
              {mind.summary !== undefined && <>: {shown(mind.summary)}</>}
              {mind.capabilities.length > 0 && (
                <> (can: {mind.capabilities.map(shown).join(", ")})</>
              )}
              {!mind.current && <> (by a profile it has since replaced)</>}
              <br />
              <code>{mind.address}</code>
            </li>
          ))}
        </ul>
      )}
      {listing.unlisted > 0 && (
        <p>
          {String(listing.unlisted)} more that an indexer named{" "}
          {listing.unlisted === 1 ? "is" : "are"} not listed: what it named could not be verified as
          its author&apos;s own.
          {listing.notAsked.length > 0 && (
            <>
              {" "}
              To verify it, a host you did not choose would have had to be asked, and none was:{" "}
              {listing.notAsked.map((origin) => (
                <code key={origin}>{shown(origin)} </code>
              ))}
            </>
          )}
        </p>
      )}
      <h3>Who was asked</h3>
      <ul>
        {listing.sources.map((source) => (
          <li key={source.indexer}>
            <code>{shown(source.indexer)}</code>:{" "}
            {source.failure === undefined
              ? `answered, with ${String(source.results ?? 0)} ${source.results === 1 ? "result" : "results"}`
              : `gave no answer that was taken (${shown(source.failure)})`}
          </li>
        ))}
      </ul>
      <Why reason={WHY.listing} about="the listing" />
    </>
  );
}
