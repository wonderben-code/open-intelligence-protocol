// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import type { Lookup } from "@oip/client";
import { isMindAddress } from "@oip/core";
import { useState } from "react";

import { browse, type Listing } from "../oip/browse.ts";
import { shown } from "../oip/text.ts";
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

/** Where a reader starts: an address to look up, or the minds an indexer lists. */
export function Home({
  lookup,
  settings,
}: {
  lookup: Lookup | undefined;
  settings: Settings;
}): React.JSX.Element {
  const [typed, setTyped] = useState("");
  const [wrong, setWrong] = useState(false);
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
  const list = (): void => {
    if (lookup === undefined) return;
    setListed({ state: "asking" });
    browse(lookup).then(
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
      {lookup === undefined ? (
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
              <p id="address-wrong" className="failed">
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
              <button type="button" onClick={list} disabled={listed.state === "asking"}>
                List the minds the indexers know
              </button>
            )}
            <div aria-live="polite">
              {listed.state === "asking" && <p>Asking the indexers, and verifying each profile.</p>}
              {listed.state === "failed" && <p className="failed">{listed.failure.message}</p>}
              {listed.state === "listed" && <Minds listing={listed.listing} />}
            </div>
          </section>
        </>
      )}
    </>
  );
}

function Minds({ listing }: { listing: Listing }): React.JSX.Element {
  if (listing.minds.length === 0) return <p>The indexers list no mind.</p>;
  return (
    <>
      <ul className="minds">
        {listing.minds.map((mind) => (
          <li key={mind.address}>
            <a href={hashOf({ page: "mind", address: mind.address })}>{shown(mind.name)}</a>,{" "}
            {shown(mind.kind)}
            {mind.summary !== undefined && <>: {shown(mind.summary)}</>}
            {mind.capabilities.length > 0 && <> (can: {mind.capabilities.map(shown).join(", ")})</>}
            <br />
            <code>{mind.address}</code>
          </li>
        ))}
      </ul>
      <Why reason={WHY.listing} about="the listing" />
    </>
  );
}
