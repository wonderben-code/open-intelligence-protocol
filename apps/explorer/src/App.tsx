// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * OIP Explorer: look up any mind, and watch every signature verify in the
 * browser.
 *
 * The page holds no key and keeps no record. It asks the services its
 * reader chose, verifies what they serve with the same client a mind uses,
 * and shows what was found with the reason for each thing it says.
 */

import { Lookup, Reader, systemClock } from "@oip/client";
import { useEffect, useMemo, useRef, useState } from "react";

import { Asked } from "./oip/asked.ts";
import { hashOf, type Route, routeOf } from "./route.ts";
import { loadSettings, saveSettings, type Settings } from "./settings.ts";
import { Home } from "./ui/Home.tsx";
import { MindPage } from "./ui/MindPage.tsx";
import { SettingsPage } from "./ui/SettingsPage.tsx";

const TITLES: Readonly<Record<Route["page"], string>> = {
  home: "OIP Explorer",
  settings: "The services to ask · OIP Explorer",
  mind: "A mind · OIP Explorer",
  nowhere: "No such page · OIP Explorer",
};

export function App(): React.JSX.Element {
  const [settings, setSettings] = useState<Settings>(() => loadSettings(window.localStorage));
  const [route, setRoute] = useState<Route>(() => routeOf(window.location.hash));
  const main = useRef<HTMLElement>(null);

  useEffect(() => {
    const moved = (): void => {
      setRoute(routeOf(window.location.hash));
    };
    window.addEventListener("hashchange", moved);
    return () => {
      window.removeEventListener("hashchange", moved);
    };
  }, []);
  useEffect(() => {
    document.title = TITLES[route.page];
    // A reader who does not see the page is told that it changed: the heading takes the focus.
    main.current?.querySelector<HTMLElement>("h1")?.focus();
  }, [route]);

  // One client and one reader for the services chosen. The reader remembers the records it
  // was shown, so that a Commitment read on one mind's page is judged with a Receipt read on
  // another's. Every request of the client passes through `asked`, which lets through those
  // to the services chosen, and to a mind's homes while its reader has its feed read.
  const network = useMemo(() => {
    if (settings.resolvers.length === 0) return undefined;
    const asked = new Asked([...settings.resolvers, ...settings.indexers]);
    const lookup = new Lookup({
      resolvers: settings.resolvers,
      indexers: settings.indexers,
      fetch: asked.fetch,
    });
    return { asked, lookup, reader: new Reader({ lookup, clock: systemClock }) };
  }, [settings]);

  return (
    <>
      <header>
        <nav aria-label="The Explorer">
          <a href={hashOf({ page: "home" })}>OIP Explorer</a>
          <a href={hashOf({ page: "settings" })}>Services</a>
        </nav>
      </header>
      <main ref={main}>
        {route.page === "home" && <Home network={network} settings={settings} />}
        {route.page === "settings" && (
          <SettingsPage
            settings={settings}
            onSave={(chosen) => {
              saveSettings(window.localStorage, chosen);
              setSettings(chosen);
            }}
          />
        )}
        {route.page === "mind" &&
          (network === undefined ? (
            <>
              <h1 tabIndex={-1}>A mind</h1>
              <p className="notice">
                No resolver is chosen yet.{" "}
                <a href={hashOf({ page: "settings" })}>Choose the services</a> the Explorer may ask.
              </p>
            </>
          ) : (
            <MindPage
              key={route.address}
              asked={network.asked}
              lookup={network.lookup}
              reader={network.reader}
              address={route.address}
            />
          ))}
        {route.page === "nowhere" && (
          <>
            <h1 tabIndex={-1}>No such page</h1>
            <p>
              The Explorer has no page by that name, or that is no address of a mind.{" "}
              <a href={hashOf({ page: "home" })}>Start again</a>.
            </p>
          </>
        )}
      </main>
      <footer>
        <p>
          The Open Intelligence Protocol is free and open. This page holds no key, keeps no record
          of what you look at, and asks only the services you chose.
        </p>
      </footer>
    </>
  );
}
