// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";

import { MAX_SERVICES, parseOrigins, type Settings } from "../settings.ts";

/** The services the Explorer may ask. Nothing else is ever asked without a click. */
export function SettingsPage({
  settings,
  onSave,
}: {
  settings: Settings;
  onSave: (settings: Settings) => void;
}): React.JSX.Element {
  const [resolvers, setResolvers] = useState(settings.resolvers.join("\n"));
  const [indexers, setIndexers] = useState(settings.indexers.join("\n"));
  const [said, setSaid] = useState("");
  const [wrong, setWrong] = useState<readonly string[]>([]);
  const save = (event: React.SyntheticEvent): void => {
    event.preventDefault();
    const asked = parseOrigins(resolvers);
    const listing = parseOrigins(indexers);
    const refused = [...asked.wrong, ...listing.wrong];
    setWrong(refused);
    if (refused.length > 0) {
      setSaid("");
      return;
    }
    onSave({ resolvers: asked.origins, indexers: listing.origins });
    setResolvers(asked.origins.join("\n"));
    setIndexers(listing.origins.join("\n"));
    setSaid("Kept, in this browser.");
  };
  return (
    <>
      <h1 tabIndex={-1}>The services to ask</h1>
      <p>
        The Explorer asks the resolvers and the indexers named here, and nobody else. A mind&apos;s
        feed is at the homes its own log names, and those are asked only when you say so on the
        mind&apos;s page. What you choose is kept in this browser, and is sent nowhere.
      </p>
      <form onSubmit={save} noValidate>
        <label htmlFor="resolvers">Resolvers, one HTTPS origin to a line</label>
        <textarea
          id="resolvers"
          name="resolvers"
          rows={3}
          spellCheck={false}
          value={resolvers}
          onChange={(event) => {
            setResolvers(event.target.value);
          }}
        />
        <label htmlFor="indexers">Indexers, one HTTPS origin to a line</label>
        <textarea
          id="indexers"
          name="indexers"
          rows={3}
          spellCheck={false}
          value={indexers}
          onChange={(event) => {
            setIndexers(event.target.value);
          }}
        />
        <p>At most {String(MAX_SERVICES)} of each are asked.</p>
        <button type="submit">Keep these</button>
        <div aria-live="polite">
          {wrong.length > 0 && (
            <p className="failed">
              Not an HTTPS origin, such as https://resolver.example: {wrong.join(", ")}
            </p>
          )}
          {said !== "" && <p className="verified">{said}</p>}
        </div>
      </form>
    </>
  );
}
