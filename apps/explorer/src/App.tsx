// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { Lookup } from "@oip/client";
import { useState } from "react";

/** The first cut: resolves an address with the client, in the browser. */
export function App(): React.JSX.Element {
  const [said, setSaid] = useState("Nothing asked yet.");
  const ask = async (address: string, resolver: string): Promise<void> => {
    const lookup = new Lookup({ resolvers: [resolver] });
    const resolved = await lookup.resolve(address);
    setSaid(`${address} is a mind of kind ${resolved.state.kind}.`);
  };
  return (
    <main>
      <h1>OIP Explorer</h1>
      <button
        type="button"
        onClick={() => {
          void ask("did:oip:none", "https://resolver.example").catch((error: unknown) => {
            setSaid(String(error));
          });
        }}
      >
        Ask
      </button>
      <p>{said}</p>
    </main>
  );
}
