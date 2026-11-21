// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Which services the Explorer asks: the resolvers and the indexers its
 * reader chose. They are kept in the browser's own storage, and go nowhere.
 */

import { httpsOrigin } from "@oip/client";

/** The services a reader chose. */
export interface Settings {
  /** The resolvers that are asked for a mind's log, by origin. */
  readonly resolvers: readonly string[];
  /** The indexers that are asked what minds there are, by origin. */
  readonly indexers: readonly string[];
}

/** The settings of a reader who has chosen nothing yet. */
export const NO_SETTINGS: Settings = { resolvers: [], indexers: [] };

/** The name the settings are kept under. */
export const SETTINGS_KEY = "oip-explorer/settings/1";
/** The most services of a kind that are asked. */
export const MAX_SERVICES = 8;

/**
 * Reads origins as a reader types them: one to a line, or with commas
 * between.
 *
 * @returns The origins, each once, and what was typed that is no HTTPS origin.
 */
export function parseOrigins(text: string): { origins: string[]; wrong: string[] } {
  const origins: string[] = [];
  const wrong: string[] = [];
  for (const typed of text.split(/[\s,]+/u).filter((part) => part !== "")) {
    const origin = httpsOrigin(typed);
    if (origin === undefined) wrong.push(typed);
    else if (!origins.includes(origin)) origins.push(origin);
  }
  return { origins: origins.slice(0, MAX_SERVICES), wrong };
}

const originsIn = (value: unknown): string[] =>
  Array.isArray(value)
    ? parseOrigins(value.filter((one): one is string => typeof one === "string").join("\n")).origins
    : [];

/** The settings kept in a browser's storage. What is kept there and is none gives no settings. */
export function loadSettings(storage: Pick<Storage, "getItem">): Settings {
  try {
    const kept: unknown = JSON.parse(storage.getItem(SETTINGS_KEY) ?? "null");
    if (typeof kept !== "object" || kept === null) return NO_SETTINGS;
    const { resolvers, indexers } = kept as { resolvers?: unknown; indexers?: unknown };
    return { resolvers: originsIn(resolvers), indexers: originsIn(indexers) };
  } catch {
    // Storage that cannot be read, or holds something else under the name.
    return NO_SETTINGS;
  }
}

/** Keeps the settings. A browser that keeps nothing loses them when the page is closed. */
export function saveSettings(storage: Pick<Storage, "setItem">, settings: Settings): void {
  try {
    storage.setItem(SETTINGS_KEY, JSON.stringify(settings));
  } catch {
    // Storage that is full or switched off: the settings hold for this visit.
  }
}
