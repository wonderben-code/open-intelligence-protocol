// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Where in the Explorer a reader is, as the part of the address after `#`
 * says. The site is static files: nothing of an address reaches whoever
 * serves them.
 */

import { isMindAddress } from "@oip/core";

/** A page of the Explorer. */
export type Route =
  | { readonly page: "home" }
  | { readonly page: "settings" }
  | { readonly page: "mind"; readonly address: string }
  | { readonly page: "nowhere" };

/** The page a fragment names. */
export function routeOf(hash: string): Route {
  const path = hash.replace(/^#/u, "");
  if (path === "" || path === "/") return { page: "home" };
  if (path === "/settings") return { page: "settings" };
  const [, address] = /^\/mind\/(.+)$/u.exec(path) ?? [];
  if (address !== undefined) {
    let named = address;
    try {
      named = decodeURIComponent(address);
    } catch {
      // What is no encoding of anything is no address either.
    }
    return isMindAddress(named) ? { page: "mind", address: named } : { page: "nowhere" };
  }
  return { page: "nowhere" };
}

/** The fragment that names a page. */
export function hashOf(route: Route): string {
  if (route.page === "mind") return `#/mind/${route.address}`;
  return route.page === "settings" ? "#/settings" : "#/";
}
