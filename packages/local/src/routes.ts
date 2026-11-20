// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * How a client reaches a network that runs on this machine. Its services
 * are known by HTTPS origins, as any service is, and answer on ports of
 * `127.0.0.1`. A route says which port an origin is at. The client is as it
 * is: it is given a `fetch` and a socket that do the carrying.
 */

import type { Fetch, OpenSocket } from "@oip/client";

/** A request for an origin that has a route goes where the route says: everything else as it is. */
export function routed(routes: Readonly<Record<string, string>>, fetch: Fetch): Fetch {
  return async (request) => {
    const url = new URL(request.url);
    const place = routes[url.origin];
    if (place === undefined) return fetch(request);
    const body = request.body === null ? undefined : new Uint8Array(await request.arrayBuffer());
    return fetch(
      new Request(`${place}${url.pathname}${url.search}`, {
        method: request.method,
        headers: request.headers,
        redirect: request.redirect,
        signal: request.signal,
        ...(body === undefined ? {} : { body }),
      }),
    );
  };
}

/** A socket to an origin that has a route is opened where the route says, without TLS. */
export function routedSocket(
  routes: Readonly<Record<string, string>>,
  open: OpenSocket,
): OpenSocket {
  return (url, protocol) => {
    const asked = new URL(url);
    const place = routes[`https://${asked.host}`];
    return open(
      place === undefined
        ? url
        : `${place.replace(/^http:/u, "ws:")}${asked.pathname}${asked.search}`,
      protocol,
    );
  };
}
