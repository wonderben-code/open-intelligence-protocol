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

/** Where a route leads: a port of this machine, over plain HTTP, and nowhere else. */
const ROUTED = /^http:\/\/127\.0\.0\.1(?::\d{1,5})?(?:[/?#]|$)/u;

/**
 * How a mind that runs unattended asks: under a guard, but for what a route
 * carried.
 *
 * A mind asks at URLs that the records of strangers name: where a recipient
 * is reached, where a mind's feed is served. On a person's machine that is
 * the person's own doing. A gateway does it for whoever sends it a packet,
 * and must not be led to the machine it runs on or the network behind it
 * (BUILD.md 3.7). So everything it asks goes through `guarded`, which is to
 * refuse such addresses: `GuardedFetcher.fetch` of `@oip/server` does.
 *
 * A request for a port of this machine over plain HTTP goes as it is. A
 * client asks nothing but HTTPS, so such a request is one a route carried
 * (`routed`), and a route is the operator's own setting.
 *
 * @param plain - How a routed request is made. Default: the platform's `fetch`.
 */
export function guardedReach(guarded: Fetch, plain: Fetch = (request) => fetch(request)): Fetch {
  return (request) => (ROUTED.test(request.url) ? plain(request) : guarded(request));
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
