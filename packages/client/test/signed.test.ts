// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { formatKeyRef, utf8 } from "@oip/core";
import { LogBook } from "@oip/identity";
import { RequestNonces, verifyRequest } from "@oip/net";
import { clause } from "@oip/testkit";
import { at, KeyMind, LATER, witness } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import { signedAsking } from "../src/signed.ts";
import type { Asking } from "../src/transport.ts";

const ada = new KeyMind("ada");
const key = {
  keyRef: formatKeyRef(ada.address, ada.versionId(), ada.operational().publicKey),
  signer: ada.operational(),
};
const book = new LogBook(witness([ada.events]));
book.hold(ada.events, LATER);

/** Randomness that counts: each nonce is another, and a test can say which. */
function counting() {
  let next = 0;
  return { bytes: (length: number) => new Uint8Array(length).fill(++next) };
}

/** What a service makes of a request, at a time. */
const judged = (asking: Asking, seconds: number, nonces = new RequestNonces()) =>
  verifyRequest(
    {
      method: asking.method,
      url: asking.url,
      headers: [...(asking.headers ?? [])],
      ...(asking.body === undefined ? {} : { body: asking.body.bytes }),
    },
    { now: at(seconds), view: book, nonces },
  );

describe(`${clause("L1 13.3")} a request a mind signs`, () => {
  const put: Asking = {
    method: "PUT",
    url: "https://host.example/oip/v1/minds/m",
    body: { bytes: utf8('{"oip":"1"}'), mediaType: "application/oip+json" },
  };

  it("is one a service takes as the mind's: with a body, and without", async () => {
    const signed = await signedAsking(put, key, at(100), counting());
    expect(signed.headers?.map(([name]) => name)).toStrictEqual([
      "Content-Digest",
      "Signature-Input",
      "Signature",
    ]);
    const taken = judged(signed, 100);
    expect(taken.ok && taken.value.mind).toBe(ada.address);
    const get: Asking = { method: "GET", url: "https://host.example/oip/v1/minds/m/mailbox" };
    const asked = await signedAsking(get, key, at(100), counting());
    expect(asked.headers?.map(([name]) => name)).toStrictEqual(["Signature-Input", "Signature"]);
    expect(judged(asked, 100).ok).toBe(true);
    // The headers a request had stay, before those of the signature.
    const more = await signedAsking(
      { ...get, headers: [["x-request", "1"]] },
      key,
      at(100),
      counting(),
    );
    expect(more.headers?.[0]).toStrictEqual(["x-request", "1"]);
  });

  it("is signed at the whole second, is good for 300 seconds, and has a nonce of its own", async () => {
    const randomness = counting();
    const first = await signedAsking(put, key, at(100) + 999_999_999n, randomness);
    const second = await signedAsking(put, key, at(100) + 999_999_999n, randomness);
    const input = (asking: Asking): string =>
      asking.headers?.find(([name]) => name === "Signature-Input")?.[1] ?? "";
    const made = Number(at(100) / 1_000_000_000n);
    expect(input(first)).toContain(`created=${String(made)};expires=${String(made + 300)};`);
    // Sixteen bytes of 1, and then of 2, in base64url.
    expect(input(first)).toContain('nonce="AQEBAQEBAQEBAQEBAQEBAQ"');
    expect(input(second)).toContain('nonce="AgICAgICAgICAgICAgICAg"');
    // A service takes each once, and for 300 seconds.
    const nonces = new RequestNonces();
    expect(judged(first, 400, nonces).ok).toBe(true);
    expect(judged(first, 400, nonces).ok).toBe(false);
    expect(judged(second, 400, nonces).ok).toBe(true);
    expect(judged(second, 401).ok).toBe(false);
  });

  it("is not made with randomness that does not give what was asked", async () => {
    for (const bytes of [() => new Uint8Array(3), () => "sixteen bytes!!!" as never]) {
      await expect(signedAsking(put, key, at(100), { bytes })).rejects.toThrow(
        /did not give what was asked/u,
      );
    }
  });
});
