// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The checks of a signed request (Layer 1, 13.3), which are the same
 * wherever an implementation asks for one: publication to a resolver that
 * requires it, and a mind's own requests to its host.
 */

import type { WireAnswer, WireAsking, WireClient } from "./client.ts";
import { describe, expectProblem } from "./client.ts";
import type { WireMind } from "./minds.ts";
import type { Recorder } from "./report.ts";
import { expect } from "./report.ts";

/** A request that the implementation takes when it is signed as 13.3 asks. */
export interface SignedRequest {
  readonly method: string;
  readonly path: string;
  /** The body, if the request has one. */
  readonly body?: unknown;
  /** The mind whose signature the implementation accepts for it. */
  readonly signer: WireMind;
}

/** Where the checks of a signed request are made. */
export interface AuthenticationChecks {
  /** What the checks are called: `<name>-unsigned`, and so on. */
  readonly name: string;
  /** What is asked, in words: "draining a mailbox". */
  readonly what: string;
  /** The clause that asks for the request to be signed, besides 13.3. */
  readonly clause: string;
  /**
   * A request that is taken when signed. Each call gives one that can be
   * sent whatever became of the last.
   */
  readonly request: () => SignedRequest | Promise<SignedRequest>;
  /** Whether an answer says the request was taken. */
  readonly taken: (answer: WireAnswer) => boolean;
  /** Whether the request has a body, which its signature then covers. */
  readonly withBody: boolean;
  /** A mind whose log the implementation has never been shown. */
  readonly stranger: WireMind;
}

const SECOND = 1_000_000_000n;

/** Runs the checks of 13.3 on one kind of request. */
export async function authenticationChecks(
  suite: Recorder,
  client: WireClient,
  checks: AuthenticationChecks,
): Promise<void> {
  const { name, what, taken } = checks;
  const clauses = ["L1 13.3", checks.clause] as const;
  /** Asks once more, signed by the mind whose request it is, by a stranger or by nobody. */
  const asked = async (
    by: "mind" | "stranger" | "nobody",
    signature?: WireAsking["signature"],
  ): Promise<WireAnswer> => {
    const { method, path, body, signer } = await checks.request();
    return client.ask(method, path, {
      ...(body === undefined ? {} : { body }),
      ...(by === "nobody" ? {} : { signedBy: by === "mind" ? signer : checks.stranger }),
      ...(signature === undefined ? {} : { signature }),
    });
  };

  await suite.check(
    { id: `${name}-signed`, clauses, title: `${what}, signed by the mind, is taken` },
    async () => {
      const answer = await asked("mind");
      expect(taken(answer), `a request signed as 13.3 asks is taken; got ${describe(answer)}`);
    },
  );

  await suite.check(
    { id: `${name}-unsigned`, clauses, title: `${what} without a signature is refused` },
    async () => {
      expectProblem(await asked("nobody"), "unauthorised", "a request with no signature");
    },
  );

  await suite.check(
    { id: `${name}-replayed`, clauses, title: `${what} with a signature seen before is refused` },
    async () => {
      const { method, path, body, signer } = await checks.request();
      const prepared = await client.prepare(method, path, {
        ...(body === undefined ? {} : { body }),
        signedBy: signer,
      });
      const first = await client.send(prepared);
      expect(taken(first), `a request signed as 13.3 asks is taken; got ${describe(first)}`);
      expectProblem(await client.send(prepared), "unauthorised", "the same signed request again");
    },
  );

  await suite.check(
    {
      id: `${name}-expired`,
      clauses,
      title: `${what} with a signature made more than 300 seconds ago is refused`,
    },
    async () => {
      const created = client.now() - 900n * SECOND;
      expectProblem(
        await asked("mind", { created, expires: created + 300n * SECOND }),
        "unauthorised",
        "a signature that expired 600 seconds ago",
      );
    },
  );

  await suite.check(
    {
      id: `${name}-ahead`,
      clauses,
      title: `${what} with a signature made more than 300 seconds ahead of the clock is refused`,
    },
    async () => {
      const created = client.now() + 900n * SECOND;
      expectProblem(
        await asked("mind", { created, expires: created + 300n * SECOND }),
        "unauthorised",
        "a signature made 900 seconds in the future",
      );
    },
  );

  await suite.check(
    {
      id: `${name}-unknown-key`,
      clauses,
      title: `${what} signed with a key of no log the implementation holds is refused`,
    },
    async () => {
      expectProblem(
        await asked("stranger"),
        "unauthorised",
        "a signature by a mind the implementation has never been shown",
      );
    },
  );

  if (!checks.withBody) return;
  await suite.check(
    {
      id: `${name}-digest`,
      clauses,
      title: `${what} whose body is not the one its signature covers is refused`,
    },
    async () => {
      const { method, path, body, signer } = await checks.request();
      const prepared = await client.prepare(method, path, { body, signedBy: signer });
      // The same request with one more byte of body: the digest that was signed is of another.
      const other = new Uint8Array((prepared.body?.length ?? 0) + 1).fill(0x20);
      other.set(prepared.body ?? new Uint8Array(0));
      expectProblem(
        await client.send({ ...prepared, body: other }),
        "unauthorised",
        "a body other than the one Content-Digest names",
      );
    },
  );
}
