// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * How long a test, and a hook that sets one up, may run before it is taken
 * for hung.
 *
 * A timeout is there to end what will never end. It is not a budget: the
 * benchmarks hold the budgets (BUILD.md, Section 3.8). The tests run on
 * machines of every speed, many files at once, with coverage, and under
 * mutation testing. A test that takes four seconds alone has taken more than
 * sixty beside the others on a shared runner, and failed a run in which
 * nothing was wrong. A hook that starts a service has ten seconds by
 * default, which a busy machine does not always give it.
 */
export const testTimeouts = { testTimeout: 300_000, hookTimeout: 300_000 } as const;
