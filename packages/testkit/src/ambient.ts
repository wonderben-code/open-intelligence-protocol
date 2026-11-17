// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A run-time check of purity. The lint rules forbid a pure package from
 * naming the clock or a source of randomness; this shows that it does not
 * reach them by any name, by replacing them with traps while its code runs.
 */

/**
 * Runs `run` with the clock and the sources of randomness replaced by traps,
 * and throws if any was reached. `run` must be synchronous and should only
 * call the code under test: assertions belong after it returns, because a
 * test runner reads the clock too.
 *
 * It reports a trap that was reached even if the code under test caught the
 * exception the trap threw.
 */
export function withAmbientTrapped<T>(run: () => T): T {
  const reached: string[] = [];
  const trap = (name: string) => (): never => {
    reached.push(name);
    throw new Error(`pure code reached ${name}`);
  };

  const RealDate = Date;
  const realRandom = Math.random.bind(Math);
  const realNow = performance.now.bind(performance);
  const realGetRandomValues = crypto.getRandomValues.bind(crypto);
  const realRandomUUID = crypto.randomUUID.bind(crypto);

  globalThis.Date = new Proxy(RealDate, {
    construct(target, args: unknown[]) {
      if (args.length === 0) trap("new Date()")();
      return Reflect.construct(target, args) as object;
    },
    apply: trap("Date()"),
    get(target, key) {
      return key === "now" ? trap("Date.now()") : (Reflect.get(target, key) as unknown);
    },
  });
  Math.random = trap("Math.random()");
  performance.now = trap("performance.now()");
  crypto.getRandomValues = trap("crypto.getRandomValues()");
  crypto.randomUUID = trap("crypto.randomUUID()");

  try {
    return run();
  } finally {
    globalThis.Date = RealDate;
    Math.random = realRandom;
    performance.now = realNow;
    crypto.getRandomValues = realGetRandomValues;
    crypto.randomUUID = realRandomUUID;
    if (reached.length > 0) {
      // Deliberately replaces whatever `run` threw: reaching a trap is the finding.
      // eslint-disable-next-line no-unsafe-finally
      throw new Error(`pure code reached ambient state: ${[...new Set(reached)].join(", ")}`);
    }
  }
}
