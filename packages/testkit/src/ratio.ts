// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The cost of one piece of work against another, as a ratio that depends
 * neither on how fast the machine is nor on what else it is doing
 * (ADR-0020).
 *
 * A shared machine does not run at one speed. It slows for seconds at a
 * time, by half and more, when other work arrives on it. Two pieces of work
 * measured one after the other meet different weather, and the ratio of the
 * two says as much about the weather as about the code.
 *
 * So the pieces are run turn about: one sample of each, then one of each
 * again, starting with another piece each turn. A turn takes milliseconds,
 * and what slows one sample of it slows the others. Each turn gives a ratio
 * for each piece, and the middle of a piece's ratios is its answer: a turn
 * that a garbage collection fell into is one turn among many.
 */

/** A piece of work. If it returns a promise, the promise is awaited, and the wait is timed. */
export type Work = () => unknown;

/** How a ratio is measured. */
export interface RatioOptions {
  /** How long the measuring takes, in milliseconds, unless `minTurns` takes longer. Default 2000. */
  readonly budgetMs?: number;
  /** The least turns, however long one takes. Default 15. */
  readonly minTurns?: number;
  /** The most turns. Default 400. */
  readonly maxTurns?: number;
  /**
   * The least one sample lasts, in milliseconds. Work that is faster is run
   * several times for one sample, so that the clock's own cost is small
   * beside it. Default 0.25.
   */
  readonly sampleMs?: number;
  /** How long each piece is run before it is measured, in milliseconds. Default 100. */
  readonly warmupMs?: number;
  /** The clock, in milliseconds. Default: `performance.now`. */
  readonly now?: () => number;
}

/** What was measured. */
export interface Measured<K extends string> {
  /** For each piece of work, the middle of its time over the reference's, turn by turn. */
  readonly ratios: Readonly<Record<K, number>>;
  /** The middle time of one run of the reference, in milliseconds. */
  readonly reference: number;
  /** The middle time of one run of each piece of work, in milliseconds. */
  readonly latencies: Readonly<Record<K, number>>;
  /**
   * The least time of one run of each piece of work, in milliseconds: what
   * a ceiling in milliseconds is compared with, since other work on the
   * machine only ever adds time.
   */
  readonly fastest: Readonly<Record<K, number>>;
  /** How many turns were taken. */
  readonly turns: number;
}

/** The middle of some values: of an even number of them, half-way between the two in the middle. */
export function middle(values: readonly number[]): number {
  const sorted = values.toSorted((a, b) => a - b);
  const half = Math.floor(sorted.length / 2);
  const upper = sorted[half] ?? Number.NaN;
  return sorted.length % 2 === 1 ? upper : ((sorted[half - 1] ?? Number.NaN) + upper) / 2;
}

/** The most runs of a warm-up. */
const MAX_WARMUP_RUNS = 100_000;

const isThenable = (value: unknown): value is PromiseLike<unknown> =>
  typeof (value as { then?: unknown } | null)?.then === "function";

/**
 * What takes one sample of a piece of work: the time of one run, in
 * milliseconds. The piece is warmed up first, and timed to see how many
 * runs make a sample.
 */
async function samplerOf(
  run: Work,
  options: Required<Pick<RatioOptions, "sampleMs" | "warmupMs" | "now">>,
): Promise<() => number | Promise<number>> {
  const { now, sampleMs, warmupMs } = options;
  const started = now();
  // Whether it is awaited is seen once: an await that is not needed would be timed with fast work.
  const first = run();
  const awaited = isThenable(first);
  if (awaited) await first;
  let runs = 1;
  let elapsed = now() - started;
  // Twice at least, and bounded in runs too: a clock that does not move ends no warm-up.
  while (runs < 2 || (elapsed < warmupMs && runs < MAX_WARMUP_RUNS)) {
    if (awaited) await run();
    else run();
    runs++;
    elapsed = now() - started;
  }
  const each = elapsed / runs;
  const batch = each > 0 ? Math.max(1, Math.ceil(sampleMs / each)) : 1;
  if (awaited) {
    return async () => {
      const from = now();
      for (let done = 0; done < batch; done++) await run();
      return (now() - from) / batch;
    };
  }
  return () => {
    const from = now();
    for (let done = 0; done < batch; done++) run();
    return (now() - from) / batch;
  };
}

/**
 * Measures pieces of work against a reference, turn about.
 *
 * @param reference - What the others are measured against.
 * @param work - The pieces of work, each by a name.
 * @returns For each piece, the ratio of its time to the reference's.
 */
export async function ratiosOver<K extends string>(
  reference: Work,
  work: Readonly<Record<K, Work>>,
  options: RatioOptions = {},
): Promise<Measured<K>> {
  const now = options.now ?? (() => performance.now());
  const budgetMs = options.budgetMs ?? 2000;
  const minTurns = Math.max(1, options.minTurns ?? 15);
  const maxTurns = Math.max(minTurns, options.maxTurns ?? 400);
  const sampling = {
    now,
    sampleMs: options.sampleMs ?? 0.25,
    warmupMs: options.warmupMs ?? 100,
  };
  const names = Object.keys(work) as K[];
  const samplers = [await samplerOf(reference, sampling)];
  for (const name of names) samplers.push(await samplerOf(work[name], sampling));
  const pieces = samplers.map((sample) => ({ sample, times: [] as number[] }));
  const started = now();
  let turns = 0;
  while (turns < maxTurns && (turns < minTurns || now() - started < budgetMs)) {
    for (let step = 0; step < pieces.length; step++) {
      // Each turn starts with another piece, so that none is always the one after the slow one.
      const piece = pieces[(step + turns) % pieces.length];
      if (piece !== undefined) piece.times.push(await piece.sample());
    }
    turns++;
  }
  const [of = [], ...others] = pieces.map((piece) => piece.times);
  const ratios = {} as Record<K, number>;
  const latencies = {} as Record<K, number>;
  const fastest = {} as Record<K, number>;
  for (const [index, name] of names.entries()) {
    const taken = others[index] ?? [];
    ratios[name] = middle(taken.map((time, turn) => time / (of[turn] ?? Number.NaN)));
    latencies[name] = middle(taken);
    fastest[name] = Math.min(...taken);
  }
  return { ratios, reference: middle(of), latencies, fastest, turns };
}

/**
 * What was measured, as lines for a log: the reference, and each piece of
 * work with its time and its ratio.
 */
export function describeMeasured<K extends string>(
  title: string,
  referenceName: string,
  measured: Measured<K>,
): string {
  const lines = [
    `${title} (${String(measured.turns)} turns, turn about)`,
    `  ${referenceName}: ${measured.reference.toFixed(4)} ms`,
  ];
  for (const name of Object.keys(measured.ratios) as K[]) {
    lines.push(
      `  ${name}: ${measured.latencies[name].toFixed(4)} ms, ${measured.ratios[name].toFixed(3)} of the reference`,
    );
  }
  return lines.join("\n");
}

/** Writes what was measured to the output of the run, for whoever reads the log of it. */
export function reportMeasured<K extends string>(
  title: string,
  referenceName: string,
  measured: Measured<K>,
): void {
  process.stdout.write(`${describeMeasured(title, referenceName, measured)}\n`);
}
