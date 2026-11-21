// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A service's metrics, in the text format a Prometheus server reads
 * (BUILD.md, M5): counters, gauges and histograms, each with labels.
 *
 * A label's values are a small set the service chose: a route as the
 * service names it, a problem code, a status. Never a path as it was
 * asked for or a mind's address: each new value is a new series, kept for
 * as long as the service runs, and a stranger would choose them. As a
 * second line, a metric holds a bounded number of series, and what is
 * beyond the bound is counted under one series that says so.
 */

/** The values of a metric's labels, by label name. */
export type Labels = Readonly<Record<string, string>>;

/** A value that only rises: requests, failures. */
export interface Counter {
  /** Adds to the series with these labels. One, if no amount is given. */
  add(labels?: Labels, amount?: number): void;
}

/** A value that goes up and down: open sockets, the size of a queue. */
export interface Gauge {
  set(value: number, labels?: Labels): void;
}

/** How values are spread: durations, sizes. */
export interface Histogram {
  observe(value: number, labels?: Labels): void;
}

/** The most series one metric holds. */
export const MAX_SERIES = 200;

/** Upper bounds for durations in seconds, from a millisecond to ten seconds. */
export const DURATION_BUCKETS: readonly number[] = [
  0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
];

const NAME = /^[a-z][a-z0-9_]*$/u;

type Kind = "counter" | "gauge" | "histogram";

interface Series {
  readonly labels: Labels;
  value: number;
  /** For a histogram: how many values fell at or under each bound, and how many there were. */
  readonly counts: number[];
  count: number;
}

interface Metric {
  readonly kind: Kind;
  readonly help: string;
  readonly labelNames: readonly string[];
  readonly buckets: readonly number[];
  readonly series: Map<string, Series>;
}

/** A label's value as the format writes it. */
function quoted(value: string): string {
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"').replaceAll("\n", "\\n")}"`;
}

function written(labels: Labels, more?: readonly [string, string]): string {
  const pairs = [...Object.entries(labels), ...(more === undefined ? [] : [more])];
  return pairs.length === 0
    ? ""
    : `{${pairs.map(([name, value]) => `${name}=${quoted(value)}`).join(",")}}`;
}

/** A number as the format writes it. */
function number(value: number): string {
  if (Number.isNaN(value)) return "NaN";
  if (value === Number.POSITIVE_INFINITY) return "+Inf";
  if (value === Number.NEGATIVE_INFINITY) return "-Inf";
  return String(value);
}

/** The metrics of one service. */
export class Metrics {
  readonly #metrics = new Map<string, Metric>();

  #register(
    name: string,
    kind: Kind,
    help: string,
    labelNames: readonly string[],
    buckets: readonly number[] = [],
  ): Metric {
    if (!NAME.test(name) || labelNames.some((label) => !NAME.test(label) || label === "le")) {
      throw new TypeError("a metric's name and its labels are lower-case letters, digits and _");
    }
    if (this.#metrics.has(name)) throw new TypeError(`the metric ${name} is registered twice`);
    if (
      buckets.some(
        (bound, at) => !Number.isFinite(bound) || bound <= (buckets[at - 1] ?? -Infinity),
      )
    ) {
      throw new TypeError("a histogram's bounds are numbers, each greater than the last");
    }
    const metric: Metric = { kind, help, labelNames, buckets, series: new Map() };
    this.#metrics.set(name, metric);
    return metric;
  }

  /** The series of a metric for some labels: the one held, or a new one while there is room. */
  #series(metric: Metric, given: Labels = {}): Series {
    // Every label of the metric, in its order, and no other: one given that is not the
    // metric's is a mistake in the service, and is not written.
    let labels: Record<string, string> = {};
    for (const name of metric.labelNames) labels[name] = given[name] ?? "";
    let key = JSON.stringify(Object.values(labels));
    let series = metric.series.get(key);
    if (series === undefined && metric.series.size >= MAX_SERIES) {
      labels = Object.fromEntries(metric.labelNames.map((name) => [name, "(other)"]));
      key = JSON.stringify(Object.values(labels));
      series = metric.series.get(key);
    }
    if (series === undefined) {
      series = { labels, value: 0, counts: metric.buckets.map(() => 0), count: 0 };
      metric.series.set(key, series);
    }
    return series;
  }

  /** Registers a counter. */
  counter(name: string, help: string, labelNames: readonly string[] = []): Counter {
    const metric = this.#register(name, "counter", help, labelNames);
    return {
      add: (labels, amount = 1) => {
        if (!Number.isFinite(amount) || amount < 0) throw new TypeError("a counter only rises");
        this.#series(metric, labels).value += amount;
      },
    };
  }

  /** Registers a gauge. */
  gauge(name: string, help: string, labelNames: readonly string[] = []): Gauge {
    const metric = this.#register(name, "gauge", help, labelNames);
    return {
      set: (value, labels) => {
        this.#series(metric, labels).value = value;
      },
    };
  }

  /** Registers a histogram, with the upper bounds of its buckets. */
  histogram(
    name: string,
    help: string,
    labelNames: readonly string[] = [],
    buckets: readonly number[] = DURATION_BUCKETS,
  ): Histogram {
    const metric = this.#register(name, "histogram", help, labelNames, buckets);
    return {
      observe: (value, labels) => {
        if (Number.isNaN(value)) return;
        const series = this.#series(metric, labels);
        series.value += value;
        series.count++;
        metric.buckets.forEach((bound, at) => {
          if (value <= bound) series.counts[at] = (series.counts[at] ?? 0) + 1;
        });
      },
    };
  }

  /** Everything, in the text format (version 0.0.4), as `/metrics` serves it. */
  render(): string {
    const lines: string[] = [];
    for (const [name, metric] of this.#metrics) {
      lines.push(`# HELP ${name} ${metric.help.replaceAll("\\", "\\\\").replaceAll("\n", "\\n")}`);
      lines.push(`# TYPE ${name} ${metric.kind}`);
      for (const series of metric.series.values()) {
        if (metric.kind !== "histogram") {
          lines.push(`${name}${written(series.labels)} ${number(series.value)}`);
          continue;
        }
        metric.buckets.forEach((bound, at) => {
          lines.push(
            `${name}_bucket${written(series.labels, ["le", number(bound)])} ${series.counts[at] ?? 0}`,
          );
        });
        lines.push(`${name}_bucket${written(series.labels, ["le", "+Inf"])} ${series.count}`);
        lines.push(`${name}_sum${written(series.labels)} ${number(series.value)}`);
        lines.push(`${name}_count${written(series.labels)} ${series.count}`);
      }
    }
    return `${lines.join("\n")}\n`;
  }
}

/** The media type of the text format. */
export const METRICS_MEDIA_TYPE = "text/plain; version=0.0.4; charset=utf-8";
