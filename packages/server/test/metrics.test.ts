// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { MAX_SERIES, Metrics } from "../src/index.ts";

describe("a service's metrics", () => {
  it("are written in the text format: a counter, a gauge and a histogram", () => {
    const metrics = new Metrics();
    const requests = metrics.counter("oip_requests_total", "Requests answered.", [
      "route",
      "status",
    ]);
    const sockets = metrics.gauge("oip_sockets", "Sockets open.");
    const seconds = metrics.histogram(
      "oip_request_seconds",
      "How long a request took.",
      ["route"],
      [0.1, 1],
    );
    requests.add({ route: "/inbox", status: "202" });
    requests.add({ route: "/inbox", status: "202" }, 2);
    requests.add({ route: "/inbox", status: "400" });
    sockets.set(3);
    sockets.set(2);
    for (const value of [0.05, 0.1, 0.5, 2]) seconds.observe(value, { route: "/inbox" });
    expect(metrics.render()).toBe(
      [
        "# HELP oip_requests_total Requests answered.",
        "# TYPE oip_requests_total counter",
        'oip_requests_total{route="/inbox",status="202"} 3',
        'oip_requests_total{route="/inbox",status="400"} 1',
        "# HELP oip_sockets Sockets open.",
        "# TYPE oip_sockets gauge",
        "oip_sockets 2",
        "# HELP oip_request_seconds How long a request took.",
        "# TYPE oip_request_seconds histogram",
        'oip_request_seconds_bucket{route="/inbox",le="0.1"} 2',
        'oip_request_seconds_bucket{route="/inbox",le="1"} 3',
        'oip_request_seconds_bucket{route="/inbox",le="+Inf"} 4',
        'oip_request_seconds_sum{route="/inbox"} 2.65',
        'oip_request_seconds_count{route="/inbox"} 4',
        "",
      ].join("\n"),
    );
  });

  it("writes a label's value so that it cannot end its line or its quotes", () => {
    const metrics = new Metrics();
    metrics.counter("oip_odd_total", "Odd\nhelp \\ text.", ["what"]).add({ what: 'a "b"\n\\c' });
    expect(metrics.render()).toBe(
      [
        "# HELP oip_odd_total Odd\\nhelp \\\\ text.",
        "# TYPE oip_odd_total counter",
        'oip_odd_total{what="a \\"b\\"\\n\\\\c"} 1',
        "",
      ].join("\n"),
    );
  });

  it("has the labels it was registered with, each one, and no other", () => {
    const metrics = new Metrics();
    const counter = metrics.counter("oip_x_total", "X.", ["route", "status"]);
    counter.add({ status: "200", route: "/a" });
    counter.add({ route: "/a" });
    counter.add({ route: "/a", status: "200", mind: "oip:mind:someone" });
    counter.add();
    expect(metrics.render().split("\n").slice(2, -1)).toStrictEqual([
      'oip_x_total{route="/a",status="200"} 2',
      'oip_x_total{route="/a",status=""} 1',
      'oip_x_total{route="",status=""} 1',
    ]);
  });

  it("holds a bounded number of series, and counts the rest under one that says so", () => {
    const metrics = new Metrics();
    const counter = metrics.counter("oip_y_total", "Y.", ["who"]);
    for (let n = 0; n < MAX_SERIES + 50; n++) counter.add({ who: `stranger-${n}` });
    // One held before the bound was reached still counts as itself.
    counter.add({ who: "stranger-0" });
    const lines = metrics.render().split("\n").slice(2, -1);
    expect(lines).toHaveLength(MAX_SERIES + 1);
    expect(lines[0]).toBe('oip_y_total{who="stranger-0"} 2');
    expect(lines.at(-1)).toBe('oip_y_total{who="(other)"} 50');
  });

  it("spreads values over its buckets by their upper bounds, and leaves out what is no number", () => {
    const metrics = new Metrics();
    const sizes = metrics.histogram("oip_bytes", "Sizes.", [], [10, 100]);
    for (const value of [0, 10, 10.5, 100, 101, Number.NaN, Number.POSITIVE_INFINITY])
      sizes.observe(value);
    expect(metrics.render().split("\n").slice(2, -1)).toStrictEqual([
      'oip_bytes_bucket{le="10"} 2',
      'oip_bytes_bucket{le="100"} 4',
      'oip_bytes_bucket{le="+Inf"} 6',
      "oip_bytes_sum +Inf",
      "oip_bytes_count 6",
    ]);
    const durations = new Metrics();
    durations.histogram("oip_seconds", "Durations.").observe(0.003);
    expect(durations.render()).toContain('oip_seconds_bucket{le="0.005"} 1');
    expect(durations.render()).toContain('oip_seconds_bucket{le="0.0025"} 0');
  });

  it("writes a gauge as it stands, whatever number it is", () => {
    const metrics = new Metrics();
    const gauge = metrics.gauge("oip_g", "G.", ["k"]);
    gauge.set(-1.5, { k: "a" });
    gauge.set(Number.NaN, { k: "b" });
    gauge.set(Number.NEGATIVE_INFINITY, { k: "c" });
    expect(metrics.render().split("\n").slice(2, -1)).toStrictEqual([
      'oip_g{k="a"} -1.5',
      'oip_g{k="b"} NaN',
      'oip_g{k="c"} -Inf',
    ]);
  });

  it("takes names of lower-case letters, digits and _, once each, and a counter that only rises", () => {
    const metrics = new Metrics();
    for (const name of ["", "Requests", "1x", "a-b", "a b", "a{b}"]) {
      expect(() => metrics.counter(name, "h"), name).toThrow(TypeError);
      expect(() => metrics.counter("oip_ok_total", "h", [name]), name).toThrow(TypeError);
    }
    // `le` is the histogram's own label.
    expect(() => metrics.histogram("oip_h", "h", ["le"])).toThrow(TypeError);
    metrics.counter("oip_once_total", "h");
    expect(() => metrics.gauge("oip_once_total", "h")).toThrow(/registered twice/u);
    for (const bounds of [[1, 1], [2, 1], [Number.NaN], [1, Number.POSITIVE_INFINITY]]) {
      expect(() =>
        metrics.histogram(`oip_b${bounds.length}_${String(bounds[0]).length}`, "h", [], bounds),
      ).toThrow(TypeError);
    }
    const counter = metrics.counter("oip_up_total", "h");
    for (const amount of [-1, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => counter.add({}, amount)).toThrow(TypeError);
    }
    counter.add({}, 0);
    counter.add({}, 0.5);
    expect(metrics.render()).toContain("oip_up_total 0.5");
    expect(new Metrics().render()).toBe("\n");
  });
});
