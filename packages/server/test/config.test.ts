// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import {
  ConfigError,
  describeConfig,
  flag,
  integer,
  list,
  origin,
  readConfig,
  text,
} from "../src/index.ts";

const SETTINGS = {
  PORT: integer("the port to listen on", { min: 1, max: 65_535, fallback: 8080 }),
  ORIGIN: origin("the origin clients reach this service at"),
  DATABASE: text("the database file", { fallback: "/data/service.db" }),
  TOKEN: text("the token of the metrics endpoint", { secret: true }),
  PUBLISH_OPEN: flag("whether anyone may publish", true),
  ALLOW: list("address ranges fetched from besides the public ones", text("a range"), []),
  PEERS: list("the origins of the resolvers followed", origin("an origin"), []),
};

const SET = { OIP_T_ORIGIN: "https://resolver.example", OIP_T_TOKEN: "s3cret-token" };

function problemsOf(environment: Record<string, string | undefined>): readonly string[] {
  try {
    readConfig("OIP_T_", SETTINGS, environment);
  } catch (error) {
    if (error instanceof ConfigError) return error.problems;
    throw error;
  }
  return [];
}

describe("a service's configuration", () => {
  it("is read from the variables with the service's prefix, with a default where one is given", () => {
    expect(readConfig("OIP_T_", SETTINGS, SET)).toStrictEqual({
      PORT: 8080,
      ORIGIN: "https://resolver.example",
      DATABASE: "/data/service.db",
      TOKEN: "s3cret-token",
      PUBLISH_OPEN: true,
      ALLOW: [],
      PEERS: [],
    });
    expect(
      readConfig("OIP_T_", SETTINGS, {
        ...SET,
        OIP_T_PORT: "443",
        OIP_T_DATABASE: "./x.db",
        OIP_T_PUBLISH_OPEN: "false",
        OIP_T_ALLOW: "10.0.0.0/8, fd00::/8",
        OIP_T_PEERS: "https://a.example,https://b.example:8443",
        // Another service's, and nobody's.
        OIP_HOST_PORT: "1",
        PATH: "/usr/bin",
      }),
    ).toStrictEqual({
      PORT: 443,
      ORIGIN: "https://resolver.example",
      DATABASE: "./x.db",
      TOKEN: "s3cret-token",
      PUBLISH_OPEN: false,
      ALLOW: ["10.0.0.0/8", "fd00::/8"],
      PEERS: ["https://a.example", "https://b.example:8443"],
    });
  });

  it("says everything that is wrong at once, and the service does not start", () => {
    expect(
      problemsOf({
        OIP_T_PORT: "0",
        OIP_T_PUBLISH_OPEN: "yes",
        OIP_T_PEERS: "https://a.example,http://b.example",
        OIP_T_PROT: "443",
      }),
    ).toStrictEqual([
      'OIP_T_PORT: "0" is not a whole number from 1 to 65535',
      "OIP_T_ORIGIN is not set: the origin clients reach this service at",
      "OIP_T_TOKEN is not set: the token of the metrics endpoint",
      'OIP_T_PUBLISH_OPEN: "yes" is not true or false',
      'OIP_T_PEERS: "https://a.example,http://b.example" is not a list separated by commas, each an HTTPS origin, such as https://host.example',
      "OIP_T_PROT is no setting of this service",
    ]);
    expect(() => readConfig("OIP_T_", SETTINGS, {})).toThrow(
      /the configuration is wrong:\n- OIP_T_ORIGIN/u,
    );
  });

  it("never shows a secret: not in what is wrong, and not in what is logged", () => {
    const problems = problemsOf({ ...SET, OIP_T_TOKEN: "" });
    expect(problems).toStrictEqual(["OIP_T_TOKEN: its value is not text that is not empty"]);
    const config = readConfig("OIP_T_", SETTINGS, SET);
    const described = describeConfig("OIP_T_", SETTINGS, config);
    expect(described).toStrictEqual({
      OIP_T_PORT: "8080",
      OIP_T_ORIGIN: '"https://resolver.example"',
      OIP_T_DATABASE: '"/data/service.db"',
      OIP_T_TOKEN: "(set)",
      OIP_T_PUBLISH_OPEN: "true",
      OIP_T_ALLOW: "[]",
      OIP_T_PEERS: "[]",
    });
    expect(JSON.stringify(described)).not.toContain("s3cret");
    // A list of secrets is a secret.
    const tokens = { TOKENS: list("tokens", text("a token", { secret: true })) };
    expect(
      describeConfig("X_", tokens, readConfig("X_", tokens, { X_TOKENS: "a,b" })),
    ).toStrictEqual({
      X_TOKENS: "(set)",
    });
    try {
      readConfig("X_", tokens, { X_TOKENS: "a,,b" });
      throw new Error("it started");
    } catch (error) {
      expect((error as ConfigError).problems).toStrictEqual([
        "X_TOKENS: its value is not a list separated by commas, each text that is not empty",
      ]);
    }
  });

  it("takes a whole number in its plain form, within its bounds", () => {
    const setting = integer("n", { min: 0, max: 1000 });
    for (const good of ["0", "7", "1000"])
      expect(setting.read(good)).toStrictEqual({ value: Number(good) });
    for (const bad of [
      "",
      " 7",
      "7 ",
      "+7",
      "-1",
      "07",
      "7.0",
      "1e2",
      "0x10",
      "1001",
      "seven",
      "9".repeat(17),
    ]) {
      expect(setting.read(bad), bad).toStrictEqual({ expected: "a whole number from 0 to 1000" });
    }
  });

  it("takes an origin as it is written: HTTPS, a host, perhaps a port, and no more", () => {
    const setting = origin("o");
    for (const good of [
      "https://host.example",
      "https://host.example:8443",
      "https://[2001:db8::1]:8443",
    ]) {
      expect(setting.read(good)).toStrictEqual({ value: good });
    }
    for (const bad of [
      "http://host.example",
      "https://host.example/",
      "https://host.example/path",
      "https://host.example?x",
      "https://user@host.example",
      "https://HOST.example",
      "https://host.example:443",
      "host.example",
      "",
    ]) {
      expect(setting.read(bad), bad).toStrictEqual({
        expected: "an HTTPS origin, such as https://host.example",
      });
    }
  });

  it("takes a flag as true or false, and a setting with no default as one that must be set", () => {
    expect(flag("f").read("true")).toStrictEqual({ value: true });
    expect(flag("f").read("false")).toStrictEqual({ value: false });
    for (const bad of ["", "1", "TRUE", "yes"]) {
      expect(flag("f").read(bad)).toStrictEqual({ expected: "true or false" });
    }
    const required = { ON: flag("whether it is on") };
    expect(() => readConfig("X_", required, {})).toThrow(ConfigError);
    // A default of `false` is a default.
    expect(readConfig("X_", { ON: flag("f", false) }, {})).toStrictEqual({ ON: false });
    expect(
      readConfig("X_", { N: integer("n", { min: 0, max: 9, fallback: 0 }) }, {}),
    ).toStrictEqual({ N: 0 });
  });

  it("reads a setting from its own variable only, and not from one a prototype brings", () => {
    const inherited = Object.create({ X_ON: "true" }) as Record<string, string>;
    expect(readConfig("X_", { ON: flag("f", false) }, inherited)).toStrictEqual({ ON: false });
    // A setting is the service's own: a name such as `constructor` is no setting.
    expect(() => readConfig("X_", { ON: flag("f", false) }, { X_constructor: "x" })).toThrow(
      /X_constructor is no setting/u,
    );
  });
});
