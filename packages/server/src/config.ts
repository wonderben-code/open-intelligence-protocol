// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A service's configuration, read from its environment when it starts and
 * checked whole (BUILD.md, M5). A service that is misconfigured does not
 * start: it says every setting that is wrong, and why, and stops. It does
 * not run with a default in place of a value it could not read, and a
 * setting it does not know is a mistake too, since it is most often a
 * known one misspelt.
 *
 * A setting may be a secret. Its value is never part of a message or of
 * the summary a service logs (CLAUDE.md, "Secrets").
 */

/** One setting: where it is read from and how. */
export interface Setting<T> {
  /** For the operator: what the setting is. */
  readonly doc: string;
  /** The value when the variable is not set. A setting without one must be set. */
  readonly fallback?: T;
  /** Whether the value must never be shown. */
  readonly secret?: boolean;
  /**
   * Reads the variable's text.
   *
   * @returns The value, or the reason it is none, as a sentence fragment
   *   that follows "is not" (for example "a whole number from 1 to 65535").
   */
  readonly read: (text: string) => { readonly value: T } | { readonly expected: string };
}

/** The settings of a service, each under the name of the variable after the service's prefix. */
export type Settings = Readonly<Record<string, Setting<unknown>>>;

/** The configuration that a set of settings gives. */
export type ConfigOf<S extends Settings> = {
  readonly [K in keyof S]: S[K] extends Setting<infer T> ? T : never;
};

/** A configuration that a service cannot start with. */
export class ConfigError extends Error {
  /** Each thing that is wrong, one sentence for each. */
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super(`the configuration is wrong:\n${problems.map((problem) => `- ${problem}`).join("\n")}`);
    this.name = "ConfigError";
    this.problems = problems;
  }
}

/** A whole number within bounds. */
export function integer(
  doc: string,
  bounds: { readonly min: number; readonly max: number; readonly fallback?: number },
): Setting<number> {
  const expected = `a whole number from ${bounds.min} to ${bounds.max}`;
  return {
    doc,
    ...(bounds.fallback === undefined ? {} : { fallback: bounds.fallback }),
    read: (text) => {
      const value = /^(?:0|[1-9]\d{0,15})$/u.test(text) ? Number(text) : Number.NaN;
      return Number.isSafeInteger(value) && value >= bounds.min && value <= bounds.max
        ? { value }
        : { expected };
    },
  };
}

/** `true` or `false`. */
export function flag(doc: string, fallback?: boolean): Setting<boolean> {
  return {
    doc,
    ...(fallback === undefined ? {} : { fallback }),
    read: (text) =>
      text === "true" || text === "false"
        ? { value: text === "true" }
        : { expected: "true or false" },
  };
}

/** Text that is not empty. */
export function text(
  doc: string,
  options: { readonly fallback?: string; readonly secret?: boolean } = {},
): Setting<string> {
  return {
    doc,
    ...(options.fallback === undefined ? {} : { fallback: options.fallback }),
    ...(options.secret === true ? { secret: true } : {}),
    read: (value) => (value === "" ? { expected: "text that is not empty" } : { value }),
  };
}

/** One of a few words. */
export function choice<T extends string>(
  doc: string,
  words: readonly [T, ...T[]],
  fallback?: T,
): Setting<T> {
  return {
    doc,
    ...(fallback === undefined ? {} : { fallback }),
    read: (value) => {
      const word = words.find((known) => known === value);
      return word === undefined ? { expected: `one of ${words.join(", ")}` } : { value: word };
    },
  };
}

/**
 * An HTTPS origin: the scheme, the host and perhaps a port, and nothing
 * after them. It is what a service calls itself, and what a `Hello` must
 * name (Layer 1, 13.3).
 */
export function origin(doc: string, fallback?: string): Setting<string> {
  const expected = "an HTTPS origin, such as https://host.example";
  return {
    doc,
    ...(fallback === undefined ? {} : { fallback }),
    read: (value) => {
      let url: URL;
      try {
        url = new URL(value);
      } catch {
        return { expected };
      }
      // As it was written: an origin the URL parser had to tidy is not what a client compares with.
      return url.protocol === "https:" && url.origin === value ? { value } : { expected };
    },
  };
}

/** A list separated by commas, each item read by `item`. An empty text is an empty list. */
export function list<T>(
  doc: string,
  item: Setting<T>,
  fallback?: readonly T[],
): Setting<readonly T[]> {
  return {
    doc,
    ...(fallback === undefined ? {} : { fallback }),
    ...(item.secret === true ? { secret: true } : {}),
    read: (value) => {
      const values: T[] = [];
      for (const part of value === "" ? [] : value.split(",")) {
        const read = item.read(part.trim());
        if ("expected" in read)
          return { expected: `a list separated by commas, each ${read.expected}` };
        values.push(read.value);
      }
      return { value: values };
    },
  };
}

/**
 * Reads a service's configuration from its environment.
 *
 * @param prefix - What every variable of the service starts with, such as `OIP_HOST_`.
 * @param settings - The settings, each named by what follows the prefix.
 * @param environment - The environment: `process.env`, or a test's own.
 * @throws ConfigError with everything that is wrong, if anything is: a
 *   value that is none, a setting that must be set and is not, and a
 *   variable with the prefix that is no setting.
 */
export function readConfig<S extends Settings>(
  prefix: string,
  settings: S,
  environment: Readonly<Record<string, string | undefined>>,
): ConfigOf<S> {
  const problems: string[] = [];
  const config: Record<string, unknown> = {};
  for (const [name, setting] of Object.entries(settings)) {
    // The environment's own variable: nothing a prototype brings is a setting.
    const given = Object.hasOwn(environment, prefix + name)
      ? environment[prefix + name]
      : undefined;
    if (given === undefined) {
      if (Object.hasOwn(setting, "fallback")) config[name] = setting.fallback;
      else problems.push(`${prefix}${name} is not set: ${setting.doc}`);
      continue;
    }
    const read = setting.read(given);
    if ("expected" in read) {
      const shown = setting.secret === true ? "its value" : JSON.stringify(given);
      problems.push(`${prefix}${name}: ${shown} is not ${read.expected}`);
    } else {
      config[name] = read.value;
    }
  }
  for (const variable of Object.keys(environment).sort()) {
    if (variable.startsWith(prefix) && !Object.hasOwn(settings, variable.slice(prefix.length))) {
      problems.push(`${variable} is no setting of this service`);
    }
  }
  if (problems.length > 0) throw new ConfigError(problems);
  return config as ConfigOf<S>;
}

/**
 * A configuration as a service may log it when it starts: each setting by
 * its variable, a secret as whether it is set.
 */
export function describeConfig<S extends Settings>(
  prefix: string,
  settings: S,
  config: ConfigOf<S>,
): Record<string, string> {
  const described: Record<string, string> = {};
  for (const [name, setting] of Object.entries(settings)) {
    const value = (config as Record<string, unknown>)[name];
    described[prefix + name] = setting.secret === true ? "(set)" : JSON.stringify(value);
  }
  return described;
}
