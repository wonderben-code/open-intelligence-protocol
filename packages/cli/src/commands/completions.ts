// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `oip completions`: a script that teaches a shell the commands and their
 * options, written from the commands themselves so that it cannot fall
 * behind them.
 */

import { type Command, UsageError } from "../command.ts";

/** The options every command takes, as `run.ts` has them. */
const EVERY = ["dir", "json", "get", "help", "version"];

/** A string inside single quotes of a shell. */
const quoted = (text: string): string => `'${text.replaceAll("'", "'\\''")}'`;

/** The script for bash, which zsh also takes through `bashcompinit`. */
function bash(commands: readonly Command[]): string[] {
  const firsts = [...new Set(commands.map(({ name }) => name.split(" ")[0] ?? ""))];
  const seconds = new Map<string, string[]>();
  for (const { name } of commands) {
    const [first = "", second] = name.split(" ");
    if (second !== undefined) seconds.set(first, [...(seconds.get(first) ?? []), second]);
  }
  const flagsOf = (command: Command): string =>
    [...Object.keys(command.flags), ...EVERY].map((flag) => `--${flag}`).join(" ");
  return [
    "_oip() {",
    '  local cur="${COMP_WORDS[COMP_CWORD]}"',
    '  local first="${COMP_WORDS[1]}" second="${COMP_WORDS[2]}"',
    `  local flags="${EVERY.map((flag) => `--${flag}`).join(" ")}"`,
    '  case "$first $second" in',
    ...commands
      .filter(({ name }) => name.includes(" "))
      .map((command) => `    "${command.name}") flags="${flagsOf(command)}" ;;`),
    "    *)",
    '      case "$first" in',
    ...commands
      .filter(({ name }) => !name.includes(" "))
      .map((command) => `        ${command.name}) flags="${flagsOf(command)}" ;;`),
    "      esac ;;",
    "  esac",
    '  if [[ "$cur" == -* ]]; then',
    '    COMPREPLY=($(compgen -W "$flags" -- "$cur"))',
    "  elif [[ $COMP_CWORD -eq 1 ]]; then",
    `    COMPREPLY=($(compgen -W "${firsts.join(" ")}" -- "$cur"))`,
    "  elif [[ $COMP_CWORD -eq 2 ]]; then",
    '    case "$first" in',
    ...[...seconds].map(
      ([first, words]) =>
        `      ${first}) COMPREPLY=($(compgen -W "${words.join(" ")}" -- "$cur")) ;;`,
    ),
    '      *) COMPREPLY=($(compgen -f -- "$cur")) ;;',
    "    esac",
    "  else",
    '    COMPREPLY=($(compgen -f -- "$cur"))',
    "  fi",
    "}",
    "complete -F _oip oip",
  ];
}

/** The script for fish. */
function fish(commands: readonly Command[]): string[] {
  const firsts = [...new Set(commands.map(({ name }) => name.split(" ")[0] ?? ""))];
  const lines = ["complete -c oip -f", ...EVERY.map((flag) => `complete -c oip -l ${flag}`)];
  for (const first of firsts) {
    const own = commands.filter(({ name }) => name.split(" ")[0] === first);
    const [only] = own;
    const summary =
      own.length === 1 && only !== undefined ? only.summary : `${first}: see oip --help`;
    lines.push(`complete -c oip -n __fish_use_subcommand -a ${first} -d ${quoted(summary)}`);
  }
  for (const command of commands) {
    const [first = "", second] = command.name.split(" ");
    const seen =
      second === undefined
        ? `__fish_seen_subcommand_from ${first}`
        : `__fish_seen_subcommand_from ${first}; and __fish_seen_subcommand_from ${second}`;
    if (second !== undefined) {
      lines.push(
        `complete -c oip -n ${quoted(`__fish_seen_subcommand_from ${first}; and not __fish_seen_subcommand_from ${second}`)} -a ${second} -d ${quoted(command.summary)}`,
      );
    }
    for (const [flag, { type, describes }] of Object.entries(command.flags)) {
      lines.push(
        `complete -c oip -n ${quoted(seen)} -l ${flag}${type === "string" ? " -r" : ""} -d ${quoted(describes)}`,
      );
    }
  }
  return lines;
}

/** The command, made from the commands it completes: `commands/index.ts` gives them. */
export function completionsOf(commands: () => readonly Command[]): Command {
  return {
    name: "completions",
    summary: "Prints a script that teaches a shell the commands and their options",
    positionals: "<shell>",
    flags: {},
    notes: [
      "The shell is bash, zsh or fish. Load what this prints when the shell starts:",
      "  bash:  source <(oip completions bash)",
      "  zsh:   source <(oip completions zsh)",
      "  fish:  oip completions fish | source",
    ],
    example: "oip completions bash",
    run(_context, given) {
      const [shell, ...more] = given.positionals;
      const all = commands();
      const scripts: Readonly<Record<string, () => string[]>> = {
        bash: () => [
          "# oip: completion for bash. Load it with: source <(oip completions bash)",
          ...bash(all),
        ],
        zsh: () => [
          "# oip: completion for zsh. Load it with: source <(oip completions zsh)",
          "autoload -U +X compinit && compinit",
          "autoload -U +X bashcompinit && bashcompinit",
          ...bash(all),
        ],
        fish: () => [
          "# oip: completion for fish. Load it with: oip completions fish | source",
          ...fish(all),
        ],
      };
      const script =
        shell === undefined
          ? undefined
          : Object.hasOwn(scripts, shell)
            ? scripts[shell]
            : undefined;
      if (script === undefined || more.length > 0) {
        return Promise.reject(new UsageError("completions takes one shell: bash, zsh or fish"));
      }
      const lines = script();
      return Promise.resolve({ lines, json: { shell, script: `${lines.join("\n")}\n` } });
    },
  };
}
