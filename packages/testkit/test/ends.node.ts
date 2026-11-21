// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** A script that ends as its argument says, for the tests of `inNode`. */

const [how] = process.argv.slice(2);

if (how === "well") {
  process.stdout.write(JSON.stringify({ ended: "well" }));
} else if (how === "flags") {
  // How the engine was started: what `inNode` asked of it.
  process.stdout.write(JSON.stringify({ flags: process.execArgv }));
} else if (how === "badly") {
  process.stderr.write("the first line of what went wrong\n");
  process.stderr.write("and the last\n");
  process.exitCode = 3;
} else if (how === "silently") {
  process.exitCode = 1;
} else if (how === "killed") {
  process.kill(process.pid, "SIGKILL");
} else {
  // It never ends: whoever started it stops it.
  setInterval(() => undefined, 1000);
}
