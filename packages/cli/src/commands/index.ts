// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import type { Command } from "../command.ts";
import { demo } from "./demo.ts";
import { init } from "./init.ts";
import { show } from "./show.ts";

/** Every command, in the order the help lists them. */
export const COMMANDS: readonly Command[] = [init, show, demo];
