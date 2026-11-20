// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import type { Command } from "../command.ts";
import { demo } from "./demo.ts";
import { find } from "./find.ts";
import { addKey, fork, revokeKey, rotate } from "./identity.ts";
import { inbox } from "./inbox.ts";
import { init } from "./init.ts";
import { publishLocation, publishProfile, publishRecord } from "./publish.ts";
import { resolve } from "./resolve.ts";
import { send } from "./send.ts";
import { show } from "./show.ts";

/** Every command, in the order the help lists them. */
export const COMMANDS: readonly Command[] = [
  init,
  show,
  rotate,
  addKey,
  revokeKey,
  fork,
  publishProfile,
  publishLocation,
  publishRecord,
  resolve,
  find,
  send,
  inbox,
  demo,
];
