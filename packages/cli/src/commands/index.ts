// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import type { Command } from "../command.ts";
import { collectiveCreate, collectiveSign } from "./collective.ts";
import { completionsOf } from "./completions.ts";
import { commit, intent, offer, receipt, status } from "./deal.ts";
import { delegate, revoke } from "./delegation.ts";
import { demo } from "./demo.ts";
import { doctor } from "./doctor.ts";
import { find } from "./find.ts";
import { addKey, fork, revokeKey, rotate } from "./identity.ts";
import { inbox } from "./inbox.ts";
import { init } from "./init.ts";
import { keysBackup, keysRestore } from "./keys.ts";
import { publishLocation, publishProfile, publishRecord } from "./publish.ts";
import { resolve } from "./resolve.ts";
import { send } from "./send.ts";
import { show } from "./show.ts";
import { verify } from "./verify.ts";

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
  intent,
  offer,
  commit,
  receipt,
  status,
  delegate,
  revoke,
  collectiveCreate,
  collectiveSign,
  verify,
  keysBackup,
  keysRestore,
  doctor,
  demo,
  completionsOf(() => COMMANDS),
];
