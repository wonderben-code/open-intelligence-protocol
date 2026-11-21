// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0
// expect: pure-no-node-builtins
import { readFileSync } from "node:fs";

export const read = readFileSync;
