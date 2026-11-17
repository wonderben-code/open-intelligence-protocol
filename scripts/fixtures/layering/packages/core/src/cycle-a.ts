// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0
// expect: no-circular
import { b } from "./cycle-b.ts";

export const a: string = b;
