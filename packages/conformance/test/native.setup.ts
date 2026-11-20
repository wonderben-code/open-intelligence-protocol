// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * With `OIP_ED25519=native`, every test of the suite runs with OpenSSL doing
 * the arithmetic of each signature, as a service does (ADR-0016): the golden
 * vectors, and the differential tests against the Python checker.
 */

import { useNativeEd25519 } from "@oip/server";

if (!useNativeEd25519()) {
  throw new Error("OIP_ED25519=native was asked for, and OpenSSL is not in use");
}
