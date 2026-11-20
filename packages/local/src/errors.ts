// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What was asked cannot be done as it was asked: there is no mind in the
 * directory, no passphrase to be had, no such file. The message says what
 * to do about it. A program that runs for a person shows it as it is.
 */
export class UsageError extends Error {
  /** The name of the error: `UsageError`. */
  override readonly name = "UsageError";
}
