// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The errors an A2A server answers with (A2A, Section 5.4), and those of
 * JSON-RPC 2.0 that an A2A server uses.
 */

/** Thrown where a request of an A2A client is answered with an error. */
export class Fault extends Error {
  override readonly name = "Fault";
  /** The JSON-RPC error code (A2A, 5.4 and 9.5). */
  readonly code: number;
  /** What an `ErrorInfo` gives as the reason, for an error that A2A defines. */
  readonly reason: string | undefined;

  constructor(code: number, reason: string | undefined, message: string) {
    super(message);
    this.code = code;
    this.reason = reason;
  }
}

/** The task is none the caller can name: there is no such task, or it is another agent's. */
export const taskNotFound = (): Fault =>
  new Fault(-32001, "TASK_NOT_FOUND", "There is no such task.");

/** The task has ended, and cannot be cancelled. */
export const taskNotCancelable = (): Fault =>
  new Fault(-32002, "TASK_NOT_CANCELABLE", "The task has ended, and cannot be cancelled.");

/** The gateway sends no push notifications. */
export const pushNotSupported = (): Fault =>
  new Fault(
    -32003,
    "PUSH_NOTIFICATION_NOT_SUPPORTED",
    "This agent sends no push notifications: ask for the task with GetTask.",
  );

/** The operation is one this agent does not do, or does not do for a task in this state. */
export const unsupported = (what: string): Fault =>
  new Fault(-32004, "UNSUPPORTED_OPERATION", what);

/** A part is of a media type the agent cannot be given. */
export const contentTypeNotSupported = (what: string): Fault =>
  new Fault(-32005, "CONTENT_TYPE_NOT_SUPPORTED", what);

/** The client speaks a version of A2A this agent does not. */
export const versionNotSupported = (asked: string): Fault =>
  new Fault(
    -32009,
    "VERSION_NOT_SUPPORTED",
    `This agent speaks A2A 1.0, and was asked in ${asked}: send the header A2A-Version: 1.0.`,
  );

/** JSON-RPC 2.0: what was sent is no JSON. */
export const parseError = (): Fault => new Fault(-32700, undefined, "The request is not JSON.");

/** JSON-RPC 2.0: what was sent is no request. */
export const invalidRequest = (what: string): Fault => new Fault(-32600, undefined, what);

/** JSON-RPC 2.0: there is no such method. */
export const methodNotFound = (method: string): Fault =>
  new Fault(-32601, undefined, `There is no method ${method}.`);

/** JSON-RPC 2.0: the parameters are not those of the method. */
export const invalidParams = (what: string): Fault => new Fault(-32602, undefined, what);

/** JSON-RPC 2.0: the server could not do what was asked, and the fault is its own. */
export const internal = (what: string): Fault => new Fault(-32603, undefined, what);
