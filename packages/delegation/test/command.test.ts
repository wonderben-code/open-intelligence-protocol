// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { OIP_COMMANDS } from "@oip/schema";
import { clause } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import {
  covers,
  DELEGABLE_TYPES,
  isCommand,
  isDelegableCommand,
  isDelegableType,
  SEND_COMMAND,
  signCommand,
} from "../src/index.ts";

describe(`${clause("L1 11.2")} commands`, () => {
  it("are a slash and a segment, any number of times", () => {
    for (const command of ["/a", "/oip/sign/Intent", "/x402/pay", "/a.b/c_d/e-f", "/0"]) {
      expect(isCommand(command)).toBe(true);
    }
    for (const command of [
      "",
      "/",
      "a",
      "a/b",
      "/a/",
      "//a",
      "/a//b",
      "/a b",
      "/a/é",
      "/a\n",
      5,
      null,
    ]) {
      expect(isCommand(command)).toBe(false);
    }
  });

  it("cover a command that is equal, or that goes on after a slash", () => {
    expect(covers("/x402/pay", "/x402/pay")).toBe(true);
    expect(covers("/x402/pay", "/x402/pay/usd")).toBe(true);
    expect(covers("/x402", "/x402/pay/usd")).toBe(true);
    // By whole segments: a longer segment is another command.
    expect(covers("/x402/pay", "/x402/payments")).toBe(false);
    expect(covers("/x402/pay/usd", "/x402/pay")).toBe(false);
    expect(covers("/x402/pay", "/x403/pay")).toBe(false);
    // What is no command covers nothing and is covered by nothing.
    expect(covers("/x402/", "/x402/pay")).toBe(false);
    expect(covers("", "/x402")).toBe(false);
    expect(covers("/x402", "/x402/")).toBe(false);
    expect(covers(undefined, "/x402")).toBe(false);
    expect(covers("/x402", 5)).toBe(false);
  });

  it("under /oip are exactly the four that sign and the one that sends", () => {
    expect([...OIP_COMMANDS].sort()).toStrictEqual(
      [...DELEGABLE_TYPES.map(signCommand), SEND_COMMAND].sort(),
    );
    for (const command of OIP_COMMANDS) expect(isDelegableCommand(command)).toBe(true);
  });

  it("reserve every other command whose first segment is oip, so that no grant is a blanket", () => {
    for (const reserved of [
      "/oip",
      "/oip/sign",
      "/oip/sign/Delegation",
      "/oip/sign/Revocation",
      "/oip/sign/Collective",
      "/oip/sign/Intent/more",
      "/oip/send/now",
      "/oip/anything",
    ]) {
      expect(isCommand(reserved)).toBe(true);
      expect(isDelegableCommand(reserved)).toBe(false);
    }
    // The reservation is of the segment `oip`, and of no command that begins with those letters.
    for (const other of ["/oipx", "/oip-pay/now", "/oip.v2/sign", "/x402/pay", "/OIP/sign"]) {
      expect(isDelegableCommand(other)).toBe(true);
    }
    expect(isDelegableCommand("oip/send")).toBe(false);
    expect(isDelegableCommand(undefined)).toBe(false);
  });

  it("name the delegable types, and no other", () => {
    expect(DELEGABLE_TYPES).toStrictEqual(["Intent", "Offer", "Commitment", "Receipt"]);
    for (const type of DELEGABLE_TYPES) {
      expect(isDelegableType(type)).toBe(true);
      expect(covers(signCommand(type), `/oip/sign/${type}`)).toBe(true);
    }
    for (const type of [
      "Delegation",
      "Revocation",
      "Collective",
      "Lineage",
      "Genesis",
      "Location",
      "",
      5,
    ]) {
      expect(isDelegableType(type)).toBe(false);
    }
    // One type's command does not cover another's.
    expect(covers(signCommand("Intent"), signCommand("Offer"))).toBe(false);
  });
});
