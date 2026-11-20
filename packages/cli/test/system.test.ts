// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { homedir } from "node:os";
import { PassThrough } from "node:stream";

import { describe, expect, it } from "vitest";

import { type Process, systemEdges } from "../src/index.ts";

/** A process that is none: what it wrote is kept, and what it listens for can be sent. */
function fake(terminal: boolean) {
  const stdin = Object.assign(new PassThrough(), terminal ? { isTTY: true } : {});
  const written = { out: "", err: "" };
  const heard = new Map<string, () => void>();
  const of: Process = {
    env: { OIP_DIR: "/somewhere" },
    stdin,
    stdout: { write: (text: string) => (written.out += text) },
    stderr: { write: (text: string) => (written.err += text) },
    once: (signal, listener) => heard.set(signal, listener),
  };
  return { of, stdin, written, heard };
}

describe("the edges of a real process", () => {
  it("are its environment, its home directory, and its two streams", () => {
    const { of, written } = fake(false);
    const edges = systemEdges(of);
    expect(edges.env).toBe(of.env);
    expect(edges.home).toBe(homedir());
    edges.out("to standard output\n");
    edges.err("to standard error\n");
    expect(written).toStrictEqual({ out: "to standard output\n", err: "to standard error\n" });
    // What a test gives in their place is absent: the platform's own are used.
    expect(edges.fetch).toBeUndefined();
    expect(edges.clock).toBeUndefined();
    expect(edges.webSocket).toBeUndefined();
    expect(edges.scryptN).toBeUndefined();
    expect(typeof edges.keychain).toBe("function");
  });

  it("ask for a secret only where there is a terminal, and never show what is typed", async () => {
    expect(systemEdges(fake(false).of).secret).toBeUndefined();
    const { of, stdin, written } = fake(true);
    const { secret } = systemEdges(of);
    expect(secret).toBeTypeOf("function");
    const asked = secret?.("Passphrase: ");
    stdin.write("correct horse battery staple\n");
    expect(await asked).toBe("correct horse battery staple");
    // The question is asked on standard error, so that standard output stays what was asked for.
    expect(written.err).toBe("Passphrase: \n");
    expect(written.out).toBe("");
    // A second question is answered by what is typed next, and by nothing of the first.
    const again = secret?.("The same again: ");
    stdin.write("another\n");
    expect(await again).toBe("another");
    expect(written.err).toBe("Passphrase: \nThe same again: \n");
    expect(written.err + written.out).not.toContain("correct horse");
  });

  it("say when the process is asked to stop: at an interrupt, or when it is told to end", async () => {
    for (const signal of ["SIGINT", "SIGTERM"] as const) {
      const { of, heard } = fake(false);
      let stopped = false;
      const waiting = systemEdges(of)
        .stopped()
        .then(() => {
          stopped = true;
        });
      await Promise.resolve();
      expect(stopped).toBe(false);
      expect([...heard.keys()].sort()).toStrictEqual(["SIGINT", "SIGTERM"]);
      heard.get(signal)?.();
      await waiting;
      expect(stopped).toBe(true);
    }
  });
});
