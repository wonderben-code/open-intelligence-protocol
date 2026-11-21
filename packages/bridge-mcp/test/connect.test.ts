// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The gateway's connection to an MCP server, against a server made with
 * the MCP project's own library: over HTTP, with the requests handed to
 * the server in this process, and as a command on this machine.
 */

import { fileURLToPath } from "node:url";

import { createMcpHandler } from "@modelcontextprotocol/server";
import { UsageError } from "@oip/local";
import { clause } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import { everyPage, MAX_LISTED, MAX_PAGES, pinned } from "../src/connect.ts";
import { connector, endpointOf, NONE, Refused, type Target } from "../src/index.ts";
import { factory, TOOLS } from "./fixture/server.ts";

const URL_OF = "https://tools.example/mcp";
const HTTP: Target = { kind: "http", url: URL_OF };

/** Where a request goes, however `fetch` was told. */
const urlOf = (input: string | URL | Request): string =>
  typeof input === "string" ? input : input instanceof URL ? input.href : input.url;

/** A `fetch` that hands a request to the fixture server, and notes what was asked. */
function served(): {
  fetch: typeof fetch;
  asked: { url: string; init: RequestInit }[];
  line: { cut: boolean };
} {
  const handler = createMcpHandler(factory);
  const asked: { url: string; init: RequestInit }[] = [];
  const line = { cut: false };
  return {
    asked,
    line,
    fetch: (input, init = {}) => {
      if (line.cut) return Promise.reject(new TypeError("fetch failed"));
      const url = urlOf(input);
      asked.push({ url, init });
      return handler.fetch(new Request(url, init));
    },
  };
}

describe("how a bridged mind names its server", () => {
  it(`${clause("L0 1.2")} is the server's URL, or \`stdio:\` and the operator's name for a command`, () => {
    expect(endpointOf(HTTP)).toBe(URL_OF);
    // As a URL is written whole: a host in lower case, and a path.
    expect(endpointOf({ kind: "http", url: "https://Tools.Example" })).toBe(
      "https://tools.example/",
    );
    expect(endpointOf({ kind: "http", url: "https://tools.example:8443/mcp?tenant=7" })).toBe(
      "https://tools.example:8443/mcp?tenant=7",
    );
    expect(endpointOf({ kind: "stdio", label: "files.v2_a-b", command: "x", args: [] })).toBe(
      "stdio:files.v2_a-b",
    );
  });

  it("is plain HTTP for a server on this machine alone", () => {
    for (const url of [
      "http://localhost:3000/mcp",
      "http://127.0.0.1:3000/mcp",
      "http://[::1]/mcp",
    ]) {
      expect(endpointOf({ kind: "http", url })).toBe(url);
    }
    for (const url of [
      "http://tools.example/mcp",
      "http://127.0.0.1.example/mcp",
      "http://10.0.0.7/mcp",
      "ftp://tools.example/mcp",
      "file:///etc/passwd",
    ]) {
      expect(() => endpointOf({ kind: "http", url }), url).toThrow("is not reached over HTTPS");
    }
  });

  it("is none for a URL with a name or a password in it, or a label that is no label", () => {
    for (const url of [
      "https://user@tools.example/mcp",
      "https://user:pass@tools.example/mcp",
      "https://tools.example/mcp#part",
    ]) {
      expect(() => endpointOf({ kind: "http", url }), url).toThrow(
        "credentials go in the credentials file",
      );
    }
    expect(() => endpointOf({ kind: "http", url: "tools.example/mcp" })).toThrow("is no URL");
    for (const label of ["", "Files", "has space", "-leading", "a/b", "é", "x".repeat(65)]) {
      const target: Target = { kind: "stdio", label, command: "x", args: [] };
      expect(() => endpointOf(target), label).toThrow(UsageError);
    }
    expect(() => endpointOf({ kind: "stdio", label: "files", command: "", args: [] })).toThrow(
      "has a command",
    );
  });
});

describe("a connection to a server over HTTP", () => {
  it(`${clause("L0 2.1")} lists the server's tools and calls one, as the server's own library serves them`, async () => {
    const { fetch } = served();
    const server = await connector({ version: "1.2.3", fetch })(HTTP, NONE);
    try {
      const listed = (await server.tools()) as { name: string; inputSchema: unknown }[];
      expect(listed.map(({ name }) => name)).toStrictEqual(["echo", "environment", "boom"]);
      expect(listed).toHaveLength(TOOLS);
      expect(listed[0]?.inputSchema).toMatchObject({
        type: "object",
        properties: { text: { type: "string" } },
        required: ["text"],
      });
      expect(await server.call("echo", { text: "Habari." })).toMatchObject({
        content: [{ type: "text", text: "Habari." }],
      });
    } finally {
      await server.close();
    }
  });

  it(`${clause("L0 2.1")} gives a tool's failure as the server's result, and a call the server will not make as a refusal`, async () => {
    const { fetch } = served();
    const server = await connector({ version: "1.2.3", fetch })(HTTP, NONE);
    try {
      // A tool that throws has run: the server says so in a result.
      expect(await server.call("boom", {})).toMatchObject({
        isError: true,
        content: [{ type: "text", text: "The disk is full." }],
      });
      // So have arguments the tool does not take: MCP has the server say that in a result too.
      expect(await server.call("echo", { text: 7 })).toMatchObject({ isError: true });
      // A tool the server does not have is no call at all.
      await expect(server.call("no_such_tool", {})).rejects.toBeInstanceOf(Refused);
    } finally {
      await server.close();
    }
  });

  it(`${clause("L0 2.1")} sends the operator's headers with each request, to the server's own origin and nowhere else`, async () => {
    const { fetch, asked } = served();
    const credentials = { headers: { Authorization: "Bearer t0p-s3cret" }, env: {} };
    const server = await connector({ version: "1.2.3", fetch })(HTTP, credentials);
    try {
      await server.call("echo", { text: "With a key." });
    } finally {
      await server.close();
    }
    expect(asked.length).toBeGreaterThan(0);
    for (const { url, init } of asked) {
      expect(new URL(url).origin).toBe("https://tools.example");
      expect(new Headers(init.headers).get("authorization")).toBe("Bearer t0p-s3cret");
      // A server that answers with a redirect sends the gateway nowhere.
      expect(init.redirect).toBe("error");
    }
  });

  it("makes no request of another origin, whatever it is told", async () => {
    const reached: string[] = [];
    // A server whose every answer is a way elsewhere: here, by a `fetch` that would follow.
    const elsewhere: typeof fetch = (input) => {
      reached.push(urlOf(input));
      return Promise.resolve(
        new Response(null, { status: 307, headers: { location: "https://elsewhere.example/mcp" } }),
      );
    };
    await expect(connector({ version: "1.2.3", fetch: elsewhere })(HTTP, NONE)).rejects.toThrow();
    expect(reached.every((url) => new URL(url).origin === "https://tools.example")).toBe(true);
    // And a target that is none is not connected to, whatever a file in the gateway's directory says.
    await expect(
      connector({ version: "1.2.3", fetch: elsewhere })(
        { kind: "http", url: "http://tools.example/mcp" },
        NONE,
      ),
    ).rejects.toThrow(UsageError);
  });
});

describe("a connection to a server over HTTP, at its edges", () => {
  it("says what the server calls itself", async () => {
    const { fetch } = served();
    const server = await connector({ version: "1.2.3", fetch })(HTTP, NONE);
    expect(server.name).toBe("fixture-server");
    await server.close();
  });

  it("does not take a call that the line dropped for a refusal: whether the tool ran is not known", async () => {
    const { fetch, line } = served();
    const server = await connector({ version: "1.2.3", fetch })(HTTP, NONE);
    try {
      line.cut = true;
      const failed = await server.call("echo", { text: "Lost." }).catch((error: unknown) => error);
      expect(failed).toBeInstanceOf(Error);
      expect(failed).not.toBeInstanceOf(Refused);
    } finally {
      line.cut = false;
      await server.close();
    }
  });

  it("is made with the platform's own `fetch` where no other is given", async () => {
    // A port of this machine that nothing listens on.
    const { createServer } = await import("node:net");
    const port = await new Promise<number>((resolve) => {
      const taken = createServer().listen(0, "127.0.0.1", () => {
        const { port: free } = taken.address() as { port: number };
        taken.close(() => {
          resolve(free);
        });
      });
    });
    const local: Target = { kind: "http", url: `http://127.0.0.1:${String(port)}/mcp` };
    await expect(connector({ version: "1.2.3" })(local, NONE)).rejects.toThrow();
  });

  it("reaches one origin, however a request names where it goes", async () => {
    const reached: { url: string; redirect: unknown }[] = [];
    const inner: typeof fetch = (input, init) => {
      reached.push({ url: urlOf(input), redirect: init?.redirect });
      return Promise.resolve(new Response("{}"));
    };
    const one = pinned("https://tools.example", inner);
    await one("https://tools.example/mcp");
    await one(new URL("https://tools.example/mcp?page=2"));
    await one(new Request("https://tools.example/other"), { redirect: "follow" });
    expect(reached).toStrictEqual([
      { url: "https://tools.example/mcp", redirect: "error" },
      { url: "https://tools.example/mcp?page=2", redirect: "error" },
      // Whatever the caller asked: a redirect is an error.
      { url: "https://tools.example/other", redirect: "error" },
    ]);
    for (const elsewhere of [
      "https://elsewhere.example/mcp",
      "http://tools.example/mcp",
      "https://tools.example:8443/mcp",
      "https://tools.example.evil.example/mcp",
    ]) {
      await expect(one(elsewhere), elsewhere).rejects.toThrow("the server's own origin alone");
      await expect(one(new URL(elsewhere))).rejects.toThrow(TypeError);
      await expect(one(new Request(elsewhere))).rejects.toThrow(TypeError);
    }
    expect(reached).toHaveLength(3);
  });
});

describe("a list of tools that comes in pages", () => {
  it(`${clause("L0 2.1")} is read to its end, page after page`, async () => {
    const pages: Record<string, { tools: unknown[]; nextCursor?: string }> = {
      first: { tools: [{ name: "a" }, { name: "b" }], nextCursor: "second" },
      second: { tools: [{ name: "c" }], nextCursor: "third" },
      third: { tools: [{ name: "d" }] },
    };
    const asked: (string | undefined)[] = [];
    const listed = await everyPage((cursor) => {
      asked.push(cursor);
      return Promise.resolve(pages[cursor ?? "first"] ?? { tools: [] });
    });
    expect(listed).toStrictEqual([{ name: "a" }, { name: "b" }, { name: "c" }, { name: "d" }]);
    expect(asked).toStrictEqual([undefined, "second", "third"]);
  });

  it("is read within bounds: a server that never ends its list does not keep the gateway", async () => {
    let asked = 0;
    const endless = await everyPage(() => {
      asked += 1;
      return Promise.resolve({ tools: [{ name: `tool-${String(asked)}` }], nextCursor: "more" });
    });
    expect(asked).toBe(MAX_PAGES);
    expect(endless).toHaveLength(MAX_PAGES);
    // And one that lists a great many at once is read as far as the bound.
    asked = 0;
    const wide = await everyPage(() => {
      asked += 1;
      return Promise.resolve({
        tools: Array.from({ length: 3000 }, (_, at) => ({
          name: `${String(asked)}-${String(at)}`,
        })),
        nextCursor: "more",
      });
    });
    expect(asked).toBe(2);
    expect(wide).toHaveLength(MAX_LISTED);
  });
});

describe("a connection to a server that is a command", () => {
  const command: Target = {
    kind: "stdio",
    label: "fixture",
    command: process.execPath,
    args: [
      "--conditions=@oip/source",
      fileURLToPath(new URL("fixture/server.ts", import.meta.url)),
    ],
  };

  it(`${clause("L0 2.1")} starts the command with the operator's variables, and without the gateway's own`, async () => {
    process.env["OIP_PASSPHRASE_FOR_THIS_TEST"] = "the gateway's own secret";
    try {
      const credentials = { headers: {}, env: { FIXTURE_KEY: "k-123" } };
      const server = await connector({ version: "1.2.3", stderr: "ignore" })(command, credentials);
      try {
        expect(server.name).toBe("fixture-server");
        expect((await server.tools()).length).toBe(TOOLS);
        expect(await server.call("environment", { name: "FIXTURE_KEY" })).toMatchObject({
          content: [{ type: "text", text: "k-123" }],
        });
        // What opens the gateway's keys is in its environment. The command is not given it.
        expect(
          await server.call("environment", { name: "OIP_PASSPHRASE_FOR_THIS_TEST" }),
        ).toMatchObject({
          content: [{ type: "text", text: "(not set)" }],
        });
        await expect(server.call("no_such_tool", {})).rejects.toBeInstanceOf(Refused);
      } finally {
        await server.close();
      }
    } finally {
      delete process.env["OIP_PASSPHRASE_FOR_THIS_TEST"];
    }
  });

  it("is refused where there is no such command", async () => {
    await expect(
      // What such a command writes to its standard error is the gateway's log, unless told otherwise.
      connector({ version: "1.2.3" })({ ...command, command: "/no/such/command-anywhere" }, NONE),
    ).rejects.toThrow();
  });
});
