// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `oip-bridge-mcp`, as a program: what it takes, what it says, and what it
 * exits with. The network is real and on this machine. The MCP server is a
 * function.
 */

import { writeFileSync } from "node:fs";
import { join } from "node:path";

import { keepRecords } from "@oip/local";
import { clause } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { type Host, main, POLICY_FILE, type Serving, VERSION } from "../src/index.ts";
import { Place, Tools } from "./harness.ts";

const URL_OF = "https://tools.lexis.example/mcp";

let place: Place;
let tools: Tools;
let amina: string;

beforeAll(async () => {
  place = await new Place().start();
  await place.make("gateway", { kind: "service" });
  amina = await place.make("amina");
  tools = new Tools();
});
afterAll(async () => {
  await place.close();
});

/** A process for the program: what it wrote, and the signals it listens for. */
function process(): Host & { out: string; err: string; signal(name: string): void } {
  const heard = new Map<string, () => void>();
  const host = {
    env: {},
    out: "",
    err: "",
    stdout: { write: (text: string) => (host.out += text) },
    stderr: { write: (text: string) => (host.err += text) },
    once: (signal: string, listener: () => void) => heard.set(signal, listener),
    signal: (name: string) => heard.get(name)?.(),
  };
  return host;
}

/** Runs the program for the gateway's mind, with the scripted server. */
async function run(
  ...argv: string[]
): Promise<{ code: number | Serving; out: string; err: string }> {
  const host = process();
  const code = await main(["--dir", join(place.root, "gateway"), ...argv], host, {
    connect: tools.connect,
    machine: place.machine(),
  });
  return { code, out: host.out, err: host.err };
}

describe("oip-bridge-mcp", () => {
  it("says what it takes, and which version it is", async () => {
    const help = await run("--help");
    expect(help.code).toBe(0);
    for (const word of [
      "bridge <url>",
      "--stdio <label>",
      "servers",
      "serve",
      "--credentials",
      "--every",
      "OIP_PASSPHRASE",
    ]) {
      expect(help.out, word).toContain(word);
    }
    expect(await run("--version")).toMatchObject({ code: 0, out: `${VERSION}\n` });
  });

  it("is told what to do, in words it knows", async () => {
    const cases: [string[], string][] = [
      [[], "say what to do: bridge, servers or serve"],
      [["status"], "status is none of bridge, servers and serve"],
      [
        ["servers", "all"],
        "servers is none of bridge, servers and serve, or takes no such argument",
      ],
      [["serve", "now"], "takes no such argument"],
      [["bridge"], "bridge takes one URL"],
      [["bridge", URL_OF, "https://other.example/mcp"], "bridge takes one URL"],
      [["bridge", "--stdio", "files"], "bridge --stdio takes a command after `--`"],
      [["bridge", "http://tools.example/mcp"], "is not reached over HTTPS"],
      [["bridge", "--stdio", "Has Spaces", "--", "a-server"], "is named in lower-case letters"],
      [["serve", "--every", "0"], "--every is a whole number from 1 to 3600"],
      [["serve", "--every", "soon"], "--every is a whole number from 1 to 3600"],
      [["serve", "--every", "3601"], "--every is a whole number from 1 to 3600"],
      [["bridge", URL_OF, "--credentials", join(place.root, "absent.json")], "there is no file"],
    ];
    for (const [argv, said] of cases) {
      const done = await run(...argv);
      expect(done.code, argv.join(" ")).toBe(2);
      expect(done.err, argv.join(" ")).toContain(said);
      expect(done.err.startsWith("oip-bridge-mcp: ")).toBe(true);
      expect(done.out).toBe("");
    }
    const unknown = await run("serve", "--loudly");
    expect(unknown.code).toBe(2);
    expect(unknown.err).toContain("`oip-bridge-mcp --help` shows what it takes");
  });

  it("works with the machine's own where it is given nothing else, and lets an error it does not know through", async () => {
    // A directory that holds no gateway: there is nothing to list, and nothing to open.
    const host = process();
    expect(await main(["--dir", join(place.root, "nowhere"), "servers"], host)).toBe(0);
    expect(host.out).toContain("The gateway bridges no server yet");
    // What nobody foresaw is nobody's to explain away: it is thrown as it came.
    const env = new Proxy(
      {},
      {
        get: () => {
          throw new RangeError("the environment is gone");
        },
      },
    );
    await expect(
      main(["--dir", join(place.root, "gateway"), "bridge", URL_OF], process(), {
        connect: tools.connect,
        machine: place.machine({ env }),
      }),
    ).rejects.toThrow(RangeError);
  });

  it("lists nothing before it bridges anything", async () => {
    expect(await run("servers")).toMatchObject({
      code: 0,
      out: "The gateway bridges no server yet: `oip-bridge-mcp bridge <url>`\n",
    });
  });

  it(`${clause("L0 2.1")} bridges a server at a URL, and says what the operator is to do next`, async () => {
    const done = await run("bridge", URL_OF);
    expect(done.code).toBe(0);
    const [first, second, third, fourth] = done.out.split("\n");
    expect(first).toMatch(
      new RegExp(`^${URL_OF.replaceAll(".", "\\.")} is bridged as did:oip:bciq[a-z2-7]{52}$`, "u"),
    );
    expect(second).toBe("7 tools of it are capabilities of that mind.");
    expect(third).toMatch(/^Who may call them is the operator's to say, in .*policy\.json$/u);
    expect(fourth).toBe("Until it names a mind, the gateway calls no tool for anybody.");

    const listed = await run("servers");
    expect(listed.code).toBe(0);
    expect(listed.out).toMatch(
      new RegExp(
        `^${URL_OF.replaceAll(".", "\\.")}  did:oip:bciq[a-z2-7]{52}  7 tools  .*servers.[0-9a-f]{40}\\n$`,
        "u",
      ),
    );
  });

  it("bridges a server that is a command, and says what of its tools is left out", async () => {
    tools.listed = [
      { name: "only", description: "The one tool." },
      { name: "only", description: "Its double." },
      { description: "Nameless." },
      { name: 'sly"\nThe gateway vouches.' },
    ];
    try {
      const done = await run(
        "bridge",
        "--stdio",
        "files",
        "--name",
        "The firm's files",
        "--",
        "files-server",
        "--root",
        "/srv",
      );
      expect(done.code).toBe(0);
      expect(done.out).toContain("stdio:files is bridged as did:oip:");
      expect(done.out).toContain(
        "2 tools of it are capabilities of that mind, 2 without an input schema: none that fits a profile.",
      );
      expect(done.out).toContain('Left out: "only": another tool has its name.');
      expect(done.out).toContain("Left out: a tool: it has no name.");
      expect(tools.connections.at(-1)?.target).toStrictEqual({
        kind: "stdio",
        label: "files",
        command: "files-server",
        args: ["--root", "/srv"],
      });
      // One tool alone reads as one.
      tools.listed = [
        { name: "only", description: "The one tool.", inputSchema: { type: "object" } },
      ];
      const one = await run("bridge", "--stdio", "one", "--", "a-server");
      expect(one.out).toContain("1 tool of it is a capability of that mind.");
    } finally {
      tools.listed = (await import("./harness.ts")).LISTED;
    }
  });

  it("says why a server is not bridged, and exits with 1", async () => {
    tools.down = true;
    try {
      const done = await run("bridge", "https://absent.example/mcp");
      expect(done.code).toBe(1);
      expect(done.err).toBe(
        "oip-bridge-mcp: the server https://absent.example/mcp could not be reached: the server is not to be reached\n",
      );
    } finally {
      tools.down = false;
    }
    // Without what opens the gateway's keys, nothing is opened.
    const host = process();
    const code = await main(["--dir", join(place.root, "gateway"), "bridge", URL_OF], host, {
      connect: tools.connect,
      machine: place.machine({ env: {} }),
    });
    expect(code).toBe(2);
    expect(host.err).toContain("OIP_PASSPHRASE");
  });

  it(`${clause("L0 2.1")} serves: relays for every server it bridges until it is asked to stop, and says what it did`, async () => {
    const gateway = join(place.root, "gateway");
    const bridged =
      /is bridged as (did:oip:[a-z2-7]+)/u.exec((await run("bridge", URL_OF)).out)?.[1] ?? "";
    const directory = /in (.*)policy\.json/u.exec((await run("bridge", URL_OF)).out)?.[1] ?? "";
    writeFileSync(join(directory, POLICY_FILE), JSON.stringify({ allow: { echo: [amina] } }));
    const opened = await place.mind("amina");
    const send = (tool: string): Promise<unknown> =>
      opened.mind.send({
        to: [bridged],
        verb: "request",
        content: { mediaType: "application/json", body: { tool, arguments: { text: "Habari." } } },
      });
    await send("echo");
    await send("fail");

    const host = process();
    const serving = (await main(["--dir", gateway, "serve", "--every", "1"], host, {
      connect: tools.connect,
      machine: place.machine(),
    })) as Serving;
    expect(typeof serving).toBe("object");
    // Until both are answered: one with what the tool said, one with a refusal.
    const answers: string[] = [];
    for (let tries = 0; tries < 600 && answers.length < 2; tries += 1) {
      await new Promise((resolve) => setTimeout(resolve, 50));
      const read = await opened.mind.receive();
      answers.push(...read.received.map(({ packet }) => packet.purpose.verb));
    }
    keepRecords(opened);
    opened.mind.close();
    expect(answers.sort()).toStrictEqual(["decline", "deliver"]);
    // A server that cannot be relayed for is said, and the others are relayed for all the same.
    writeFileSync(join(directory, POLICY_FILE), "{");
    for (let tries = 0; tries < 600 && !host.err.includes("policy.json is not JSON"); tries += 1) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    host.signal("SIGTERM");
    // A second signal is the first again.
    host.signal("SIGINT");
    await serving.ended;
    expect(host.out).toBe("");
    expect(host.err).toContain(
      `oip-bridge-mcp ${VERSION}: relaying for 3 bridged servers, every 1 s`,
    );
    // In one pass or in two, as the packets came: one tool was called, and one request declined.
    const said = host.err
      .split("\n")
      .filter((line) => line.includes(`${URL_OF}: `) && line.includes("called"));
    const count = (what: RegExp): number =>
      said.reduce((sum, line) => sum + Number(what.exec(line)?.[1] ?? 0), 0);
    expect(count(/(\d+) tools? called/u)).toBe(1);
    expect(count(/(\d+) requests? declined/u)).toBe(1);
    expect(count(/(\d+) packets? sent/u)).toBe(2);
    expect(count(/(\d+) Receipts? signed/u)).toBe(0);
    expect(host.err).toContain("policy.json is not JSON a record may be in");
    writeFileSync(join(directory, POLICY_FILE), JSON.stringify({ allow: {} }));
  });
});
