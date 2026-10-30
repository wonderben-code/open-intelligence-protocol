import importlib.util, json
REPO = "/home/claude/open-intelligence-protocol/spec/test-vectors/"
s = importlib.util.spec_from_file_location("ov", REPO + "oip_vectors.py"); ov = importlib.util.module_from_spec(s); s.loader.exec_module(ov)
C = json.load(open(REPO + "vectors.json", encoding="utf-8"))["cases"]
proof = C["collective_log"][0]["proof"][0]
p = len(ov.jcs(proof)) + 1
addr = len(C["collective"]) + 3
n = 256
genesis = 200 + n * addr + n * p
print("member proof bytes ~", p, "| 256-member collective genesis ~", genesis // 1024, "KiB")
ev = 200 + n * addr + 129 * p
print("each later event (129-of-256 threshold, membership restated) ~", ev // 1024, "KiB")
for lim in (256, 1024):
    k = 0; tot = genesis
    while tot + ev <= lim * 1024: tot += ev; k += 1
    print(f"Bundle exceeds {lim} KiB after genesis + {k + 1} events")
