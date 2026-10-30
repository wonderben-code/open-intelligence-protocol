import base64, copy, hashlib, importlib.util, json, re
from decimal import Decimal
REPO = "/home/claude/open-intelligence-protocol/spec/test-vectors/"
s = importlib.util.spec_from_file_location("ov", REPO + "oip_vectors.py"); ov = importlib.util.module_from_spec(s); s.loader.exec_module(ov)
V = json.load(open(REPO + "vectors.json", encoding="utf-8")); C = V["cases"]
# 1. proofValue without 'z' prefix still verifies in oip_vectors
it = C["intent"]; p = dict(it["proof"][0]); p["proofValue"] = "x" + p["proofValue"][1:]
print("1. proofValue 'x'+base58 verifies in oip_vectors.verify_proof:", ov.verify_proof(it, p, p["verificationMethod"].split("#")[1]))
# 2. canonical content-ID shape for every content ID / key hash / address in vectors
ids = set(re.findall(r"b[a-z2-7]{55}(?![a-z2-7])", json.dumps(C)))
canon = re.compile(r"^bciq[a-p][a-z2-7]{50}[aiqy]$")
print("2. all", len(ids), "content IDs match ^bciq[a-p][a-z2-7]{50}[aiqy]$:", all(canon.match(i) for i in ids))
# 3. spec-literal policy evaluation of the vector policy on crafted amounts
DEC = re.compile(r"^-?(0|[1-9][0-9]*)(\.[0-9]+)?$")
def spec_le(got, val):
    isnum = lambda x: type(x) is int or (isinstance(x, str) and bool(DEC.match(x)))
    if isnum(got) and isnum(val): return Decimal(str(got)) <= Decimal(str(val))
    if isinstance(got, str) and isinstance(val, str): return [ord(c) for c in got] <= [ord(c) for c in val]
    return False
for amt in ["120", "900", "0500000", "1e9", "9000 ", "4,000,000"]:
    doc = {k: v for k, v in copy.deepcopy(C["commitment_accepted"]).items() if k != "proof"}
    doc["terms"]["price"]["amount"] = amt
    print(f"3. amount {amt!r:12} policy <= '500': spec-literal={spec_le(amt, '500')!s:5}  oip_vectors={ov.policy_ok(C['delegation']['policy'], doc)}")
# 4. every proof in vectors (including nested) verifies with an independent check of the key's multikey
def all_proofs(rec, path):
    out = []
    if isinstance(rec, dict):
        for p in rec.get("proof", []) if isinstance(rec.get("proof"), list) else []:
            out.append((rec, p, path))
        for k, v in rec.items():
            if k != "proof": out += all_proofs(v, path + "." + k)
    elif isinstance(rec, list):
        for i, v in enumerate(rec): out += all_proofs(v, f"{path}[{i}]")
    return out
ps = all_proofs(C, "cases")
ok = sum(ov.verify_proof(r, p, p["verificationMethod"].split("#")[1]) for r, p, _ in ps)
print("4. proofs found:", len(ps), "verify:", ok, "| proofValue lengths all 64:", all(len(ov.b58decode(p["proofValue"][1:])) == 64 for _, p, _ in ps))
# 5. purposes per record type
from collections import Counter
print("5. (type, purpose) pairs:", sorted(Counter((r.get("type"), p["proofPurpose"]) for r, p, _ in ps).items()))
