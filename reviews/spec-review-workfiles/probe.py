"""Probe oip_vectors.py for divergences from the spec text, and check
vector-level details (VM grammar, X25519 derivation, content-ID tails)."""
import copy, hashlib, importlib.util, json, re, sys
REPO = "/home/claude/open-intelligence-protocol/spec/test-vectors/"
spec = importlib.util.spec_from_file_location("ov", REPO + "oip_vectors.py")
ov = importlib.util.module_from_spec(spec); spec.loader.exec_module(ov)
V = json.load(open(REPO + "vectors.json", encoding="utf-8")); C = V["cases"]

def reg():
    r = ov.Registry()
    for n in ("amina_log", "lexis_ltd_log", "lexis_agent_log", "lexis_fork_log", "researcher_log", "collective_log"):
        r.add(C[n])
    return r

# 1. every verificationMethod in every record (incl. nested) matches core 6.1 grammar
B58 = "[1-9A-HJ-NP-Za-km-z]"
KR = re.compile(rf"^did:oip:b[a-z2-7]{{55}}\?versionId=(0|[1-9][0-9]*)-b[a-z2-7]{{55}}#z{B58}+$")
CK = re.compile(rf"^did:key:(z{B58}+)#(z{B58}+)$")
vms = []
def walk(x):
    if isinstance(x, dict):
        if "verificationMethod" in x: vms.append(x["verificationMethod"])
        for v in x.values(): walk(v)
    elif isinstance(x, list):
        for v in x: walk(v)
walk(C)
badvm = [v for v in vms if not (KR.match(v) or (CK.match(v) and CK.match(v).group(1) == CK.match(v).group(2)))]
print("1. VMs checked:", len(vms), "non-conforming:", badvm)

# 2. content-ID tails: canonical base32 needs last char in {a,i,q,y}
cids = set()
def walkc(x):
    if isinstance(x, str):
        for m in re.findall(r"b[a-z2-7]{55}(?![a-z2-7])", x): cids.add(m)
    elif isinstance(x, dict):
        for v in x.values(): walkc(v)
    elif isinstance(x, list):
        for v in x: walkc(v)
walkc(C)
print("2. content IDs seen:", len(cids), "tails:", sorted({c[-1] for c in cids}))
import base64
c0 = C["content_ids"]["intent"]; alt = c0[:-1] + chr(ord(c0[-1]) + 1)
dec = lambda s: base64.b32decode(s[1:].upper() + "=" * (-len(s[1:]) % 8))
print("   lenient decode of", c0[-3:], "and", alt[-3:], "equal bytes:", dec(c0) == dec(alt), "| alt matches spec regex:", bool(re.match(r"^b[a-z2-7]{55}$", alt)))

# 3. X25519 derivation vs the README's stated rule
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization as S
raw = lambda sk: sk.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw)
readme_rule = ov.multikey_x25519(raw(X25519PrivateKey.from_private_bytes(hashlib.sha256(b"oip-test-vector:amina").digest())))
gen_rule = ov.multikey_x25519(raw(X25519PrivateKey.from_private_bytes(hashlib.sha256(b"oip-test-vector-x25519:amina").digest())))
print("3. vector agreement key:", C["amina_log"][0]["agreement"][0]["key"][:12], "| README rule gives", readme_rule[:12], "| generator rule gives", gen_rule[:12], "| X25519 in keys map:", any(v["multikey"].startswith("z6LS") for v in V["keys"].values()))

# 4. duplicate revealed control keys bypass nextThreshold in oip_vectors.verify_log
k1, k2, k3 = ov.Key("t-c0"), ov.Key("t-n1"), ov.Key("t-n2")
g = {"oip": "1", "type": "Genesis", "kind": "agent", "created": ov.T0,
     "controller": {"keys": [k1.mk], "next": [ov.key_hash(k2.mk), ov.key_hash(k3.mk)], "nextThreshold": 2}}
g = ov.sign(g, ov.create_proof(g, k1, ov.did_key_vm(k1.mk), "capabilityInvocation", ov.T0))
m = ov.did(ov.content_id(g))
u = {"oip": "1", "type": "Update", "mind": m, "seq": 1, "prev": ov.content_id(g), "created": ov.T0,
     "controller": {"keys": [k2.mk, k2.mk], "next": [ov.key_hash(ov.Key("attacker-next").mk)], "nextThreshold": 1}}
u = ov.sign(u, ov.create_proof(u, k2, ov.did_key_vm(k2.mk), "capabilityInvocation", ov.T0))
try:
    ov.verify_log([g, u], ov.Registry()); print("4. 2-of-2 rotation signed by ONE key (listed twice): ACCEPTED by oip_vectors.py (spec 4.3 requires distinct keys)")
except ValueError as e:
    print("4. rejected:", e)

# 5. collective: events after Retire are accepted by oip_vectors.py
r = reg(); coll = C["collective_log"][0]; cm = C["collective"]
a_op1, r_op = ov.Key("amina-phone"), ov.Key("researcher-ops")
a_vm = C["collective_log"][0]["proof"][0]["verificationMethod"]; r_vm = C["collective_log"][0]["proof"][2]["verificationMethod"]
def mk(ev):
    return ov.sign(ev, ov.create_proof(ev, a_op1, a_vm, "capabilityInvocation", ev["created"]),
                   ov.create_proof(ev, r_op, r_vm, "capabilityInvocation", ev["created"]))
ret = mk({"oip": "1", "type": "Retire", "mind": cm, "seq": 1, "prev": ov.content_id(coll), "created": "2026-10-30T11:00:00Z"})
upd = mk({"oip": "1", "type": "Update", "mind": cm, "seq": 2, "prev": ov.content_id(ret), "created": "2026-10-30T11:01:00Z", "homes": ["https://evil.example"]})
weird = mk({"oip": "1", "type": "Frobnicate", "mind": cm, "seq": 3, "prev": ov.content_id(upd), "created": "2026-10-30T11:02:00Z"})
try:
    st = ov.verify_log([coll, ret, upd, weird], r); print("5. collective log with Update after Retire and unknown type 'Frobnicate': ACCEPTED; homes =", st.homes, "(spec 4.6 rejects)")
except ValueError as e:
    print("5. rejected:", e)

# 6. wrong proofPurpose counts in oip_vectors.verify_signed_by (spec core 5.6: must not count)
it = {k: v for k, v in C["intent"].items() if k != "proof"}
it = ov.sign(it, ov.create_proof(it, ov.Key("amina-laptop"), C["intent"]["proof"][0]["verificationMethod"], "capabilityInvocation", it["created"]))
print("6. Intent signed with proofPurpose capabilityInvocation counts for author in oip_vectors.py:", ov.verify_signed_by(it, C["amina"], r))

# 7. delegated proof counts even when record lists no `authority` (spec L2 7.1(2) requires r.authority)
doc = {k: v for k, v in copy.deepcopy(C["commitment_accepted"]).items() if k not in ("proof", "authority")}
doc = ov.sign(doc, ov.create_proof(doc, ov.Key("lexis-agent-i1"), C["commitment_accepted"]["proof"][0]["verificationMethod"], "assertionMethod", doc["created"]))
print("7. Commitment WITHOUT authority counts for Lexis Ltd in oip_vectors.py:", ov.verify_signed_by(doc, C["lexis_ltd"], r, delegations=[C["delegation"]]))

# 8. policy semantics: oip_vectors._cmp vs spec 11.3
from decimal import Decimal
DEC = re.compile(r"^-?(0|[1-9][0-9]*)(\.[0-9]+)?$")
def spec_stmt(op, got, val):
    isnum = lambda x: (type(x) is int) or (isinstance(x, str) and bool(DEC.match(x)))
    if isnum(got) and isnum(val): a, b = Decimal(str(got)), Decimal(str(val))
    elif op in ("==", "!="): return (json.dumps(got) == json.dumps(val)) == (op == "==")
    elif isinstance(got, str) and isinstance(val, str): a, b = got, val
    else: return False
    return {"==": a == b, "!=": a != b, "<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
for got in ["1e9", "1_000", " 900", "+900", "900.00", "Infinity"]:
    pyv = ov.policy_ok([["<=", ".x", "500"]], {"x": got})
    print(f"8. amount {got!r:12} <= '500': spec={spec_stmt('<=', got, '500')!s:5} oip_vectors.py={pyv}")
print("   ts '2026-12-01T00:00:00.5Z' <= '2026-12-01T00:00:00Z' (spec code-point order):", spec_stmt("<=", "2026-12-01T00:00:00.5Z", "2026-12-01T00:00:00Z"), "(true instant order: False)")
print("   JSON null present, ['==', '.x', None]: spec=", spec_stmt("==", None, None), " oip_vectors.py=", ov.policy_ok([["==", ".x", None]], {"x": None}))

# 9. delegation expiry compared as strings in oip_vectors.verify_signed_by
d = {k: v for k, v in C["delegation"].items() if k != "proof"}; d["expires"] = "2026-10-30T10:20:00Z"
dd = ov.sign(d, ov.create_proof(d, ov.Key("lexisltd-ops"), C["delegation"]["proof"][0]["verificationMethod"], "capabilityDelegation", d["created"]))
c2 = {k: v for k, v in copy.deepcopy(C["commitment_accepted"]).items() if k != "proof"}
c2["created"] = "2026-10-30T10:20:00.5Z"; c2["authority"] = [C["lexis_ltd"] + "/" + ov.content_id(dd)]
c2 = ov.sign(c2, ov.create_proof(c2, ov.Key("lexis-agent-i1"), C["commitment_accepted"]["proof"][0]["verificationMethod"], "assertionMethod", c2["created"]))
print("9. record created 0.5 s AFTER delegation expiry counts in oip_vectors.py:", ov.verify_signed_by(c2, C["lexis_ltd"], r, delegations=[dd]))

# 10. spec 6.2 literal reading: after a routine op-key rotation, old Entry/Checkpoint/Ack fail
lex_log = C["lexis_agent_log"]
newop = ov.Key("lexis-agent-i2"); c2k = ov.Key("lexis-agent-control-2")
rot = {"oip": "1", "type": "Update", "mind": C["lexis_agent"], "seq": 2, "prev": ov.content_id(lex_log[1]), "created": "2026-10-31T09:00:00Z",
       "controller": {"keys": [c2k.mk], "next": [ov.key_hash(ov.Key("lexis-agent-control-3").mk)]},
       "keys": [{"key": newop.mk, "label": "i2"}]}
rot = ov.sign(rot, ov.create_proof(rot, c2k, ov.did_key_vm(c2k.mk), "capabilityInvocation", rot["created"]))
r2 = ov.Registry()
for n in ("amina_log", "lexis_ltd_log", "researcher_log", "lexis_fork_log"): r2.add(C[n])
r2.add(lex_log + [rot])
latest = r2.state(C["lexis_agent"])
old_key = C["feed_entry"]["proof"][0]["verificationMethod"].split("#")[1]
print("10. after routine rotation (no compromise), Entry seq 0 key in latest state:", old_key in latest.keys, "-> spec 6.2 makes the historical feed entry invalid")
