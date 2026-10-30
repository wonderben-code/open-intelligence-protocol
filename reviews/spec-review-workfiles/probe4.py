import importlib.util, json
REPO = "/home/claude/open-intelligence-protocol/spec/test-vectors/"
s = importlib.util.spec_from_file_location("ov", REPO + "oip_vectors.py"); ov = importlib.util.module_from_spec(s); s.loader.exec_module(ov)
C = json.load(open(REPO + "vectors.json", encoding="utf-8"))["cases"]
r = ov.Registry(); r.add(C["amina_log"])
it = {k: v for k, v in C["intent"].items() if k != "proof"}
lap = ov.Key("amina-laptop")
unpinned = C["amina"] + "#" + lap.mk
p = ov.create_proof(it, lap, unpinned, "assertionMethod", it["created"])
print("v) Intent proof with UNVERSIONED verificationMethod", unpinned[:20] + "...#" + lap.mk[:8], "counts in oip_vectors.py:", ov.verify_signed_by(ov.sign(it, p), C["amina"], r))
# kind collective with key controller
c0, c1 = ov.Key("k-c0"), ov.Key("k-c1")
g = {"oip": "1", "type": "Genesis", "kind": "collective", "created": ov.T0, "controller": {"keys": [c0.mk], "next": [ov.key_hash(c1.mk)]}}
g = ov.sign(g, ov.create_proof(g, c0, ov.did_key_vm(c0.mk), "capabilityInvocation", ov.T0))
try: ov.verify_log([g], ov.Registry()); print("vi) kind 'collective' with key controller: ACCEPTED (L1 3.6 forbids)")
except Exception as e: print("vi) rejected", e)
