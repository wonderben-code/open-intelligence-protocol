import importlib.util, json
REPO = "/home/claude/open-intelligence-protocol/spec/test-vectors/"
s = importlib.util.spec_from_file_location("ov", REPO + "oip_vectors.py"); ov = importlib.util.module_from_spec(s); s.loader.exec_module(ov)
C = json.load(open(REPO + "vectors.json", encoding="utf-8"))["cases"]
gen, upd = C["amina_log"]
c1 = ov.Key("amina-control-1")           # revealed (already used) in Update seq 1
alt = {"oip": "1", "type": "Update", "mind": C["amina"], "seq": 1, "prev": ov.content_id(gen),
       "created": "2027-01-01T00:00:00Z",
       "controller": {"keys": [c1.mk], "next": [ov.key_hash(ov.Key("attacker-next").mk)]},
       "keys": [{"key": ov.Key("attacker-op").mk}]}
alt = ov.sign(alt, ov.create_proof(alt, c1, ov.did_key_vm(c1.mk), "capabilityInvocation", alt["created"]))
ov.verify_log([gen, alt], ov.Registry())
print("revealed control key of seq 1 -> conflicting seq-1 event verifies:", ov.content_id(alt) != ov.content_id(upd))
