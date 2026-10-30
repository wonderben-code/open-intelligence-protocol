import copy, importlib.util, json, re
REPO = "/home/claude/open-intelligence-protocol/spec/test-vectors/"
s = importlib.util.spec_from_file_location("ov", REPO + "oip_vectors.py"); ov = importlib.util.module_from_spec(s); s.loader.exec_module(ov)
C = json.load(open(REPO + "vectors.json", encoding="utf-8"))["cases"]
# unknown event type in a key-controlled log
c0, c1, c2 = ov.Key("u-c0"), ov.Key("u-c1"), ov.Key("u-c2")
g = {"oip": "1", "type": "Genesis", "kind": "agent", "created": ov.T0, "controller": {"keys": [c0.mk], "next": [ov.key_hash(c1.mk)]}}
g = ov.sign(g, ov.create_proof(g, c0, ov.did_key_vm(c0.mk), "capabilityInvocation", ov.T0))
e = {"oip": "1", "type": "Frobnicate", "mind": ov.did(ov.content_id(g)), "seq": 1, "prev": ov.content_id(g), "created": ov.T0,
     "controller": {"keys": [c1.mk], "next": [ov.key_hash(c2.mk)]}}
e = ov.sign(e, ov.create_proof(e, c1, ov.did_key_vm(c1.mk), "capabilityInvocation", ov.T0))
try: ov.verify_log([g, e], ov.Registry()); print("i) key-controlled log with event type 'Frobnicate': ACCEPTED")
except ValueError as x: print("i) rejected", x)
# revoked handling: 'revoked' with compromisedSince is ignored entirely
src = open(REPO + "oip_vectors.py").read()
print("ii) 'revoked' / 'compromisedSince' / 'notBefore' referenced in oip_vectors.py:", "revoked" in src, "compromisedSince" in src, "notBefore" in src)
# version-id with wrong seq part
ver = "5-" + C["content_ids"]["amina_update"]
try: ov.verify_log(C["amina_log"], ov.Registry(), upto_version=ver); print("iii) wrong-seq version-id accepted")
except ValueError as x: print("iii) wrong-seq version-id rejected:", x)
# canonical base32 structure of content IDs
ids = set(re.findall(r"b[a-z2-7]{55}", json.dumps(C)))
print("iv) 5th char range:", sorted({i[4] for i in ids}), "| last char:", sorted({i[-1] for i in ids}))
