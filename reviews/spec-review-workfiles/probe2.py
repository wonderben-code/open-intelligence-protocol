import copy, importlib.util, json
REPO = "/home/claude/open-intelligence-protocol/spec/test-vectors/"
s = importlib.util.spec_from_file_location("ov", REPO + "oip_vectors.py"); ov = importlib.util.module_from_spec(s); s.loader.exec_module(ov)
V = json.load(open(REPO + "vectors.json", encoding="utf-8")); C = V["cases"]
# a) identity event signed with the wrong proofPurpose
c0, c1 = ov.Key("w-c0"), ov.Key("w-c1")
g = {"oip": "1", "type": "Genesis", "kind": "agent", "created": ov.T0, "controller": {"keys": [c0.mk], "next": [ov.key_hash(c1.mk)]}}
g = ov.sign(g, ov.create_proof(g, c0, ov.did_key_vm(c0.mk), "assertionMethod", ov.T0))
try: ov.verify_log([g], ov.Registry()); print("a) Genesis signed with proofPurpose assertionMethod: ACCEPTED by oip_vectors.py (core 5.6: must not count)")
except ValueError as e: print("a) rejected", e)
# b) policy '==' true vs "True"
print("b) policy ['==','.x',true] with x='True':", ov.policy_ok([["==", ".x", True]], {"x": "True"}), "(spec 11.3: JCS forms differ -> false)")
# c) proof with forbidden extra member 'id'
it = {k: v for k, v in C["intent"].items() if k != "proof"}
p = ov.create_proof(it, ov.Key("amina-laptop"), C["intent"]["proof"][0]["verificationMethod"], "assertionMethod", it["created"], id="urn:x")
r = ov.Registry(); [r.add(C[n]) for n in ("amina_log",)]
print("c) proof containing 'id' counts in oip_vectors.py:", ov.verify_signed_by(ov.sign(it, p), C["amina"], r), "(core 5.2: MUST NOT contain id)")
# d) Bundle size: how many Update events before a Bundle exceeds 1 MiB
ev = C["amina_log"][1]; n = len(ov.jcs(ev)); print("d) one key-controlled Update with 2 op keys =", n, "bytes canonical -> Bundle exceeds 1 MiB after ~", (1 << 20) // n, "events")
# e) content-ID prefix: every content ID starts 'bciq'
import re
ids = set(re.findall(r"b[a-z2-7]{55}", json.dumps(C)))
print("e) all content IDs start with 'bciq':", all(i.startswith("bciq") for i in ids), len(ids))
