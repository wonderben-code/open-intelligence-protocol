import copy, importlib.util, json
REPO = "/home/claude/open-intelligence-protocol/spec/test-vectors/"
s = importlib.util.spec_from_file_location("ov", REPO + "oip_vectors.py"); ov = importlib.util.module_from_spec(s); s.loader.exec_module(ov)
C = json.load(open(REPO + "vectors.json", encoding="utf-8"))["cases"]
r = ov.Registry()
for n in ("amina_log", "lexis_ltd_log", "lexis_agent_log", "lexis_fork_log", "researcher_log", "collective_log"): r.add(C[n])
for amt, cur in (("4,000,000", "USD"), ("500", "BTC")):
    doc = {k: v for k, v in copy.deepcopy(C["commitment_accepted"]).items() if k != "proof"}
    doc["terms"]["price"] = {"amount": amt, "currency": cur}
    doc["promise"] = f"Lexis Ltd will pay {amt} {cur}."
    doc = ov.sign(doc, ov.create_proof(doc, ov.Key("lexis-agent-i1"), C["commitment_accepted"]["proof"][0]["verificationMethod"], "assertionMethod", doc["created"]))
    print(f"Commitment binding Lexis Ltd to {amt} {cur}: counts for Lexis Ltd under the 500 cap ->", ov.verify_signed_by(doc, C["lexis_ltd"], r, delegations=[C["delegation"]]))
