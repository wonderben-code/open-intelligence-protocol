"""Probes: collective height griefing, stale Location lockout, charter tie-break."""
import harness as h
ov = h.ov
K = h.K
T = "2026-10-30T09:00:00Z"


def person(label):
    c0, c1 = K(label + "-c0"), K(label + "-c1")
    op, inv = K(label + "-op"), K(label + "-inv")
    g = ov.key_controlled_genesis("agent", c0, c1, [op], created=T,
                                  extra={"invocation": [{"key": inv.mk}]})
    addr = ov.did(ov.content_id(g))
    return {"log": [g], "addr": addr, "inv": inv,
            "inv_vm": ov.op_vm(addr, g, inv.mk),
            "op": op, "op_vm": ov.op_vm(addr, g, op.mk)}


def collective(label, members, threshold, created="2026-10-30T09:30:00Z", with_inv=True,
               ops=None):
    g = {"oip": "1", "type": "Genesis", "kind": "collective", "created": created,
         "controller": {"members": [m["addr"] for m in members], "threshold": threshold}}
    inv = K(label + "-inv")
    if with_inv:
        g["invocation"] = [{"key": inv.mk}]
    g = ov.sign(g, *[ov.create_proof(g, m["inv"], m["inv_vm"], "capabilityInvocation",
                                     created) for m in members])
    addr = ov.did(ov.content_id(g))
    return {"log": [g], "addr": addr, "inv": inv, "inv_vm": ov.op_vm(addr, g, inv.mk)}


def V_of(*minds, records=(), seen=None):
    V = ov.Verifier(seen=seen)
    for m in minds:
        V.add_log(m["log"])
    for r in records:
        V.add(r)
    return V


P = {n: person(n) for n in ["p1", "p2", "p3", "p4", "p5", "p6", "p7",
                             "p8", "p9", "p10", "q1", "q2"]}
D1 = collective("D1", [P["p1"], P["p2"], P["p3"]], 2)
D2 = collective("D2", [D1, P["p4"], P["p5"]], 2)
D3 = collective("D3", [D2, P["p6"], P["p7"]], 2)
C1 = collective("C1", [P["p8"], P["p9"], P["p10"]], 2)
Y = collective("Y", [C1, P["q1"], P["q2"]], 2, created="2026-10-30T10:00:00Z")
everyone = list(P.values()) + [D1, D2, D3, C1, Y]

print("=== 1. A member collective can invalidate the collective it belongs to")
V = V_of(*everyone)
print("   before: Y verifies with height", V.log(Y["addr"]).height)
# Later, C1's own members (without Y's other members) add D3 to C1.
upd = ov.member_event("Update", C1["addr"], C1["log"][0], "2026-11-05T00:00:00Z",
                      [(P[n]["inv"], P[n]["inv_vm"]) for n in ("p8", "p9", "p10")] +
                      [(D3["inv"], D3["inv_vm"])],
                      {"controller": {"members": [P["p8"]["addr"], P["p9"]["addr"],
                                                  P["p10"]["addr"], D3["addr"]],
                                      "threshold": 3}})
C1b = dict(C1, log=C1["log"] + [upd])
V = V_of(*[m for m in everyone if m is not C1], C1b)
print("   C1 alone after adding D3: height", V.log(C1["addr"]).height, "(valid)")
V = V_of(*[m for m in everyone if m is not C1], C1b)
try:
    V.log(Y["addr"])
    print("   after: Y still verifies")
except ValueError as e:
    print("   after: Y's whole log is REJECTED:", e)

print("\n=== 2. A stale max-seq Location signed by a former quorum stays current")
coll = h.C["collective_log"][0]
cid = h.C["collective"]
amina, lexis, researcher = h.C["amina"], h.C["lexis_agent"], h.C["researcher"]
a_upd = h.C["amina_log"][1]
res_gen = h.C["researcher_log"][0]
fork_ev = h.C["lexis_agent_log"][1]
a_op1, r_op, t_op = K("amina-phone"), K("researcher-ops"), K("lexis-agent-i1")
loc_old = {"oip": "1", "type": "Location", "author": cid, "seq": 2**53 - 1,
           "created": "2026-10-30T12:00:00Z", "ttl": 900, "status": "active",
           "endpoints": [{"binding": "https", "url": "https://evil.example/oip",
                          "priority": 1}]}
loc_old = ov.sign(loc_old,
                  ov.create_proof(loc_old, a_op1, ov.op_vm(amina, a_upd, a_op1.mk),
                                  "assertionMethod", loc_old["created"]),
                  ov.create_proof(loc_old, r_op, ov.op_vm(researcher, res_gen, r_op.mk),
                                  "assertionMethod", loc_old["created"]))
# 31 Oct: the collective removes the researcher (new members Amina, Lexis agent).
c_rm = ov.member_event("Update", cid, coll, "2026-10-31T00:00:00Z",
                       [(K("amina-invocation"), ov.op_vm(amina, a_upd, K("amina-invocation").mk)),
                        (K("lexis-agent-invocation"),
                         ov.op_vm(lexis, fork_ev, K("lexis-agent-invocation").mk))],
                       {"controller": {"members": [amina, lexis], "threshold": 2}})
V2 = h.verifier(extra_logs=[[coll, c_rm]],
                seen={ov.content_id(loc_old): "2026-10-30T12:00:00Z"})
print("   old max-seq Location (signed by Amina and the since-removed researcher,"
      " first seen 30 Oct) counts for the collective on 1 Dec:",
      V2.counts_for(loc_old, cid),
      "-> no later Location can have a higher seq")

print("\n=== 3. Charter tie-break (L2 6.2: same completion time -> lower content ID)")
charter = h.C["collective_charter"]
base = ov.variant_of(charter)
alt = ov.variant_of(charter, assignments=[{"mind": researcher, "role": "steward"}])
amina_vm1 = ov.op_vm(amina, a_upd, a_op1.mk)
res_vm = ov.op_vm(researcher, res_gen, r_op.mk)


def by_two(doc):
    return ov.sign(doc, ov.create_proof(doc, a_op1, amina_vm1, "assertionMethod", doc["created"]),
                   ov.create_proof(doc, r_op, res_vm, "assertionMethod", doc["created"]))


c_a, c_b = by_two(base), by_two(alt)
lower = min((ov.content_id(c_a), "lexis is steward"), (ov.content_id(c_b), "researcher is steward"))
steward = h.C["commitment_by_steward"]
res_commit = ov.signed(ov.variant_of(steward), r_op, res_vm)
results = []
for order in ((c_a, c_b), (c_b, c_a)):
    V3 = ov.Verifier(logs=[h.C[n] for n in ov.LOG_NAMES])
    for r in order:
        V3.add(r)
    results.append((V3.counts_for(steward, cid), V3.counts_for(res_commit, cid)))
print("   charter in force by spec:", lower[1])
print("   (lexis steward commit counts, researcher steward commit counts) by insertion order:",
      results, "-> result depends on store order, not on content ID")
