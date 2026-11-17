"""Probes: gateway proof purpose on a bridged Genesis; removal race for a
verifier without witness evidence."""
import harness as h
ov = h.ov
K = h.K
C = h.C

print("=== 1. L0 1.2 gateway proof (assertionMethod) on a bridged Genesis")
gw_c0, gw_c1, gw_op = K("gw-c0"), K("gw-c1"), K("gw-op")
gw_gen = ov.key_controlled_genesis("service", gw_c0, gw_c1, [gw_op])
gw = ov.did(ov.content_id(gw_gen))
b_c0, b_c1, b_op = K("br-c0"), K("br-c1"), K("br-op")
g = {"oip": "1", "type": "Genesis", "kind": "service", "created": "2026-10-30T09:00:00Z",
     "controller": {"keys": [b_c0.mk], "next": [ov.key_hash(b_c1.mk)], "nextThreshold": 1},
     "keys": [{"key": b_op.mk}],
     "ext": {"oip.bridge": {"protocol": "mcp", "endpoint": "https://tools.example/mcp",
                            "gateway": gw, "assurance": "bridged"}}}
gp_assert = ov.create_proof(g, gw_op, ov.op_vm(gw, gw_gen, gw_op.mk), "assertionMethod", g["created"])
g = ov.sign(g, ov.create_proof(g, b_c0, ov.did_key_vm(b_c0.mk), "capabilityInvocation", g["created"]),
            gp_assert)
V = ov.Verifier(logs=[[gw_gen], [g]])
print("   bridged genesis log verifies:", bool(V.log(ov.did(ov.content_id(g)))))
print("   gateway's assertionMethod proof is by a valid key of the gateway (core 5.4/5.6, L1 6.1):",
      V.valid_key(g, gp_assert, gw))
gp_inv = ov.create_proof(g, gw_op, ov.op_vm(gw, gw_gen, gw_op.mk), "capabilityInvocation",
                         g["created"])
print("   same proof with capabilityInvocation instead:", V.valid_key(g, gp_inv, gw),
      "(and operational keys are not capabilityInvocation keys in the DID document)")

print("\n=== 2. Removal race: verifier saw the proof before it saw the removal")
amina = C["amina"]
a_gen, a_upd = C["amina_log"]
a_op1, a_op2 = K("amina-phone"), K("amina-laptop")
rm = ov.control_event("Update", amina, a_upd, "2026-11-02T08:00:00Z",
                      [K("amina-control-2")], [K("amina-control-3")],
                      fields={"keys": [{"key": a_op2.mk, "label": "amina-laptop"}]})
# A former holder of the phone key signs on 3 Nov; the verifier receives it on
# 3 Nov and only fetches Amina's log (with the 2 Nov removal) on 4 Nov.
rec = ov.signed(ov.variant_of(C["intent"], created="2026-11-03T08:00:00Z",
                              expires="2026-11-09T08:00:00Z"),
                a_op1, ov.op_vm(amina, a_upd, a_op1.mk))
seen = {ov.content_id(rec): "2026-11-03T08:00:00Z",
        ov.content_id(rm): "2026-11-04T08:00:00Z"}
V = h.verifier(extra_logs=[[a_gen, a_upd, rm]], seen=seen)
print("   record signed a day AFTER the removal counts:", V.counts_for(rec, amina),
      "(removal's evaluation time is the verifier's own first sight of it)")
seen[ov.content_id(rm)] = "2026-11-02T08:00:00Z"     # with a witness's first-seen time
V = h.verifier(extra_logs=[[a_gen, a_upd, rm]], seen=seen)
print("   same, with witness evidence for the removal:", V.counts_for(rec, amina))
