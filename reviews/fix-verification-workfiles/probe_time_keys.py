"""Probes: evaluation-time evidence, stale invocation keys, disputed status,
one proof counting for several parties, Commitment author rule."""
import harness as h
ov = h.ov
C = h.C
K = h.K

amina, lexis, ltd = C["amina"], C["lexis_agent"], C["lexis_ltd"]
researcher, collective = C["researcher"], C["collective"]
a_gen, a_upd = C["amina_log"]
res_gen, res_upd = C["researcher_log"]
coll = C["collective_log"][0]
a_op1, a_op2, a_inv = K("amina-phone"), K("amina-laptop"), K("amina-invocation")
a_c2, a_c3 = K("amina-control-2"), K("amina-control-3")
r_c2, r_c3 = K("researcher-control-2"), K("researcher-control-3")
r_inv, r_op = K("researcher-invocation"), K("researcher-ops")
t_op, t_inv = K("lexis-agent-i1"), K("lexis-agent-invocation")
fork_ev = C["lexis_agent_log"][1]
amina_vm1 = h.vm(amina, a_upd, a_op1)
amina_inv = h.vm(amina, a_upd, a_inv)
res_inv = h.vm(researcher, res_upd, r_inv)
agent_vm = h.vm(lexis, fork_ev, t_op)

print("=== 1. Evidence is per proof in core 9.3-9.4, per content ID in the checker")
# Amina's phone key is declared compromised since 31 Oct 00:00 (event of 2 Nov).
a_cmp = ov.control_event("Update", amina, a_upd, "2026-11-02T08:00:00Z",
                         [a_c2], [a_c3], fields={
                             "keys": [{"key": a_op2.mk, "label": "amina-laptop"}],
                             "revoked": [{"key": a_op1.mk,
                                          "compromisedSince": "2026-10-31T00:00:00Z"}]})
proposed = C["commitment_proposed"]          # agent-signed only, 30 Oct 10:20
# The verifier saw the proposal on 30 Oct 10:20 (own first-seen record).
seen = {ov.content_id(proposed): "2026-10-30T10:20:00Z"}
# On 5 Nov a thief who holds the phone key adds "Amina's" proof dated 30 Oct.
p_thief = ov.create_proof(proposed, a_op1, amina_vm1, "assertionMethod",
                          "2026-10-30T10:25:00Z")
completed = ov.sign(proposed, p_thief)
V = h.verifier(extra_logs=[[a_gen, a_upd, a_cmp]], seen=seen)
ok = V.counts_for(completed, amina)
h.show("late-added proof by compromised key, record seen early", ok, False,
       "Spec: tau(p) is when the verifier first obtained *this proof* (5 Nov), "
       "after compromisedSince; the checker uses the record's first-seen time.")
print("   status:", ov.commitment_status(V, completed, [completed],
                                         ov.ts("2026-11-06T00:00:00Z")))

print("\n=== 2. Revoked invocation keys append a takeover event to the collective")
thief = K("thief-ops")
a_inv_rev = ov.control_event(
    "Update", amina, a_upd, "2026-11-02T08:00:00Z", [a_c2], [a_c3],
    fields={"invocation": [], "revoked": [{"key": a_inv.mk,
                                           "compromisedSince": "2026-11-01T00:00:00Z"}]})
r_inv_rev = ov.control_event(
    "Update", researcher, res_upd, "2026-11-02T09:00:00Z", [r_c2], [r_c3],
    fields={"invocation": [], "revoked": [{"key": r_inv.mk,
                                           "compromisedSince": "2026-11-01T00:00:00Z"}]})
# 1 Dec: thief signs with both stolen (revoked) invocation keys, pinned to old
# versions, and gives the collective an operational key of its own.
takeover = ov.member_event("Update", collective, coll, "2026-12-01T00:00:00Z",
                           [(a_inv, amina_inv), (r_inv, res_inv)],
                           {"keys": [{"key": thief.mk, "label": "ops"}]})
V2 = h.verifier(extra_logs=[[a_gen, a_upd, a_inv_rev], [res_gen, res_upd, r_inv_rev],
                            [coll, takeover]])
try:
    log = V2.log(collective)
    print("   checker ACCEPTS the takeover; collective keys now:", log.latest.keys == [thief.mk])
except ValueError as e:
    print("   checker rejects:", e)
# The thief now signs a Delegation as the collective (own authority).
d = {"oip": "1", "type": "Delegation", "author": collective,
     "created": "2026-12-01T00:10:00Z", "delegate": lexis, "subject": collective,
     "command": "/oip/sign/Commitment", "policy": [],
     "expires": "2027-12-01T00:00:00Z", "nonce": "thiefnonce01"}
d = h.ov.signed(d, thief, ov.op_vm(collective, takeover, thief.mk))
print("   thief's Delegation counts for the collective:", V2.counts_for(d, collective))

print("\n=== 3. A forgery made after the compromise declaration shows as 'disputed'")
a_decl = ov.control_event("Update", amina, a_upd, "2026-11-02T08:00:00Z",
                          [a_c2], [a_c3], fields={
                              "keys": [{"key": a_op2.mk, "label": "amina-laptop"}],
                              "revoked": [{"key": a_op1.mk,
                                           "compromisedSince": "2026-10-30T10:00:00Z"}]})
r_vm = ov.op_vm(researcher, res_gen, r_op.mk)
forged = {"oip": "1", "type": "Commitment", "author": researcher,
          "created": "2026-11-10T00:00:00Z",
          "parties": [{"mind": amina, "role": "debtor", "required": True},
                      {"mind": researcher, "role": "creditor", "required": True}],
          "promise": "Amina will pay the researcher 5000 USD.",
          "terms": {"price": {"amount": "5000", "currency": "USD"}}}
forged = ov.sign(forged,
                 ov.create_proof(forged, r_op, r_vm, "assertionMethod", forged["created"]),
                 ov.create_proof(forged, a_op1, amina_vm1, "assertionMethod",
                                 "2026-11-10T00:00:00Z"))
V3 = h.verifier(extra_logs=[[a_gen, a_upd, a_decl]],
                seen={ov.content_id(forged): "2026-11-10T00:00:00Z"})
st = ov.commitment_status(V3, forged, [forged], ov.ts("2026-11-11T00:00:00Z"))
print(f"   status of a commitment forged on 10 Nov with a key Amina disowned on 2 Nov: {st!r}"
      " (L2 8.3 step 1 reads this as Amina withdrawing her own signature)")

print("\n=== 4. One proof counts for several parties")
deleg_ref = ov.record_ref(ltd, C["delegation"])
self_deal = {"oip": "1", "type": "Commitment", "author": lexis,
             "created": "2026-10-30T12:00:00Z",
             "parties": [{"mind": ltd, "role": "debtor", "required": True},
                         {"mind": lexis, "role": "creditor", "required": True}],
             "promise": "Lexis Ltd will pay its own agent 500 USD.",
             "terms": {"price": {"amount": "500", "currency": "USD"}}}
self_deal = ov.signed(self_deal, t_op, agent_vm, authority=[deleg_ref])
V4 = h.verifier()
print("   agent alone binds Lexis Ltd to pay the agent (delegation):",
      ov.commitment_accepted(V4, self_deal))
steward = {"oip": "1", "type": "Commitment", "author": lexis,
           "created": "2026-10-30T12:00:00Z",
           "parties": [{"mind": collective, "role": "debtor", "required": True},
                       {"mind": lexis, "role": "creditor", "required": True}],
           "promise": "The collective will pay its steward 500 USD.",
           "terms": {"price": {"amount": "500", "currency": "USD"}}}
steward = ov.signed(steward, t_op, agent_vm)      # no authority member at all
print("   steward alone binds the collective to pay the steward (role, no "
      "authority member):", ov.commitment_accepted(V4, steward))
# Dual agency: Lexis Ltd also delegates to Amina's assistant.
s_op = K("amina-assistant-ops")
asst = C["assistant"]
asst_gen = C["assistant_log"][0]
asst_vm = ov.op_vm(asst, asst_gen, s_op.mk)
l_op = K("lexisltd-ops")
ltd_vm = ov.op_vm(ltd, C["lexis_ltd_log"][0], l_op.mk)
d2 = ov.signed({"oip": "1", "type": "Delegation", "author": ltd,
                "created": "2026-10-30T09:31:00Z", "delegate": asst, "subject": ltd,
                "command": "/oip/sign/Commitment",
                "policy": [["==", ".terms.price.currency", "USD"],
                           ["<=", ".terms.price.amount", "500"]],
                "expires": "2026-11-30T09:30:00Z", "nonce": "dualagency01"}, l_op, ltd_vm)
both = {"oip": "1", "type": "Commitment", "author": asst,
        "created": "2026-10-30T12:00:00Z",
        "parties": [{"mind": ltd, "role": "debtor", "required": True},
                    {"mind": amina, "role": "creditor", "required": True}],
        "promise": "Lexis Ltd will translate; Amina pays 150 USD.",
        "terms": {"price": {"amount": "150", "currency": "USD"}}}
both = ov.signed(both, s_op, asst_vm,
                 authority=[ov.record_ref(amina, C["delegation_amina"]),
                            ov.record_ref(ltd, d2)])
V5 = h.verifier(records=[d2])
print("   one proof by one agent accepts a deal between its two principals:",
      ov.commitment_accepted(V5, both))

print("\n=== 5. Commitment author must be a party or a party's delegate (L2 5.2)")
outsider = {"oip": "1", "type": "Commitment", "author": researcher,
            "created": "2026-10-30T12:00:00Z",
            "parties": [{"mind": ltd, "role": "debtor", "required": True},
                        {"mind": amina, "role": "creditor", "required": True}],
            "promise": "Lexis Ltd will translate; Amina pays 100 USD.",
            "terms": {"price": {"amount": "100", "currency": "USD"}}}
outsider = ov.sign(outsider,
                   ov.create_proof(outsider, r_op, r_vm, "assertionMethod", outsider["created"]),
                   ov.create_proof(outsider, l_op, ltd_vm, "assertionMethod", outsider["created"]),
                   ov.create_proof(outsider, a_op1, amina_vm1, "assertionMethod", outsider["created"]))
h.show("commitment authored by a non-party", ov.commitment_accepted(V4, outsider), False,
       "L2 5.2: the author MUST be a party or a delegate of one.")
