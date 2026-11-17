"""Probe: chain search over a proof's `authority` is exponential."""
import time
import math
import harness as h
ov = h.ov
K = h.K
C = h.C
ltd, lexis = C["lexis_ltd"], C["lexis_agent"]
t_op = K("lexis-agent-i1")
agent_vm = ov.op_vm(lexis, C["lexis_agent_log"][1], t_op.mk)
base = ov.variant_of(C["commitment_proposed"])

for n in (7, 8, 9, 10):
    junk = [{"oip": "1", "type": "Delegation", "author": ltd, "delegate": ltd,
             "subject": ltd, "command": "/oip/sign/Commitment", "policy": [],
             "created": "2026-10-30T09:00:00Z", "expires": "2026-11-30T00:00:00Z",
             "nonce": f"junknonce{i:03d}"} for i in range(n)]   # unsigned, inline
    rec = ov.signed(base, t_op, agent_vm, authority=junk)
    V = h.verifier()
    t0 = time.time()
    ok = V.counts_for(rec, ltd)
    dt = time.time() - t0
    paths = sum(math.perm(n, k) for k in range(1, 9))
    print(f"authority of {n:2d} junk delegations: {paths:>12,} prefixes explored, "
          f"{dt:7.2f} s, counts={ok}")
paths16 = sum(math.perm(16, k) for k in range(1, 9))
print(f"authority of 16 (the maximum): {paths16:,} prefixes per principal checked")
