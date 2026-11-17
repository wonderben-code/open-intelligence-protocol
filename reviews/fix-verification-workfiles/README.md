# Fix verification work files

The probe scripts behind [2026-11-17-fix-verification.md](../2026-11-17-fix-verification.md), written by the independent reviewer against the pre-publication candidate (commit `ab980a8`) and kept here for the record. Each runs as `python3 <script>` from this directory; `harness.py` imports the repository's checker.

| Script | Findings |
|---|---|
| `probe_time_keys.py` | N1 (collective takeover with removed invocation keys), N2 (evidence per proof), N6 (one proof for several parties), M9 (Commitment author rule) |
| `probe_collectives.py` | N3 (collective heights), N7 (stale `Location` of a collective), M9 (charter tie-break) |
| `probe_chain_dos.py` | N4 (exponential chain search) |
| `probe_ed25519.py` | N5 (small-order and mixed-order Ed25519 points) |
| `probe_misc.py` | N8 (outracing a removal), N9 (gateway proof on a bridged genesis) |

Run against the published revision, the attacks fail: the takeover is rejected, the chain check is immediate, a mixed-order key cannot be listed, and the multi-party abuses do not count. Some probes assume the candidate's data model and need adjusting to say what they intend: `probe_time_keys.py` section 1 records evidence by the record's content ID, where evidence is now kept per proof (its scenario is the vector `late-cosignature-backdated`); section 4 builds prices without `payer` and `payee`, which are now required; and `probe_collectives.py` section 1 expects a collective to be able to add a taller member, which heights fixed at genesis now forbid. N8 concerns which evidence a verifier must hold (core 9.4), which the probe can only illustrate.
