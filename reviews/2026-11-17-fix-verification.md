# Fix verification: specification revision 2026-11-17

**Reviewer:** independent agent, 17 November 2026, with no access to the author's reasoning.
**Scope:** `spec/core.md`, `spec/layer-1-mind-network.md` (L1), `spec/layer-2-mind-web.md` (L2), `spec/layer-0-bridge.md` (L0), `spec/README.md`, `spec/CHANGELOG.md`, `papers/02-technical-architecture.md` (Draft 2), `spec/test-vectors/oip_vectors.py` and `vectors.json`, `BUILD.md`, checked against the findings of `reviews/2026-10-30-paper-review.md` (P-C1…P-I14) and `reviews/2026-10-30-spec-review.md` (S-C1…S-I21).
**Method:** read every document; ran `python3 spec/test-vectors/oip_vectors.py --check` (passes: 18 checks, 3 must-accept, 36 negative cases); built attack records with `oip_vectors.py` imported as a module. Probe scripts are outside the repository, in the reviewer's scratch directory (`fixcheck/`). No repository file other than this one was changed.

_Status: in progress._

## Summary

(to be completed)

## Verdicts on the earlier findings

(in progress)

## New findings

(draft notes, being expanded)

- N1 (Critical): revoked invocation keys, pinned to old versions, append a takeover event to a collective (probe `probe_time_keys.py` §2: checker accepts; spec L1 6.4 counts such proofs for every verifier that is not a witness).
- N2 (Important): checker keys evidence by content ID, so a proof added late inherits the record's first-seen time (probe §1: backdated proof by a compromised key counts; Commitment becomes `overdue`).
- N3 (Important): a member collective that deepens itself to height 4 invalidates every collective it belongs to (`probe_collectives.py` §1).
- N4 (Important): chain search over `authority` is exponential: ~1.2 µs per prefix, 582,913,216 prefixes for 16 entries (`probe_chain_dos.py`).
- N5 (Important): checker accepts mixed-order and small-order Ed25519 keys (OpenSSL 4.0.2 via `cryptography` 50.0.1), contrary to core 4.4 and BUILD.md §3; core 4.4 itself admits the identity point (`probe_ed25519.py`).
- N6 (Important): one proof counts for several parties; a role holder needs no `authority` member (`probe_time_keys.py` §4).
- N7 (Important): a stale max-`seq` Location signed by a former quorum stays current for a collective (`probe_collectives.py` §2).
- N8 (Minor): checker ignores the charter tie-break (`probe_collectives.py` §3) and the L2 5.2 author rule (`probe_time_keys.py` §5).
- Checked and sound: a forgery made after a compromise declaration shows `proposed`, not `disputed` (the key's removal, L1 6.1 item 3, rejects it).

## Verdict

(to be completed)
