# Spec review working files

Snapshot of the scripts written by the independent specification reviewer on 30 October 2026, saved so the work is not lost if the session ends.

- `indep_check.py`: an independent re-implementation of the OIP rules, written from `spec/*.md` alone (it does not import `oip_vectors.py`), applied to every record in `vectors.json`. Run with `python3 indep_check.py ../../spec/test-vectors/vectors.json`.
- `probe*.py`, `dup.py`, `size.py`: probes of `oip_vectors.py` and the spec rules (divergences, attack constructions, duplicate keys, sizes).

The reviewer's findings are in [../2026-10-30-spec-review.md](../2026-10-30-spec-review.md) once complete. These scripts are review evidence, not part of the specification.
