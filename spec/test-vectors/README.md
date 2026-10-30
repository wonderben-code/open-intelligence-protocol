# OIP Test Vectors

**Revision 2026-10-30 · Status: Draft**

`vectors.json` contains deterministic records for the scenario used throughout the papers: Amina (a person), Lexis Ltd (an institution), the Lexis translation agent and its fork, a research agent, and a 2-of-3 collective. It includes identity logs, a delegation, a location record, a Participant profile, a feed entry, a context packet, and an Intent, Offer, Commitment and Receipt.

`oip_vectors.py` is an independent, dependency-light Python implementation of the core algorithms. It generates the vectors and checks them:

```
python3 oip_vectors.py           # regenerate vectors.json and check it
python3 oip_vectors.py --check   # check the existing vectors.json
```

It needs only the `cryptography` package.

The checks cover: address derivation, identity-log verification with pre-rotation, fork lineage, rejection of a tampered rotation, signatures on every record, delegation policy enforcement (a 120 USD commitment is within the agent's authority; 900 USD is not), co-signing without changing a content ID, the 2-of-3 collective threshold, and JCS canonicalisation.

**All keys are derived from public seeds** (`SHA-256("oip-test-vector:" + label)`). They are for testing only and must never be used for anything real.

Implementations claiming conformance must reproduce every value here that falls within the profiles they claim. Vectors for sealing (HPKE), checkpoints and sessions with resumption will be added by the reference implementation, in both this generator and the TypeScript tests.
