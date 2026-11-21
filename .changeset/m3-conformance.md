---
"@oip/conformance": minor
---

The reference adapter judges signing through a delegation chain and through a charter role (`countsFor`), sending on another mind's behalf (`sentFor`) and status (`status`), with `@oip/delegation` and `@oip/web`. The seven positive checks of delegation, charter roles and status run: a packet sent on another's behalf, co-signing, two agents signing for their principals, the amounts a delegation's policy allows, a two-step chain, a collective's threshold and role, and every status of an Intent, an Offer and a Commitment.

Differential testing against the Python checker covers delegation and status: generated policies, generated delegation chains with a record signed under each, and generated sets of Layer 2 records whose status is asked; and, made by hand with the answer each must give, 63 policies and every way a chain that counts is changed. `pnpm test:differential:delegation` runs it, and the Python checker answers a `policy` question for it.
