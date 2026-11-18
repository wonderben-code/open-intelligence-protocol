# @oip/delegation

Delegation for the [Open Intelligence Protocol](../../README.md): what one mind lets another sign for it, and whether a proof that says it acts for another does ([Layer 1, Section 11](../../spec/layer-1-mind-network.md)).

It is being built in milestone M3 of [BUILD.md](../../BUILD.md). So far it has the two parts that need no log and no evidence.

## Commands (Layer 1, 11.2)

A command is `/` and a segment, any number of times. `covers(granted, needed)` holds when the two are equal or `needed` goes on after a `/`, so a command covers by whole segments: `/x402/pay` covers `/x402/pay/usd` and does not cover `/x402/payments`.

Under `/oip` there are exactly five commands: `/oip/sign/Intent`, `/oip/sign/Offer`, `/oip/sign/Commitment`, `/oip/sign/Receipt` and `/oip/send`. Every other command whose first segment is `oip` is reserved, `/oip` and `/oip/sign` among them, so there are no blanket grants. `isDelegableCommand` says whether a command may be granted.

## Policies (Layer 1, 11.3)

A policy is a list of statements about the record being authorised, taken without its `proof`. `evaluatePolicy(policy, record)` answers whether every statement holds, and if not, which statement and why.

```ts
import { evaluatePolicy } from "@oip/delegation";

const policy = [
  ["==", ".terms.price.currency", "USD"],
  ["<=", ".terms.price.amount", "500"],
  ["all", ".parties", ["!=", ".mind", "did:oip:the-delegate"]],
];
evaluatePolicy(policy, commitment); // { ok: true, value: true }, or the statements that fail
```

Three rules shape it:

- **Ordering is defined between decimals and nothing else.** `<`, `<=`, `>` and `>=` compare integers and decimal strings by value. Asked of anything else, they are an error. `==` and `!=` compare by value where both sides are decimals (`5` equals `"5.0"`), and by canonical form otherwise.
- **Every statement is evaluated in full.** Nothing is skipped because an earlier part already decided the answer.
- **An error anywhere fails the policy.** A selector that does not resolve, an ordering on what is no decimal, a quantifier over what is no array: each fails the whole policy, even under `not` or `or`. So a policy that constrains a member which may be absent must require it.

A quantifier tries its statement on every element of an array, so a policy can ask for work in proportion to the record. One policy is evaluated for at most `MAX_POLICY_STEPS` statements (100,000), counting a statement once for each value it is tried on; a policy that needs more does not hold. The specification sets no such bound yet, which is a question queued for the maintainer.

Nothing here does I/O or reads a clock, and nothing throws on what arrives from outside.
