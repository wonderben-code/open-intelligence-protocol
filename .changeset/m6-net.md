---
"@oip/net": minor
---

- `SealedOpener`: a receiver of sealed records may give, for an agreement key, a function that opens with the key in place of the key itself. A keystore then opens a sealed packet without handing its key out. What an opener answers is checked: anything but bytes is a record that does not open.
- `Sessions.held` and `Sessions.restore`, with `HeldSession` and `HeldChain`: what a receiver holds of a session as plain data, and a receiver made from it again. A receiver that stops keeps its place in every chain (Layer 1, 14.3).
