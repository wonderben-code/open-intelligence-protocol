---
"@oip/net": minor
---

- `SealedOpener`: a receiver of sealed records may give, for an agreement key, a function that opens with the key in place of the key itself. A keystore then opens a sealed packet without handing its key out. What an opener answers is checked: anything but bytes is a record that does not open.
