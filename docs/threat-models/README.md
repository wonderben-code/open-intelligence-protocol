# Threat models

One for each service and each tool (BUILD.md 3.7). Each says what the thing protects, who can reach it and how, what could go wrong, what stops it, and what is left.

| Model                      | What it covers                                                           |
| -------------------------- | ------------------------------------------------------------------------ |
| [resolver.md](resolver.md) | `@oip/resolver`: publication, resolution, the stream, duplicity evidence |

## How they are written

- **Assets**: what would be lost or made false.
- **Who can reach it**: the entry points, and what each caller is trusted with. A caller is trusted with nothing unless the model says so.
- **Threats**, by the six kinds of STRIDE: spoofing, tampering, repudiation, information disclosure, denial of service, elevation of privilege. Each has what stops it, with the code and the test that show it, and what is left.
- **Left open**: what is not stopped, and where it is tracked.

A model is kept with the code. A change that adds an entry point, a setting or a kind of stored data changes the model in the same commit.
