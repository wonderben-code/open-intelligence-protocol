#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
# SPDX-License-Identifier: Apache-2.0
"""
Writes a requirements file under .github/requirements/ with every package
pinned to an exact version and the SHA-256 of every file PyPI serves for it,
so that CI installs exactly those files (pip --require-hashes).

Usage:  python3 scripts/pin-python-requirements.py vector-checker.txt cryptography==50.0.1 cffi==2.1.1 pycparser==3.0
        python3 scripts/pin-python-requirements.py reuse.txt            (re-pins the versions already in the file)

List every package the tool needs, with its own dependencies: with hashes,
pip installs nothing that is not listed.
"""
import json
import re
import sys
import urllib.request
from pathlib import Path

DIRECTORY = Path(__file__).resolve().parent.parent / ".github" / "requirements"
HEADER = [
    "# Pinned, with hashes, so that CI installs exactly these files (pip --require-hashes).",
    "# Every package is listed, with its own dependencies.",
    "# Regenerate with scripts/pin-python-requirements.py when a new version is adopted.",
    "",
]


def pins(target, arguments):
    if arguments:
        return [argument.split("==") for argument in arguments]
    return re.findall(r"^([A-Za-z0-9_.-]+)==(\S+)", target.read_text(), flags=re.M)


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    target = DIRECTORY / sys.argv[1]
    lines = list(HEADER)
    for name, version in pins(target, sys.argv[2:]):
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json") as response:
            files = json.load(response)["urls"]
        hashes = sorted({file["digests"]["sha256"] for file in files})
        if not hashes:
            raise SystemExit(f"PyPI lists no files for {name}=={version}")
        lines.append(f"{name}=={version} \\")
        lines += [f"    --hash=sha256:{digest}" + (" \\" if i < len(hashes) - 1 else "")
                  for i, digest in enumerate(hashes)]
    target.write_text("\n".join(lines) + "\n")
    print(f"{target.name}: pinned {len(lines) - len(HEADER)} lines")


if __name__ == "__main__":
    main()
