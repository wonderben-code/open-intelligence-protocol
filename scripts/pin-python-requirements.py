#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
# SPDX-License-Identifier: Apache-2.0
"""
Writes .github/requirements/vector-checker.txt: the Python checker's
dependencies, pinned to exact versions with the SHA-256 of every file PyPI
serves for them, so that CI installs exactly those files.

Usage:  python3 scripts/pin-python-requirements.py cryptography==50.0.1 cffi==2.1.1 pycparser==3.0

With no arguments it re-pins the versions already in the file.
"""
import json
import re
import sys
import urllib.request
from pathlib import Path

TARGET = Path(__file__).resolve().parent.parent / ".github" / "requirements" / "vector-checker.txt"
HEADER = [
    "# Pinned, with hashes, so that CI installs exactly these files (pip --require-hashes).",
    "# The Python checker needs only `cryptography`; cffi and pycparser are its own dependencies.",
    "# Regenerate with scripts/pin-python-requirements.py when a new version is adopted.",
    "",
]


def pins(arguments):
    if arguments:
        return [argument.split("==") for argument in arguments]
    return re.findall(r"^([A-Za-z0-9_.-]+)==(\S+)", TARGET.read_text(), flags=re.M)


def main():
    lines = list(HEADER)
    for name, version in pins(sys.argv[1:]):
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json") as response:
            files = json.load(response)["urls"]
        hashes = sorted({file["digests"]["sha256"] for file in files})
        if not hashes:
            raise SystemExit(f"PyPI lists no files for {name}=={version}")
        lines.append(f"{name}=={version} \\")
        lines += [f"    --hash=sha256:{digest}" + (" \\" if i < len(hashes) - 1 else "")
                  for i, digest in enumerate(hashes)]
    TARGET.write_text("\n".join(lines) + "\n")
    print(f"{TARGET.name}: pinned {len(lines) - len(HEADER)} lines")


if __name__ == "__main__":
    main()
