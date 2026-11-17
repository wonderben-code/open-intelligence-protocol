"""Shared harness: import the repository's checker and rebuild the vectors."""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "..", "spec", "test-vectors"))
sys.dont_write_bytecode = True
import oip_vectors as ov  # noqa: E402

VEC = ov.build()
C = VEC["cases"]
K = ov.Key


def vm(mind, event, key):
    return ov.op_vm(mind, event, key.mk)


def verifier(extra_logs=(), records=(), seen=None):
    return ov.verifier_for(C, extra_logs, records, seen)


def show(name, ok, expect, note=""):
    flag = "AS SPEC" if ok == expect else "DIFFERS FROM SPEC"
    print(f"[{flag}] {name}: checker says {ok!r}; spec says {expect!r}. {note}")
