#!/usr/bin/env python3
"""
Open Intelligence Protocol (OIP): test-vector generator and checker.

A dependency-light Python implementation of the core OIP algorithms in
spec/ (core, Layer 1, Layer 2) and Appendix A of
papers/02-technical-architecture.md:

  * JCS canonicalisation (RFC 8785) for OIP's restricted JSON profile
  * content IDs, key hashes and Multikeys
  * W3C Data Integrity proofs (eddsa-jcs-2022) with proof purposes, and
    strict Ed25519 verification (core 4.4: S < L, A and R of order L)
  * did:oip identity logs: pre-rotation, majority thresholds, forks,
    lineage, collectives and their heights, key removal, compromise,
    retirement, and duplicity resolved by first-seen evidence
  * evaluation times: time rules use evidence (per proof, and per event
    for identity events), never a signer's own claim
  * delegation chains (exactly as listed, root first), policies that fail
    closed, revocation, and packets sent on another mind's behalf
  * collective threshold signing and charter roles
  * Layer 2 status (Intent, Offer, Commitment) and bridged-mind assurance

It writes vectors.json, with positive cases, cases that must be accepted,
negative cases that every implementation must reject, and controls showing
that each negative case fails only for its stated reason, and checks it.

Run:  python3 oip_vectors.py            -> writes vectors.json and checks it
      python3 oip_vectors.py --check    -> checks an existing vectors.json
      python3 oip_vectors.py --judge    -> reads cases in the vectors' format
                                           on standard input and prints one
                                           verdict per case (see judge())

Requires only the `cryptography` package. Licensed Apache-2.0.
STATUS: DRAFT. Tracks the spec revision in REVISION and may change.
"""
import base64
import copy
import hashlib
import json
import re
import sys
from decimal import Decimal
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

REVISION = "2026-11-17"
OIP_VERSION = "1"
MAX_SAFE_INT = 2**53 - 1
RAW = serialization.Encoding.Raw, serialization.PublicFormat.Raw
SKEW_NS = 300 * 10**9           # clock-skew tolerance (core 9.1)

MAX_PROOFS = 256                # proofs per record
MAX_CHAIN = 8                   # delegations per chain
MAX_AUTHORITY = 8               # entries in a proof's `authority`
MAX_NESTING = 4                 # greatest collective height
MAX_DEPTH = 64                  # nesting of arrays and objects (core 1.9)
MAX_RECORD_BYTES = 2**20        # canonical form of a record (core 1.6)
MAX_DURATION = 64               # characters in a duration (core 1.5)

IDENTITY_TYPES = ("Genesis", "Update", "Fork", "Merge", "Retire")
# Every record type this revision defines (core 11). `Merge` is reserved.
RECORD_TYPES = IDENTITY_TYPES + (
    "Delegation", "Revocation", "Lineage", "Collective", "Intent", "Offer",
    "Commitment", "Receipt", "Packet", "Entry", "Checkpoint", "Ack",
    "QueryResult", "Forwarded", "Location", "Participant", "Hello",
    "Session", "Resume", "Branch", "Bundle", "LogPage", "FeedPage",
    "DuplicityEvidence", "Sealed")
# The containers (core 1.6), and for each the members that hold the records
# it carries. The limits on size and depth apply to each carried record and
# to the container without them.
CONTAINERS = {"Bundle": ("log", "location", "participant"),
              "LogPage": ("events",), "FeedPage": ("entries",),
              "DuplicityEvidence": ("pairs",)}
SHORT_NAMESPACES = ("x402", "ap2", "acp", "l402", "vc", "as2")   # core 8.1
NAMESPACE_RE = re.compile(r"[a-z0-9-]+(\.[a-z0-9-]+)+")
CURRENT_STATE_TYPES = ("Location", "Participant", "Hello")
DELEGABLE_TYPES = ("Intent", "Offer", "Commitment", "Receipt")
OIP_COMMANDS = ("/oip/send",) + tuple("/oip/sign/" + t
                                      for t in DELEGABLE_TYPES)
RECEIPT_OUTCOMES = ("accepted", "progress", "fulfilled", "broken",
                    "cancelled", "disputed", "revoked")

CID = r"bciq[a-p][a-z2-7]{50}[aiqy]"   # the one canonical spelling
CID_RE = re.compile(CID)
ADDR_RE = re.compile(r"did:oip:" + CID)
RECREF_RE = re.compile(r"did:oip:" + CID + r"/(" + CID + r")")
B58 = "[1-9A-HJ-NP-Za-km-z]"
KEYREF_RE = re.compile(r"(did:oip:" + CID + r")\?versionId="
                       r"((?:0|[1-9][0-9]*)-" + CID + r")#(z" + B58 + r"+)")
CTLREF_RE = re.compile(r"did:key:(z" + B58 + r"+)#(z" + B58 + r"+)")
DECIMAL_RE = re.compile(r"-?(0|[1-9][0-9]*)(\.[0-9]+)?")
NONNEG_DECIMAL_RE = re.compile(r"(0|[1-9][0-9]*)(\.[0-9]+)?")
TS_RE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):"
                   r"([0-9]{2})(?:\.([0-9]{1,9}))?Z")
COMMAND_RE = re.compile(r"/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*")
# The form of a public key as a Multikey (core 4.1): necessary, not
# sufficient. The keys are decoded, and their points checked, where used.
ED_MK_RE = re.compile("z6Mk" + B58 + "{44}")
X_MK_RE = re.compile("z6LS" + B58 + "{44}")
VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)-" + CID)
# An HTTPS origin (Layer 1, 3.13): `https://`, then a host and an optional
# port written with ASCII letters, digits and . - : [ ] only.
ORIGIN_RE = re.compile(r"https://[A-Za-z0-9.:\[\]-]+")
SEL_TOKEN = re.compile(r'\.([A-Za-z0-9_]+)|\[(0|[1-9][0-9]*)\]|'
                       r'\[("(?:[^"\\]|\\.)*")\]')
MAX_POLICY_DEPTH = 8
ORDERING_OPS = ("<", "<=", ">", ">=")
OPS = ("==", "!=") + ORDERING_OPS


def fullmatch(rx, value) -> bool:
    return isinstance(value, str) and rx.fullmatch(value) is not None

# ---------------------------------------------------------------- encodings


B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = B58_ALPHABET[r] + out
    pad = len(data) - len(data.lstrip(b"\0"))
    return "1" * pad + out


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + B58_ALPHABET.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\0" * pad + body


def b32lower(data: bytes) -> str:
    return base64.b32encode(data).decode().lower().rstrip("=")


def jcs(value) -> bytes:
    """RFC 8785 JCS for OIP's JSON profile: objects, arrays, strings,
    booleans, null and integers within +/-(2^53-1). Floats are forbidden
    in OIP records (decimals travel as strings)."""
    def ser(v):
        if v is None:
            return "null"
        if v is True:
            return "true"
        if v is False:
            return "false"
        if isinstance(v, int):
            if abs(v) > MAX_SAFE_INT:
                raise ValueError("integer outside safe range")
            return str(v)
        if isinstance(v, float):
            raise ValueError("floats are not allowed in OIP records")
        if isinstance(v, str):
            return json.dumps(v, ensure_ascii=False)
        if isinstance(v, list):
            return "[" + ",".join(ser(x) for x in v) + "]"
        if isinstance(v, dict):
            keys = sorted(v.keys(), key=lambda k: k.encode("utf-16-be"))
            return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" +
                                  ser(v[k]) for k in keys) + "}"
        raise TypeError(f"unsupported type {type(v)}")
    return ser(value).encode("utf-8")


def multihash_sha256(data: bytes) -> bytes:
    return b"\x12\x20" + hashlib.sha256(data).digest()


def content_id(obj: dict) -> str:
    """'b' + base32lower(multihash(SHA-256(JCS(obj without proof)))).
    The digest equals eddsa-jcs-2022's transformedDocumentHash."""
    unsecured = {k: v for k, v in obj.items() if k != "proof"}
    return "b" + b32lower(multihash_sha256(jcs(unsecured)))


def key_hash(multikey: str) -> str:
    """Pre-rotation commitment: content-ID encoding of SHA-256(Multikey)."""
    return "b" + b32lower(multihash_sha256(multikey.encode("utf-8")))


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def proof_digest(proof: dict) -> str:
    """Digest of one proof, used by feed entries to commit to proofs."""
    return sha256_digest(jcs(proof))


def multikey_ed25519(pub: bytes) -> str:
    return "z" + b58encode(b"\xed\x01" + pub)


def multikey_x25519(pub: bytes) -> str:
    return "z" + b58encode(b"\xec\x01" + pub)


def ed25519_pub_from_multikey(mk: str) -> Ed25519PublicKey:
    if not isinstance(mk, str) or not mk.startswith("z"):
        raise ValueError("not a Multikey")
    raw = b58decode(mk[1:])
    if raw[:2] != b"\xed\x01" or len(raw) != 34:
        raise ValueError("not an Ed25519 Multikey")
    if not ed_has_order_l(raw[2:]):
        raise ValueError("an Ed25519 key must be a point of order L (core 4.4)")
    return Ed25519PublicKey.from_public_bytes(raw[2:])


def check_x25519_multikey(mk: str):
    if not isinstance(mk, str) or not mk.startswith("z"):
        raise ValueError("not a Multikey")
    raw = b58decode(mk[1:])
    if raw[:2] != b"\xec\x01" or len(raw) != 34:
        raise ValueError("not an X25519 Multikey")

# ---------------------------------------------------------------- Ed25519 points
# Core 4.4 accepts a signature only if S < L and A and R canonically encode
# points of order exactly L. OpenSSL checks S < L and the cofactorless
# equation but accepts small-order and mixed-order points, so this checker
# decodes A and R itself (RFC 8032 reference arithmetic) before calling it.

ED_P = 2**255 - 19
ED_L = 2**252 + 27742317777372353535851937790883648493
ED_D = -121665 * pow(121666, ED_P - 2, ED_P) % ED_P
ED_SQRT_M1 = pow(2, (ED_P - 1) // 4, ED_P)
ED_IDENTITY = (0, 1, 1, 0)


def ed_add(P, Q):
    """Point addition in extended coordinates (RFC 8032, 5.1.4)."""
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % ED_P
    b = (y1 + x1) * (y2 + x2) % ED_P
    c = 2 * t1 * t2 * ED_D % ED_P
    d = 2 * z1 * z2 % ED_P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % ED_P, g * h % ED_P, f * g % ED_P, e * h % ED_P)


def ed_mul(s, P):
    Q = ED_IDENTITY
    while s > 0:
        if s & 1:
            Q = ed_add(Q, P)
        P = ed_add(P, P)
        s >>= 1
    return Q


def ed_is_identity(P) -> bool:
    x, y, z, _ = P
    return x % ED_P == 0 and (y - z) % ED_P == 0


def ed_decode(b):
    """RFC 8032, 5.1.3. The point, or None if b is not the canonical
    encoding of a curve point."""
    if not isinstance(b, (bytes, bytearray)) or len(b) != 32:
        return None
    n = int.from_bytes(b, "little")
    sign, y = n >> 255, n & ((1 << 255) - 1)
    if y >= ED_P:
        return None
    u, v = (y * y - 1) % ED_P, (ED_D * y * y + 1) % ED_P
    x = u * pow(v, 3, ED_P) * \
        pow(u * pow(v, 7, ED_P), (ED_P - 5) // 8, ED_P) % ED_P
    if (v * x * x - u) % ED_P == 0:
        pass
    elif (v * x * x + u) % ED_P == 0:
        x = x * ED_SQRT_M1 % ED_P
    else:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = ED_P - x
    return (x, y, 1, x * y % ED_P)


def ed_encode(P) -> bytes:
    x, y, z, _ = P
    zi = pow(z, ED_P - 2, ED_P)
    x, y = x * zi % ED_P, y * zi % ED_P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


ED_B = ed_decode(bytes.fromhex("58" + "66" * 31))
_ORDER_L = {}


def ed_has_order_l(b) -> bool:
    """True if b canonically encodes a point of order exactly L: in the
    prime-order subgroup and not the identity (core 4.4)."""
    if not isinstance(b, (bytes, bytearray)):
        return False
    key = bytes(b)
    if key not in _ORDER_L:
        P = ed_decode(key)
        _ORDER_L[key] = P is not None and not ed_is_identity(P) and \
            ed_is_identity(ed_mul(ED_L, P))
    return _ORDER_L[key]

# ---------------------------------------------------------------- values


def _days_from_civil(y: int, m: int, d: int) -> int:
    """Days from 1970-01-01 in the proleptic Gregorian calendar, which is
    the calendar of RFC 3339. Year 0000 exists in it and is a leap year."""
    y -= m <= 2
    era = y // 400
    yoe = y - era * 400
    doy = (153 * (m - 3 if m > 2 else m + 9) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _days_in_month(y: int, m: int) -> int:
    if m == 2:
        return 29 if y % 4 == 0 and (y % 100 != 0 or y % 400 == 0) else 28
    return 30 if m in (4, 6, 9, 11) else 31


def ts(s) -> int:
    """RFC 3339 UTC timestamp -> integer nanoseconds since the epoch.
    Timestamps are compared as instants, never as strings. The date and
    time must be real: no month 13, no 30 February, no second 60."""
    m = TS_RE.fullmatch(s) if isinstance(s, str) else None
    if not m:
        raise ValueError(f"bad timestamp {s!r}")
    y, mo, d, h, mi, se = (int(g) for g in m.groups()[:6])
    if not (1 <= mo <= 12 and 1 <= d <= _days_in_month(y, mo) and
            h <= 23 and mi <= 59 and se <= 59):
        raise ValueError(f"not a real date and time: {s!r}")
    frac = (m.group(7) or "").ljust(9, "0")
    seconds = ((_days_from_civil(y, mo, d) * 24 + h) * 60 + mi) * 60 + se
    return seconds * 10**9 + int(frac)


def as_decimal(v):
    """An integer or a decimal string (core 1.3) as a Decimal; else None."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return Decimal(v)
    if fullmatch(DECIMAL_RE, v) and len(v) <= 64:
        return Decimal(v)
    return None


def is_amount(v) -> bool:
    """A non-negative decimal string of at most 64 characters."""
    return fullmatch(NONNEG_DECIMAL_RE, v) and len(v) <= 64

# ---------------------------------------------------------------- JSON profile


def _text_ok(text: str) -> bool:
    """core 1.1: valid Unicode, and no noncharacter (RFC 7493, 2.1): no
    unpaired surrogate, nothing from U+FDD0 to U+FDEF, and no code point
    whose last sixteen bits are FFFE or FFFF."""
    for ch in text:
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDFFF or 0xFDD0 <= cp <= 0xFDEF or \
           cp & 0xFFFE == 0xFFFE:
            return False
    return True


def values_ok(value) -> bool:
    """What core Section 1 requires of every value in a record, whatever
    the record is: numbers are integers within +/-(2^53-1) (1.2), strings
    and member names are valid Unicode without noncharacters (1.1), and
    arrays and objects nest at most MAX_DEPTH deep (1.9). It does not
    recurse."""
    pending = [(value, 1)]
    while pending:
        v, depth = pending.pop()
        if v is None or isinstance(v, bool):
            continue
        if isinstance(v, int):
            if abs(v) > MAX_SAFE_INT:
                return False
        elif isinstance(v, float):
            return False                    # read_json() never returns one
        elif isinstance(v, str):
            if not _text_ok(v):
                return False
        elif isinstance(v, (list, dict)):
            if depth > MAX_DEPTH:
                return False
            if isinstance(v, dict):
                if not all(isinstance(k, str) and _text_ok(k) for k in v):
                    return False
                v = v.values()
            pending.extend((item, depth + 1) for item in v)
        else:
            return False
    return True


_NUMBER_RE = re.compile(
    r"(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([-+]?[0-9]+))?")


def _integer(text: str) -> int:
    """The value of a JSON number if it is an integer within the safe
    range (core 1.2). Validity depends on the value, not on how it is
    written: `1.0` and `1e2` are 1 and 100. Exact: no float is involved."""
    m = _NUMBER_RE.fullmatch(text)
    if not m:
        raise ValueError(f"not a JSON number: {text[:40]!r}")
    sign, whole, frac, exp = m.groups()
    # A number may be written with any count of digits, so the digits are
    # handled as text: int() refuses a long run of them, and a number
    # written at length can still be a small integer (1 followed by five
    # thousand zeros, e-5000, is 1).
    frac = frac or ""
    significant = (whole + frac).lstrip("0")
    if not significant:
        return 0                            # -0 is 0 (core 2.2)
    mantissa = significant.rstrip("0")
    zeros = len(significant) - len(mantissa)
    if len(mantissa) > 16:
        # More than 16 significant digits: beyond the safe range, or with
        # a fractional part.
        raise ValueError("number outside the safe range, or with a "
                         "fractional part")
    exp_sign = -1 if exp and exp[0] == "-" else 1
    exp_digits = (exp or "0").lstrip("+-").lstrip("0") or "0"
    if len(exp_digits) > 18:
        # Larger than any count of digits a text can hold.
        raise ValueError("number with a fractional part" if exp_sign < 0
                         else "number outside the safe range")
    shift = zeros + exp_sign * int(exp_digits) - len(frac)
    if shift < 0:
        raise ValueError("number with a fractional part")
    if shift > 16:
        raise ValueError("number outside the safe range")
    value = int(mantissa) * 10**shift
    if value > MAX_SAFE_INT:
        raise ValueError("number outside the safe range")
    return -value if sign else value


def _no_duplicates(pairs):
    out = {}
    for name, value in pairs:
        if name in out:
            raise ValueError(f"duplicate member name {name[:40]!r}")
        out[name] = value
    return out


def _no_constant(name):
    raise ValueError(f"{name} is not JSON")


def read_json(text: str):
    """Parse JSON text under the profile of core Section 1: RFC 8259, no
    duplicate member names, valid Unicode without noncharacters, integers
    within the safe range judged by value, and nesting of at most
    MAX_DEPTH. Raises ValueError (or RecursionError, for very deep
    nesting) on anything else."""
    value = json.loads(text, object_pairs_hook=_no_duplicates,
                       parse_int=_integer, parse_float=_integer,
                       parse_constant=_no_constant)
    if not values_ok(value):
        raise ValueError("outside the JSON profile of core Section 1")
    return value


def json_ok(text) -> bool:
    """Whether a text is JSON within the profile of core Section 1."""
    try:
        read_json(text)
        return isinstance(text, str)
    except (ValueError, RecursionError, TypeError):
        return False

# ---------------------------------------------------------------- keys


class Key:
    """Deterministic Ed25519 key from a label (TEST VECTORS ONLY)."""

    def __init__(self, label: str):
        self.label = label
        seed = hashlib.sha256(("oip-test-vector:" + label).encode()).digest()
        self.sk = Ed25519PrivateKey.from_private_bytes(seed)
        self.pub = self.sk.public_key().public_bytes(*RAW)
        self.mk = multikey_ed25519(self.pub)
        self.seed_hex = seed.hex()
        h = hashlib.sha512(seed).digest()       # RFC 8032, 5.1.5
        a = int.from_bytes(h[:32], "little")
        self.scalar = (a & ((1 << 254) - 8)) | (1 << 254)


class AgreementKey:
    def __init__(self, label: str):
        seed = hashlib.sha256(("oip-test-vector-x25519:" + label).encode()) \
            .digest()
        self.sk = X25519PrivateKey.from_private_bytes(seed)
        self.seed_hex = seed.hex()
        self.mk = multikey_x25519(self.sk.public_key().public_bytes(*RAW))

# ---------------------------------------------------------------- proofs


PROOF_REQUIRED = {"type", "cryptosuite", "verificationMethod",
                  "proofPurpose", "created", "proofValue"}


def purpose_for(record_type) -> str:
    """The proof purpose a record type requires (core 5.6)."""
    if record_type in IDENTITY_TYPES:
        return "capabilityInvocation"
    if record_type == "Delegation":
        return "capabilityDelegation"
    if record_type == "Hello":
        return "authentication"
    return "assertionMethod"


def create_proof(doc: dict, key: Key, verification_method: str,
                 purpose: str, created: str, **extra) -> dict:
    """W3C Data Integrity, cryptosuite eddsa-jcs-2022. Each proof in a
    proof set covers the record without its `proof` member, so adding a
    co-signature never changes the content ID or the other proofs."""
    unsecured = {k: v for k, v in doc.items() if k != "proof"}
    config = {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022",
              "verificationMethod": verification_method,
              "proofPurpose": purpose, "created": created, **extra}
    if "@context" in unsecured:
        config["@context"] = unsecured["@context"]
    hash_data = hashlib.sha256(jcs(config)).digest() + \
        hashlib.sha256(jcs(unsecured)).digest()
    return {**config, "proofValue": "z" + b58encode(key.sk.sign(hash_data))}


def verify_proof(doc: dict, proof, pub_multikey: str) -> bool:
    """Check one proof's form and signature (core 5.2-5.4). Whether the key
    may sign for anyone is decided separately (Verifier.valid_key)."""
    if not isinstance(proof, dict):
        return False
    allowed = set(PROOF_REQUIRED) | {"authority"}
    if proof.get("proofPurpose") == "authentication":
        allowed |= {"challenge", "domain"}
    if "authority" in proof and (
            not isinstance(proof["authority"], list) or
            not 1 <= len(proof["authority"]) <= MAX_AUTHORITY):
        return False
    if "@context" in doc:
        # core 5.2: present on the proof, with the same value. The values
        # are compared in canonical form: Python's own comparison takes
        # true for 1, and a missing member for null.
        allowed.add("@context")
        try:
            if "@context" not in proof or \
               jcs(proof["@context"]) != jcs(doc["@context"]):
                return False
        except Exception:
            return False
    if not PROOF_REQUIRED <= set(proof) or not set(proof) <= allowed:
        return False
    if proof["type"] != "DataIntegrityProof" or \
       proof["cryptosuite"] != "eddsa-jcs-2022":
        return False
    pv = proof["proofValue"]
    try:
        ts(proof["created"])
        if not isinstance(pv, str) or not pv.startswith("z"):
            return False
        sig = b58decode(pv[1:])
        if len(sig) != 64:
            return False
        if int.from_bytes(sig[32:], "little") >= ED_L or \
           not ed_has_order_l(sig[:32]):
            return False                    # core 4.4: S < L, R of order L
        unsecured = {k: v for k, v in doc.items() if k != "proof"}
        config = {k: v for k, v in proof.items() if k != "proofValue"}
        hash_data = hashlib.sha256(jcs(config)).digest() + \
            hashlib.sha256(jcs(unsecured)).digest()
        ed25519_pub_from_multikey(pub_multikey).verify(sig, hash_data)
        return True
    except Exception:
        return False


def sign(doc: dict, *proofs) -> dict:
    out = copy.deepcopy(doc)
    out["proof"] = list(out.get("proof", [])) + list(proofs)
    return out

# ---------------------------------------------------------------- references


def did(mind_id: str) -> str:
    return "did:oip:" + mind_id


def did_key_vm(mk: str) -> str:
    return f"did:key:{mk}#{mk}"


def version_id(event: dict) -> str:
    return f"{event.get('seq', 0)}-{content_id(event)}"


def op_vm(mind: str, at_event: dict, mk: str) -> str:
    """Key reference for an operational key, pinned to a log version."""
    return f"{mind}?versionId={version_id(at_event)}#{mk}"


def parse_key_ref(vm):
    """-> (address, version-id, multikey) or None."""
    m = KEYREF_RE.fullmatch(vm) if isinstance(vm, str) else None
    return m.groups() if m else None


def parse_control_ref(vm):
    """-> multikey of a did:key control-key reference, or None."""
    m = CTLREF_RE.fullmatch(vm) if isinstance(vm, str) else None
    return m.group(1) if m and m.group(1) == m.group(2) else None


def ref_cid(ref):
    """Content ID named by a record-ref, or None."""
    m = RECREF_RE.fullmatch(ref) if isinstance(ref, str) else None
    return m.group(1) if m else None


def record_ref(author: str, record: dict) -> str:
    return f"{author}/{content_id(record)}"

# ---------------------------------------------------------------- identity


class State:
    """Identity state after one event of a log."""

    def __init__(self):
        self.mind = None
        self.kind = None
        self.controller = None      # "key" or "member"
        self.next = []              # key-controlled: committed key hashes
        self.next_threshold = None
        self.members = []           # member-controlled
        self.threshold = None
        self.keys = []              # operational keys (Multikeys)
        self.invocation = []        # keys for other minds' identity events
        self.revoked_keys = set()   # revoked keys never return
        self.agreement = []
        self.homes = []
        self.also_known_as = []
        self.parents = []
        self.children = []
        self.compromised = {}       # key -> compromisedSince (ns)
        self.retired = False
        self.seq = -1
        self.head = None
        self.version = None
        self.created = None

    def copy(self):
        return copy.deepcopy(self)


class Log:
    """A verified identity log: its events and the state after each. For a
    duplicitous mind (Layer 1, 7.3) it holds only the events before the
    divergence, plus the later events of every branch, whose removals and
    compromise declarations all apply."""

    def __init__(self, mind, events, states, times, height=0):
        self.mind, self.events, self.states = mind, events, states
        self.times = times          # evaluation time of each event (ns)
        self.height = height        # 0 for key-controlled minds
        self.duplicitous = False
        self.branch_tails = []      # [(time, state, event)] after divergence
        self.failed = None          # why a prefix verified no further

    @property
    def latest(self) -> State:
        return self.states[-1]

    def index(self, version):
        for i, st in enumerate(self.states):
            if st.version == version:
                return i
        return None

    def removal_time(self, i, key, keyset="keys"):
        """Evaluation time of the first event after position i that removes
        the key from `keyset` or retires the mind (Layer 1, 6.1 and 6.4),
        or None. Under duplicity, removals in every branch apply (7.3)."""
        later = [(self.times[j], self.states[j], self.events[j])
                 for j in range(i + 1, len(self.events))]
        found = [when for when, st, ev in later + self.branch_tails
                 if ev["type"] == "Retire" or key not in getattr(st, keyset)]
        return min(found) if found else None

    def compromised_since(self, key):
        found = [st.compromised[key] for st in
                 [self.latest] + [s for _, s, _ in self.branch_tails]
                 if key in st.compromised]
        return min(found) if found else None

    def state_at(self, t):
        """State after the last event whose evaluation time is at or
        before t."""
        found = None
        for when, st in zip(self.times, self.states):
            if when > t:
                break
            found = st
        return found

    def members_ever(self):
        out = set()
        for st in self.states:
            out.update(st.members)
        return out


def _check_key_controller(ctl) -> int:
    """Validate a key controller (Layer 1, 3.4); return nextThreshold."""
    if not isinstance(ctl, dict) or set(ctl) - {"keys", "next",
                                                "nextThreshold"}:
        raise ValueError("bad key controller")
    keys, nxt = ctl.get("keys"), ctl.get("next")
    if not isinstance(keys, list) or not 1 <= len(keys) <= 16 or \
       len(set(keys)) != len(keys):
        raise ValueError("controller.keys must list 1-16 distinct keys "
                         "(thresholds count distinct keys)")
    for k in keys:
        ed25519_pub_from_multikey(k)
    if not isinstance(nxt, list) or len(nxt) > 16 or \
       len(set(nxt)) != len(nxt) or \
       not all(fullmatch(CID_RE, h) for h in nxt):
        raise ValueError("controller.next must list 0-16 distinct key hashes")
    if not nxt:
        if "nextThreshold" in ctl:
            raise ValueError("nextThreshold must be absent when next is empty")
        return 0
    t = ctl.get("nextThreshold", 1)
    if not isinstance(t, int) or isinstance(t, bool) or \
       not 1 <= t <= len(nxt) or 2 * t <= len(nxt):
        raise ValueError("nextThreshold must be a majority of next")
    return t


def _check_member_controller(ctl, self_address):
    """Validate a member controller (Layer 1, 3.4)."""
    if not isinstance(ctl, dict) or set(ctl) - {"members", "threshold"}:
        raise ValueError("bad member controller")
    members, t = ctl.get("members"), ctl.get("threshold")
    if not isinstance(members, list) or not 1 <= len(members) <= 256 or \
       len(set(members)) != len(members) or \
       not all(fullmatch(ADDR_RE, m) for m in members) or \
       self_address in members:
        raise ValueError("members must be 1-256 distinct addresses, "
                         "not including the collective itself")
    if not isinstance(t, int) or isinstance(t, bool) or \
       not 1 <= t <= len(members) or 2 * t <= len(members):
        raise ValueError("threshold must be a majority of members")


def _key_entries(entries, limit, checker):
    if not isinstance(entries, list) or len(entries) > limit:
        raise ValueError("too many key entries")
    out = []
    for e in entries:
        if not isinstance(e, dict) or set(e) - {"key", "label"} or \
           ("label" in e and (not isinstance(e["label"], str) or
                              len(e["label"]) > 64)):
            raise ValueError("bad key entry")
        checker(e["key"])
        out.append(e["key"])
    if len(set(out)) != len(out):
        raise ValueError("duplicate key entry")
    return out


def _is_int(v, lo, hi) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def _strings(items, pattern, lo, hi) -> bool:
    """A list of lo to hi distinct strings of one form."""
    return isinstance(items, list) and lo <= len(items) <= hi and \
        all(isinstance(i, str) and pattern.fullmatch(i) for i in items) and \
        len(set(items)) == len(items)


def _controller_ok(ctl, self_address) -> bool:
    """Layer 1, 3.4: a key controller or a member controller, with no
    other members, and a threshold that is a majority."""
    if not isinstance(ctl, dict):
        return False
    if "keys" in ctl and "next" in ctl and \
       not set(ctl) - {"keys", "next", "nextThreshold"}:
        nxt = ctl["next"]
        if not _strings(ctl["keys"], ED_MK_RE, 1, 16) or \
           not _strings(nxt, CID_RE, 0, 16):
            return False
        if "nextThreshold" not in ctl:
            return len(nxt) <= 1        # the default of 1 is a majority
        t = ctl["nextThreshold"]
        return _is_int(t, 1, 16) and nxt != [] and t <= len(nxt) < 2 * t
    if set(ctl) == {"members", "threshold"}:
        members, t = ctl["members"], ctl["threshold"]
        return _strings(members, ADDR_RE, 1, 256) and \
            self_address not in members and \
            _is_int(t, 1, 256) and t <= len(members) < 2 * t
    return False


def _entries_ok(entries, limit, pattern) -> bool:
    """Layer 1, 3.5: key entries, with distinct keys and no other members."""
    return isinstance(entries, list) and len(entries) <= limit and all(
        isinstance(e, dict) and not set(e) - {"key", "label"} and
        isinstance(e.get("key"), str) and pattern.fullmatch(e["key"]) and
        ("label" not in e or (isinstance(e["label"], str) and
                              len(e["label"]) <= 64))
        for e in entries) and \
        len({e["key"] for e in entries}) == len(entries)


def event_ok(ev: dict) -> bool:
    """The shape of an identity event (Layer 1, Section 3), as far as the
    event alone shows it. What depends on the log (the chain, the keys
    committed to, the proofs) is verify_log's."""
    t = ev.get("type")
    if "recovery" in ev or "height" in ev and t != "Genesis":
        return False                        # 3.12; 3.6
    ctl = ev.get("controller")
    if t == "Genesis":
        kind = ev.get("kind")
        if any(k in ev for k in ("mind", "seq", "prev")) or \
           not isinstance(kind, str) or not 1 <= len(kind) <= 64 or \
           not _controller_ok(ctl, None):
            return False
        member = "members" in ctl
        if kind == "collective" and not member or \
           "height" in ev and not (member and _is_int(ev["height"], 1, 4)):
            return False
        parents = ev.get("parents", [])
        if not isinstance(parents, list) or len(parents) > 16 or not all(
                isinstance(q, dict) and set(q) == {"mind", "at"} and
                isinstance(q.get("mind"), str) and
                ADDR_RE.fullmatch(q["mind"]) and
                isinstance(q.get("at"), str) and
                VERSION_RE.fullmatch(q["at"]) for q in parents):
            return False
        if not isinstance(ev.get("inherits", {}), dict):
            return False
    else:
        if not isinstance(ev.get("mind"), str) or \
           not ADDR_RE.fullmatch(ev["mind"]) or \
           not _is_int(ev.get("seq"), 1, MAX_SAFE_INT) or \
           not isinstance(ev.get("prev"), str) or \
           not CID_RE.fullmatch(ev["prev"]):
            return False
        # A member that is present with the value null is not absent.
        if "controller" in ev and not _controller_ok(ctl, ev["mind"]):
            return False
        revoked = ev.get("revoked", [])
        if not isinstance(revoked, list) or len(revoked) > 80 or not all(
                isinstance(r, dict) and
                not set(r) - {"key", "compromisedSince"} and
                isinstance(r.get("key"), str) and
                ED_MK_RE.fullmatch(r["key"]) for r in revoked):
            return False                    # 3.7: no other members
        for r in revoked:
            if "compromisedSince" in r:
                ts(r["compromisedSince"])
        gone = {r["key"] for r in revoked}
        if any(e["key"] in gone for name in ("keys", "invocation")
               for e in ev.get(name, []) if isinstance(e, dict) and
               isinstance(e.get("key"), str)):
            return False                    # 4.5
        if t == "Fork" and (
                not isinstance(ev.get("child"), str) or
                not ADDR_RE.fullmatch(ev["child"]) or
                not isinstance(ev.get("terms", {}), dict)):
            return False
        if t == "Retire" and (
                "successor" in ev and not (
                    isinstance(ev["successor"], str) and
                    ADDR_RE.fullmatch(ev["successor"])) or
                not isinstance(ev.get("reason", ""), str) or
                isinstance(ctl, dict) and ctl.get("next")):
            return False                    # 3.10
    seen = set()
    for name, limit, pattern in (("keys", 64, ED_MK_RE),
                                 ("invocation", 16, ED_MK_RE),
                                 ("agreement", 16, X_MK_RE)):
        if name in ev:
            if not _entries_ok(ev[name], limit, pattern):
                return False
            keys = {e["key"] for e in ev[name]}
            if keys & seen:
                return False                # 3.5: one set for each key
            seen |= keys
    homes, aka = ev.get("homes", []), ev.get("alsoKnownAs", [])
    return isinstance(homes, list) and len(homes) <= 8 and \
        all(isinstance(h, str) and ORIGIN_RE.fullmatch(h) for h in homes) and \
        isinstance(aka, list) and len(aka) <= 16 and \
        all(isinstance(a, str) for a in aka)


def _dated_within(p, tau) -> bool:
    """core 9.3: a proof dated more than 300 seconds after the evidence
    that it existed counts for nothing. Evidence for an identity event is
    evidence for the proofs it stood with (core 9.4), so tau is the
    event's."""
    try:
        return ts(p.get("created")) <= tau + SKEW_NS
    except (TypeError, ValueError):
        return False


def _control_signed(event, mk, tau) -> bool:
    """True if control key mk has a valid capabilityInvocation proof, not
    dated more than 300 seconds after the event's evidence tau."""
    for p in event.get("proof", []):
        if isinstance(p, dict) and \
           parse_control_ref(p.get("verificationMethod")) == mk and \
           p.get("verificationMethod") == did_key_vm(mk) and \
           p.get("proofPurpose") == "capabilityInvocation" and \
           _dated_within(p, tau) and verify_proof(event, p, mk):
            return True
    return False


EVENT_TYPES = ("Genesis", "Update", "Fork", "Retire")


def unread_event(ev) -> bool:
    """Layer 1, 4.9: whether this verifier cannot read an event. It is of
    another version of the protocol, or of a type this revision does not
    define (`Merge` among them), or has the reserved member, or lists in
    `critical` an extension the verifier does not implement, and this one
    implements none. Such an event may depend on rules the verifier does
    not have, for its form, its place and its signatures alike."""
    if not isinstance(ev, dict):
        return False
    oip, etype = ev.get("oip"), ev.get("type")
    if isinstance(oip, str) and oip != OIP_VERSION:
        return True
    if isinstance(etype, str) and etype not in EVENT_TYPES:
        return True
    if "recovery" in ev:
        return True
    critical = ev.get("critical", [])
    return not isinstance(critical, list) or len(critical) > 0


def _signed_at_all(event, mk) -> bool:
    """True if control key mk has a valid capabilityInvocation proof on the
    event, whatever its date."""
    return any(isinstance(p, dict) and
               p.get("verificationMethod") == did_key_vm(mk) and
               p.get("proofPurpose") == "capabilityInvocation" and
               verify_proof(event, p, mk)
               for p in event.get("proof", []))


def _members_named(event) -> set:
    """The minds with a proof on an identity event that verifies under a
    key reference of their own and names no authority. Whether such a
    proof counts is for the member's log and the evidence to say (Layer 1,
    6.4); that it is there at all is a fact about the event."""
    named = set()
    for p in event.get("proof", []):
        ref = parse_key_ref(p.get("verificationMethod")) \
            if isinstance(p, dict) else None
        if ref and "authority" not in p and \
           p.get("proofPurpose") == "capabilityInvocation" and \
           verify_proof(event, p, ref[2]):
            named.add(ref[0])
    return named


def invalid_event(ev, before) -> bool:
    """Layer 1, 4.9: whether an event that does not verify is invalid: one
    this verifier can read, and that is wrong whoever judges it and
    whenever. `before` is the state after the events before it, or None
    for a first event. Every other event that fails is undecided.

    This is written from the text of 4.9, apart from verify_log: nothing
    here reads evidence, another mind's log, or the order in which
    verify_log happens to make its checks."""
    if unread_event(ev):
        return False
    try:
        return _wrong_for_everyone(ev, before)
    except (ValueError, KeyError, TypeError, AttributeError):
        return True         # too malformed to say more: not well formed


def _wrong_for_everyone(ev, before) -> bool:
    # Not well formed (4.8).
    if not isinstance(ev, dict) or not values_ok(ev) or not record_ok(ev):
        return True
    proofs = ev.get("proof")
    if not isinstance(proofs, list) or not proofs or \
       len(proofs) > MAX_PROOFS or \
       not all(isinstance(p, dict) for p in proofs):
        return True
    etype, ctl = ev["type"], ev.get("controller")
    # Not in its place (4.1, 4.2, 4.6).
    if before is None:
        if etype != "Genesis":
            return True
        mind, keys, invocation, revoked = did(content_id(ev)), [], [], set()
    else:
        if etype == "Genesis" or before.retired or \
           ev.get("mind") != before.mind or \
           ev.get("seq") != before.seq + 1 or \
           ev.get("prev") != before.head or \
           ts(ev["created"]) < before.created:
            return True
        mind, keys, invocation, revoked = before.mind, before.keys, \
            before.invocation, before.revoked_keys
    # It sets keys that the state before it does not allow (3.5, 4.5).
    if "keys" in ev:
        keys = _key_entries(ev["keys"], 64, ed25519_pub_from_multikey)
    if "invocation" in ev:
        invocation = _key_entries(ev["invocation"], 16,
                                  ed25519_pub_from_multikey)
    if "agreement" in ev:
        _key_entries(ev["agreement"], 16, check_x25519_multikey)
    if set(keys) & set(invocation) or set(keys + invocation) & revoked:
        return True
    if before is not None:
        for r in ev.get("revoked", []):
            if ("keys" in ev and r["key"] in keys) or \
               ("invocation" in ev and r["key"] in invocation):
                return True
    # The proofs on it could not authorise it under any evidence.
    by_members = before.controller == "member" if before is not None \
        else isinstance(ctl, dict) and "members" in ctl
    if by_members:
        if ctl is not None:
            _check_member_controller(ctl, mind)
        named = _members_named(ev)
        if before is None:
            return any(m not in named for m in ctl["members"])
        if len([m for m in before.members if m in named]) < before.threshold:
            return True
        return ctl is not None and any(
            m not in named for m in ctl["members"]
            if m not in before.members)
    _check_key_controller(ctl)
    if before is not None:
        if not before.next or len(ctl["keys"]) < before.next_threshold or \
           any(key_hash(mk) not in before.next for mk in ctl["keys"]) or \
           etype == "Retire" and ctl["next"]:
            return True
    return not all(_signed_at_all(ev, mk) for mk in ctl["keys"])


def log_intake(events, verifier) -> dict:
    """Layer 1, 4.9, for a copy of a log: how many of its events verify,
    from the first, and whether the next is undecided (True), invalid
    (False), or there is none (None)."""
    if not isinstance(events, list) or not events:
        return {"verified": 0, "undecided": False}      # no log at all
    try:
        log = verify_log(events, verifier, prefix=True)
    except ValueError:
        return {"verified": 0,
                "undecided": not invalid_event(events[0], None)}
    if log.failed is None:
        return {"verified": len(log.events), "undecided": None}
    return {"verified": len(log.events),
            "undecided": not invalid_event(events[len(log.events)],
                                           log.states[-1])}


def verify_log(events, verifier, depth=0, prefix=False) -> Log:
    """Verify an identity log (Layer 1, Section 4). Raises ValueError.
    Each event's evaluation time is fixed first (core 9.5); members' proofs
    on a collective's events are judged at that time (Layer 1, 6.4).

    With `prefix`, a log whose genesis verifies is returned as far as it
    verifies, with `failed` set to the reason the next event does not:
    where branches are weighed against each other (Layer 1, 7.3), a branch
    counts for the events it has that verify."""
    done = {"states": [], "times": [], "height": 0}
    try:
        return _replay_log(events, verifier, depth, done)
    except ValueError as e:
        states = done["states"]
        if not prefix or not states:
            raise
        log = Log(states[0].mind, events[:len(states)], states,
                  done["times"], done["height"])
        log.failed = e
        return log


def _replay_log(events, verifier, depth, done) -> Log:
    if not isinstance(events, list) or not events:
        raise ValueError("empty log")
    st, states, times, height = State(), done["states"], done["times"], 0
    for i, ev in enumerate(events):
        if not isinstance(ev, dict) or ev.get("oip") != OIP_VERSION:
            raise ValueError("unknown oip version")
        if not values_ok(ev):
            raise ValueError("an event outside the JSON profile of core "
                             "Section 1")
        etype = ev.get("type")
        if etype == "Merge":
            raise ValueError("Merge is reserved in this revision")
        if etype not in ("Genesis", "Update", "Fork", "Retire"):
            raise ValueError("unknown event type")
        if "recovery" in ev:
            raise ValueError("recovery is reserved in this revision")
        if not record_ok(ev):
            raise ValueError("an event is a well-formed record of its type "
                             "(Layer 1, 4.8)")
        if ev.get("critical"):
            raise ValueError("the event depends on an extension this "
                             "verifier does not implement (core 8.3)")
        created = ts(ev.get("created"))
        proofs = ev.get("proof")
        if not isinstance(proofs, list) or not proofs or \
           len(proofs) > MAX_PROOFS or \
           not all(isinstance(p, dict) for p in proofs):
            raise ValueError("bad proof set")   # core 5.1
        when = verifier.event_time(ev)
        tau = verifier.evidence(ev)
        if times:
            when = max(when, times[-1])     # never before its predecessor
        if "expires" in ev and when > ts(ev["expires"]) + SKEW_NS:
            raise ValueError("the event is evaluated more than 300 seconds "
                             "after it expires, so no proof on it counts "
                             "(core 9.6)")
        ctl = ev.get("controller")
        if i == 0:
            if etype != "Genesis" or any(k in ev for k in
                                         ("mind", "seq", "prev")):
                raise ValueError("first event must be a Genesis without "
                                 "mind, seq or prev")
            st.mind = did(content_id(ev))
            kind = ev.get("kind")
            if not isinstance(kind, str) or not 1 <= len(kind) <= 64:
                raise ValueError("bad kind")
            if isinstance(ctl, dict) and "members" in ctl:
                _check_member_controller(ctl, st.mind)
                signers = verifier.member_signers(ev, ctl["members"], depth,
                                                  identity_at=when)
                if len(signers) != len(ctl["members"]):
                    raise ValueError("every founding member must sign with "
                                     "an invocation key valid at the "
                                     "event's evaluation time")
                height = 1 + max(verifier.log(m, depth + 1).height
                                 for m in signers)
                declared = ev.get("height", height)
                if not isinstance(declared, int) or \
                   isinstance(declared, bool) or \
                   not height <= declared <= MAX_NESTING:
                    raise ValueError("a collective's height is at most 4 and "
                                     "above every founding member's")
                height = declared
                st.controller = "member"
                st.members, st.threshold = list(ctl["members"]), \
                    ctl["threshold"]
            else:
                if "height" in ev:
                    raise ValueError("only a collective's genesis has a "
                                     "height")
                st.next_threshold = _check_key_controller(ctl)
                for mk in ctl["keys"]:
                    if not _control_signed(ev, mk, tau):
                        raise ValueError("genesis not signed by its keys")
                st.controller, st.next = "key", list(ctl["next"])
            if kind == "collective" and st.controller != "member":
                raise ValueError("a collective needs a member controller")
            st.kind = kind
            st.parents = list(ev.get("parents", []))
        else:
            if etype == "Genesis":
                raise ValueError("Genesis must be the first event")
            if st.retired:
                raise ValueError("no event may follow a Retire")
            if ev.get("mind") != st.mind or ev.get("seq") != st.seq + 1 or \
               ev.get("prev") != st.head:
                raise ValueError(f"broken chain at event {i}")
            if created < st.created:
                raise ValueError("created must not decrease along a log")
            if "height" in ev:
                raise ValueError("height is fixed by the genesis")
            if st.controller == "member":
                signers = verifier.member_signers(ev, st.members, depth,
                                                  identity_at=when)
                if len(signers) < st.threshold:
                    raise ValueError("collective event lacks the threshold "
                                     "of current members")
                new = set()
                if ctl is not None:
                    _check_member_controller(ctl, st.mind)
                    added = [m for m in ctl["members"] if m not in st.members]
                    if added:
                        new = verifier.member_signers(ev, added, depth,
                                                      identity_at=when)
                        if len(new) != len(added):
                            raise ValueError("added members must sign")
                if any(verifier.log(m, depth + 1).height >= height
                       for m in signers | new):
                    raise ValueError("a member's height must be below the "
                                     "collective's (Layer 1, 4.7)")
                if ctl is not None:
                    st.members, st.threshold = list(ctl["members"]), \
                        ctl["threshold"]
            else:
                t_new = _check_key_controller(ctl)
                if len(ctl["keys"]) < st.next_threshold or not st.next:
                    raise ValueError("too few distinct control keys")
                for mk in ctl["keys"]:
                    if key_hash(mk) not in st.next:
                        raise ValueError("control key not committed by the "
                                         "previous event (pre-rotation)")
                    if not _control_signed(ev, mk, tau):
                        raise ValueError("control key did not sign")
                if etype == "Retire" and ctl["next"]:
                    raise ValueError("a Retire commits to no next keys")
                st.next, st.next_threshold = list(ctl["next"]), t_new
            if etype == "Fork":
                if not fullmatch(ADDR_RE, ev.get("child")):
                    raise ValueError("Fork needs a child address")
                st.children.append(ev["child"])
            if etype == "Retire":
                st.retired = True
        if "keys" in ev:
            st.keys = _key_entries(ev["keys"], 64, ed25519_pub_from_multikey)
        if "invocation" in ev:
            st.invocation = _key_entries(ev["invocation"], 16,
                                         ed25519_pub_from_multikey)
        if set(st.keys) & set(st.invocation):
            raise ValueError("a key cannot be both operational and invocation")
        if set(st.keys + st.invocation) & st.revoked_keys:
            raise ValueError("a revoked key cannot be added again")
        if "agreement" in ev:
            st.agreement = _key_entries(ev["agreement"], 16,
                                        check_x25519_multikey)
        if "homes" in ev:
            st.homes = list(ev["homes"])
        if "alsoKnownAs" in ev:
            st.also_known_as = list(ev["alsoKnownAs"])
        if i > 0 and "revoked" in ev:
            for r in ev["revoked"]:
                k = r["key"]
                if ("keys" in ev and k in st.keys) or \
                   ("invocation" in ev and k in st.invocation):
                    raise ValueError("a revoked key must not remain in keys")
                st.keys = [x for x in st.keys if x != k]
                st.invocation = [x for x in st.invocation if x != k]
                st.revoked_keys.add(k)
                if "compromisedSince" in r:
                    c = ts(r["compromisedSince"])
                    st.compromised[k] = min(c, st.compromised.get(k, c))
        st.seq = ev.get("seq", 0)
        st.head = content_id(ev)
        st.version = f"{st.seq}-{st.head}"
        st.created = created
        states.append(st.copy())
        times.append(when)
        done["height"] = height
    return Log(st.mind, events, states, times, height)

# ---------------------------------------------------------------- policies


_MISSING = object()


def parse_selector(selector):
    """Selector grammar (Layer 1, 11.3): "." alone, or one or more of
    .name, [index] and ["quoted name"]. Returns the path, or None."""
    if selector == ".":
        return []
    if not isinstance(selector, str) or not selector:
        return None
    parts, pos = [], 0
    while pos < len(selector):
        m = SEL_TOKEN.match(selector, pos)
        if not m:
            return None
        if m.group(1) is not None:
            parts.append(m.group(1))
        elif m.group(2) is not None:
            parts.append(int(m.group(2)))
        else:
            try:
                parts.append(json.loads(m.group(3)))
            except ValueError:
                return None
        pos = m.end()
    return parts


def _select(obj, selector):
    cur = obj
    for part in parse_selector(selector):
        if isinstance(part, int):
            if not isinstance(cur, list) or part >= len(cur):
                return _MISSING
        elif not isinstance(cur, dict) or part not in cur:
            return _MISSING
        cur = cur[part]
    return cur


def statement_valid(s, depth=0) -> bool:
    if depth > MAX_POLICY_DEPTH or not isinstance(s, list) or not s:
        return False
    op = s[0]
    if op in OPS:
        return len(s) == 3 and parse_selector(s[1]) is not None
    if op == "not":
        return len(s) == 2 and statement_valid(s[1], depth + 1)
    if op in ("and", "or"):
        return len(s) == 2 and isinstance(s[1], list) and \
            1 <= len(s[1]) <= 64 and \
            all(statement_valid(x, depth + 1) for x in s[1])
    if op in ("all", "any"):
        return len(s) == 3 and parse_selector(s[1]) is not None and \
            statement_valid(s[2], depth + 1)
    return False


def policy_valid(policy) -> bool:
    return isinstance(policy, list) and len(policy) <= 64 and \
        all(statement_valid(s) for s in policy)


class PolicyError(Exception):
    """A statement that cannot be evaluated (Layer 1, 11.3): a selector
    that does not resolve, an ordering on a non-decimal, or a quantifier
    over a non-array. Any error makes the whole policy fail."""


def _compare(op, got, val) -> bool:
    a, b = as_decimal(got), as_decimal(val)
    if op in ORDERING_OPS:
        if a is None or b is None:
            raise PolicyError("ordering compares decimals only")
        return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
    if a is not None and b is not None:
        eq = a == b
    else:
        try:
            eq = jcs(got) == jcs(val)
        except (TypeError, ValueError):
            raise PolicyError("value has no canonical form")
    return eq if op == "==" else not eq


def statement_holds(s, obj) -> bool:
    """Evaluate a statement in full, without short-circuiting, so that an
    error anywhere is raised (and fails the policy) rather than skipped."""
    op = s[0]
    if op == "not":
        return not statement_holds(s[1], obj)
    if op in ("and", "or"):
        results = [statement_holds(x, obj) for x in s[1]]
        return all(results) if op == "and" else any(results)
    got = _select(obj, s[1])
    if got is _MISSING:
        raise PolicyError(f"{s[1]} does not resolve")
    if op in ("all", "any"):
        if not isinstance(got, list):
            raise PolicyError(f"{s[1]} is not an array")
        results = [statement_holds(s[2], item) for item in got]
        return all(results) if op == "all" else any(results)
    return _compare(op, got, s[2])


def policy_ok(policy, record) -> bool:
    """Every statement must hold for the record without its proofs
    (Layer 1, 11.3). Ordering compares decimals only; equality compares
    decimals numerically and other values by canonical form. An error
    anywhere fails the policy, so negation and disjunction cannot turn a
    missing or malformed value into a pass."""
    if not policy_valid(policy):
        return False
    obj = {k: v for k, v in record.items() if k != "proof"} \
        if isinstance(record, dict) else record
    try:
        return all([statement_holds(s, obj) for s in policy])
    except PolicyError:
        return False


def command_valid(command) -> bool:
    """OIP commands are the leaf commands of Layer 1, 11.2; /oip, /oip/sign
    and other /oip/... commands are reserved. Extensions use their own
    first segment."""
    if not fullmatch(COMMAND_RE, command):
        return False
    if command == "/oip" or command.startswith("/oip/"):
        return command in OIP_COMMANDS
    return True


def command_covers(granted: str, needed: str) -> bool:
    """Path-segment prefix match."""
    return needed == granted or needed.startswith(granted + "/")

# ---------------------------------------------------------------- records


_DURATION_TIME = (r"(?:[0-9]+H(?:[0-9]+M)?(?:[0-9]+S)?|"
                  r"[0-9]+M(?:[0-9]+S)?|[0-9]+S)")
DURATION_RE = re.compile(r"P(?:[0-9]+D(?:T" + _DURATION_TIME + r")?|T" +
                         _DURATION_TIME + r")")


def is_duration(v) -> bool:
    """core 1.5: days, hours, minutes and seconds, in at most 64
    characters."""
    return fullmatch(DURATION_RE, v) and len(v) <= MAX_DURATION


def _part_ok(part) -> bool:
    """One record, or a container without the records it carries: the
    values of core 1.1 and 1.2, at most 64 deep (1.9), in at most 1 MiB of
    canonical form (1.6)."""
    return values_ok(part) and len(jcs(part)) <= MAX_RECORD_BYTES


def profile_ok(r: dict) -> bool:
    """core 1.1, 1.2, 1.6 and 1.9 for a record. For a container the limits
    on size and depth apply to each record it carries, counted from that
    record, and to the container without the members that hold them. How
    far a `Sealed` record may exceed the size is not yet settled (OEP-0001,
    open questions), so its size is not judged here."""
    carrying = CONTAINERS.get(r.get("type"))
    if carrying is None:
        if r.get("type") == "Sealed":
            return values_ok(r)
        return _part_ok(r)
    carried = []
    for name in carrying:
        member = r.get(name, [])
        if isinstance(member, list):
            for item in member:
                # A pair of events (DuplicityEvidence) is two records.
                carried.extend(item if isinstance(item, list) and
                               name == "pairs" else [item])
        else:
            carried.append(member)
    rest = {k: v for k, v in r.items() if k not in carrying}
    return _part_ok(rest) and all(_part_ok(c) for c in carried)


def record_ok(r) -> bool:
    """Structural checks this generator relies on (not a full schema)."""
    try:
        if not isinstance(r, dict) or r.get("oip") != OIP_VERSION:
            return False
        if not profile_ok(r):
            return False                    # core 1.1, 1.2, 1.6 and 1.9
        t = r.get("type")
        if not isinstance(t, str):
            return False
        if "proof" in r and (
                not isinstance(r["proof"], list) or
                not 1 <= len(r["proof"]) <= MAX_PROOFS or
                not all(isinstance(p, dict) for p in r["proof"])):
            return False                    # core 5.1
        if "ext" in r and (
                not isinstance(r["ext"], dict) or not all(
                    isinstance(block, dict) and (
                        name in SHORT_NAMESPACES or name.startswith("oip.")
                        or fullmatch(NAMESPACE_RE, name))
                    for name, block in r["ext"].items())):
            return False                    # core 8.1
        critical = r.get("critical", [])
        if not isinstance(critical, list) or not all(
                isinstance(n, str) and isinstance(r.get("ext"), dict) and
                n in r["ext"] for n in critical):
            return False                    # core 8.3
        if t not in RECORD_TYPES and not critical:
            return False                    # core 7: a critical extension
        if t not in ("Bundle", "LogPage", "FeedPage", "DuplicityEvidence",
                     "Sealed"):
            ts(r["created"])
        if "expires" in r:
            ts(r["expires"])
        if t in ("Genesis", "Update", "Fork", "Retire") and not event_ok(r):
            return False                    # Layer 1, Section 3
        if t in ("Offer", "Commitment"):
            price = r.get("terms", {}).get("price")
            if price is not None and (
                    not is_amount(price.get("amount")) or
                    not isinstance(price.get("currency"), str)):
                return False
        if t == "Intent":
            budget = r.get("constraints", {}).get("budget")
            if budget is not None and not is_amount(budget.get("max")):
                return False
        if t == "Commitment":
            parties = r["parties"]
            if not 2 <= len(parties) <= 64 or \
               len({p["mind"] for p in parties}) != len(parties):
                return False
            roles = [p["role"] for p in parties]
            if "debtor" not in roles or "creditor" not in roles:
                return False
            if any(p["role"] in ("debtor", "creditor") and
                   p.get("required") is not True for p in parties):
                return False
            if not isinstance(r["promise"], str) or \
               not isinstance(r["terms"], dict):
                return False
            price = r["terms"].get("price")
            minds = {p["mind"] for p in parties}
            if price is not None and (                 # Layer 2, 5.1
                    price.get("payer") not in minds or
                    price.get("payee") not in minds or
                    price["payer"] == price["payee"]):
                return False
        if t == "Receipt":
            o = r["outcome"]
            if o not in RECEIPT_OUTCOMES and ":" not in o:
                return False
            if o == "revoked" and not ref_cid(r.get("supersedes")):
                return False
        if t == "Delegation":
            for f in ("author", "delegate", "subject"):
                if not fullmatch(ADDR_RE, r[f]):
                    return False
            if r["delegate"] == r["author"]:
                return False                    # Layer 1, 11.1
            if not command_valid(r["command"]) or \
               not policy_valid(r.get("policy", [])):
                return False
            ts(r["expires"])
            if "notBefore" in r:
                ts(r["notBefore"])
            if not isinstance(r["nonce"], str) or \
               not 8 <= len(r["nonce"]) <= 64:
                return False
        if t == "Revocation":
            if not ref_cid(r["revokes"]):
                return False
        if t in ("Packet", "Session"):
            if not isinstance(r["nonce"], str) or \
               not 8 <= len(r["nonce"]) <= 64:
                return False
        if t == "Packet" and "session" not in r and "expires" not in r:
            return False
        if t == "Packet":
            retention = r.get("constraints", {}).get("retention", "none")
            if retention != "none" and not is_duration(retention):
                return False                # core 1.5
        return True
    except (KeyError, TypeError, ValueError, AttributeError):
        return False

# ---------------------------------------------------------------- verifier


class Verifier:
    """A verifier's view: identity logs (one or more branches per mind),
    records it holds (for record-refs, revocations and charters) and its
    evidence (core 9.4). `seen` maps evidence to the earliest time the
    verifier can show, whether from itself, a witness it trusts or an
    anchor: a proof's digest (Layer 1, 10.1) for a proof on a record, and
    a content ID for an identity event. With no evidence, this generator
    assumes the verifier obtained each proof or event at its own `created`
    time (the test vectors' convention); a live verifier uses the earliest
    evidence it holds, which for a proof received live is its receipt."""

    def __init__(self, logs=(), records=(), seen=None, branches=()):
        self.raw, self.cache, self.store = {}, {}, {}
        self.seen = dict(seen or {})
        self.apply_compromise = True
        self.visiting = set()
        for log in logs:
            self.add_log(log)
        for log in branches:
            self.add_branch(log)
        for r in records:
            self.add(r)

    def add_log(self, events):
        """Hold `events` as the mind's log, replacing any held before."""
        self.raw[did(content_id(events[0]))] = [events]
        self.cache.clear()

    def add_branch(self, events):
        """Hold `events` as a further branch of the mind's log."""
        self.raw.setdefault(did(content_id(events[0])), []).append(events)
        self.cache.clear()

    def add(self, record):
        self.store[content_id(record)] = record

    def log(self, mind, depth=0) -> Log:
        if mind in self.cache:
            return self.cache[mind]
        if depth > MAX_NESTING:
            raise ValueError("collectives nest at most 4 deep")
        if mind in self.visiting:
            raise ValueError("a collective cannot contain itself")
        self.visiting.add(mind)
        try:
            branches = self.raw[mind]
            if len(branches) == 1:
                log = verify_log(branches[0], self, depth)
            else:
                log = self.resolve_branches(branches, depth)
        finally:
            self.visiting.discard(mind)
        self.cache[mind] = log
        return log

    # -- duplicity (Layer 1, Section 7) -------------------------------------
    def evidence(self, event):
        """tau(e): the earliest evidence that an identity event existed."""
        seen = self.seen.get(content_id(event))
        return ts(seen) if seen else ts(event["created"])

    def resolve_branches(self, branches, depth) -> Log:
        """Never by length or recency: at each point of divergence the
        event with strictly the earliest evidence wins (7.3). If evidence
        cannot separate them, the mind is duplicitous: only the events
        before the divergence stand, and every branch's later removals and
        compromise declarations apply. A copy takes part with the events it
        has that verify; one that is still in the contest at a position and
        holds an event there that does not verify stops the log there."""
        # A copy whose first event does not verify raises here: it is in
        # the contest, and holds an event at the first position that does
        # not verify.
        cands = [verify_log(events, self, depth, prefix=True)
                 for events in branches]

        def settled(left, log):
            """Where evidence cannot separate the events at a position, the
            later events of every copy that is left apply, so each must
            have verified to its end."""
            for lg in left:
                if lg.failed is not None:
                    raise ValueError("a copy that is left does not verify "
                                     f"to its end: {lg.failed}")
            return log
        k = 0
        while True:
            # The verifier knows the log only as far as the copies it relies
            # on verify. A copy still in the contest that holds an event
            # here that did not verify may hold the mind's own event, which
            # this verifier cannot judge (Layer 1, 4.9): the log does not
            # verify, whatever another copy holds at this position.
            for lg in cands:
                if lg.failed is not None and len(lg.events) == k:
                    raise ValueError("a copy that is left holds an event at "
                                     f"position {k} that does not verify: "
                                     f"{lg.failed}")
            heads = {}
            for lg in cands:
                if k < len(lg.events):
                    heads.setdefault(content_id(lg.events[k]), []).append(lg)
            if not heads:
                return cands[0]
            if len(heads) == 1:
                cands = next(iter(heads.values()))    # prefixes are not forks
                k += 1
                continue
            tau = {h: self.evidence(g[0].events[k]) for h, g in heads.items()}
            first = min(tau.values())
            winners = [h for h, t in tau.items() if t == first]
            if len(winners) == 1:
                cands = heads[winners[0]]
                k += 1
                continue
            base = cands[0]
            out = Log(base.mind, base.events[:k], base.states[:k],
                      base.times[:k], base.height)
            out.duplicitous = True
            out.branch_tails = [(lg.times[j], lg.states[j], lg.events[j])
                                for lg in cands
                                for j in range(k, len(lg.events))]
            return settled(cands, out)

    def resolve(self, ref):
        if isinstance(ref, dict):
            return ref
        cid = ref_cid(ref)
        return self.store.get(cid) if cid else None

    # -- evaluation time (core, Section 9) --------------------------------
    def t_of(self, record, p):
        """t(p) = max(p.created, tau(p)); None if the proof claims to be
        from the future relative to the evidence. Evidence is for this
        proof (its digest): evidence that the record existed says nothing
        about a co-signature added later (core 9.4)."""
        try:
            created = ts(p.get("created"))
            seen = self.seen.get(proof_digest(p))
        except (TypeError, ValueError, AttributeError):
            return None
        tau = ts(seen) if seen else created
        if created > tau + SKEW_NS:
            return None
        return max(created, tau)

    def event_time(self, event):
        """Evaluation time of an identity event: max(created, tau(e)), where
        tau(e) is evidence for the event as a whole (core 9.5)."""
        created = ts(event["created"])
        seen = self.seen.get(content_id(event))
        if not seen:
            return created
        if created > ts(seen) + SKEW_NS:
            raise ValueError("identity event dated after the evidence that "
                             "it existed")
        return max(created, ts(seen))

    # -- key validity (Layer 1, Section 6) ---------------------------------
    def valid_key(self, record, p, mind, depth=0, identity_at=None) -> bool:
        """Layer 1, 6.1 for operational keys. With identity_at (a member's
        proof on another mind's identity event, Layer 1, 6.4) the key must
        be an invocation key at the pinned version that was not removed, nor
        the member retired, before the event's evaluation time identity_at.
        Compromise declarations do not reach into other minds' logs."""
        if not isinstance(p, dict):
            return False
        ref = parse_key_ref(p.get("verificationMethod"))
        if not ref or ref[0] != mind:
            return False
        _, version, mk = ref
        rtype = record.get("type")
        if p.get("proofPurpose") != purpose_for(rtype):
            return False
        try:
            log = self.log(mind, depth)
        except (KeyError, ValueError):
            return False
        i = log.index(version)
        if i is None or log.states[i].retired:
            return False        # Layer 1, 6.1 item 2: not the Retire itself
        if identity_at is not None:
            # A proof that names an authority is made for that principal,
            # not by the member for itself (6.4); and core 9.3.
            if "authority" in p or \
               not _dated_within(p, self.evidence(record)):
                return False
            if mk not in log.states[i].invocation:
                return False
            removed = log.removal_time(i, mk, "invocation")
            if removed is not None and identity_at >= removed:
                return False
            return verify_proof(record, p, mk)
        if mk not in log.states[i].keys:
            return False
        t = self.t_of(record, p)
        if t is None:
            return False
        removed = log.removal_time(i, mk)
        if removed is not None and t >= removed:
            return False
        compromised = log.compromised_since(mk)
        if self.apply_compromise and compromised is not None and \
           t >= compromised:
            return False
        if rtype in CURRENT_STATE_TYPES and \
           (mk not in log.latest.keys or log.latest.retired or
                log.duplicitous):
            return False
        return verify_proof(record, p, mk)

    def member_signers(self, record, members, depth,
                       identity_at=None) -> set:
        """Distinct members with a proof by one of their own valid keys."""
        out = set()
        for p in record.get("proof", []):
            ref = parse_key_ref(p.get("verificationMethod")) \
                if isinstance(p, dict) else None
            if ref and ref[0] in members and ref[0] not in out and \
               self.valid_key(record, p, ref[0], depth + 1, identity_at):
                out.add(ref[0])
        return out

    # -- signing for a party (Layer 2, Section 7) ---------------------------
    def signed_time(self, record, mind, depth=0):
        """Earliest evaluation time at which `record` counts for `mind`,
        or None if it never does."""
        if not record_ok(record):
            return None
        if record.get("critical"):
            return None     # core 8.3: this verifier implements no extension
        proofs = record.get("proof")
        if not isinstance(proofs, list) or not proofs or \
           len(proofs) > MAX_PROOFS:
            return None
        times = [self.t_of(record, p) for p in proofs
                 if self.valid_key(record, p, mind, depth)]
        try:
            log = self.log(mind, depth)
        except (KeyError, ValueError):
            log = None
        collective = log is not None and log.latest.controller == "member"
        if collective:
            times.append(self.collective_time(record, log, depth))
        if record["type"] in DELEGABLE_TYPES:
            times.append(self.delegated_time(record, mind, depth))
            if collective:
                times.append(self.role_time(record, mind, log, depth))
        times = [t for t in times if t is not None]
        if "expires" in record:
            limit = ts(record["expires"]) + SKEW_NS
            times = [t for t in times if t <= limit]
        return min(times) if times else None

    def counts_for(self, record, mind) -> bool:
        return self.signed_time(record, mind) is not None

    def collective_time(self, record, log, depth):
        """Earliest T at which the members of the collective's state at T
        holding proofs with t(p) <= T reach that state's threshold. Only
        proofs without `authority` count towards a threshold: a proof that
        names an authority acts for that principal. A current-state record
        needs the threshold of the collective's latest state (Layer 2,
        7.1 item 3).

        The threshold can first be met when a proof is made or when an
        event of the collective changes its members or its threshold, so T
        ranges over both (Layer 1, 9.5). A duplicitous collective signs
        nothing from its first conflicting event on: its state from then on
        is not known (Layer 1, 7.3)."""
        if record.get("type") == "Hello":
            return None         # core 11: by the author's own key, never a threshold
        current = record.get("type") in CURRENT_STATE_TYPES
        if current and (log.latest.retired or log.duplicitous):
            return None
        everyone = set(log.latest.members) if current else log.members_ever()
        cands = []
        for p in record.get("proof", []):
            if not isinstance(p, dict) or "authority" in p:
                continue
            ref = parse_key_ref(p.get("verificationMethod"))
            if ref and ref[0] in everyone and \
               self.valid_key(record, p, ref[0], depth + 1):
                cands.append((self.t_of(record, p), ref[0]))
        if not cands:
            return None
        unknown_from = min((when for when, _, _ in log.branch_tails),
                           default=None)
        for t in sorted({t for t, _ in cands} | set(log.times)):
            if unknown_from is not None and t >= unknown_from:
                return None
            st = log.latest if current else log.state_at(t)
            if st is None or st.retired:
                continue
            signers = {m for (u, m) in cands if u <= t and m in st.members}
            if len(signers) >= st.threshold:
                return t
        return None

    def charter_in_force(self, mind, t, depth, also=()):
        """Layer 2, 6.2: the charter whose signature for the collective was
        completed most recently at or before t; on a tie, the one with the
        lower content ID."""
        best = None
        known = {content_id(c): c for c in list(self.store.values()) +
                 list(also) if isinstance(c, dict)}
        for cid, c in sorted(known.items()):
            if c.get("type") != "Collective" or c.get("author") != mind:
                continue
            tc = self.signed_time(c, mind, depth)
            if tc is not None and tc <= t and (best is None or tc > best[0]):
                best = (tc, c)
        return best[1] if best else None

    def role_time(self, record, mind, log, depth, signer=None):
        """A member holding a role in the charter in force at t(p), whose
        power covers the record, signs for the collective when its proof's
        `authority` names that charter (Layer 2, 7.1 item 4)."""
        need = "/oip/sign/" + record["type"]
        best = None
        for p in record.get("proof", []):
            auth = p.get("authority") if isinstance(p, dict) else None
            if not isinstance(auth, list) or len(auth) != 1:
                continue
            charter = self.resolve(auth[0])
            if not isinstance(charter, dict) or \
               charter.get("type") != "Collective" or \
               charter.get("author") != mind:
                continue
            ref = parse_key_ref(p.get("verificationMethod"))
            if not ref or (signer and ref[0] != signer) or \
               not self.valid_key(record, p, ref[0], depth + 1):
                continue
            member, t = ref[0], self.t_of(record, p)
            st = log.state_at(t)
            if st is None or st.retired or member not in st.members:
                continue
            in_force = self.charter_in_force(mind, t, depth, [charter])
            if in_force is None or \
               content_id(in_force) != content_id(charter):
                continue
            roles = {a.get("role") for a in charter.get("assignments", [])
                     if isinstance(a, dict) and a.get("mind") == member}
            for role in roles:
                spec = charter.get("roles", {}).get(role)
                for power in (spec or {}).get("powers", []):
                    if command_valid(power.get("command")) and \
                       command_covers(power["command"], need) and \
                       policy_ok(power.get("policy", []), record):
                        best = t if best is None else min(best, t)
        return best

    def acts_for(self, record, signer, principal) -> bool:
        """True if a proof by `signer` counts for `principal` through a
        delegation or a charter role (the Layer 2, 5.2 author rule)."""
        if self.delegated_time(record, principal, 0,
                               signer=signer) is not None:
            return True
        try:
            log = self.log(principal)
        except (KeyError, ValueError):
            return False
        return log.latest.controller == "member" and \
            self.role_time(record, principal, log, 0, signer) is not None

    # -- delegation (Layer 1, Section 11) ----------------------------------
    def delegated_time(self, record, principal, depth, need=None,
                       signer=None):
        """A proof by D counts for P when its own `authority` lists exactly
        a valid chain from P to D, root first (Layer 1, 11.4 and 11.6). The
        chain sits in the proof, so a delegated co-signer can sign at any
        time without changing the record's content ID, and one proof acts
        for at most one principal."""
        need = need or "/oip/sign/" + record["type"]
        best = None
        for p in record.get("proof", []):
            auth = p.get("authority") if isinstance(p, dict) else None
            if not isinstance(auth, list) or not 1 <= len(auth) <= MAX_CHAIN:
                continue
            ref = parse_key_ref(p.get("verificationMethod"))
            if not ref or ref[0] == principal or \
               (signer and ref[0] != signer):
                continue
            chain = [self.resolve(a) for a in auth]
            if not all(isinstance(d, dict) and d.get("type") == "Delegation"
                       for d in chain) or \
               not self.valid_key(record, p, ref[0], depth):
                continue
            t = self.t_of(record, p)
            if self.chain_ok(chain, record, need, t, principal, ref[0],
                             depth):
                best = t if best is None else min(best, t)
        return best

    def chain_ok(self, chain, record, need, t, principal, signer,
                 depth) -> bool:
        """Layer 1, 11.4 for the delegations exactly as listed, root first."""
        if any(not record_ok(d) for d in chain):
            return False
        if chain[0]["author"] != principal or \
           any(d["subject"] != principal for d in chain) or \
           any(chain[i]["delegate"] != chain[i + 1]["author"]
               for i in range(len(chain) - 1)) or \
           chain[-1]["delegate"] != signer:
            return False
        for i, d in enumerate(chain):
            td = self.signed_time(d, d["author"], depth)
            if td is None or td > t:
                return False            # signed by its author, before use
            if "notBefore" in d and t < ts(d["notBefore"]) - SKEW_NS:
                return False
            if t > ts(d["expires"]) + SKEW_NS:
                return False
            tr = self.revoked_time(d, depth)
            if tr is not None and tr <= t:
                return False
            if i > 0:
                parent = chain[i - 1]
                if not command_covers(parent["command"], d["command"]):
                    return False
                inherited = {jcs(s) for s in d.get("policy", [])}
                if any(jcs(s) not in inherited
                       for s in parent.get("policy", [])):
                    return False
                if ts(d["expires"]) > ts(parent["expires"]):
                    return False
        if not command_covers(chain[-1]["command"], need):
            return False
        return all(policy_ok(d.get("policy", []), record) for d in chain)

    def revoked_time(self, d, depth=0):
        """Evaluation time of the earliest valid revocation of d."""
        cid, best = content_id(d), None
        for r in list(self.store.values()):
            if r.get("type") == "Revocation" and \
               r.get("author") == d.get("author") and \
               ref_cid(r.get("revokes")) == cid:
                t = self.signed_time(r, r["author"], depth)
                if t is not None:
                    best = t if best is None else min(best, t)
        return best

    def sent_for(self, packet, subject) -> bool:
        """Layer 1, 11.2: a packet counts as sent on `subject`'s behalf when
        it names the subject in `provenance.onBehalfOf` and a proof by its
        sender lists a chain from the subject that covers /oip/send."""
        if not record_ok(packet) or packet.get("type") != "Packet" or \
           not isinstance(packet.get("provenance"), dict) or \
           packet["provenance"].get("onBehalfOf") != subject:
            return False
        t = self.delegated_time(packet, subject, 0, need="/oip/send",
                                signer=packet.get("from"))
        return t is not None and (
            "expires" not in packet or t <= ts(packet["expires"]) + SKEW_NS)

    # -- lineage (Layer 1, Section 8) ---------------------------------------
    def lineage(self, child) -> dict:
        out = {}
        for par in self.log(child).states[0].parents:
            parent, at = par.get("mind"), par.get("at")
            try:
                plog = self.log(parent)
            except (KeyError, ValueError):
                out[parent] = "claimed"
                continue
            i_at = plog.index(at)
            ack = False
            if i_at is not None:
                ack = any(ev["type"] == "Fork" and ev.get("child") == child
                          for ev in plog.events[i_at:])
                ack = ack or any(
                    r.get("type") == "Lineage" and
                    r.get("author") == parent and r.get("child") == child and
                    self.signed_time(r, parent) is not None
                    for r in list(self.store.values()))
            out[parent] = "acknowledged" if ack else "claimed"
        return out

# ---------------------------------------------------------------- status


def commitment_accepted(V, c) -> bool:
    """Layer 2, 7.3: counts for its author, whose author is a party or
    signs for one (5.2), and for every required party."""
    if not record_ok(c) or V.signed_time(c, c.get("author")) is None:
        return False
    minds = [p["mind"] for p in c["parties"]]
    if c["author"] not in minds and \
       not any(V.acts_for(c, c["author"], m) for m in minds):
        return False
    return all(V.signed_time(c, p["mind"]) is not None
               for p in c["parties"] if p.get("required"))


def bridge_assurance(V, participant) -> str:
    """Layer 0, 1.3: `bridged` only if the mind's genesis and profile name
    the same gateway, and the gateway's own feed entry for that genesis,
    named in the profile, counts for the gateway; `claimed` for any other
    `oip.bridge` block; otherwise `native`."""
    block = (participant.get("ext") or {}).get("oip.bridge")
    if block is None:
        return "native"
    mind, gateway = participant.get("author"), block.get("gateway")
    try:
        genesis = V.log(mind).events[0]
    except (KeyError, ValueError):
        return "claimed"
    declared = (genesis.get("ext") or {}).get("oip.bridge") or {}
    entry = V.resolve(block.get("attestation"))
    if V.signed_time(participant, mind) is None or \
       declared.get("gateway") != gateway or not isinstance(entry, dict) or \
       entry.get("type") != "Entry" or entry.get("author") != gateway or \
       entry.get("object") != content_id(genesis) or \
       entry.get("objectType") != "Genesis" or \
       V.signed_time(entry, gateway) is None:
        return "claimed"
    return "bridged"


ALLOWED_STATUS = {"Intent": ("satisfied", "withdrawn"),
                  "Offer": ("withdrawn",)}


def _supersession(V, record, records):
    """Layer 2, Section 8: a superseding record with `status` has that
    status itself; otherwise the strongest valid superseding record by the
    same author decides (satisfied, then withdrawn, then an edit)."""
    allowed = ALLOWED_STATUS[record["type"]]
    if record.get("supersedes") and record.get("status") in allowed:
        return record["status"]
    cid, found = content_id(record), set()
    for r in records:
        if r.get("type") == record["type"] and \
           r.get("author") == record["author"] and \
           ref_cid(r.get("supersedes")) == cid and \
           V.signed_time(r, r["author"]) is not None:
            status = r.get("status")
            if status is None:
                found.add("superseded")
            elif status in allowed:
                found.add(status)
    for status in ("satisfied", "withdrawn", "superseded"):
        if status in found:
            return status
    return None


def intent_status(V, intent, records, at) -> str:
    icid = content_id(intent)
    status = _supersession(V, intent, records)
    if status:
        return status
    for c in records:
        if c.get("type") == "Commitment" and c.get("closesIntent") is True \
           and any(ref_cid(x) == icid for x in c.get("resolves", [])) and \
           commitment_accepted(V, c) and \
           V.signed_time(c, intent["author"]) is not None:
            return "satisfied"
    if "expires" in intent and at > ts(intent["expires"]):
        return "expired"
    return "open"


def offer_status(V, offer, records, at) -> str:
    ocid = content_id(offer)
    status = _supersession(V, offer, records)
    if status:
        return status
    if "expires" in offer and at > ts(offer["expires"]):
        return "expired"
    quantity = offer.get("terms", {}).get("quantity")
    if isinstance(quantity, int) and not isinstance(quantity, bool):
        n = sum(1 for c in records if c.get("type") == "Commitment" and
                any(ref_cid(x) == ocid for x in c.get("resolves", [])) and
                commitment_accepted(V, c) and
                V.signed_time(c, offer["author"]) is not None)
        if n >= quantity:
            return "exhausted"
    return "open"


def commitment_status(V, c, records, at) -> str:
    if not commitment_accepted(V, c):
        V.apply_compromise = False
        try:
            withdrawn = commitment_accepted(V, c)
        finally:
            V.apply_compromise = True
        return "disputed" if withdrawn else "proposed"
    ccid = content_id(c)
    parties = {p["mind"] for p in c["parties"]}
    receipts = [r for r in records if r.get("type") == "Receipt" and
                ref_cid(r.get("about")) == ccid and
                r.get("author") in parties and
                V.signed_time(r, r["author"]) is not None]
    by_cid = {content_id(r): r for r in receipts}
    superseded = {ref_cid(r.get("supersedes")) for r in receipts
                  if ref_cid(r.get("supersedes")) in by_cid and
                  by_cid[ref_cid(r["supersedes"])]["author"] == r["author"]}
    R = [r for r in receipts if content_id(r) not in superseded and
         r["outcome"] != "revoked"]
    required = [p["mind"] for p in c["parties"] if p.get("required")]
    creditors = [p["mind"] for p in c["parties"] if p["role"] == "creditor"]
    cancelled = [r for r in R if r["outcome"] == "cancelled"]
    if cancelled and all(any(V.signed_time(r, m) is not None
                             for r in cancelled) for m in required):
        return "cancelled"
    F = [r for r in R if r["outcome"] == "fulfilled"]
    if any(V.signed_time(r, m) is not None for r in F for m in creditors) \
       or (c["terms"].get("selfReport") is True and F):
        candidate = "fulfilled"
    elif F:
        candidate = "claimed-fulfilled"
    else:
        candidate = "accepted"
    outcomes = {r["outcome"] for r in R}
    if candidate in ("fulfilled", "claimed-fulfilled") and \
       outcomes & {"broken", "disputed"}:
        return "disputed"
    if candidate == "accepted" and "broken" in outcomes:
        return "broken"
    if candidate == "accepted" and "disputed" in outcomes:
        return "disputed"
    deadline = c["terms"].get("deadline")
    if candidate == "accepted" and deadline and at > ts(deadline):
        return "overdue"
    return candidate

# ---------------------------------------------------------------- scenario


T0 = "2026-10-30T09:00:00Z"


def key_controlled_genesis(kind, control, nxt, op_keys, created=T0,
                           agreement=None, homes=None, parents=None,
                           next_keys=None, next_threshold=1, extra=None):
    nexts = next_keys if next_keys is not None else [nxt]
    g = {"oip": OIP_VERSION, "type": "Genesis", "kind": kind,
         "created": created,
         "controller": {"keys": [control.mk],
                        "next": [key_hash(k.mk) for k in nexts],
                        "nextThreshold": next_threshold},
         "keys": [{"key": k.mk, "label": k.label} for k in op_keys]}
    if agreement:
        g["agreement"] = [{"key": a.mk, "label": "main"} for a in agreement]
    if homes:
        g["homes"] = homes
    if parents:
        g["parents"] = parents
    if extra:
        g.update(extra)
    return sign(g, create_proof(g, control, did_key_vm(control.mk),
                                "capabilityInvocation", created))


def control_event(etype, mind, prev, created, reveal, nxt, fields=None,
                  next_threshold=1, signers=None):
    """A later event of a key-controlled log, signed by its control keys."""
    ev = {"oip": OIP_VERSION, "type": etype, "mind": mind,
          "seq": prev.get("seq", 0) + 1, "prev": content_id(prev),
          "created": created,
          "controller": {"keys": [k.mk for k in reveal],
                         "next": [key_hash(k.mk) for k in nxt]}}
    if nxt:
        ev["controller"]["nextThreshold"] = next_threshold
    ev.update(fields or {})
    return sign(ev, *[create_proof(ev, k, did_key_vm(k.mk),
                                   "capabilityInvocation", created)
                      for k in (signers if signers is not None else reveal)])


def member_event(etype, mind, prev, created, signers, fields=None):
    """A later event of a collective's log, signed by members."""
    ev = {"oip": OIP_VERSION, "type": etype, "mind": mind,
          "seq": prev.get("seq", 0) + 1, "prev": content_id(prev),
          "created": created}
    ev.update(fields or {})
    return sign(ev, *[create_proof(ev, key, vm, "capabilityInvocation",
                                   created) for key, vm in signers])


def signed(doc, key, vm, created=None, purpose=None, authority=None):
    extra = {"authority": authority} if authority else {}
    return sign(doc, create_proof(doc, key, vm,
                                  purpose or purpose_for(doc["type"]),
                                  created or doc["created"], **extra))

# ---------------------------------------------------------------- derived


def cid_digest(cid: str) -> bytes:
    """The 32-byte SHA-256 digest inside a content ID."""
    body = cid[1:].upper()
    raw = base64.b32decode(body + "=" * (-len(body) % 8))
    assert raw[:2] == b"\x12\x20"
    return raw[2:]


def merkle_root(leaves) -> bytes:
    """RFC 9162 Merkle Tree Hash; each leaf input is a 32-byte digest."""
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return hashlib.sha256(b"\x01" + merkle_root(leaves[:k]) +
                          merkle_root(leaves[k:])).digest()


def checkpoint_root(entry_cids) -> str:
    root = merkle_root([cid_digest(c) for c in entry_cids])
    return "b" + b32lower(b"\x12\x20" + root)


def did_document(V, mind, version=None) -> dict:
    """DID resolution result for a did:oip address (Layer 1, 5.2), from the
    identity log alone (no location record, no verified aliases)."""
    log = V.log(mind)
    st = log.latest if version is None else log.states[log.index(version)]

    def vm_id(mk):
        return f"{mind}?versionId={st.version}#{mk}" if version \
            else f"{mind}#{mk}"
    doc = {"id": mind,
           "verificationMethod": [
               {"id": vm_id(mk), "type": "Multikey", "controller": mind,
                "publicKeyMultibase": mk}
               for mk in st.keys + st.invocation + st.agreement],
           "authentication": [vm_id(k) for k in st.keys],
           "assertionMethod": [vm_id(k) for k in st.keys],
           "capabilityDelegation": [vm_id(k) for k in st.keys],
           "capabilityInvocation": [vm_id(k) for k in st.invocation],
           "keyAgreement": [vm_id(k) for k in st.agreement]}
    if st.homes:
        doc["service"] = [{"id": f"{mind}#home-{n}", "type": "OIPHome",
                           "serviceEndpoint": h}
                          for n, h in enumerate(st.homes)]
    meta = {"versionId": st.version, "deactivated": st.retired,
            "parents": st.parents, "children": st.children}
    if log.duplicitous:
        meta["duplicitous"] = True      # Layer 1, 5.2 and 7.3
    if st.controller == "key":
        meta["nextKeyHashes"] = st.next
        if st.next:
            meta["nextThreshold"] = st.next_threshold
    else:
        meta["members"], meta["threshold"] = st.members, st.threshold
    return {"didDocument": doc, "didDocumentMetadata": meta}

# ---------------------------------------------------------------- build


def build():
    V = {"spec_revision": REVISION, "status": "draft",
         "note": "Ed25519 keys derive from SHA-256('oip-test-vector:'+label); "
                 "X25519 keys from SHA-256('oip-test-vector-x25519:'+label). "
                 "Never use these keys for anything real.",
         "assumption": "Unless a case gives `seen` times, a verifier is "
                       "taken to have obtained each proof and identity "
                       "event at its own `created` time. `seen` maps a "
                       "proof's digest, or an identity event's content ID, "
                       "to the earliest evidence that it existed.",
         "baseline": {"logs": list(LOG_NAMES),
                      "records": list(RECORD_NAMES)},
         "keys": {}, "cases": {}, "valid": [], "negative": [],
         "controls": []}

    def k(label):
        key = Key(label)
        V["keys"][label] = {"seed_hex": key.seed_hex, "multikey": key.mk}
        return key

    # --- Amina: a human, key-controlled -------------------------------
    a_c0, a_c1, a_c2, a_c3, a_c4 = (k(f"amina-control-{i}") for i in range(5))
    a_op1, a_op2 = k("amina-phone"), k("amina-laptop")
    a_inv = k("amina-invocation")
    a_x = AgreementKey("amina")
    V["keys"]["x25519:amina"] = {"seed_hex": a_x.seed_hex,
                                 "multikey": a_x.mk, "type": "X25519"}
    a_gen = key_controlled_genesis("human", a_c0, a_c1, [a_op1],
                                   agreement=[a_x],
                                   homes=["https://amina.example"])
    amina = did(content_id(a_gen))
    a_upd = control_event("Update", amina, a_gen, "2026-10-30T09:05:00Z",
                          [a_c1], [a_c2], fields={
                              "keys": [{"key": a_op1.mk, "label": a_op1.label},
                                       {"key": a_op2.mk,
                                        "label": a_op2.label}],
                              "invocation": [{"key": a_inv.mk,
                                              "label": a_inv.label}]})
    amina_vm1 = op_vm(amina, a_upd, a_op1.mk)
    amina_vm2 = op_vm(amina, a_upd, a_op2.mk)
    amina_inv = op_vm(amina, a_upd, a_inv.mk)

    # --- Lexis Ltd (institution) and its translation agent -------------
    l_c0, l_c1 = k("lexisltd-control-0"), k("lexisltd-control-1")
    l_op = k("lexisltd-ops")
    ltd_gen = key_controlled_genesis("institution", l_c0, l_c1, [l_op])
    lexis_ltd = did(content_id(ltd_gen))
    ltd_vm = op_vm(lexis_ltd, ltd_gen, l_op.mk)

    t_c0, t_c1, t_c2 = k("lexis-agent-control-0"), \
        k("lexis-agent-control-1"), k("lexis-agent-control-2")
    t_op, t_inv = k("lexis-agent-i1"), k("lexis-agent-invocation")
    agent_gen = key_controlled_genesis("agent", t_c0, t_c1, [t_op],
                                       homes=["https://lexis.example"])
    lexis = did(content_id(agent_gen))

    # --- Forks: one acknowledged by a Fork event, one by a Lineage record
    f_c0, f_c1 = k("lexis-fork-control-0"), k("lexis-fork-control-1")
    f_op = k("lexis-fork-i1")
    child_gen = key_controlled_genesis(
        "agent", f_c0, f_c1, [f_op], created="2026-10-30T09:10:00Z",
        parents=[{"mind": lexis, "at": version_id(agent_gen)}])
    child = did(content_id(child_gen))
    fork_ev = control_event("Fork", lexis, agent_gen, "2026-10-30T09:11:00Z",
                            [t_c1], [t_c2], fields={
                                "child": child,
                                "invocation": [{"key": t_inv.mk,
                                                "label": t_inv.label}]})
    agent_vm = op_vm(lexis, fork_ev, t_op.mk)
    agent_inv = op_vm(lexis, fork_ev, t_inv.mk)
    child_vm = op_vm(child, child_gen, f_op.mk)

    g_c0, g_c1 = k("lexis-fork2-control-0"), k("lexis-fork2-control-1")
    g_op = k("lexis-fork2-i1")
    child2_gen = key_controlled_genesis(
        "agent", g_c0, g_c1, [g_op], created="2026-10-30T09:12:00Z",
        parents=[{"mind": lexis, "at": version_id(fork_ev)}])
    child2 = did(content_id(child2_gen))
    lineage = signed({"oip": OIP_VERSION, "type": "Lineage", "author": lexis,
                      "created": "2026-10-30T09:13:00Z", "child": child2},
                     t_op, agent_vm)

    # --- A researcher agent, and a 2-of-3 collective -------------------
    r_c0, r_c1, r_c2 = k("researcher-control-0"), k("researcher-control-1"), \
        k("researcher-control-2")
    r_op, r_inv = k("researcher-ops"), k("researcher-invocation")
    res_gen = key_controlled_genesis("agent", r_c0, r_c1, [r_op])
    researcher = did(content_id(res_gen))
    res_upd = control_event("Update", researcher, res_gen,
                            "2026-10-30T09:02:00Z", [r_c1], [r_c2], fields={
                                "invocation": [{"key": r_inv.mk,
                                                "label": r_inv.label}]})
    res_vm = op_vm(researcher, res_gen, r_op.mk)
    res_inv = op_vm(researcher, res_upd, r_inv.mk)

    founders = [(a_inv, amina_inv), (t_inv, agent_inv), (r_inv, res_inv)]

    def coll_genesis(threshold, signers, members=(amina, lexis, researcher),
                     created="2026-10-30T09:20:00Z", height=None,
                     invocation=None):
        g = {"oip": OIP_VERSION, "type": "Genesis", "kind": "collective",
             "created": created,
             "controller": {"members": list(members),
                            "threshold": threshold}}
        if height is not None:
            g["height"] = height
        if invocation:
            g["invocation"] = [{"key": key.mk, "label": key.label}
                               for key in invocation]
        return sign(g, *[create_proof(g, key, vm, "capabilityInvocation",
                                      created) for key, vm in signers])

    coll = coll_genesis(2, founders)
    collective = did(content_id(coll))

    # --- A 2-of-3 pre-rotation (thresholds count distinct keys) --------
    m_c0 = k("multi-control-0")
    m_k1, m_k2, m_k3, m_k4 = (k(f"multi-next-{i}") for i in (1, 2, 3, 4))
    m_op = k("multi-ops")
    m_gen = key_controlled_genesis("institution", m_c0, None, [m_op],
                                   next_keys=[m_k1, m_k2, m_k3],
                                   next_threshold=2)
    multi = did(content_id(m_gen))
    m_upd = control_event("Update", multi, m_gen, "2026-10-30T09:06:00Z",
                          [m_k1, m_k2], [m_k4])

    # --- Amina's assistant agent ---------------------------------------
    s_c0, s_c1 = k("amina-assistant-control-0"), \
        k("amina-assistant-control-1")
    s_op = k("amina-assistant-ops")
    asst_gen = key_controlled_genesis("agent", s_c0, s_c1, [s_op],
                                      created="2026-10-30T09:03:00Z")
    assistant = did(content_id(asst_gen))
    asst_vm = op_vm(assistant, asst_gen, s_op.mk)

    # --- A gateway and an MCP server it bridges (Layer 0, Section 1) ---
    gw_c0, gw_c1, gw_op = k("gateway-control-0"), k("gateway-control-1"), \
        k("gateway-ops")
    gw_gen = key_controlled_genesis("service", gw_c0, gw_c1, [gw_op],
                                    created="2026-10-30T08:00:00Z",
                                    homes=["https://gateway.example"])
    gateway = did(content_id(gw_gen))
    gw_vm = op_vm(gateway, gw_gen, gw_op.mk)
    br_c0, br_c1, br_op = k("bridged-control-0"), k("bridged-control-1"), \
        k("bridged-ops")
    bridge_block = {"protocol": "mcp", "endpoint": "https://tools.example/mcp",
                    "gateway": gateway, "assurance": "bridged"}
    br_gen = key_controlled_genesis("service", br_c0, br_c1, [br_op],
                                    created="2026-10-30T08:10:00Z",
                                    extra={"ext": {"oip.bridge":
                                                   bridge_block}})
    bridged = did(content_id(br_gen))
    br_vm = op_vm(bridged, br_gen, br_op.mk)
    gw_entry = signed({"oip": OIP_VERSION, "type": "Entry",
                       "author": gateway, "seq": 0,
                       "created": "2026-10-30T08:11:00Z",
                       "object": content_id(br_gen), "objectType": "Genesis",
                       "proofs": [proof_digest(p) for p in br_gen["proof"]]},
                      gw_op, gw_vm)
    br_participant = signed({
        "oip": OIP_VERSION, "type": "Participant", "author": bridged,
        "created": "2026-10-30T08:12:00Z", "name": "Example MCP tools",
        "kind": "service",
        "summary": "An MCP server, bridged into OIP by its gateway.",
        "ext": {"oip.bridge": {**bridge_block,
                               "attestation": record_ref(gateway,
                                                         gw_entry)}}},
        br_op, br_vm)

    logs = {"amina_log": [a_gen, a_upd], "lexis_ltd_log": [ltd_gen],
            "lexis_agent_log": [agent_gen, fork_ev],
            "lexis_fork_log": [child_gen], "lexis_fork2_log": [child2_gen],
            "researcher_log": [res_gen, res_upd], "collective_log": [coll],
            "multi_log": [m_gen, m_upd], "assistant_log": [asst_gen],
            "gateway_log": [gw_gen], "bridged_log": [br_gen]}

    # --- Delegations ---------------------------------------------------
    # Lexis Ltd lets its agent commit the firm to work it is paid for, up
    # to 500 USD a commitment, and never to a deal with the agent itself.
    usd_500 = [["==", ".terms.price.currency", "USD"],
               ["<=", ".terms.price.amount", "500"]]
    ltd_policy = usd_500 + [["==", ".terms.price.payee", lexis_ltd],
                            ["all", ".parties", ["!=", ".mind", lexis]]]
    deleg = signed({"oip": OIP_VERSION, "type": "Delegation",
                    "author": lexis_ltd, "created": "2026-10-30T09:30:00Z",
                    "delegate": lexis, "subject": lexis_ltd,
                    "command": "/oip/sign/Commitment", "policy": ltd_policy,
                    "expires": "2026-11-30T09:30:00Z",
                    "nonce": "6c1f0e9d2b8a4735"}, l_op, ltd_vm)
    deleg_ref = record_ref(lexis_ltd, deleg)
    sub_deleg = signed({"oip": OIP_VERSION, "type": "Delegation",
                        "author": lexis, "created": "2026-10-30T09:45:00Z",
                        "delegate": child, "subject": lexis_ltd,
                        "command": "/oip/sign/Commitment",
                        "policy": ltd_policy + [
                            ["<=", ".terms.price.amount", "200"],
                            ["all", ".parties", ["!=", ".mind", child]]],
                        "expires": "2026-11-15T00:00:00Z",
                        "nonce": "9e4b2a7c1d3f5086"}, t_op, agent_vm)
    sub_ref = record_ref(lexis, sub_deleg)
    # Amina lets her assistant commit her to pay up to 150 USD, only in
    # deals between her and Lexis Ltd.
    amina_deleg = signed({
        "oip": OIP_VERSION, "type": "Delegation", "author": amina,
        "created": "2026-10-30T09:35:00Z", "delegate": assistant,
        "subject": amina, "command": "/oip/sign/Commitment",
        "policy": [["==", ".terms.price.currency", "USD"],
                   ["<=", ".terms.price.amount", "150"],
                   ["==", ".terms.price.payer", amina],
                   ["all", ".parties",
                    ["or", [["==", ".mind", amina],
                            ["==", ".mind", lexis_ltd]]]]],
        "expires": "2026-11-30T09:00:00Z", "nonce": "3b7e1f9a0c5d2e84"},
        a_op2, amina_vm2)
    amina_deleg_ref = record_ref(amina, amina_deleg)
    send_deleg = signed({
        "oip": OIP_VERSION, "type": "Delegation", "author": amina,
        "created": "2026-10-30T09:36:00Z", "delegate": assistant,
        "subject": amina, "command": "/oip/send",
        "policy": [["==", ".provenance.onBehalfOf", amina]],
        "expires": "2026-11-30T09:00:00Z", "nonce": "2f8c4a6e1b3d5079"},
        a_op2, amina_vm2)
    send_ref = record_ref(amina, send_deleg)

    # --- Layer 2: intent -> offer -> commitment -> receipt -------------
    intent = signed({"oip": OIP_VERSION, "type": "Intent", "author": amina,
                     "created": "2026-10-30T10:00:00Z",
                     "expires": "2026-10-31T10:00:00Z",
                     "want": "Translate a 12-page Swahili commercial lease "
                             "into English, legally accurate.",
                     "constraints": {"deadline": "2026-11-02T17:00:00Z",
                                     "budget": {"max": "150",
                                                "currency": "USD"}},
                     "audience": {"query": {"tags": ["lang:sw", "lang:en",
                                                     "domain:legal/*"]}}},
                    a_op2, amina_vm2)
    intent_ref = record_ref(amina, intent)

    offer = signed({"oip": OIP_VERSION, "type": "Offer", "author": lexis,
                    "created": "2026-10-30T10:04:00Z",
                    "expires": "2026-10-30T22:00:00Z", "answers": intent_ref,
                    "provides": "English translation of the lease, reviewed "
                                "by a qualified lawyer.",
                    "terms": {"summary": "120 USD, delivered by 1 Nov "
                                         "18:00 UTC.",
                              "price": {"amount": "120", "currency": "USD"},
                              "deliveryBy": "2026-11-01T18:00:00Z"}},
                   t_op, agent_vm)
    offer_ref = record_ref(lexis, offer)
    withdrawal = signed(variant_of(intent, created="2026-10-30T10:10:00Z",
                                   supersedes=intent_ref, status="withdrawn"),
                        a_op2, amina_vm2)
    edit = signed(variant_of(intent, created="2026-10-30T10:12:00Z",
                             supersedes=intent_ref,
                             constraints__budget={"max": "200",
                                                  "currency": "USD"}),
                  a_op2, amina_vm2)
    offer_withdrawal = signed(variant_of(offer,
                                         created="2026-10-30T10:15:00Z",
                                         supersedes=offer_ref,
                                         status="withdrawn"),
                              t_op, agent_vm)
    offer_edit = signed(variant_of(offer, created="2026-10-30T10:16:00Z",
                                   supersedes=offer_ref,
                                   terms__summary="110 USD, delivered by 1 "
                                                  "Nov 18:00 UTC.",
                                   terms__price={"amount": "110",
                                                 "currency": "USD"}),
                        t_op, agent_vm)
    offer_glossary = signed({
        "oip": OIP_VERSION, "type": "Offer", "author": lexis_ltd,
        "created": "2026-10-30T10:50:00Z", "expires": "2026-11-06T10:50:00Z",
        "provides": "A certified glossary of the lease's legal terms, in "
                    "Swahili and English.",
        "terms": {"summary": "150 USD for one glossary, by 3 Nov.",
                  "price": {"amount": "150", "currency": "USD"},
                  "quantity": 1}}, l_op, ltd_vm)
    glossary_ref = record_ref(lexis_ltd, offer_glossary)

    def usd(amount, payer=amina, payee=lexis_ltd):
        return {"amount": amount, "currency": "USD", "payer": payer,
                "payee": payee}

    commit = {"oip": OIP_VERSION, "type": "Commitment", "author": lexis,
              "created": "2026-10-30T10:20:00Z",
              "parties": [{"mind": lexis_ltd, "role": "debtor",
                           "required": True},
                          {"mind": amina, "role": "creditor",
                           "required": True}],
              "promise": "Lexis Ltd will deliver an English translation of "
                         "the lease by 1 Nov 2026 18:00 UTC; Amina will pay "
                         "120 USD on delivery.",
              "terms": {"deadline": "2026-11-01T18:00:00Z",
                        "price": usd("120")},
              "resolves": [intent_ref, offer_ref], "closesIntent": True}
    p_agent = create_proof(commit, t_op, agent_vm, "assertionMethod",
                           commit["created"], authority=[deleg_ref])
    p_amina = create_proof(commit, a_op1, amina_vm1, "assertionMethod",
                           "2026-10-30T10:22:00Z")
    commit_proposed = sign(commit, p_agent)
    commit_accepted = sign(commit, p_agent, p_amina)
    assert content_id(commit_proposed) == content_id(commit_accepted)
    commit_ref = record_ref(lexis, commit)

    receipt = signed({"oip": OIP_VERSION, "type": "Receipt", "author": amina,
                      "created": "2026-11-01T17:40:00Z", "about": commit_ref,
                      "outcome": "fulfilled",
                      "statement": "Translation received on time.",
                      "evidence": [{"kind": "uri",
                                    "ref": "https://lexis.example/d/7731.pdf",
                                    "digest": sha256_digest(
                                        b"example deliverable")}]},
                     a_op1, amina_vm1)
    receipt_by_debtor = signed({
        "oip": OIP_VERSION, "type": "Receipt", "author": lexis_ltd,
        "created": "2026-11-01T16:00:00Z", "about": commit_ref,
        "outcome": "fulfilled", "statement": "Translation delivered."},
        l_op, ltd_vm)
    receipt_broken = signed({
        "oip": OIP_VERSION, "type": "Receipt", "author": amina,
        "created": "2026-11-01T18:30:00Z", "about": commit_ref,
        "outcome": "broken",
        "statement": "Nothing had been delivered by the deadline."},
        a_op1, amina_vm1)
    cancel_amina = signed({
        "oip": OIP_VERSION, "type": "Receipt", "author": amina,
        "created": "2026-10-31T09:00:00Z", "about": commit_ref,
        "outcome": "cancelled", "statement": "Cancelled by agreement."},
        a_op1, amina_vm1)
    cancel_ltd = signed({
        "oip": OIP_VERSION, "type": "Receipt", "author": lexis_ltd,
        "created": "2026-10-31T09:05:00Z", "about": commit_ref,
        "outcome": "cancelled", "statement": "Cancelled by agreement."},
        l_op, ltd_vm)

    # --- Two agents strike a deal, each for its principal --------------
    sent = signed({"oip": OIP_VERSION, "type": "Packet", "from": assistant,
                   "to": [lexis], "created": "2026-10-30T10:35:00Z",
                   "expires": "2026-10-31T10:35:00Z",
                   "nonce": "c4e2a9f7d1b8306e",
                   "purpose": {"verb": "request",
                               "goal": "Ask for rush delivery"},
                   "content": {"mediaType": "text/plain",
                               "body": "Could the translation be ready "
                                       "twelve hours early?"},
                   "provenance": {"onBehalfOf": amina}},
                  s_op, asst_vm, authority=[send_ref])
    rush = {"oip": OIP_VERSION, "type": "Commitment", "author": lexis,
            "created": "2026-10-30T10:40:00Z",
            "parties": [{"mind": lexis_ltd, "role": "debtor",
                         "required": True},
                        {"mind": amina, "role": "creditor",
                         "required": True}],
            "promise": "Lexis Ltd will deliver the translation by 1 Nov 2026 "
                       "06:00 UTC, twelve hours early; Amina will pay a "
                       "30 USD rush fee on delivery.",
            "terms": {"deadline": "2026-11-01T06:00:00Z",
                      "price": usd("30")}}
    rush_agent = create_proof(rush, t_op, agent_vm, "assertionMethod",
                              rush["created"], authority=[deleg_ref])
    rush_asst = create_proof(rush, s_op, asst_vm, "assertionMethod",
                             "2026-10-30T10:41:00Z",
                             authority=[amina_deleg_ref])
    rush_accepted = sign(rush, rush_agent, rush_asst)
    assert content_id(sign(rush, rush_agent)) == content_id(rush_accepted)

    # --- The collective's charter, and a commitment by its steward -----
    steward_policy = usd_500 + [["==", ".terms.price.payee", collective],
                                ["all", ".parties", ["!=", ".mind", lexis]]]
    charter = {"oip": OIP_VERSION, "type": "Collective", "author": collective,
               "created": "2026-10-30T09:25:00Z",
               "name": "Open Translation Cell",
               "purpose": "Translate and review legal documents.",
               "roles": {"steward": {"purpose": "Accept routine work",
                                     "powers": [{"command":
                                                 "/oip/sign/Commitment",
                                                 "policy": steward_policy}]}},
               "assignments": [{"mind": lexis, "role": "steward"}]}
    charter = sign(charter,
                   create_proof(charter, a_op1, amina_vm1, "assertionMethod",
                                charter["created"]),
                   create_proof(charter, r_op, res_vm, "assertionMethod",
                                charter["created"]))
    charter_ref = record_ref(collective, charter)
    steward_doc = {
        "oip": OIP_VERSION, "type": "Commitment", "author": lexis,
        "created": "2026-10-30T10:30:00Z",
        "parties": [{"mind": collective, "role": "debtor", "required": True},
                    {"mind": amina, "role": "creditor", "required": True}],
        "promise": "The Open Translation Cell will review the English "
                   "translation of the lease by 2 Nov 2026 12:00 UTC for "
                   "300 USD.",
        "terms": {"deadline": "2026-11-02T12:00:00Z",
                  "price": usd("300", payee=collective)}}
    steward_commit = signed(steward_doc, t_op, agent_vm,
                            authority=[charter_ref])

    # --- A commitment signed through the two-step delegation chain -----
    chain_doc = {
        "oip": OIP_VERSION, "type": "Commitment", "author": child,
        "created": "2026-10-30T11:00:00Z",
        "parties": [{"mind": lexis_ltd, "role": "debtor", "required": True},
                    {"mind": amina, "role": "creditor", "required": True}],
        "promise": "Lexis Ltd will produce a certified glossary for the "
                   "lease by 3 Nov 2026; Amina will pay 150 USD.",
        "terms": {"deadline": "2026-11-03T12:00:00Z", "price": usd("150")},
        "resolves": [glossary_ref]}
    chain_commit = sign(chain_doc,
                        create_proof(chain_doc, f_op, child_vm,
                                     "assertionMethod", chain_doc["created"],
                                     authority=[deleg_ref, sub_ref]),
                        create_proof(chain_doc, a_op1, amina_vm1,
                                     "assertionMethod",
                                     "2026-10-30T11:05:00Z"))

    # --- Context packet carrying the session and the offer -------------
    session = {"oip": OIP_VERSION, "type": "Session",
               "participants": sorted([amina, lexis]),
               "nonce": "5d2e8b1c9a7f4e30", "created": "2026-10-30T10:03:00Z"}
    packet = signed({"oip": OIP_VERSION, "type": "Packet", "from": lexis,
                     "to": [amina], "created": "2026-10-30T10:04:05Z",
                     "expires": "2026-10-30T22:00:00Z",
                     "nonce": "a7f3c9e2b1d04f86",
                     "session": content_id(session), "seq": 0,
                     "purpose": {"verb": "propose",
                                 "goal": "Offer to translate your lease"},
                     "content": {"parts": [
                         {"mediaType": "application/oip+json",
                          "body": session},
                         {"mediaType": "application/oip+json",
                          "body": offer}]},
                     "constraints": {"retention": "P30D",
                                     "prohibitedUses": ["train"]}},
                    t_op, agent_vm)
    ack = signed({"oip": OIP_VERSION, "type": "Ack", "author": amina,
                  "packet": content_id(packet),
                  "received": "2026-10-30T10:04:06Z",
                  "created": "2026-10-30T10:04:06Z"}, a_op2, amina_vm2)
    hello = signed({"oip": OIP_VERSION, "type": "Hello", "author": lexis,
                    "created": "2026-10-30T10:06:00Z"}, t_op, agent_vm)
    hello = sign({k2: v for k2, v in hello.items() if k2 != "proof"},
                 create_proof({k2: v for k2, v in hello.items()
                               if k2 != "proof"}, t_op, agent_vm,
                              "authentication", hello["created"],
                              challenge="q8xG3kZ2pV7mT0wR5nY1aB",
                              domain="https://host.example"))

    # --- Layer 1 records for the agent: profile, feed, location --------
    participant = signed({
        "oip": OIP_VERSION, "type": "Participant", "author": lexis,
        "created": "2026-10-30T09:40:00Z", "name": "Lexis Translation Agent",
        "kind": "agent",
        "summary": "Legal translation between Swahili, English and French.",
        "capabilities": [{
            "id": "translate-legal-sw-en",
            "summary": "Translate Swahili commercial-law documents to and "
                       "from English",
            "tags": ["oasf:natural_language_processing/translation",
                     "domain:legal/commercial", "lang:sw", "lang:en"],
            "subject": "cap.nlp.translation.legal",
            "inputs": ["text/plain", "application/pdf"],
            "outputs": ["text/markdown"]}],
        "actsFor": [{"mind": lexis_ltd, "authority": deleg_ref}]},
        t_op, agent_vm)
    entry = signed({"oip": OIP_VERSION, "type": "Entry", "author": lexis,
                    "seq": 0, "created": "2026-10-30T10:04:01Z",
                    "object": content_id(offer), "objectType": "Offer",
                    "proofs": [proof_digest(p) for p in offer["proof"]]},
                   t_op, agent_vm)
    entry1 = signed({"oip": OIP_VERSION, "type": "Entry", "author": lexis,
                     "seq": 1, "prev": content_id(entry),
                     "created": "2026-10-30T10:23:00Z",
                     "object": content_id(commit),
                     "objectType": "Commitment",
                     "proofs": [proof_digest(p)
                                for p in commit_accepted["proof"]]},
                    t_op, agent_vm)
    checkpoint = signed({"oip": OIP_VERSION, "type": "Checkpoint",
                         "author": lexis, "created": "2026-10-30T10:30:00Z",
                         "size": 2, "head": content_id(entry1),
                         "root": checkpoint_root([content_id(entry),
                                                  content_id(entry1)])},
                        t_op, agent_vm)
    location = signed({
        "oip": OIP_VERSION, "type": "Location", "author": lexis, "seq": 1,
        "created": "2026-10-30T10:05:00Z", "ttl": 900, "status": "active",
        "endpoints": [
            {"binding": "https", "url": "https://lexis.example/oip",
             "instance": "i1", "priority": 10},
            {"binding": "wss", "url": "wss://lexis.example/oip/ws",
             "instance": "i1", "priority": 20},
            {"binding": "mailbox",
             "url": "https://mailbox.example/oip/mbox/" + lexis[8:],
             "priority": 90}],
        "homes": ["https://lexis.example"],
        "participant": content_id(participant),
        "feed": {"seq": 0, "head": content_id(entry)}}, t_op, agent_vm)

    records = {"delegation": deleg, "delegation_sub": sub_deleg,
               "delegation_amina": amina_deleg,
               "delegation_send": send_deleg,
               "intent": intent, "intent_withdrawal": withdrawal,
               "intent_edit": edit, "offer": offer,
               "offer_withdrawal": offer_withdrawal, "offer_edit": offer_edit,
               "offer_glossary": offer_glossary,
               "commitment_proposed": commit_proposed,
               "commitment_accepted": commit_accepted, "receipt": receipt,
               "receipt_by_debtor": receipt_by_debtor,
               "receipt_broken": receipt_broken,
               "receipt_cancel_amina": cancel_amina,
               "receipt_cancel_ltd": cancel_ltd,
               "packet_on_behalf": sent,
               "commitment_agents": rush_accepted,
               "collective_charter": charter,
               "commitment_by_steward": steward_commit,
               "commitment_via_chain": chain_commit, "lineage": lineage,
               "session": session, "packet": packet, "ack": ack,
               "hello": hello, "participant": participant,
               "location": location, "feed_entry": entry,
               "feed_entry_1": entry1, "checkpoint": checkpoint,
               "gateway_entry": gw_entry,
               "bridged_participant": br_participant}
    dv = Verifier(logs=logs.values())
    V["cases"] = {
        **logs, **records,
        "amina": amina, "lexis_ltd": lexis_ltd, "lexis_agent": lexis,
        "lexis_fork": child, "lexis_fork2": child2,
        "researcher": researcher, "collective": collective, "multi": multi,
        "assistant": assistant, "gateway": gateway, "bridged": bridged,
        "did_document_amina": did_document(dv, amina),
        "did_document_amina_at_genesis": did_document(
            dv, amina, version_id(a_gen)),
        "did_document_collective": did_document(dv, collective),
        "status": [
            {"of": "intent", "at": "2026-10-30T12:00:00Z",
             "records": ["intent", "commitment_accepted"],
             "expect": "satisfied"},
            {"of": "intent", "at": "2026-10-30T12:00:00Z",
             "records": ["intent", "commitment_proposed"], "expect": "open"},
            {"of": "intent", "at": "2026-10-30T12:00:00Z",
             "records": ["intent", "intent_withdrawal",
                         "commitment_accepted"], "expect": "withdrawn"},
            {"of": "intent_withdrawal", "at": "2026-10-30T12:00:00Z",
             "records": ["intent", "intent_withdrawal"],
             "expect": "withdrawn"},
            {"of": "intent", "at": "2026-10-30T12:00:00Z",
             "records": ["intent", "intent_edit"], "expect": "superseded"},
            {"of": "intent_edit", "at": "2026-10-30T12:00:00Z",
             "records": ["intent", "intent_edit"], "expect": "open"},
            {"of": "offer", "at": "2026-10-30T12:00:00Z",
             "records": ["offer", "commitment_accepted"], "expect": "open"},
            {"of": "offer", "at": "2026-10-31T12:00:00Z",
             "records": ["offer"], "expect": "expired"},
            {"of": "commitment_proposed", "at": "2026-10-30T12:00:00Z",
             "records": ["commitment_proposed"], "expect": "proposed"},
            {"of": "commitment_accepted", "at": "2026-10-31T12:00:00Z",
             "records": ["commitment_accepted"], "expect": "accepted"},
            {"of": "commitment_accepted", "at": "2026-11-01T19:00:00Z",
             "records": ["commitment_accepted"], "expect": "overdue"},
            {"of": "commitment_accepted", "at": "2026-11-01T19:00:00Z",
             "records": ["commitment_accepted", "receipt"],
             "expect": "fulfilled"},
            {"of": "commitment_agents", "at": "2026-10-31T12:00:00Z",
             "records": ["commitment_agents"], "expect": "accepted"},
            {"of": "intent", "at": "2026-10-31T12:00:00Z",
             "records": ["intent"], "expect": "expired"},
            {"of": "offer", "at": "2026-10-30T12:00:00Z",
             "records": ["offer", "offer_withdrawal"], "expect": "withdrawn"},
            {"of": "offer", "at": "2026-10-30T12:00:00Z",
             "records": ["offer", "offer_edit"], "expect": "superseded"},
            {"of": "offer_glossary", "at": "2026-10-30T12:00:00Z",
             "records": ["offer_glossary"], "expect": "open"},
            {"of": "offer_glossary", "at": "2026-10-30T12:00:00Z",
             "records": ["offer_glossary", "commitment_via_chain"],
             "expect": "exhausted"},
            {"of": "commitment_accepted", "at": "2026-11-01T17:00:00Z",
             "records": ["commitment_accepted", "receipt_by_debtor"],
             "expect": "claimed-fulfilled"},
            {"of": "commitment_accepted", "at": "2026-11-01T19:00:00Z",
             "records": ["commitment_accepted", "receipt_broken"],
             "expect": "broken"},
            {"of": "commitment_accepted", "at": "2026-11-01T19:00:00Z",
             "records": ["commitment_accepted", "receipt_by_debtor",
                         "receipt_broken"], "expect": "disputed"},
            {"of": "commitment_accepted", "at": "2026-10-31T12:00:00Z",
             "records": ["commitment_accepted", "receipt_cancel_amina"],
             "expect": "accepted"},
            {"of": "commitment_accepted", "at": "2026-10-31T12:00:00Z",
             "records": ["commitment_accepted", "receipt_cancel_amina",
                         "receipt_cancel_ltd"], "expect": "cancelled"}],
        "content_ids": {n: content_id(o) for n, o in [
            ("amina_genesis", a_gen), ("amina_update", a_upd),
            ("delegation", deleg), ("delegation_sub", sub_deleg),
            ("delegation_amina", amina_deleg), ("intent", intent),
            ("offer", offer), ("commitment", commit),
            ("commitment_agents", rush), ("receipt", receipt),
            ("collective_charter", charter), ("session", session),
            ("packet", packet), ("checkpoint", checkpoint),
            ("bridged_genesis", br_gen)]},
        "jcs_example": {"input": {"b": 2, "a": [1, "x"], "é": True},
                        "output": jcs({"b": 2, "a": [1, "x"],
                                       "é": True}).decode()},
    }

    # ------------------------------------------------- must also be valid
    a_inv_claim = control_event(
        "Update", amina, a_upd, "2026-11-02T08:00:00Z", [a_c2], [a_c3],
        fields={"invocation": [],
                "revoked": [{"key": a_inv.mk,
                             "compromisedSince": "2026-10-30T09:00:00Z"}]})
    V["valid"].append({
        "name": "collective-survives-member-compromise-claim",
        "reason": "On 2 Nov Amina removes her invocation key and declares it "
                  "compromised since 30 Oct 09:00, before the collective's "
                  "genesis. Her proof on the genesis is judged at the "
                  "genesis's evaluation time (30 Oct 09:20, before the "
                  "removal), and compromise declarations do not reach into "
                  "other minds' logs, so the collective's log still "
                  "verifies.",
        "kind": "log", "log": [coll],
        "extraLogs": [[a_gen, a_upd, a_inv_claim]]})
    late_removal = control_event(
        "Update", amina, a_upd, "2026-10-30T10:00:00Z", [a_c2], [a_c3],
        fields={"keys": [{"key": a_op2.mk, "label": a_op2.label}]})
    V["valid"].append({
        "name": "backdated-removal-cannot-withdraw",
        "reason": "Amina removes her phone key in an event dated 30 Oct but "
                  "first seen on 2 Nov. A removal takes effect from its "
                  "evaluation time, so her Receipt signed with that key on "
                  "1 Nov still counts.",
        "kind": "countsFor", "record": receipt, "mind": amina,
        "extraLogs": [[a_gen, a_upd, late_removal]],
        "seen": {content_id(late_removal): "2026-11-02T08:00:00Z"}})
    revocation = signed({"oip": OIP_VERSION, "type": "Revocation",
                         "author": lexis_ltd,
                         "created": "2026-11-10T00:00:00Z",
                         "revokes": deleg_ref}, l_op, ltd_vm)
    backdated_rev = signed({"oip": OIP_VERSION, "type": "Revocation",
                            "author": lexis_ltd,
                            "created": "2026-10-30T12:00:00Z",
                            "revokes": deleg_ref}, l_op, ltd_vm)
    nov5 = signed(variant_of(commit, created="2026-11-05T00:00:00Z"), t_op,
                  agent_vm, authority=[deleg_ref])
    V["valid"].append({
        "name": "revocation-takes-effect-from-evidence",
        "reason": "A revocation dated 30 Oct but first seen on 10 Nov does "
                  "not void a commitment first seen on 5 Nov.",
        "kind": "countsFor", "record": nov5, "mind": lexis_ltd,
        "extraRecords": [backdated_rev],
        "seen": {proof_digest(backdated_rev["proof"][0]):
                 "2026-11-10T00:00:00Z"}})
    # Duplicity: Amina's first control key, which she failed to destroy,
    # signs a second event at position 1 (Layer 1, Section 7).
    a_upd_alt = control_event(
        "Update", amina, a_gen, "2026-10-30T09:05:30Z", [a_c1],
        [k("amina-control-2b")],
        fields={"keys": [{"key": a_op1.mk, "label": a_op1.label},
                         {"key": k("amina-tablet").mk,
                          "label": "amina-tablet"}]})
    V["valid"].append({
        "name": "duplicity-resolved-by-first-seen",
        "reason": "Two valid events sit at position 1 of Amina's log. The "
                  "one first seen at 09:05 wins over the one first seen at "
                  "11:00, whichever is longer or newer, so her Intent "
                  "pinned to the winning version counts.",
        "kind": "countsFor", "record": intent, "mind": amina,
        "branches": [[a_gen, a_upd_alt]],
        "seen": {content_id(a_upd): "2026-10-30T09:05:00Z",
                 content_id(a_upd_alt): "2026-10-30T11:00:00Z"}})
    early_vm = op_vm(amina, a_gen, a_op1.mk)
    early = signed(variant_of(intent, created="2026-10-30T09:50:00Z"),
                   a_op1, early_vm)
    tie = {content_id(a_upd): "2026-10-30T09:05:00Z",
           content_id(a_upd_alt): "2026-10-30T09:05:00Z"}
    V["valid"].append({
        "name": "duplicity-keeps-earlier-versions",
        "reason": "Evidence cannot separate the two events at position 1, "
                  "so Amina is duplicitous, but a record pinned to her "
                  "genesis, before the divergence, still counts.",
        "kind": "countsFor", "record": early, "mind": amina,
        "branches": [[a_gen, a_upd_alt]], "seen": tie})

    # ------------------------------------------------------------ negatives
    neg = V["negative"]

    def context(case, extra_logs, records, seen, branches):
        if extra_logs:
            case["extraLogs"] = list(extra_logs)
        if branches:
            case["branches"] = list(branches)
        if records:
            case["extraRecords"] = list(records)
        if seen:
            case["seen"] = seen
        neg.append(case)

    def bad_log(name, reason, log, extra_logs=(), seen=None):
        context({"name": name, "reason": reason, "kind": "log", "log": log},
                extra_logs, (), seen, ())

    def bad_sig(name, reason, record, mind, extra_logs=(), records=(),
                seen=None, branches=(), kind="countsFor"):
        context({"name": name, "reason": reason, "kind": kind,
                 "record": record, "mind": mind},
                extra_logs, records, seen, branches)

    def seen_at(record, when):
        """Evidence that the verifier first obtained every proof on
        `record` at `when`."""
        return {proof_digest(p): when for p in record["proof"]}

    variant = variant_of

    # identity logs
    bad_upd = control_event("Update", multi, m_gen, "2026-10-30T09:06:00Z",
                            [m_k1, m_k1], [k("attacker-next")],
                            signers=[m_k1])
    bad_log("threshold-duplicate-control-key",
            "Thresholds count distinct keys: one key listed twice cannot "
            "meet a 2-of-3 nextThreshold.", [m_gen, bad_upd])
    attacker = k("attacker")
    forged = control_event("Update", amina, a_gen, "2026-10-30T09:05:00Z",
                           [attacker], [k("attacker-next")])
    bad_log("pre-rotation-forged-update",
            "Correctly signed by a key whose hash the previous event did not "
            "commit to in `next`; pre-rotation, not the signature, rejects "
            "it.", [a_gen, forged])
    z_c0, z_c1 = k("zero-control-0"), k("zero-control-1")
    bad_log("next-threshold-zero",
            "nextThreshold must be at least 1 and a majority of `next`.",
            [key_controlled_genesis("agent", z_c0, z_c1, [],
                                    next_threshold=0)])
    bad_log("next-threshold-minority",
            "nextThreshold 1 of 2 is not a majority of `next`.",
            [key_controlled_genesis("agent", z_c0, None, [],
                                    next_keys=[z_c1, k("zero-control-2")],
                                    next_threshold=1)])
    bad_log("collective-threshold-zero",
            "A collective's threshold must be at least 1.",
            [coll_genesis(0, founders)])
    bad_log("collective-threshold-minority",
            "Threshold 1 of 3 is not a majority, so two disjoint members "
            "could each sign conflicting events.",
            [coll_genesis(1, founders)])
    bad_log("collective-genesis-missing-founder",
            "Every founding member must sign the genesis.",
            [coll_genesis(2, founders[:2])])
    bad_log("collective-signed-with-operational-keys",
            "Members sign a collective's identity events with invocation "
            "keys; everyday operational keys cannot change any identity.",
            [coll_genesis(2, [(a_op1, amina_vm1), (t_op, agent_vm),
                              (r_op, res_vm)])])
    c_retire = member_event("Retire", collective, coll,
                            "2026-10-31T00:00:00Z", founders[::2],
                            {"reason": "Work complete."})
    c_after = member_event("Update", collective, c_retire,
                           "2026-10-31T01:00:00Z", founders[::2],
                           {"homes": ["https://cell.example"]})
    bad_log("event-after-retire",
            "No event may follow a Retire, for collectives as for "
            "key-controlled minds.", [coll, c_retire, c_after])
    mg = control_event("Merge", amina, a_gen, "2026-10-30T09:05:00Z",
                       [a_c1], [a_c2],
                       fields={"child": collective, "retire": False})
    bad_log("merge-reserved",
            "Merge is reserved; a verifier of this revision rejects a log "
            "containing it.", [a_gen, mg])
    bad_log("recovery-reserved",
            "`recovery` is a reserved member name; a verifier of this "
            "revision rejects an event containing it.",
            [key_controlled_genesis(
                "human", z_c0, z_c1, [],
                extra={"recovery": {"keys": [key_hash(z_c1.mk)]}})])
    gid = content_id(a_gen)
    odd = gid[:-1] + chr(ord(gid[-1]) + 1)
    bad_prev = {kk: v for kk, v in a_upd.items() if kk != "proof"}
    bad_prev["prev"] = odd
    bad_prev = sign(bad_prev, create_proof(bad_prev, a_c1,
                                           did_key_vm(a_c1.mk),
                                           "capabilityInvocation",
                                           bad_prev["created"]))
    bad_log("non-canonical-content-id",
            "`prev` spells the genesis content ID with non-zero padding "
            "bits. It decodes to the same bytes, but content IDs have one "
            "canonical spelling and are compared as strings.",
            [a_gen, bad_prev])
    rk1 = control_event("Update", amina, a_upd, "2026-11-02T08:00:00Z",
                        [a_c2], [a_c3], fields={
                            "keys": [{"key": a_op2.mk, "label": a_op2.label}],
                            "revoked": [{"key": a_op1.mk}]})
    rk2 = control_event("Update", amina, rk1, "2026-11-03T08:00:00Z",
                        [a_c3], [a_c4], fields={
                            "keys": [{"key": a_op1.mk, "label": a_op1.label},
                                     {"key": a_op2.mk,
                                      "label": a_op2.label}]})
    bad_log("revoked-key-readded",
            "A key listed in `revoked` can never be added again.",
            [a_gen, a_upd, rk1, rk2])

    # proof purpose and key ownership
    bad_sig("wrong-proof-purpose",
            "An Intent needs an assertionMethod proof; an authentication "
            "proof does not count.",
            signed(variant(intent), a_op2, amina_vm2,
                   purpose="authentication"), amina)
    imp_vm = f"{lexis}?versionId={version_id(fork_ev)}#{attacker.mk}"
    bad_sig("delegated-key-not-in-signers-log",
            "The delegate's proof names a key that is not in the delegate's "
            "identity log (paper Appendix A.5, first draft).",
            signed(variant(commit), attacker, imp_vm, authority=[deleg_ref]),
            lexis_ltd)
    outside = signed(variant(commit, authority=[deleg_ref]), t_op, agent_vm)
    bad_sig("delegation-outside-the-proof",
            "A delegate's proof lists the delegations it relies on in its "
            "own `authority`. A record-level `authority` member is not part "
            "of the protocol and authorises nothing.", outside, lexis_ltd)

    # delegation scope
    d_bad = signed({"oip": OIP_VERSION, "type": "Delegation",
                    "author": lexis_ltd, "created": "2026-10-30T09:31:00Z",
                    "delegate": lexis, "subject": lexis_ltd,
                    "command": "/oip/sign/Delegation", "policy": [],
                    "expires": "2026-11-30T09:30:00Z",
                    "nonce": "0d3a5c7e9b1f2468"}, l_op, ltd_vm)
    forged_deleg = signed(
        variant(deleg, policy=[], expires="2027-10-30T09:30:00Z",
                nonce="f00dfeedc0ffee11"),
        t_op, agent_vm, created="2026-10-30T09:31:00Z", authority=[d_bad])
    bad_sig("delegate-signs-delegation",
            "Delegations are not delegable: a Delegation counts only when "
            "signed by its author's own authority, so a delegate cannot "
            "widen its own grant (and /oip/sign/Delegation is not a valid "
            "command).", forged_deleg, lexis_ltd)
    blanket = signed({"oip": OIP_VERSION, "type": "Delegation",
                      "author": lexis_ltd, "created": "2026-10-30T09:32:00Z",
                      "delegate": lexis, "subject": lexis_ltd,
                      "command": "/oip", "policy": [],
                      "expires": "2026-11-30T09:30:00Z",
                      "nonce": "b1a2c3d4e5f60718"}, l_op, ltd_vm)
    bad_sig("reserved-blanket-command",
            "/oip is reserved: there are no blanket grants in this revision.",
            signed(variant(commit), t_op, agent_vm, authority=[blanket]),
            lexis_ltd)
    for name, amount, currency, why in (
            ("policy-currency", "400", "BTC",
             "The policy pins the currency as well as the amount."),
            ("policy-negative-amount", "-900", "USD",
             "Amounts are non-negative decimal strings."),
            ("policy-not-decimal-commas", "1,000,000", "USD",
             "Ordering operators compare decimals only; '1,000,000' is "
             "not a decimal."),
            ("policy-not-decimal-exponent", "1e2", "USD",
             "'1e2' is not a decimal string."),
            ("policy-not-decimal-infinity", "-Infinity", "USD",
             "'-Infinity' is not a decimal string."),
            ("policy-not-decimal-spaces", " 400 ", "USD",
             "' 400 ' is not a decimal string."),
            ("policy-not-decimal-fullwidth", "４００", "USD",
             "Full-width digits are not decimal digits.")):
        doc = variant(commit, terms__price={**usd("0"), "amount": amount,
                                            "currency": currency})
        bad_sig(name, why, signed(doc, t_op, agent_vm, authority=[deleg_ref]),
                lexis_ltd)
    third = variant(rush, parties=[
        {"mind": researcher, "role": "debtor", "required": True},
        {"mind": amina, "role": "creditor", "required": True}],
        terms__price=usd("30", payee=researcher))
    bad_sig("policy-counterparty",
            "Amina's assistant may commit her only to deals whose parties "
            "are Amina and Lexis Ltd; a deal with the researcher is outside "
            "its delegation.",
            signed(third, s_op, asst_vm, authority=[amina_deleg_ref]), amina)

    # time: evidence beats claims
    a_rm = control_event("Update", amina, a_upd, "2026-11-02T08:00:00Z",
                         [a_c2], [a_c3], fields={
                             "keys": [{"key": a_op2.mk,
                                       "label": a_op2.label}]})
    late_intent = signed(variant(intent, created="2026-11-01T08:00:00Z",
                                 expires="2026-11-08T08:00:00Z"),
                         a_op1, amina_vm1)
    bad_sig("removed-key-backdated",
            "Amina removed her phone key on 2 Nov. A record signed with it "
            "and dated 1 Nov, first seen on 3 Nov, is evaluated at 3 Nov.",
            late_intent, amina, extra_logs=[[a_gen, a_upd, a_rm]],
            seen=seen_at(late_intent, "2026-11-03T08:00:00Z"))
    a_cmp = control_event("Update", amina, a_upd, "2026-11-02T08:00:00Z",
                          [a_c2], [a_c3], fields={
                              "keys": [{"key": a_op2.mk,
                                        "label": a_op2.label}],
                              "revoked": [{"key": a_op1.mk,
                                           "compromisedSince":
                                           "2026-10-31T00:00:00Z"}]})
    early_intent = signed(variant(intent, created="2026-10-30T23:00:00Z",
                                  expires="2026-11-08T08:00:00Z"),
                          a_op1, amina_vm1)
    bad_sig("compromised-key-backdated",
            "The phone key is compromised since 31 Oct 00:00. A record "
            "dated 30 Oct but first seen on 1 Nov is evaluated at 1 Nov.",
            early_intent, amina, extra_logs=[[a_gen, a_upd, a_cmp]],
            seen=seen_at(early_intent, "2026-11-01T00:00:00Z"))
    exp_commit = signed(variant(commit, created="2026-11-29T00:00:00Z"),
                        t_op, agent_vm, authority=[deleg_ref])
    bad_sig("expired-delegation-backdated",
            "The delegation expires on 30 Nov. A commitment dated 29 Nov but "
            "first seen on 5 Dec is evaluated at 5 Dec.", exp_commit,
            lexis_ltd, seen=seen_at(exp_commit, "2026-12-05T00:00:00Z"))
    rev_commit = signed(variant(commit, created="2026-11-05T00:00:00Z"),
                        t_op, agent_vm, authority=[deleg_ref])
    bad_sig("revoked-delegation",
            "The delegation was revoked on 10 Nov. A commitment dated 5 Nov "
            "but first seen on 12 Nov comes after the revocation.",
            rev_commit, lexis_ltd, records=[revocation],
            seen=seen_at(rev_commit, "2026-11-12T00:00:00Z"))
    c_rm = member_event("Update", collective, coll, "2026-10-31T00:00:00Z",
                        founders[:2],
                        {"controller": {"members": [amina, lexis],
                                        "threshold": 2}})
    coll_intent = {"oip": OIP_VERSION, "type": "Intent",
                   "author": collective, "created": "2026-10-30T23:00:00Z",
                   "want": "Hire a second reviewer for Swahili leases."}
    coll_intent = sign(coll_intent, *[
        create_proof(coll_intent, key, vm, "assertionMethod",
                     "2026-10-30T23:00:00Z")
        for key, vm in ((r_op, res_vm), (a_op1, amina_vm1))])
    bad_sig("removed-member-backdated",
            "The researcher left the collective on 31 Oct. Its signature on "
            "a record dated 30 Oct but first seen on 1 Nov does not count, "
            "so the 2-of-2 threshold is not met.", coll_intent, collective,
            extra_logs=[[coll, c_rm]],
            seen=seen_at(coll_intent, "2026-11-01T00:00:00Z"))
    future = signed(variant(intent), a_op2, amina_vm2,
                    created="2026-10-30T10:30:00Z")
    bad_sig("proof-from-the-future",
            "The proof claims a time more than 300 seconds after the "
            "evidence that it existed.", future, amina,
            seen=seen_at(future, "2026-10-30T10:00:00Z"))
    stale = signed(variant(intent), a_op2, amina_vm2,
                   created="2026-10-31T11:00:00Z")
    bad_sig("proof-after-record-expiry",
            "The Intent expires on 31 Oct 10:00; a proof made after that "
            "does not count.", stale, amina)

    # Layer 2 status and records
    sock = {"oip": OIP_VERSION, "type": "Commitment", "author": researcher,
            "created": "2026-10-30T11:00:00Z",
            "parties": [{"mind": researcher, "role": "debtor",
                         "required": True},
                        {"mind": child, "role": "creditor",
                         "required": True}],
            "promise": "The researcher will translate a lease for the fork.",
            "terms": {"price": usd("1", payer=child, payee=researcher)},
            "resolves": [intent_ref], "closesIntent": True}
    sock = sign(sock,
                create_proof(sock, r_op, res_vm, "assertionMethod",
                             sock["created"]),
                create_proof(sock, f_op, child_vm, "assertionMethod",
                             sock["created"]))
    neg.append({"name": "outsider-closes-intent",
                "reason": "Only a commitment that counts for the Intent's "
                          "author can satisfy it; two other minds cannot "
                          "close Amina's Intent.",
                "kind": "status", "of": intent, "records": [intent, sock],
                "at": "2026-10-30T12:00:00Z", "expect": "open"})
    a_withdraw = control_event(
        "Update", amina, a_upd, "2026-11-02T08:00:00Z", [a_c2], [a_c3],
        fields={"keys": [{"key": a_op2.mk, "label": a_op2.label}],
                "revoked": [{"key": a_op1.mk,
                             "compromisedSince": "2026-10-30T10:00:00Z"}]})
    neg.append({"name": "compromise-claim-shows-dispute",
                "reason": "Amina declares the key that co-signed the "
                          "commitment compromised since before she signed. "
                          "Her signature no longer counts, so the commitment "
                          "is not accepted; it shows as disputed, not as "
                          "merely proposed.",
                "kind": "status", "of": commit_accepted,
                "records": [commit_accepted], "at": "2026-11-03T12:00:00Z",
                "extraLogs": [[a_gen, a_upd, a_withdraw]],
                "expect": "disputed"})
    neg.append({"name": "packet-short-nonce",
                "reason": "A packet nonce has 8 to 64 characters.",
                "kind": "record",
                "record": signed(variant(packet, nonce="p1"), t_op,
                                 agent_vm)})

    # collectives: members' proofs judged at the event's evaluation time
    a_inv_gone = control_event(
        "Update", amina, a_upd, "2026-11-02T08:00:00Z", [a_c2], [a_c3],
        fields={"invocation": [],
                "revoked": [{"key": a_inv.mk,
                             "compromisedSince": "2026-11-01T00:00:00Z"}]})
    r_inv_gone = control_event(
        "Update", researcher, res_upd, "2026-11-02T09:00:00Z", [r_c2],
        [k("researcher-control-3")],
        fields={"invocation": [], "revoked": [{"key": r_inv.mk}]})
    takeover = member_event("Update", collective, coll,
                            "2026-11-01T12:00:00Z",
                            [(a_inv, amina_inv), (r_inv, res_inv)],
                            {"keys": [{"key": k("thief-ops").mk,
                                       "label": "ops"}]})
    bad_log("collective-update-with-removed-invocation-keys",
            "Amina and the researcher removed their invocation keys on "
            "2 Nov. An Update to the collective signed with those keys, "
            "dated 1 Nov but first seen on 1 Dec, is evaluated at 1 Dec, "
            "after both removals, so it lacks the threshold and cannot give "
            "the collective a key of the thief's.", [coll, takeover],
            extra_logs=[[a_gen, a_upd, a_inv_gone],
                        [res_gen, res_upd, r_inv_gone]],
            seen={content_id(takeover): "2026-12-01T00:00:00Z"})
    bad_log("collective-genesis-seen-after-founder-key-removal",
            "Amina removed the invocation key that signed the collective's "
            "genesis on 2 Nov. A verifier whose earliest evidence of the "
            "genesis is from 3 Nov cannot tell it from a forgery made later "
            "with that key, so the log fails for that verifier. Witnesses "
            "and anchors supply the earlier evidence (Layer 1, 9.6).",
            [coll], extra_logs=[[a_gen, a_upd, a_inv_gone]],
            seen={content_id(coll): "2026-11-03T00:00:00Z"})
    c2_inv = k("subcollective-invocation")
    c2_gen = coll_genesis(2, [(a_inv, amina_inv), (r_inv, res_inv)],
                          members=(amina, researcher),
                          created="2026-10-30T09:30:00Z",
                          invocation=[c2_inv])
    c2 = did(content_id(c2_gen))
    c2_inv_vm = op_vm(c2, c2_gen, c2_inv.mk)

    def join_c2(base):
        return member_event("Update", did(content_id(base)), base,
                            "2026-10-31T00:00:00Z",
                            [(a_inv, amina_inv), (r_inv, res_inv),
                             (c2_inv, c2_inv_vm)],
                            {"controller": {"members": [amina, lexis,
                                                        researcher, c2],
                                            "threshold": 3}})
    bad_log("collective-member-height",
            "A collective's height is fixed by its genesis and every "
            "member's height must be below it. The 2-of-3 collective has "
            "height 1, so another collective cannot join it. A member "
            "collective can therefore never grow taller than the "
            "collectives it belongs to allow.",
            [coll, join_c2(coll)], extra_logs=[[c2_gen]])

    # evidence is per proof
    p_late = create_proof(commit, a_op1, amina_vm1, "assertionMethod",
                          "2026-10-30T10:25:00Z")
    bad_sig("late-cosignature-backdated",
            "The verifier saw the proposed commitment on 30 Oct. A proof by "
            "Amina's phone key dated 30 Oct but added on 5 Nov, after she "
            "declared the key compromised since 31 Oct, is evaluated at "
            "5 Nov: evidence that a record existed is not evidence for a "
            "co-signature added to it later.",
            sign(commit_proposed, p_late), amina,
            extra_logs=[[a_gen, a_upd, a_cmp]],
            seen={proof_digest(p_agent): "2026-10-30T10:20:00Z",
                  proof_digest(p_late): "2026-11-05T00:00:00Z"})

    # Ed25519 edge cases (core 4.4)
    identity_mk = multikey_ed25519(ed_encode(ED_IDENTITY))
    idg = {"oip": OIP_VERSION, "type": "Genesis", "kind": "agent",
           "created": T0,
           "controller": {"keys": [identity_mk],
                          "next": [key_hash(k("identity-point-next").mk)],
                          "nextThreshold": 1}}
    idg = sign(idg, forged_proof(idg, did_key_vm(identity_mk),
                                 "capabilityInvocation", T0,
                                 lambda msg: ed_raw_sign(
                                     0, ed_encode(ED_IDENTITY), msg,
                                     nonce=7)))
    bad_log("identity-point-control-key",
            "The identity point is in the prime-order subgroup but has "
            "order 1, so anyone can sign any message for it. Core 4.4 "
            "accepts only keys of order exactly L.", [idg])
    mixed = ed_add(ed_mul(k("mixed-order-key").scalar, ED_B),
                   ed_decode((ED_P - 1).to_bytes(32, "little")))
    bad_log("mixed-order-operational-key",
            "A public key with a small-order component verifies some "
            "signatures under OpenSSL's cofactorless check and not under "
            "core 4.4, so such keys are rejected wherever they appear.",
            [key_controlled_genesis(
                "agent", k("mixed-order-control-0"),
                k("mixed-order-control-1"), [],
                extra={"keys": [{"key": multikey_ed25519(ed_encode(mixed)),
                                 "label": "mixed-order"}]})])
    s_doc = variant(intent, created="2026-10-30T10:01:00Z")
    s_ok = signed(s_doc, a_op2, amina_vm2)["proof"][0]
    sig = b58decode(s_ok["proofValue"][1:])
    s_big = sig[:32] + (int.from_bytes(sig[32:], "little") +
                        ED_L).to_bytes(32, "little")
    bad_sig("signature-s-not-reduced",
            "Adding the group order L to S gives another signature that "
            "satisfies the verification equation. Core 4.4 requires S < L, "
            "so a third party cannot alter a valid signature.",
            sign(s_doc, {**s_ok, "proofValue": "z" + b58encode(s_big)}),
            amina)
    r_doc = variant(intent, created="2026-10-30T10:02:00Z")
    bad_sig("signature-r-identity",
            "A signer that knows its private key can make a signature whose "
            "R is the identity point. OpenSSL accepts it; core 4.4 requires "
            "R to have order L, so every verifier rejects it.",
            sign(r_doc, forged_proof(
                r_doc, amina_vm2, "assertionMethod", r_doc["created"],
                lambda msg: ed_raw_sign(a_op2.scalar, a_op2.pub, msg,
                                        r_point=ED_IDENTITY))), amina)
    m_doc = variant(intent, created="2026-10-30T10:03:00Z")
    bad_sig("signature-r-mixed-order",
            "R is an honest [nonce]B with the point of order 2 added to "
            "it. The signature satisfies the verification equation as "
            "RFC 8032 writes it, multiplied by the cofactor, so a library "
            "that checks it that way accepts the signature, and one that "
            "checks without the cofactor refuses it. Core 4.4 requires R "
            "to have order exactly L, so every verifier rejects it.",
            sign(m_doc, forged_proof(
                m_doc, amina_vm2, "assertionMethod", m_doc["created"],
                lambda msg: ed_raw_sign(
                    a_op2.scalar, a_op2.pub, msg, nonce=0x4d1,
                    offset=ed_decode((ED_P - 1).to_bytes(32, "little"))))),
            amina)
    w_doc = variant(intent, created="2026-10-30T10:04:00Z")
    wrapped_vm = amina_vm2.replace("versionId=1-",
                                   "versionId=%d-" % (2**64 + 1))
    assert wrapped_vm != amina_vm2
    bad_sig("key-reference-position-wraps-around",
            "The verification method pins position 2^64+1 with the "
            "content ID of the event at position 1. A reader that keeps "
            "the position in 64 bits reads it as 1 and finds the key. A "
            "position is an integer of at most 2^53-1 (core 6.1), so this "
            "reference names no version of any log.",
            signed(w_doc, a_op2, wrapped_vm), amina)

    # delegation chains are exact
    bad_sig("chain-out-of-order",
            "A proof's `authority` lists exactly its delegation chain, root "
            "first. The same two delegations in the other order are not a "
            "chain, and verifiers do not search for one.",
            signed(variant(chain_commit), f_op, child_vm,
                   authority=[sub_ref, deleg_ref]), lexis_ltd)
    neg.append({"name": "delegation-to-self",
                "reason": "A delegation's delegate must differ from its "
                          "author.",
                "kind": "record",
                "record": signed(variant(deleg, delegate=lexis_ltd,
                                         nonce="5e7a9c1b3d0f2846"),
                                 l_op, ltd_vm)})

    # who a proof acts for, and for what
    bad_sig("role-without-charter",
            "A member signs for its collective under a charter role only "
            "when its proof's `authority` names the charter, so the "
            "steward's plain signature binds only the steward.",
            signed(steward_doc, t_op, agent_vm), collective)
    self_deal = {"oip": OIP_VERSION, "type": "Commitment", "author": lexis,
                 "created": "2026-10-30T12:00:00Z",
                 "parties": [{"mind": lexis_ltd, "role": "debtor",
                              "required": True},
                             {"mind": lexis, "role": "creditor",
                              "required": True}],
                 "promise": "Lexis Ltd will translate a contract for its own "
                            "agent, which will pay 500 USD.",
                 "terms": {"price": usd("500", payer=lexis)}}
    bad_sig("policy-self-dealing",
            "Lexis Ltd's delegation excludes its own agent as a party, so "
            "the agent cannot bind the firm to a deal with itself.",
            signed(self_deal, t_op, agent_vm, authority=[deleg_ref]),
            lexis_ltd)
    bad_sig("policy-payee",
            "Lexis Ltd's delegation lets its agent commit the firm only to "
            "deals in which the firm is paid. In this commitment Lexis Ltd "
            "pays, so it is outside the delegation.",
            signed(variant(commit, terms__price=usd("120", payer=lexis_ltd,
                                                    payee=amina)),
                   t_op, agent_vm, authority=[deleg_ref]), lexis_ltd)
    d_not = signed({"oip": OIP_VERSION, "type": "Delegation",
                    "author": lexis_ltd, "created": "2026-10-30T09:33:00Z",
                    "delegate": lexis, "subject": lexis_ltd,
                    "command": "/oip/sign/Commitment",
                    "policy": [["not", ["==", ".terms.price.currency",
                                        "BTC"]]],
                    "expires": "2026-11-30T09:30:00Z",
                    "nonce": "4a6c8e0b2d1f3957"}, l_op, ltd_vm)
    unpriced = {"oip": OIP_VERSION, "type": "Commitment", "author": lexis,
                "created": "2026-10-30T12:00:00Z",
                "parties": [{"mind": lexis_ltd, "role": "debtor",
                             "required": True},
                            {"mind": amina, "role": "creditor",
                             "required": True}],
                "promise": "Lexis Ltd will translate a second lease for "
                           "Amina, at a price to be agreed.",
                "terms": {"deadline": "2026-11-10T18:00:00Z"}}
    bad_sig("policy-negation-of-missing-member",
            "The policy says 'not priced in BTC'. This commitment has no "
            "price, so the comparison is an error, and an error fails the "
            "whole policy instead of being negated into a pass.",
            signed(unpriced, t_op, agent_vm, authority=[d_not]), lexis_ltd)
    c_loc = {"oip": OIP_VERSION, "type": "Location", "author": collective,
             "seq": MAX_SAFE_INT, "created": "2026-10-30T23:00:00Z",
             "ttl": 900, "status": "active", "endpoints": []}
    c_loc = sign(c_loc, *[create_proof(c_loc, key, vm, "assertionMethod",
                                       c_loc["created"])
                          for key, vm in ((a_op1, amina_vm1),
                                          (r_op, res_vm))])
    bad_sig("collective-location-after-member-left",
            "A location record signed under a collective's threshold counts "
            "only while its signers meet the threshold of the collective's "
            "latest state. Once the researcher has left, the record it "
            "signed with Amina is no longer current, however high its seq.",
            c_loc, collective, extra_logs=[[coll, c_rm]])
    outsider = {"oip": OIP_VERSION, "type": "Commitment",
                "author": researcher, "created": "2026-10-30T12:00:00Z",
                "parties": [{"mind": lexis_ltd, "role": "debtor",
                             "required": True},
                            {"mind": amina, "role": "creditor",
                             "required": True}],
                "promise": "Lexis Ltd will translate a second lease; Amina "
                           "will pay 100 USD.",
                "terms": {"price": usd("100")}}
    outsider = sign(outsider, *[
        create_proof(outsider, key, vm, "assertionMethod",
                     outsider["created"])
        for key, vm in ((r_op, res_vm), (l_op, ltd_vm), (a_op1, amina_vm1))])
    neg.append({"name": "commitment-author-not-a-party",
                "reason": "A Commitment's author must be one of its parties "
                          "or sign for one. Signed by both parties but "
                          "authored by an outsider, it is never accepted.",
                "kind": "status", "of": outsider, "records": [outsider],
                "at": "2026-10-30T13:00:00Z", "expect": "proposed"})
    bad_sig("packet-on-behalf-without-delegation",
            "The packet names Amina in `provenance.onBehalfOf`, but its "
            "proof lists no delegation covering /oip/send, so it was not "
            "sent on her behalf.",
            signed(variant(sent), s_op, asst_vm), amina, kind="sentFor")
    self_entry = signed({"oip": OIP_VERSION, "type": "Entry",
                         "author": bridged, "seq": 0,
                         "created": "2026-10-30T08:11:00Z",
                         "object": content_id(br_gen),
                         "objectType": "Genesis"}, br_op, br_vm)
    neg.append({"name": "bridge-self-attested",
                "reason": "A mind is bridged only when its gateway attests "
                          "it in the gateway's own feed. An attestation by "
                          "the bridged mind itself leaves the label "
                          "`claimed`.",
                "kind": "assurance",
                "record": signed(variant(br_participant, ext={
                    "oip.bridge": {**bridge_block,
                                   "attestation": record_ref(bridged,
                                                             self_entry)}}),
                    br_op, br_vm),
                "extraRecords": [self_entry], "expect": "claimed"})
    bad_sig("duplicity-unresolved",
            "Evidence cannot separate the two events at position 1 of "
            "Amina's log, so she is duplicitous: her Intent, pinned to a "
            "version after the divergence, does not count.",
            intent, amina, branches=[[a_gen, a_upd_alt]], seen=tie)

    # The JSON profile (core Section 1), on texts: what a parser must read
    # and what it must refuse. Duplicate member names are not among them,
    # because core 1.1 says receivers SHOULD reject those, not MUST.
    def json_case(section, name, reason, text):
        section.append({"name": name, "reason": reason, "kind": "json",
                        "text": text})

    deep = lambda n: "[" * n + "]" * n      # noqa: E731
    json_case(V["valid"], "json-integers-however-written",
              "Validity depends on a number's value, not on how it is "
              "written (core 1.2): these are the integers 1, 100, 1, 0 and "
              "2^53-1, and canonical form writes them 1, 100, 1, 0 and "
              "9007199254740991.",
              '{"a":1.0,"b":1e2,"c":100e-2,"d":-0,"e":9007199254740991.0}')
    json_case(V["valid"], "json-escapes-are-spellings",
              "An escape is another spelling of the same character: the "
              "member names are `oip` and `name`, and the value is one "
              "character outside the basic plane, written as a surrogate "
              "pair.",
              '{"\\u006fip":"1","na\\u006de":"\\ud83d\\ude00"}')
    json_case(V["valid"], "json-same-name-in-different-objects",
              "Member names must be distinct within one object, not across "
              "objects.",
              '{"a":{"a":1},"b":[{"a":1},{"a":2}]}')
    json_case(V["valid"], "json-nested-64-deep",
              "Arrays and objects may nest 64 deep (core 1.9).",
              deep(MAX_DEPTH))
    json_case(neg, "json-number-with-fraction",
              "A number whose value has a fractional part is rejected; "
              "decimal quantities travel as strings (core 1.2, 1.3).",
              '{"amount":1.5}')
    json_case(neg, "json-number-with-negative-exponent",
              "1e-1 is one tenth, which is not an integer.",
              '{"n":1e-1}')
    json_case(neg, "json-integer-beyond-safe-range",
              "2^53 is outside the range -(2^53-1) to 2^53-1 (core 1.2).",
              '{"n":9007199254740992}')
    json_case(neg, "json-exponent-beyond-safe-range",
              "1e16 is an integer, and outside the range.",
              '{"n":1e16}')
    json_case(neg, "json-unpaired-surrogate",
              "Every string is valid Unicode (core 1.1): an escape that "
              "writes half of a surrogate pair is not.",
              '{"s":"\\ud800"}')
    json_case(neg, "json-nested-65-deep",
              "Arrays and objects nest at most 64 deep (core 1.9).",
              deep(MAX_DEPTH + 1))
    json_case(neg, "json-noncharacter",
              "A record is an I-JSON message (core 1.1; RFC 7493, 2.1): no "
              "string in it holds a noncharacter. U+FFFE is one, however "
              "it is written.",
              '{"s":"\\ufffe"}')
    json_case(neg, "json-noncharacter-in-a-member-name",
              "Member names are strings too. U+1FFFF, the last code point "
              "of plane 1, is a noncharacter; here it is written as a pair "
              "of escapes.",
              '{"\\ud83f\\udfff":1}')
    json_case(neg, "json-noncharacter-in-the-reserved-block",
              "U+FDD0 to U+FDEF are noncharacters too, 32 of the 66.",
              '{"s":"\\ufdd0\\ufdef"}')
    json_case(neg, "json-noncharacter-in-the-last-plane",
              "U+10FFFE, the last but one code point there is, is a "
              "noncharacter: every plane ends with two.",
              '{"s":"\\udbff\\udffe"}')
    json_case(V["valid"], "json-integer-written-at-length",
              "Validity depends on a number's value, not on how it is "
              "written (core 1.2): 1 followed by 5,000 zeros and e-5000 "
              "is the integer 1, and 0.000... is 0, at any length. A "
              "reader that turns the digits into a number before it "
              "judges them cannot read this text.",
              '{"n":1' + "0" * 5000 + 'e-5000,"z":0.' + "0" * 5000 + '}')
    json_case(neg, "json-trailing-comma",
              "A record is JSON (RFC 8259), which has no trailing commas.",
              '{"a":1,}')
    json_case(neg, "json-not-a-number",
              "NaN is not JSON.",
              '{"n":NaN}')

    # Records: what makes one well formed, whoever signed it.
    def record_case(section, name, reason, record):
        section.append({"name": name, "reason": reason, "kind": "record",
                        "record": record})

    def nest(levels):
        value = []
        for _ in range(levels - 1):
            value = [value]
        return value

    def resigned(**changes):
        return signed(variant(intent, **changes), a_op2, amina_vm2)

    record_case(neg, "proof-entry-not-an-object",
                "Every entry of `proof` is an object (core 5.1). A proof "
                "that does not verify never counts and does not make the "
                "record malformed (core 5.5); an entry that is not an "
                "object at all does.",
                {**intent, "proof": intent["proof"] + ["a proof"]})
    not_a_proof = {**intent, "proof": intent["proof"] + [{"note": "x"}]}
    record_case(neg, "extension-name-not-a-namespace",
                "A member of `ext` is named by a reverse-DNS namespace, "
                "one of the short names the specification lists, or a "
                "name under `oip.` (core 8.1). Any other name makes the "
                "record malformed.",
                resigned(ext={"Example Extension": {"v": 1}}))
    record_case(neg, "unknown-type-without-critical-extension",
                "A record whose type this revision does not define is "
                "defined by an extension, and lists that extension in "
                "`critical` (core 7). Without it nobody can say what the "
                "record is.",
                resigned(type="com.example.Note"))
    extension_typed = resigned(type="com.example.Note",
                               ext={"com.example": {"v": 1}},
                               critical=["com.example"])
    record_case(V["valid"], "extension-type-with-critical-extension",
                "A record of a type an extension defines is well formed "
                "when it lists that extension in `critical` (core 7, 8.3). "
                "A reader that does not understand the extension then "
                "answers `unsupported-critical`; that is another "
                "question.", extension_typed)
    undated = variant(intent, type="com.example.Note",
                      ext={"com.example": {"v": 1}},
                      critical=["com.example"])
    del undated["created"]
    record_case(neg, "extension-type-without-created",
                "`created` is required in every record except the "
                "containers and `Sealed` (core 7), and those are types of "
                "this specification. A record of a type an extension "
                "defines carries it like any other.",
                signed(undated, a_op2, amina_vm2,
                       created=intent["created"]))

    def retaining(duration):
        return signed(variant(packet, constraints={
            "retention": duration, "prohibitedUses": ["train"]}),
            t_op, agent_vm)

    record_case(V["valid"], "duration-of-64-characters",
                "A duration string has at most 64 characters (core 1.5). "
                "This one has exactly 64.", retaining("P" + "9" * 62 + "D"))
    record_case(neg, "duration-of-65-characters",
                "One character more than core 1.5 allows. Without the "
                "limit a duration could have a million digits, and a "
                "reader that computes with it would do arithmetic on "
                "numbers of that size.", retaining("P" + "9" * 63 + "D"))
    record_case(V["valid"], "timestamp-in-year-0000",
                "Years run from 0000 to 9999, and year 0000 is a leap "
                "year (core 1.4): 29 February 0000 is a real date.",
                resigned(created="0000-02-29T00:00:00Z",
                         expires="0000-03-01T00:00:00Z",
                         constraints={"deadline": "0000-03-01T00:00:00Z"}))
    record_case(V["valid"], "receipt-rating-of-minus-zero",
                "`-0` is a decimal equal to `0` (core 1.3), so it is a "
                "score from 0 to 1.",
                signed(variant(receipt, rating={"score": "-0"}),
                       a_op1, amina_vm1))
    # The record is at depth 1, `ext` at 2 and its block at 3.
    record_case(V["valid"], "record-nested-64-deep",
                "The arrays and objects of a record nest at most 64 deep, "
                "the record itself being depth 1 (core 1.9). This one "
                "nests exactly 64.",
                resigned(ext={"com.example.deep": {"down": nest(61)}}))
    record_case(neg, "record-nested-65-deep",
                "One level more than core 1.9 allows.",
                resigned(ext={"com.example.deep": {"down": nest(62)}}))
    # The event is at depth 1, `proof` at 2 and its entry at 3.
    def padded_event(levels):
        return {**a_gen, "proof": a_gen["proof"] + [{"junk": nest(levels)}]}

    def page(event):
        return {"oip": OIP_VERSION, "type": "LogPage", "mind": amina,
                "events": [event]}

    record_case(V["valid"], "container-carries-a-record-nested-64-deep",
                "For a container the limit on depth applies to each record "
                "it carries, counted from that record, and to the "
                "container without them (core 1.9). Anyone can add an "
                "entry to an event's `proof`, where it never counts "
                "(core 5.5); here it brings the event to exactly 64 deep, "
                "which is valid. The page as a whole nests 66 deep, and "
                "must still be accepted: otherwise one junk entry would "
                "stop a log from being served.", page(padded_event(61)))
    record_case(neg, "container-carries-a-record-nested-65-deep",
                "The same page with the event one level deeper. The event "
                "is not a valid record (core 1.9), so the page is not "
                "well formed.", page(padded_event(62)))

    def junked(record, levels):
        return {**record, "proof": record["proof"] + [{"junk": nest(levels)}]}

    def evidence(levels):
        return {"oip": OIP_VERSION, "type": "DuplicityEvidence",
                "mind": amina, "pairs": [[junked(a_upd, levels), a_upd_alt]]}

    def feed_page(levels):
        return {"oip": OIP_VERSION, "type": "FeedPage", "mind": lexis,
                "entries": [junked(entry, levels)]}

    def bundle(levels):
        return {"oip": OIP_VERSION, "type": "Bundle", "mind": lexis,
                "log": [agent_gen, fork_ev],
                "location": junked(location, levels),
                "participant": participant}

    def page_with_own(levels):
        return {**page(a_gen), "ext": {"com.example.deep":
                                       {"down": nest(levels)}}}

    record_case(V["valid"], "duplicity-evidence-carries-a-record-nested-64-deep",
                "An event in a pair of `DuplicityEvidence` sits three "
                "levels down, the deepest a container carries a record. "
                "The event nests exactly 64 deep, so the whole nests 67 "
                "deep, which is the most any well-formed record can.",
                evidence(61))
    record_case(neg, "duplicity-evidence-carries-a-record-nested-65-deep",
                "The same evidence with the event one level deeper.",
                evidence(62))
    record_case(neg, "feed-page-carries-a-record-nested-65-deep",
                "The rule for containers holds for a `FeedPage` and the "
                "entries it carries.", feed_page(62))
    record_case(neg, "bundle-carries-a-location-nested-65-deep",
                "A `Bundle` carries records in three members: `log`, "
                "`location` and `participant`. Each is held to the limit.",
                bundle(62))
    record_case(neg, "container-nested-65-deep-without-its-records",
                "The limit also applies to the container without the "
                "members that hold its records: here a member of the "
                "page's own nests 65 deep.", page_with_own(62))

    # --- OEP-0002: identity clarifications ------------------------------
    o_c0, o_c1, o_op = k("oep2-control-0"), k("oep2-control-1"), k("oep2-op")
    o_op2, o_inv = k("oep2-op-2"), k("oep2-invocation")

    def homes_genesis(homes):
        return key_controlled_genesis("service", o_c0, o_c1, [o_op],
                                      homes=homes)

    nine = [f"https://home{n}.example" for n in range(9)]
    bad_log("genesis-with-nine-homes",
            "An event is a well-formed record of its type, whoever signed "
            "it (Layer 1, 4.8): a Genesis holds at most 8 homes. The "
            "signature is good. An address is the content ID of a genesis, "
            "so verifiers must agree on which geneses are well formed.",
            [homes_genesis(nine)])

    def expiring_genesis(expires):
        return key_controlled_genesis("service", o_c0, o_c1, [o_op],
                                      extra={"expires": expires})

    bad_log("event-with-malformed-expires",
            "An event is a well-formed record (Layer 1, 4.8), so its "
            "`expires`, if it has one, is a timestamp (core 1.4, core 7). "
            "There is no thirteenth month.",
            [expiring_genesis("2026-13-01T00:00:00Z")])
    bad_log("home-with-a-path",
            "A home is an HTTPS origin (Layer 1, 3.13): a host and an "
            "optional port, with no path.",
            [homes_genesis(["https://lexis.example/records"])])

    def controller_genesis(**more):
        return key_controlled_genesis(
            "service", o_c0, o_c1, [o_op],
            extra={"controller": {"keys": [o_c0.mk],
                                  "next": [key_hash(o_c1.mk)],
                                  "nextThreshold": 1, **more}})

    bad_log("controller-with-an-unknown-member",
            "A controller has no other members (Layer 1, 3.4). What "
            "decides who may extend a log is not open to members that one "
            "verifier reads and another ignores.",
            [controller_genesis(recoveryKeys=[key_hash(o_c1.mk)])])

    # A Fork may carry the key sets, as an Update does (Layer 1, 3.8).
    o_gen = key_controlled_genesis("service", o_c0, o_c1, [o_op],
                                   created="2026-10-30T09:00:00Z")
    oep2 = did(content_id(o_gen))
    o_fork = control_event(
        "Fork", oep2, o_gen, "2026-10-30T09:30:00Z", [o_c1], [],
        fields={"child": amina,
                "keys": [{"key": o_op.mk, "label": o_op.label},
                         {"key": o_op2.mk, "label": o_op2.label}]})

    def oep2_intent(at_event, key, created="2026-10-30T11:00:00Z"):
        return signed({"oip": OIP_VERSION, "type": "Intent", "author": oep2,
                       "created": created, "want": "A second opinion."},
                      key, op_vm(oep2, at_event, key.mk))

    V["valid"].append({
        "name": "key-added-by-a-fork",
        "reason": "A Fork may carry `keys`, with the meaning they have in "
                  "an Update (Layer 1, 3.8 and 4.5). The key this Fork "
                  "adds signs for the mind from then on.",
        "kind": "countsFor", "record": oep2_intent(o_fork, o_op2),
        "mind": oep2, "extraLogs": [[o_gen, o_fork]]})
    V["valid"].append({
        "name": "recovery-inside-another-member",
        "reason": "`recovery` is reserved as a member of an event itself "
                  "(Layer 1, 3.12). Inside `inherits`, which is a claim "
                  "in the author's own words, it is a word like any other.",
        "kind": "log",
        "log": [key_controlled_genesis(
            "service", o_c0, o_c1, [o_op],
            extra={"inherits": {"recovery": "three months of archives"}})]})

    # A Retire leaves the keys in their sets, and nothing follows it.
    o_retire = control_event("Retire", oep2, o_gen, "2026-10-30T10:00:00Z",
                             [o_c1], [], fields={"reason": "Wound up."})
    o_update = control_event("Update", oep2, o_gen, "2026-10-30T10:00:00Z",
                             [o_c1], [])
    bad_sig("proof-pinned-to-a-retire",
            "After a Retire a mind's keys sign nothing (Layer 1, 3.10). "
            "The Retire leaves the key in its set and no later event "
            "removes it, so the proof pins the Retire itself: Layer 1, "
            "6.1 item 2 refuses that version.",
            oep2_intent(o_retire, o_op), oep2,
            extra_logs=[[o_gen, o_retire]])

    # The same for a member's proof on a collective's identity event.
    m_gen = key_controlled_genesis(
        "human", o_c0, o_c1, [o_op], created="2026-10-30T09:01:00Z",
        extra={"invocation": [{"key": o_inv.mk, "label": o_inv.label}]})
    member = did(content_id(m_gen))
    m_retire = control_event("Retire", member, m_gen,
                             "2026-10-30T10:00:00Z", [o_c1], [])
    m_update = control_event("Update", member, m_gen,
                             "2026-10-30T10:00:00Z", [o_c1], [])

    def founded_by(at_event):
        return coll_genesis(1, [(o_inv, op_vm(member, at_event, o_inv.mk))],
                            members=(member,),
                            created="2026-10-30T11:00:00Z")

    bad_log("retired-member-signs-for-a-collective",
            "A retired mind's invocation keys sign nothing either. The "
            "founder's proof pins its own Retire, which Layer 1, 6.4 item "
            "2 refuses, so the collective has no founder that signed.",
            [founded_by(m_retire)], extra_logs=[[m_gen, m_retire]])

    # --- OEP-0002, after the review of M2 -------------------------------
    # core 8.3: an extension nobody implements, listed in `critical`.
    def extended_update(critical):
        fields = {"keys": [{"key": o_op2.mk, "label": o_op2.label}],
                  "ext": {"com.example.recovery": {"v": "1"}}}
        if critical:
            fields["critical"] = ["com.example.recovery"]
        return control_event("Update", oep2, o_gen, "2026-10-30T10:00:00Z",
                             [o_c1], [], fields=fields)

    bad_log("event-with-a-critical-extension",
            "An implementation that does not understand an extension "
            "listed in `critical` must not treat the record as valid for "
            "any decision (core 8.3). For an identity event the decision "
            "is whether the log verifies (Layer 1, 4.8): it does not, so "
            "the key this Update adds is no key of the mind. No verifier "
            "of this revision implements `com.example.recovery`.",
            [o_gen, extended_update(True)])

    def extended_intent(critical):
        doc = {"oip": OIP_VERSION, "type": "Intent", "author": oep2,
               "created": "2026-10-30T11:00:00Z", "want": "A second opinion.",
               "ext": {"com.example.escrow": {"v": "1"}}}
        if critical:
            doc["critical"] = ["com.example.escrow"]
        return signed(doc, o_op, op_vm(oep2, o_gen, o_op.mk))

    bad_sig("record-with-a-critical-extension",
            "The record is well formed and its proof verifies. It lists an "
            "extension in `critical` that no verifier of this revision "
            "implements, so it may be stored and passed on, and counts for "
            "nobody (core 8.3).", extended_intent(True), oep2,
            extra_logs=[[o_gen]])

    # Layer 1, 7.3 and 9.5: a collective whose members signed two events
    # for one position.
    two_of_three = [(a_inv, amina_inv), (t_inv, agent_inv)]
    c_retire = member_event("Retire", collective, coll,
                            "2026-10-30T22:00:00Z", two_of_three)
    c_shrink = member_event("Update", collective, coll,
                            "2026-10-30T22:00:00Z", two_of_three,
                            {"controller": {"members": [amina, lexis],
                                            "threshold": 2}})

    def signed_by_two(created):
        doc = {"oip": OIP_VERSION, "type": "Intent", "author": collective,
               "created": created,
               "want": "Hire a second reviewer for Swahili leases."}
        return sign(doc, *[create_proof(doc, key, vm, "assertionMethod",
                                        created)
                           for key, vm in ((r_op, res_vm),
                                           (a_op1, amina_vm1))])

    bad_sig("duplicitous-collective-signs-after-the-divergence",
            "At 22:00 two members retired the collective, and the same two "
            "signed another event for the same position that removes the "
            "researcher. Evidence cannot separate the two, so the "
            "collective is duplicitous. With either event alone, a record "
            "signed at 23:00 by Amina and the researcher does not count; "
            "holding both must not make it count. From its first "
            "conflicting event on, a duplicitous collective's members are "
            "not known, and nothing is signed under its threshold (Layer "
            "1, 7.3 and 9.5).", signed_by_two("2026-10-30T23:00:00Z"),
            collective, extra_logs=[[coll, c_retire]],
            branches=[[coll, c_shrink]])

    # Layer 1, 7.3: a branch counts for the events it has that verify.
    alt_intent = signed(variant(intent, created="2026-10-30T11:30:00Z"),
                        a_op1, op_vm(amina, a_upd_alt, a_op1.mk))
    a_junk = control_event("Update", amina, a_upd, "2026-10-30T12:00:00Z",
                           [attacker], [k("attacker-next")])
    bad_sig("branch-ending-in-an-invalid-event-is-not-passed-over",
            "Two valid events sit at position 1 of Amina's log. The one "
            "first seen at 09:05 wins, whatever follows it. In the copy "
            "this verifier holds, an event that does not verify follows "
            "it. Whether the verifier rejects that copy or keeps the "
            "events before the invalid one (Layer 1, 4.9), the other "
            "branch does not win by default: a record pinned to its "
            "event, first seen at 11:00, does not count.", alt_intent, amina,
            extra_logs=[[a_gen, a_upd, a_junk]],
            branches=[[a_gen, a_upd_alt]],
            seen={content_id(a_upd): "2026-10-30T09:05:00Z",
                  content_id(a_upd_alt): "2026-10-30T11:00:00Z"})

    # Layer 1, 9.5: the earliest time T ranges over the collective's own
    # events as well as the proofs.
    coll3 = coll_genesis(3, founders, created="2026-10-30T09:25:00Z")
    collective3 = did(content_id(coll3))
    c3_shrink = member_event(
        "Update", collective3, coll3, "2026-10-31T00:00:00Z", founders,
        {"controller": {"members": [amina, researcher], "threshold": 2}})
    two_of_all = {"oip": OIP_VERSION, "type": "Intent",
                  "author": collective3, "created": "2026-10-30T23:00:00Z",
                  "want": "Hire a second reviewer for Swahili leases."}
    two_of_all = sign(two_of_all, *[
        create_proof(two_of_all, key, vm, "assertionMethod",
                     "2026-10-30T23:00:00Z")
        for key, vm in ((r_op, res_vm), (a_op1, amina_vm1))])
    bad_sig("collective-threshold-not-met-before-its-members-change",
            "All three members must sign for this collective, and two "
            "have. The record is not signed by it.", two_of_all,
            collective3, extra_logs=[[coll3]])

    # Layer 1, 6.4: a member's proof that names an authority.
    def founded_with(**extra):
        g = {kk: v for kk, v in founded_by(m_update).items()
             if kk != "proof"}
        return sign(g, create_proof(g, o_inv,
                                    op_vm(member, m_update, o_inv.mk),
                                    "capabilityInvocation", g["created"],
                                    **extra))

    bad_log("member-proof-names-an-authority",
            "A proof that names an `authority` is made for that "
            "principal, not by the member for itself, so it does not "
            "count as the member's on an identity event (Layer 1, 6.4 and "
            "9.4). The collective has no founder that signed.",
            [founded_with(authority=[record_ref(member, m_gen)])],
            extra_logs=[[m_gen, m_update]])

    # core 9.3 and 9.6, for the proofs on an identity event.
    def update_proved_at(proved):
        ev = {kk: v for kk, v in o_update.items() if kk != "proof"}
        return sign(ev, create_proof(ev, o_c1, did_key_vm(o_c1.mk),
                                     "capabilityInvocation", proved))

    bad_log("event-proof-dated-after-the-evidence",
            "A proof dated more than 300 seconds after the evidence that "
            "it existed counts for nothing (core 9.3). The evidence for "
            "an identity event is evidence for the proofs it stood with, "
            "and this event was first seen at 10:00:00. Its only proof is "
            "dated 10:05:01, so nothing authorises it.",
            [o_gen, update_proved_at("2026-10-30T10:05:01Z")])
    expiring = expiring_genesis("2026-12-01T00:00:00Z")
    bad_log("event-evaluated-after-it-expires",
            "A proof evaluated more than 300 seconds after its record's "
            "`expires` does not count (core 9.6), and the proofs on an "
            "identity event are judged at the event's evaluation time "
            "(core 9.5). This genesis expires on 1 December and was first "
            "seen 301 seconds after that.", [expiring],
            seen={content_id(expiring): "2026-12-01T00:05:01Z"})

    # Layer 1, 3.6 and 3.7: the entries of `parents` and `revoked` are
    # closed, as the key entries are.
    def revoking(**entry):
        return control_event(
            "Update", oep2, o_gen, "2026-10-30T10:00:00Z", [o_c1], [],
            fields={"revoked": [{"key": o_op.mk, **entry}]})

    bad_log("revoked-entry-with-an-unknown-member",
            "An entry of `revoked` has `key`, `compromisedSince` and no "
            "other member (Layer 1, 3.7). `compromisedSince` withdraws "
            "signatures; a verifier that ignored a misspelt one would "
            "disagree with one that did not about what the mind signed.",
            [o_gen, revoking(compromisedsince="2026-10-30T09:30:00Z")])

    def revoking_many(count):
        return control_event(
            "Update", oep2, o_gen, "2026-10-30T10:00:00Z", [o_c1], [],
            fields={"revoked": [{"key": Key(f"oep2-revoked-{n}").mk}
                                for n in range(count)]})

    bad_log("event-revoking-81-keys",
            "An event revokes at most 80 keys (Layer 1, 3.7): as many as "
            "the operational and invocation keys a state can hold. Without "
            "a limit, one event of a megabyte could name seventeen "
            "thousand.", [o_gen, revoking_many(81)])

    def child_genesis(**entry):
        return key_controlled_genesis(
            "service", o_c0, o_c1, [o_op], created="2026-10-30T09:10:00Z",
            parents=[{"mind": oep2, "at": version_id(o_gen), **entry}])

    bad_log("parent-with-an-unknown-member",
            "An entry of `parents` has `mind`, `at` and no other member "
            "(Layer 1, 3.6).", [child_genesis(terms="everything")])

    # A member that is present with the value null is not absent.
    def unchanged(**fields):
        return member_event("Update", collective, coll,
                            "2026-10-30T22:00:00Z", two_of_three, fields)

    bad_log("collective-event-with-a-null-controller",
            "A collective's event may leave `controller` out. One that "
            "has it must have a controller there: `null` is a value, and "
            "it is not a controller (Layer 1, 3.4 and 4.8).",
            [coll, unchanged(controller=None)])

    # Layer 1, 4.9 and 7.3: the branch that wins, in a copy whose next
    # event this verifier cannot judge.
    def amina_extended(critical):
        fields = {"ext": {"com.example.recovery": {"v": "1"}}}
        if critical:
            fields["critical"] = ["com.example.recovery"]
        return control_event("Update", amina, a_upd, "2026-10-30T12:00:00Z",
                             [a_c2], [k("amina-control-3b")], fields=fields)

    bad_sig("winning-branch-ending-in-an-event-that-cannot-be-judged",
            "Two valid events sit at position 1 of Amina's log, and the "
            "one first seen at 09:05 wins. This record is pinned to it and "
            "signed by a key it holds. In the copy this verifier holds, "
            "the next event is Amina's own, validly signed, and lists in "
            "`critical` an extension the verifier does not implement. The "
            "verifier cannot judge that event, which may remove the key, "
            "so it does not take the events before it as her log (Layer "
            "1, 4.9 and 7.3). The log does not verify for this verifier, "
            "and nothing pinned to it counts.", intent, amina,
            extra_logs=[[a_gen, a_upd, amina_extended(True)]],
            branches=[[a_gen, a_upd_alt]],
            seen={content_id(a_upd): "2026-10-30T09:05:00Z",
                  content_id(a_upd_alt): "2026-10-30T11:00:00Z"})

    # Layer 1, 7.3 and 9.5: both branches keep the two members who sign.
    c_homed = member_event("Update", collective, coll,
                           "2026-10-30T22:00:00Z", two_of_three,
                           {"homes": ["https://collective.example"]})
    c_without_agent = member_event(
        "Update", collective, coll, "2026-10-30T22:00:00Z", two_of_three,
        {"controller": {"members": [amina, researcher], "threshold": 2}})
    bad_sig("duplicitous-collective-whose-branches-keep-the-signers",
            "At 22:00 two members signed two events for one position of "
            "the collective's log. One sets a home; the other removes the "
            "third member. Amina and the researcher are members after "
            "either, and with either event alone a record they sign at "
            "23:00 is signed by the collective. Evidence cannot separate "
            "the two events, so the collective is duplicitous, and from "
            "its first conflicting event on nothing is signed under its "
            "threshold (Layer 1, 7.3 and 9.5). The rule is one of time: a "
            "verifier does not ask, member by member, what the branches "
            "agree on.", signed_by_two("2026-10-30T23:00:00Z"), collective,
            extra_logs=[[coll, c_homed]], branches=[[coll, c_without_agent]])

    # Layer 1, 4.9 and 7.3: an event this verifier cannot judge, at a
    # position another copy fills.
    a_rival = control_event("Update", amina, a_upd, "2026-10-30T11:00:00Z",
                            [a_c2], [k("amina-control-3c")],
                            fields={"homes": ["https://amina-two.example"]})
    rival_intent = signed(variant(intent, created="2026-10-30T11:30:00Z"),
                          a_op1, op_vm(amina, a_rival, a_op1.mk))
    bad_sig("rival-to-an-event-that-cannot-be-judged",
            "Position 2 of Amina's log holds two events, both signed by the "
            "control key she committed to. One is dated 12:00 and lists in "
            "`critical` an extension this verifier does not implement; the "
            "other is dated 11:00, and this record is pinned to it. The "
            "verifier cannot judge the first, which may be Amina's own "
            "event, seen earlier by others, and may remove the key. So the "
            "second does not take the position for want of a judgement: "
            "the copy with the first is still in the contest there, and "
            "the log does not verify for this verifier (Layer 1, 4.9 and "
            "7.3).", rival_intent, amina,
            extra_logs=[[a_gen, a_upd, amina_extended(True)]],
            branches=[[a_gen, a_upd, a_rival]])

    V["valid"].append({
        "name": "home-that-is-no-host",
        "reason": "The grammar of an HTTPS origin bounds its characters "
                  "and nothing else (Layer 1, 3.13). It does not show that "
                  "a host exists, or that the text after the scheme is a "
                  "host and a port, so this string is an origin. Every "
                  "implementation must accept the same geneses.",
        "kind": "log", "log": [homes_genesis(["https://:::"])]})

    record_case(V["valid"], "container-with-created",
                "A container has no `created` (core 7). A reader ignores "
                "one there, as it ignores any member it does not recognise "
                "(core 1.7).",
                {**page(a_gen), "created": "2026-10-30T09:00:00Z"})

    # Controls: each negative case above, changed only in the respect its
    # reason names, must be accepted, so it fails for that reason alone.
    by_name = {case["name"]: case for case in neg}

    def control(name, **changes):
        case = {kk: v for kk, v in by_name[name].items() if kk != "reason"}
        for kk, v in changes.items():
            if v is None:
                case.pop(kk, None)
            else:
                case[kk] = v
        V["controls"].append(case)

    control("removed-key-backdated",
            seen=seen_at(late_intent, "2026-11-01T08:00:05Z"))
    control("compromised-key-backdated",
            seen=seen_at(early_intent, "2026-10-30T23:00:10Z"))
    control("expired-delegation-backdated",
            seen=seen_at(exp_commit, "2026-11-29T00:00:05Z"))
    control("revoked-delegation",
            seen=seen_at(rev_commit, "2026-11-05T00:00:05Z"))
    control("removed-member-backdated",
            seen=seen_at(coll_intent, "2026-10-30T23:00:05Z"))
    control("collective-update-with-removed-invocation-keys",
            seen={content_id(takeover): "2026-11-01T12:00:05Z"})
    control("collective-genesis-seen-after-founder-key-removal", seen=None)
    taller = coll_genesis(2, founders, height=2)
    control("collective-member-height", log=[taller, join_c2(taller)])
    control("late-cosignature-backdated",
            seen={proof_digest(p_agent): "2026-10-30T10:20:00Z",
                  proof_digest(p_late): "2026-10-30T10:25:05Z"})
    control("policy-negation-of-missing-member",
            record=signed(variant(unpriced, terms__price=usd("120")),
                          t_op, agent_vm, authority=[d_not]))
    control("collective-location-after-member-left", extraLogs=None)
    # The Ed25519 cases: the same record with an honest signature counts.
    control("signature-s-not-reduced", record=sign(s_doc, s_ok))
    control("signature-r-identity", record=signed(r_doc, a_op2, amina_vm2))
    control("signature-r-mixed-order",
            record=signed(m_doc, a_op2, amina_vm2))
    control("key-reference-position-wraps-around",
            record=signed(w_doc, a_op2, amina_vm2))
    control("json-noncharacter", text='{"s":"\\ufffd"}')
    control("json-noncharacter-in-a-member-name",
            text='{"\\ud83f\\udffd":1}')
    control("json-noncharacter-in-the-reserved-block",
            text='{"s":"\\ufdcf\\ufdf0"}')
    control("json-noncharacter-in-the-last-plane",
            text='{"s":"\\udbff\\udffd"}')
    control("extension-type-without-created", record=extension_typed)
    control("duration-of-65-characters",
            record=retaining("P" + "9" * 62 + "D"))
    control("duplicity-evidence-carries-a-record-nested-65-deep",
            record=evidence(61))
    control("feed-page-carries-a-record-nested-65-deep",
            record=feed_page(61))
    control("bundle-carries-a-location-nested-65-deep", record=bundle(61))
    control("container-nested-65-deep-without-its-records",
            record=page_with_own(61))
    control("proof-entry-not-an-object", record=not_a_proof)
    control("extension-name-not-a-namespace",
            record=resigned(ext={"com.example.extension": {"v": 1}}))
    control("unknown-type-without-critical-extension",
            record=extension_typed)
    control("record-nested-65-deep",
            record=resigned(ext={"com.example.deep": {"down": nest(61)}}))
    control("container-carries-a-record-nested-65-deep",
            record=page(padded_event(61)))
    control("genesis-with-nine-homes", log=[homes_genesis(nine[:8])])
    control("event-with-malformed-expires",
            log=[expiring_genesis("2026-12-01T00:00:00Z")])
    control("home-with-a-path",
            log=[homes_genesis(["https://lexis.example"])])
    control("controller-with-an-unknown-member", log=[controller_genesis()])
    # The same record pinned to an Update in the Retire's place counts.
    control("proof-pinned-to-a-retire", record=oep2_intent(o_update, o_op),
            extraLogs=[[o_gen, o_update]])
    control("retired-member-signs-for-a-collective",
            log=[founded_by(m_update)], extraLogs=[[m_gen, m_update]])
    control("event-with-a-critical-extension",
            log=[o_gen, extended_update(False)])
    control("record-with-a-critical-extension", record=extended_intent(False))
    # Signed an hour before the branches part, the record counts.
    control("duplicitous-collective-signs-after-the-divergence",
            record=signed_by_two("2026-10-30T21:00:00Z"))
    # With the evidence the other way round the other event wins, and what
    # follows the losing event does not matter.
    control("branch-ending-in-an-invalid-event-is-not-passed-over",
            seen={content_id(a_upd): "2026-10-30T11:00:00Z",
                  content_id(a_upd_alt): "2026-10-30T09:05:00Z"})
    # On 31 October the collective becomes the two who signed, with a
    # threshold of two. The record is signed by it from that moment, though
    # neither proof was made then (Layer 1, 9.5).
    control("collective-threshold-not-met-before-its-members-change",
            extraLogs=[[coll3, c3_shrink]])
    control("member-proof-names-an-authority", log=[founded_with()])
    control("event-proof-dated-after-the-evidence",
            log=[o_gen, update_proved_at("2026-10-30T10:05:00Z")])
    control("event-evaluated-after-it-expires",
            seen={content_id(expiring): "2026-12-01T00:05:00Z"})
    control("revoked-entry-with-an-unknown-member",
            log=[o_gen, revoking(compromisedSince="2026-10-30T09:30:00Z")])
    control("event-revoking-81-keys", log=[o_gen, revoking_many(80)])
    control("parent-with-an-unknown-member", log=[child_genesis()])
    control("collective-event-with-a-null-controller",
            log=[coll, unchanged()])
    # The same event without `critical`: an extension that is not critical
    # changes nothing, the log verifies to its end, and the record counts.
    control("winning-branch-ending-in-an-event-that-cannot-be-judged",
            extraLogs=[[a_gen, a_upd, amina_extended(False)]])
    # With one of the two events alone, the record counts.
    control("duplicitous-collective-whose-branches-keep-the-signers",
            branches=None)
    # The same event without `critical` can be judged. The two are then
    # separated by evidence, the event of 11:00 has the position, and the
    # record pinned to it counts.
    control("rival-to-an-event-that-cannot-be-judged",
            extraLogs=[[a_gen, a_upd, amina_extended(False)]])
    return V


def forged_proof(doc, vm, purpose, created, sign_raw) -> dict:
    """A proof whose 64-byte signature comes from sign_raw(hashData), for
    Ed25519 edge cases that ordinary libraries refuse to produce."""
    config = {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022",
              "verificationMethod": vm, "proofPurpose": purpose,
              "created": created}
    unsecured = {k: v for k, v in doc.items() if k != "proof"}
    msg = hashlib.sha256(jcs(config)).digest() + \
        hashlib.sha256(jcs(unsecured)).digest()
    return {**config, "proofValue": "z" + b58encode(sign_raw(msg))}


def ed_raw_sign(scalar, pub: bytes, msg: bytes, nonce=None, r_point=None,
                offset=None):
    """Ed25519 signing from a scalar (TEST VECTORS ONLY): R = [nonce]B, or
    r_point with its discrete log taken as 0 (the identity), and
    S = r + k * scalar mod L. With `offset`, a point of small order is
    added to R: [8]R is what it was, so the equation still holds for a
    verifier that multiplies it by the cofactor."""
    if r_point is not None:
        r, R = 0, ed_encode(r_point)
    else:
        r = nonce % ED_L
        point = ed_mul(r, ED_B)
        R = ed_encode(ed_add(point, offset) if offset is not None else point)
    k = int.from_bytes(hashlib.sha512(R + pub + msg).digest(), "little") % ED_L
    return R + ((r + k * scalar) % ED_L).to_bytes(32, "little")


def variant_of(base, **changes):
    """A copy of a record without its proofs, with changes applied
    (a double underscore selects a nested member)."""
    doc = {kk: v for kk, v in copy.deepcopy(base).items() if kk != "proof"}
    for path, value in changes.items():
        cur = doc
        parts = path.split("__")
        for part in parts[:-1]:
            cur = cur[part]
        cur[parts[-1]] = value
    return doc

# ---------------------------------------------------------------- checks


LOG_NAMES = ("amina_log", "lexis_ltd_log", "lexis_agent_log",
             "lexis_fork_log", "lexis_fork2_log", "researcher_log",
             "collective_log", "multi_log", "assistant_log", "gateway_log",
             "bridged_log")
RECORD_NAMES = ("delegation", "delegation_sub", "delegation_amina",
                "delegation_send", "intent", "offer", "offer_glossary",
                "commitment_accepted", "receipt", "commitment_agents",
                "collective_charter", "commitment_by_steward",
                "commitment_via_chain", "lineage", "participant", "location",
                "feed_entry", "feed_entry_1", "checkpoint", "packet", "ack",
                "hello", "gateway_entry", "bridged_participant")
MINDS = (("amina_log", "amina"), ("lexis_ltd_log", "lexis_ltd"),
         ("lexis_agent_log", "lexis_agent"), ("lexis_fork_log", "lexis_fork"),
         ("lexis_fork2_log", "lexis_fork2"), ("researcher_log", "researcher"),
         ("collective_log", "collective"), ("multi_log", "multi"),
         ("assistant_log", "assistant"), ("gateway_log", "gateway"),
         ("bridged_log", "bridged"))
STATUS_FN = {"Intent": lambda *a: intent_status(*a),
             "Offer": lambda *a: offer_status(*a),
             "Commitment": lambda *a: commitment_status(*a)}


def verifier_for(c, extra_logs=(), records=(), seen=None,
                 branches=()) -> Verifier:
    V = Verifier(logs=[c[n] for n in LOG_NAMES],
                 records=[c[n] for n in RECORD_NAMES], seen=seen)
    for log in extra_logs:
        V.add_log(log)
    for log in branches:
        V.add_branch(log)
    for r in records:
        V.add(r)
    return V


def _all_ids(obj, out):
    """Every content ID or address that appears anywhere in the vectors."""
    if isinstance(obj, dict):
        for v in obj.values():
            _all_ids(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _all_ids(v, out)
    elif isinstance(obj, str):
        out.update(re.findall(r"\bb[a-z2-7]{55}\b", obj))


def resign(record, key, **changes):
    """Re-sign a copy of a single-proof record after changing it."""
    p = record["proof"][0]
    doc = variant_of(record, **changes)
    extra = {"authority": p["authority"]} if "authority" in p else {}
    return sign(doc, create_proof(doc, key, p["verificationMethod"],
                                  p["proofPurpose"], doc["created"], **extra))


def check(VEC) -> list:
    """Re-verify every positive case. Returns the names of the checks."""
    c = VEC["cases"]
    assert VEC["baseline"] == {"logs": list(LOG_NAMES),
                               "records": list(RECORD_NAMES)}
    V = verifier_for(c)
    done = []
    for log, mind in MINDS:
        assert did(content_id(c[log][0])) == c[mind]
        V.log(c[mind])
    assert V.log(c["collective"]).height == 1
    done.append("identity logs verify; addresses derive from genesis")
    ids = set()
    _all_ids([VEC["cases"], VEC["valid"], VEC["controls"]], ids)
    assert ids and all(CID_RE.fullmatch(i) for i in ids), \
        [i for i in ids if not CID_RE.fullmatch(i)]
    done.append(f"all {len(ids)} content IDs use the canonical spelling")
    assert V.log(c["multi"]).latest.next_threshold == 1
    done.append("2-of-3 pre-rotation with distinct keys")
    assert V.lineage(c["lexis_fork"]) == {c["lexis_agent"]: "acknowledged"}
    assert V.lineage(c["lexis_fork2"]) == {c["lexis_agent"]: "acknowledged"}
    done.append("lineage acknowledged by a Fork event and by a Lineage record")
    for name, mind in (("intent", "amina"), ("offer", "lexis_agent"),
                       ("offer_glossary", "lexis_ltd"),
                       ("receipt", "amina"), ("packet", "lexis_agent"),
                       ("ack", "amina"), ("hello", "lexis_agent"),
                       ("delegation", "lexis_ltd"),
                       ("delegation_sub", "lexis_agent"),
                       ("delegation_amina", "amina"),
                       ("delegation_send", "amina"),
                       ("participant", "lexis_agent"),
                       ("location", "lexis_agent"),
                       ("feed_entry", "lexis_agent"),
                       ("feed_entry_1", "lexis_agent"),
                       ("checkpoint", "lexis_agent"),
                       ("lineage", "lexis_agent"),
                       ("gateway_entry", "gateway"),
                       ("bridged_participant", "bridged")):
        assert V.counts_for(c[name], c[mind]), name
    done.append("signatures count for their authors (purpose and key checks)")
    for name, mind, version in (("did_document_amina", "amina", None),
                                ("did_document_amina_at_genesis", "amina",
                                 version_id(c["amina_log"][0])),
                                ("did_document_collective", "collective",
                                 None)):
        assert did_document(V, c[mind], version) == c[name], name
    done.append("DID documents, current and versioned")
    entry, entry1, offer = c["feed_entry"], c["feed_entry_1"], c["offer"]
    acc, prop = c["commitment_accepted"], c["commitment_proposed"]
    assert entry["object"] == content_id(offer)
    assert entry["proofs"] == [proof_digest(p) for p in offer["proof"]]
    assert entry1["prev"] == content_id(entry)
    assert entry1["proofs"] == [proof_digest(p) for p in acc["proof"]]
    assert c["checkpoint"]["root"] == checkpoint_root(
        [content_id(entry), content_id(entry1)])
    assert c["location"]["feed"]["head"] == content_id(entry)
    done.append("feed entries commit to proofs; checkpoint Merkle root")
    assert c["ack"]["packet"] == content_id(c["packet"])
    assert c["packet"]["content"]["parts"][0]["body"] == c["session"]
    assert c["packet"]["session"] == content_id(c["session"])
    done.append("packet opens its session; Ack names the packet")
    assert V.sent_for(c["packet_on_behalf"], c["amina"])
    assert not V.sent_for(c["packet_on_behalf"], c["lexis_ltd"])
    done.append("packet sent on Amina's behalf under a /oip/send delegation")
    assert content_id(acc) == content_id(prop)
    assert V.counts_for(acc, c["amina"]) and V.counts_for(acc, c["lexis_ltd"])
    assert not V.counts_for(prop, c["amina"])
    assert commitment_accepted(V, acc) and not commitment_accepted(V, prop)
    done.append("co-signing keeps the content ID; delegated party proof")
    rush = c["commitment_agents"]
    assert V.counts_for(rush, c["lexis_ltd"]) and \
        V.counts_for(rush, c["amina"])
    assert content_id(sign(variant_of(rush), rush["proof"][0])) == \
        content_id(rush)
    done.append("two agents sign for their principals, in either order")
    agent_key = Key("lexis-agent-i1")
    price = prop["terms"]["price"]
    for amount, expected in (("120", True), ("500", True), ("500.01", False),
                             ("900", False)):
        doc = resign(prop, agent_key, terms__price={**price,
                                                    "amount": amount})
        assert V.counts_for(doc, c["lexis_agent"])
        assert V.counts_for(doc, c["lexis_ltd"]) is expected, amount
    done.append("delegation policy enforced (120, 500 ok; 500.01, 900 not)")
    chain = c["commitment_via_chain"]
    assert V.counts_for(chain, c["lexis_ltd"])
    assert commitment_accepted(V, chain)
    over = resign(chain, Key("lexis-fork-i1"),
                  terms__price={**chain["terms"]["price"], "amount": "300"})
    assert not V.counts_for(over, c["lexis_ltd"])
    done.append("two-step delegation chain (150 ok; 300 beyond the sub-limit)")
    assert V.counts_for(c["collective_charter"], c["collective"])
    assert V.counts_for(c["commitment_by_steward"], c["collective"])
    done.append("collective signs by 2-of-3 threshold and by a charter role")
    assert bridge_assurance(V, c["bridged_participant"]) == "bridged"
    assert bridge_assurance(V, c["participant"]) == "native"
    done.append("a bridged mind, attested in its gateway's feed")
    states = set()
    for s in c["status"]:
        rec = c[s["of"]]
        got = STATUS_FN[rec["type"]](V, rec, [c[n] for n in s["records"]],
                                     ts(s["at"]))
        assert got == s["expect"], (s, got)
        states.add(f"{rec['type']} {got}")
    done.append(f"Layer 2 status ({len(states)} states of Intent, Offer and "
                "Commitment)")
    assert jcs(c["jcs_example"]["input"]).decode() == \
        c["jcs_example"]["output"]
    done.append("JCS example")
    return done


def _case_verifier(c, case):
    return verifier_for(c, case.get("extraLogs", ()),
                        case.get("extraRecords", ()), case.get("seen"),
                        case.get("branches", ()))


def _holds(c, case) -> bool:
    """Whether a case's claim holds: the log verifies, the record counts
    for (or was sent for) the mind, the status or assurance is `expect`,
    the record is well formed, or the text is JSON within the profile of
    core Section 1."""
    kind = case["kind"]
    if kind == "json":
        return json_ok(case["text"])
    V = _case_verifier(c, case)
    if kind == "log":
        try:
            verify_log(case["log"], V)
            return True
        except ValueError:
            return False
    if kind == "countsFor":
        return V.counts_for(case["record"], case["mind"])
    if kind == "sentFor":
        return V.sent_for(case["record"], case["mind"])
    if kind == "status":
        rec = case["of"]
        return STATUS_FN[rec["type"]](V, rec, case["records"],
                                      ts(case["at"])) == case["expect"]
    if kind == "assurance":
        return bridge_assurance(V, case["record"]) == case["expect"]
    if kind == "record":
        return record_ok(case["record"])
    raise ValueError(f"unknown case kind {kind}")


def judge(c, case) -> dict:
    """The verdict on one case in the vectors' format, for differential
    testing against another implementation. `holds` says whether the case's
    claim holds, as _holds() does. For `status` and `assurance` cases,
    `value` is the result computed, whatever `expect` says (and `expect`
    may be absent). Three further kinds are questions, not cases:
    `didDocument` gives the resolution of `mind` (at `versionId`, if
    given), `lineage` the lineage of `mind`, and `intake` how far the copy
    in `log` verifies and whether the event after that is invalid or
    undecided (Layer 1, 4.9), for the verifier the case describes. An input this checker cannot process at all is
    reported as `error`, with `holds` false: an error is never an
    acceptance."""
    out = {"name": case.get("name"), "kind": case.get("kind")} \
        if isinstance(case, dict) else {"name": None, "kind": None}
    try:
        kind = case["kind"]
        if kind == "status":
            rec = case["of"]
            out["value"] = STATUS_FN[rec["type"]](
                _case_verifier(c, case), rec, case["records"], ts(case["at"]))
            out["holds"] = "expect" not in case or \
                out["value"] == case["expect"]
        elif kind == "assurance":
            out["value"] = bridge_assurance(_case_verifier(c, case),
                                            case["record"])
            out["holds"] = "expect" not in case or \
                out["value"] == case["expect"]
        elif kind == "didDocument":
            # Not a kind of case in the vectors: a question a differential
            # test asks, so that states are compared and not only verdicts.
            out["value"] = did_document(_case_verifier(c, case), case["mind"],
                                        case.get("versionId"))
            out["holds"] = True
        elif kind == "lineage":
            out["value"] = _case_verifier(c, case).lineage(case["mind"])
            out["holds"] = True
        elif kind == "intake":
            out["value"] = log_intake(case["log"], _case_verifier(c, case))
            out["holds"] = True
        else:
            out["holds"] = bool(_holds(c, case))
    except RecursionError:
        out.pop("value", None)
        out["holds"], out["error"] = False, "RecursionError"
    except Exception as e:               # malformed input is a rejection
        out.pop("value", None)
        out["holds"], out["error"] = False, f"{type(e).__name__}: {e}"
    return out


def judge_stream(c, lines, write):
    """Judge one JSON case per input line, writing one verdict per line and
    flushing, so that a caller can keep this process open and judge
    millions of cases."""
    for line in lines:
        if not line.strip():
            continue
        try:
            verdict = judge(c, json.loads(line))
        except (ValueError, RecursionError) as e:
            verdict = {"name": None, "kind": None, "holds": False,
                       "error": f"not JSON: {type(e).__name__}: {e}"}
        # ASCII only, so that no character a line reader treats as a line
        # break (U+2028, U+2029) can appear inside a verdict.
        write(json.dumps(verdict, ensure_ascii=True) + "\n")


def check_valid(VEC) -> list:
    """Cases that look suspicious but must be accepted."""
    c, done = VEC["cases"], []
    for case in VEC["valid"]:
        assert _holds(c, case), f"rejected: {case['name']}"
        done.append(case["name"])
    return done


def check_negative(VEC) -> list:
    """Every negative case must be rejected: its log fails, its record does
    not count, or its status or assurance is `expect` (not what an attacker
    wanted)."""
    c, done = VEC["cases"], []
    for case in VEC["negative"]:
        if case["kind"] in ("status", "assurance"):
            assert _holds(c, case), f"wrong result: {case['name']}"
        else:
            assert not _holds(c, case), f"accepted: {case['name']}"
        done.append(case["name"])
    return done


def check_controls(VEC) -> list:
    """Each control is a negative case changed only in the respect its
    reason names, and must be accepted: the negative fails for that reason
    alone."""
    c, done = VEC["cases"], []
    for case in VEC["controls"]:
        assert _holds(c, case), f"control rejected: {case['name']}"
        done.append(case["name"])
    return done


if __name__ == "__main__":
    out = Path(__file__).with_name("vectors.json")
    if "--judge" in sys.argv:
        # Cases are judged against the existing vectors.json. With --lines,
        # standard input holds one case per line and verdicts are written
        # as they are reached. Otherwise it holds one case, or an array of
        # cases, as a single JSON value.
        cases = json.loads(out.read_text(encoding="utf-8"))["cases"]

        def emit(text):
            sys.stdout.write(text)
            sys.stdout.flush()

        if "--lines" in sys.argv:
            judge_stream(cases, sys.stdin, emit)
        else:
            given = json.loads(sys.stdin.read())
            for one in given if isinstance(given, list) else [given]:
                emit(json.dumps(judge(cases, one), ensure_ascii=True) + "\n")
        sys.exit(0)
    if "--check" not in sys.argv:
        out.write_text(json.dumps(build(), indent=2, ensure_ascii=False) +
                       "\n", encoding="utf-8")
    vectors = json.loads(out.read_text(encoding="utf-8"))
    for line in check(vectors):
        print("ok -", line)
    print(f"ok - {len(check_valid(vectors))} must-accept cases accepted")
    print(f"ok - {len(check_negative(vectors))} negative cases rejected")
    print(f"ok - {len(check_controls(vectors))} controls accepted (each "
          "negative fails only for its stated reason)")
