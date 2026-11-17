#!/usr/bin/env python3
"""
Open Intelligence Protocol (OIP): test-vector generator and checker.

A dependency-light Python implementation of the core OIP algorithms in
spec/ (core, Layer 1, Layer 2) and Appendix A of
papers/02-technical-architecture.md:

  * JCS canonicalisation (RFC 8785) for OIP's restricted JSON profile
  * content IDs, key hashes and Multikeys
  * W3C Data Integrity proofs (eddsa-jcs-2022) with proof purposes
  * did:oip identity logs: pre-rotation, majority thresholds, forks,
    lineage, collectives, key removal, compromise and retirement
  * evaluation times: time rules use evidence, never a signer's own claim
  * delegation chains, policies and revocation
  * collective threshold signing and charter roles
  * Layer 2 status (Intent, Offer, Commitment)

It writes vectors.json, with positive cases and negative cases that every
implementation must reject, and checks it.

Run:  python3 oip_vectors.py            -> writes vectors.json and checks it
      python3 oip_vectors.py --check    -> checks an existing vectors.json

Requires only the `cryptography` package. Licensed Apache-2.0.
STATUS: DRAFT. Tracks the spec revision in REVISION and may change.
"""
import base64
import calendar
import copy
import hashlib
import json
import re
import sys
from datetime import datetime
from decimal import Decimal
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

REVISION = "2026-10-31"
OIP_VERSION = "1"
MAX_SAFE_INT = 2**53 - 1
RAW = serialization.Encoding.Raw, serialization.PublicFormat.Raw
SKEW_NS = 300 * 10**9           # clock-skew tolerance (core 9.1)

MAX_PROOFS = 256                # proofs per record
MAX_CHAIN = 8                   # delegations per chain
MAX_AUTHORITY = 16              # delegations listed in `authority`
MAX_NESTING = 4                 # collectives within collectives

IDENTITY_TYPES = ("Genesis", "Update", "Fork", "Merge", "Retire")
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
    return Ed25519PublicKey.from_public_bytes(raw[2:])


def check_x25519_multikey(mk: str):
    if not isinstance(mk, str) or not mk.startswith("z"):
        raise ValueError("not a Multikey")
    raw = b58decode(mk[1:])
    if raw[:2] != b"\xec\x01" or len(raw) != 34:
        raise ValueError("not an X25519 Multikey")

# ---------------------------------------------------------------- values


def ts(s) -> int:
    """RFC 3339 UTC timestamp -> integer nanoseconds since the epoch.
    Timestamps are compared as instants, never as strings."""
    m = TS_RE.fullmatch(s) if isinstance(s, str) else None
    if not m:
        raise ValueError(f"bad timestamp {s!r}")
    y, mo, d, h, mi, se = (int(g) for g in m.groups()[:6])
    datetime(y, mo, d, h, mi, se)           # range check
    frac = (m.group(7) or "").ljust(9, "0")
    return calendar.timegm((y, mo, d, h, mi, se, 0, 0, 0)) * 10**9 + \
        int(frac)


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
        allowed.add("@context")
        if proof.get("@context") != doc["@context"]:
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
    """A verified identity log: its events and the state after each."""

    def __init__(self, mind, events, states, times, height=0):
        self.mind, self.events, self.states = mind, events, states
        self.times = times          # evaluation time of each event (ns)
        self.height = height        # 0 for key-controlled minds

    @property
    def latest(self) -> State:
        return self.states[-1]

    def index(self, version):
        for i, st in enumerate(self.states):
            if st.version == version:
                return i
        return None

    def removal_time(self, i, key):
        """Evaluation time of the first event after position i that removes
        the key or retires the mind (Layer 1, 6.1), or None."""
        for j in range(i + 1, len(self.events)):
            if self.events[j]["type"] == "Retire" or \
               key not in self.states[j].keys:
                return self.times[j]
        return None

    def compromised_since(self, key):
        return self.latest.compromised.get(key)

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


def _control_signed(event, mk) -> bool:
    """True if control key mk has a valid capabilityInvocation proof."""
    for p in event.get("proof", []):
        if isinstance(p, dict) and \
           parse_control_ref(p.get("verificationMethod")) == mk and \
           p.get("verificationMethod") == did_key_vm(mk) and \
           p.get("proofPurpose") == "capabilityInvocation" and \
           verify_proof(event, p, mk):
            return True
    return False


def verify_log(events, verifier, depth=0) -> Log:
    """Verify an identity log (Layer 1, Section 4). Raises ValueError."""
    if not isinstance(events, list) or not events:
        raise ValueError("empty log")
    st, states, times, heights = State(), [], [], set()
    for i, ev in enumerate(events):
        if not isinstance(ev, dict) or ev.get("oip") != OIP_VERSION:
            raise ValueError("unknown oip version")
        etype = ev.get("type")
        if etype == "Merge":
            raise ValueError("Merge is reserved in this revision")
        if etype not in ("Genesis", "Update", "Fork", "Retire"):
            raise ValueError("unknown event type")
        if "recovery" in ev:
            raise ValueError("recovery is reserved in this revision")
        created = ts(ev.get("created"))
        proofs = ev.get("proof")
        if not isinstance(proofs, list) or not proofs or \
           len(proofs) > MAX_PROOFS:
            raise ValueError("bad proof set")
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
                                                  at_position=True)
                if len(signers) != len(ctl["members"]):
                    raise ValueError("every founding member must sign with "
                                     "an invocation key")
                heights.update(verifier.log(m, depth + 1).height
                               for m in signers)
                st.controller = "member"
                st.members, st.threshold = list(ctl["members"]), \
                    ctl["threshold"]
            else:
                st.next_threshold = _check_key_controller(ctl)
                for mk in ctl["keys"]:
                    if not _control_signed(ev, mk):
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
            if st.controller == "member":
                signers = verifier.member_signers(ev, st.members, depth,
                                                  at_position=True)
                if len(signers) < st.threshold:
                    raise ValueError("collective event lacks the threshold "
                                     "of current members")
                heights.update(verifier.log(m, depth + 1).height
                               for m in signers)
                if ctl is not None:
                    _check_member_controller(ctl, st.mind)
                    added = [m for m in ctl["members"] if m not in st.members]
                    if added:
                        new = verifier.member_signers(ev, added, depth,
                                                      at_position=True)
                        if len(new) != len(added):
                            raise ValueError("added members must sign")
                        heights.update(verifier.log(m, depth + 1).height
                                       for m in new)
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
                    if not _control_signed(ev, mk):
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
        when = verifier.event_time(ev)
        times.append(max(when, times[-1]) if times else when)
    height = 1 + max(heights, default=0) if st.controller == "member" else 0
    if height > MAX_NESTING:
        raise ValueError("collectives nest at most 4 deep")
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


def _compare(op, got, val) -> bool:
    a, b = as_decimal(got), as_decimal(val)
    if op in ORDERING_OPS:
        if a is None or b is None:
            return False
        return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
    if a is not None and b is not None:
        eq = a == b
    else:
        try:
            eq = jcs(got) == jcs(val)
        except (TypeError, ValueError):
            return False
    return eq if op == "==" else not eq


def statement_holds(s, obj) -> bool:
    op = s[0]
    if op == "not":
        return not statement_holds(s[1], obj)
    if op == "and":
        return all(statement_holds(x, obj) for x in s[1])
    if op == "or":
        return any(statement_holds(x, obj) for x in s[1])
    got = _select(obj, s[1])
    if op in ("all", "any"):
        if not isinstance(got, list):
            return False
        test = all if op == "all" else any
        return test(statement_holds(s[2], item) for item in got)
    return got is not _MISSING and _compare(op, got, s[2])


def policy_ok(policy, record) -> bool:
    """Every statement must hold for the record without its proofs
    (Layer 1, 11.3). Ordering compares decimals only; equality compares
    decimals numerically and other values by canonical form."""
    if not policy_valid(policy):
        return False
    obj = {k: v for k, v in record.items() if k != "proof"} \
        if isinstance(record, dict) else record
    return all(statement_holds(s, obj) for s in policy)


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


def record_ok(r) -> bool:
    """Structural checks this generator relies on (not a full schema)."""
    try:
        if not isinstance(r, dict) or r.get("oip") != OIP_VERSION:
            return False
        t = r.get("type")
        if not isinstance(t, str):
            return False
        if t not in ("Bundle", "Sealed"):
            ts(r["created"])
        if "expires" in r:
            ts(r["expires"])
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
        return True
    except (KeyError, TypeError, ValueError, AttributeError):
        return False

# ---------------------------------------------------------------- verifier


class Verifier:
    """A verifier's view: identity logs, records it holds (for record-refs,
    revocations and charters) and its evidence of when it first saw
    records. With no evidence for a record, this generator assumes the
    verifier obtained each proof at the proof's own `created` time (the
    test vectors' convention); a live verifier uses the time it received
    the proof."""

    def __init__(self, logs=(), records=(), seen=None):
        self.raw, self.cache, self.store = {}, {}, {}
        self.seen = dict(seen or {})
        self.apply_compromise = True
        self.visiting = set()
        for log in logs:
            self.add_log(log)
        for r in records:
            self.add(r)

    def add_log(self, events):
        self.raw[did(content_id(events[0]))] = events
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
            log = verify_log(self.raw[mind], self, depth)
        finally:
            self.visiting.discard(mind)
        self.cache[mind] = log
        return log

    def resolve(self, ref):
        if isinstance(ref, dict):
            return ref
        cid = ref_cid(ref)
        return self.store.get(cid) if cid else None

    # -- evaluation time (core, Section 9) --------------------------------
    def t_of(self, record, p):
        """t(p) = max(p.created, tau(p)); None if the proof claims to be
        from the future relative to the evidence."""
        try:
            created = ts(p.get("created"))
        except ValueError:
            return None
        seen = self.seen.get(content_id(record))
        tau = ts(seen) if seen else created
        if created > tau + SKEW_NS:
            return None
        return max(created, tau)

    def event_time(self, event):
        """Evaluation time of an identity event: max(created, evidence)."""
        created = ts(event["created"])
        seen = self.seen.get(content_id(event))
        return max(created, ts(seen)) if seen else created

    # -- key validity (Layer 1, Section 6) ---------------------------------
    def valid_key(self, record, p, mind, depth=0, at_position=False) -> bool:
        """Layer 1, 6.1. With at_position (member proofs on another mind's
        identity events, Layer 1, 6.4) the key is judged as of the version
        it pins: later removals and compromises do not apply."""
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
        if i is None:
            return False
        if at_position:
            return mk in log.states[i].invocation and \
                verify_proof(record, p, mk)
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
           (mk not in log.latest.keys or log.latest.retired):
            return False
        return verify_proof(record, p, mk)

    def member_signers(self, record, members, depth,
                       at_position=False) -> set:
        """Distinct members with a proof by one of their own valid keys."""
        out = set()
        for p in record.get("proof", []):
            ref = parse_key_ref(p.get("verificationMethod")) \
                if isinstance(p, dict) else None
            if ref and ref[0] in members and ref[0] not in out and \
               self.valid_key(record, p, ref[0], depth + 1, at_position):
                out.add(ref[0])
        return out

    # -- signing for a party (Layer 2, Section 7) ---------------------------
    def signed_time(self, record, mind, depth=0):
        """Earliest evaluation time at which `record` counts for `mind`,
        or None if it never does."""
        if not record_ok(record):
            return None
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
        holding proofs with t(p) <= T reach that state's threshold."""
        everyone = log.members_ever()
        cands = []
        for p in record.get("proof", []):
            ref = parse_key_ref(p.get("verificationMethod")) \
                if isinstance(p, dict) else None
            if ref and ref[0] in everyone and \
               self.valid_key(record, p, ref[0], depth + 1):
                cands.append((self.t_of(record, p), ref[0]))
        for t, _ in sorted(cands):
            st = log.state_at(t)
            if st is None or st.retired:
                continue
            signers = {m for (u, m) in cands if u <= t and m in st.members}
            if len(signers) >= st.threshold:
                return t
        return None

    def role_time(self, record, mind, log, depth):
        """A member holding a role in the charter in force at t(p), whose
        power covers the record, signs for the collective."""
        need = "/oip/sign/" + record["type"]
        charters = []
        for c in list(self.store.values()):
            if c.get("type") == "Collective" and c.get("author") == mind:
                tc = self.signed_time(c, mind, depth)
                if tc is not None:
                    charters.append((tc, c))
        best = None
        for p in record.get("proof", []):
            ref = parse_key_ref(p.get("verificationMethod")) \
                if isinstance(p, dict) else None
            if not ref or not self.valid_key(record, p, ref[0], depth + 1):
                continue
            member, t = ref[0], self.t_of(record, p)
            st = log.state_at(t)
            if st is None or st.retired or member not in st.members:
                continue
            in_force = [x for x in charters if x[0] <= t]
            if not in_force:
                continue
            charter = max(in_force, key=lambda x: x[0])[1]
            roles = {a.get("role") for a in charter.get("assignments", [])
                     if a.get("mind") == member}
            for role in roles:
                for power in charter.get("roles", {}).get(role, {}) \
                                    .get("powers", []):
                    if command_valid(power.get("command")) and \
                       command_covers(power["command"], need) and \
                       policy_ok(power.get("policy", []), record):
                        best = t if best is None else min(best, t)
        return best

    # -- delegation (Layer 1, Section 11) ----------------------------------
    def delegated_time(self, record, principal, depth):
        """A proof by D counts for P when the delegations listed in that
        proof's own `authority` form a valid chain from P to D. The chain
        sits in the proof, so a delegated co-signer can sign at any time
        without changing the record's content ID."""
        need = "/oip/sign/" + record["type"]
        best = None
        for p in record.get("proof", []):
            ref = parse_key_ref(p.get("verificationMethod")) \
                if isinstance(p, dict) else None
            auth = p.get("authority") if isinstance(p, dict) else None
            if not ref or ref[0] == principal or not auth or \
               not self.valid_key(record, p, ref[0], depth):
                continue
            ds = [d for d in (self.resolve(a) for a in auth)
                  if isinstance(d, dict) and d.get("type") == "Delegation"]
            t = self.t_of(record, p)
            for chain in self.chains(ds, principal, ref[0]):
                if self.chain_ok(chain, record, need, t, depth):
                    best = t if best is None else min(best, t)
                    break
        return best

    def chains(self, ds, principal, delegate, prefix=()):
        """Sequences d1..dn (root first) from principal to delegate."""
        if len(prefix) >= MAX_CHAIN:
            return
        head = prefix[-1]["delegate"] if prefix else principal
        for d in ds:
            if any(d is x for x in prefix) or d.get("author") != head or \
               d.get("subject") != principal:
                continue
            chain = prefix + (d,)
            if d.get("delegate") == delegate:
                yield chain
            yield from self.chains(ds, principal, delegate, chain)

    def chain_ok(self, chain, record, need, t, depth) -> bool:
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
    if V.signed_time(c, c.get("author")) is None:
        return False
    return all(V.signed_time(c, p["mind"]) is not None
               for p in c["parties"] if p.get("required"))


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
                       "taken to have obtained each proof at that proof's "
                       "`created` time.",
         "keys": {}, "cases": {}, "valid": [], "negative": []}

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
                     created="2026-10-30T09:20:00Z"):
        g = {"oip": OIP_VERSION, "type": "Genesis", "kind": "collective",
             "created": created,
             "controller": {"members": list(members),
                            "threshold": threshold}}
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

    logs = {"amina_log": [a_gen, a_upd], "lexis_ltd_log": [ltd_gen],
            "lexis_agent_log": [agent_gen, fork_ev],
            "lexis_fork_log": [child_gen], "lexis_fork2_log": [child2_gen],
            "researcher_log": [res_gen, res_upd], "collective_log": [coll],
            "multi_log": [m_gen, m_upd], "assistant_log": [asst_gen]}

    # --- Delegations ---------------------------------------------------
    usd_500 = [["==", ".terms.price.currency", "USD"],
               ["<=", ".terms.price.amount", "500"]]
    deleg = signed({"oip": OIP_VERSION, "type": "Delegation",
                    "author": lexis_ltd, "created": "2026-10-30T09:30:00Z",
                    "delegate": lexis, "subject": lexis_ltd,
                    "command": "/oip/sign/Commitment", "policy": usd_500,
                    "expires": "2026-11-30T09:30:00Z",
                    "nonce": "6c1f0e9d2b8a4735"}, l_op, ltd_vm)
    deleg_ref = record_ref(lexis_ltd, deleg)
    sub_deleg = signed({"oip": OIP_VERSION, "type": "Delegation",
                        "author": lexis, "created": "2026-10-30T09:45:00Z",
                        "delegate": child, "subject": lexis_ltd,
                        "command": "/oip/sign/Commitment",
                        "policy": usd_500 + [["<=", ".terms.price.amount",
                                              "200"]],
                        "expires": "2026-11-15T00:00:00Z",
                        "nonce": "9e4b2a7c1d3f5086"}, t_op, agent_vm)
    sub_ref = record_ref(lexis, sub_deleg)
    amina_deleg = signed({
        "oip": OIP_VERSION, "type": "Delegation", "author": amina,
        "created": "2026-10-30T09:35:00Z", "delegate": assistant,
        "subject": amina, "command": "/oip/sign/Commitment",
        "policy": [["==", ".terms.price.currency", "USD"],
                   ["<=", ".terms.price.amount", "150"],
                   ["all", ".parties",
                    ["or", [["==", ".mind", amina],
                            ["==", ".mind", lexis_ltd]]]]],
        "expires": "2026-11-30T09:00:00Z", "nonce": "3b7e1f9a0c5d2e84"},
        a_op2, amina_vm2)
    amina_deleg_ref = record_ref(amina, amina_deleg)

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
                        "price": {"amount": "120", "currency": "USD"}},
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

    # --- Two agents strike a deal, each for its principal --------------
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
                      "price": {"amount": "30", "currency": "USD"}}}
    rush_agent = create_proof(rush, t_op, agent_vm, "assertionMethod",
                              rush["created"], authority=[deleg_ref])
    rush_asst = create_proof(rush, s_op, asst_vm, "assertionMethod",
                             "2026-10-30T10:41:00Z",
                             authority=[amina_deleg_ref])
    rush_accepted = sign(rush, rush_agent, rush_asst)
    assert content_id(sign(rush, rush_agent)) == content_id(rush_accepted)

    # --- The collective's charter, and a commitment by its steward -----
    charter = {"oip": OIP_VERSION, "type": "Collective", "author": collective,
               "created": "2026-10-30T09:25:00Z",
               "name": "Open Translation Cell",
               "purpose": "Translate and review legal documents.",
               "roles": {"steward": {"purpose": "Accept routine work",
                                     "powers": [{"command":
                                                 "/oip/sign/Commitment",
                                                 "policy": usd_500}]}},
               "assignments": [{"mind": lexis, "role": "steward"}]}
    charter = sign(charter,
                   create_proof(charter, a_op1, amina_vm1, "assertionMethod",
                                charter["created"]),
                   create_proof(charter, r_op, res_vm, "assertionMethod",
                                charter["created"]))
    steward_commit = signed(
        {"oip": OIP_VERSION, "type": "Commitment", "author": lexis,
         "created": "2026-10-30T10:30:00Z",
         "parties": [{"mind": collective, "role": "debtor", "required": True},
                     {"mind": amina, "role": "creditor", "required": True}],
         "promise": "The Open Translation Cell will review the English "
                    "translation of the lease by 2 Nov 2026 12:00 UTC for "
                    "300 USD.",
         "terms": {"deadline": "2026-11-02T12:00:00Z",
                   "price": {"amount": "300", "currency": "USD"}}},
        t_op, agent_vm)

    # --- A commitment signed through the two-step delegation chain -----
    chain_commit = signed(
        {"oip": OIP_VERSION, "type": "Commitment", "author": child,
         "created": "2026-10-30T11:00:00Z",
         "parties": [{"mind": lexis_ltd, "role": "debtor", "required": True},
                     {"mind": amina, "role": "creditor", "required": True}],
         "promise": "Lexis Ltd will produce a certified glossary for the "
                    "lease by 3 Nov 2026 for 150 USD.",
         "terms": {"deadline": "2026-11-03T12:00:00Z",
                   "price": {"amount": "150", "currency": "USD"}}},
        f_op, child_vm, authority=[deleg_ref, sub_ref])

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
               "intent": intent, "intent_withdrawal": withdrawal,
               "intent_edit": edit, "offer": offer,
               "commitment_proposed": commit_proposed,
               "commitment_accepted": commit_accepted, "receipt": receipt,
               "commitment_agents": rush_accepted,
               "collective_charter": charter,
               "commitment_by_steward": steward_commit,
               "commitment_via_chain": chain_commit, "lineage": lineage,
               "session": session, "packet": packet, "ack": ack,
               "hello": hello, "participant": participant,
               "location": location, "feed_entry": entry,
               "feed_entry_1": entry1, "checkpoint": checkpoint}
    dv = Verifier(logs=logs.values())
    V["cases"] = {
        **logs, **records,
        "amina": amina, "lexis_ltd": lexis_ltd, "lexis_agent": lexis,
        "lexis_fork": child, "lexis_fork2": child2,
        "researcher": researcher, "collective": collective, "multi": multi,
        "assistant": assistant,
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
             "records": ["commitment_agents"], "expect": "accepted"}],
        "content_ids": {n: content_id(o) for n, o in [
            ("amina_genesis", a_gen), ("amina_update", a_upd),
            ("delegation", deleg), ("delegation_sub", sub_deleg),
            ("delegation_amina", amina_deleg), ("intent", intent),
            ("offer", offer), ("commitment", commit),
            ("commitment_agents", rush), ("receipt", receipt),
            ("collective_charter", charter), ("session", session),
            ("packet", packet), ("checkpoint", checkpoint)]},
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
        "reason": "On 2 Nov Amina declares her invocation key compromised "
                  "since 30 Oct 09:00, before the collective's genesis. "
                  "Identity events are judged at their position, so the "
                  "collective's log still verifies.",
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
        "seen": {content_id(backdated_rev): "2026-11-10T00:00:00Z"}})

    # ------------------------------------------------------------ negatives
    neg = V["negative"]

    def bad_log(name, reason, log, extra_logs=()):
        case = {"name": name, "reason": reason, "kind": "log", "log": log}
        if extra_logs:
            case["extraLogs"] = list(extra_logs)
        neg.append(case)

    def bad_sig(name, reason, record, mind, extra_logs=(), records=(),
                seen=None):
        case = {"name": name, "reason": reason, "kind": "countsFor",
                "record": record, "mind": mind}
        if extra_logs:
            case["extraLogs"] = list(extra_logs)
        if records:
            case["extraRecords"] = list(records)
        if seen:
            case["seen"] = seen
        neg.append(case)

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
        doc = variant(commit, terms__price={"amount": amount,
                                            "currency": currency})
        bad_sig(name, why, signed(doc, t_op, agent_vm, authority=[deleg_ref]),
                lexis_ltd)
    third = variant(rush, parties=[
        {"mind": researcher, "role": "debtor", "required": True},
        {"mind": amina, "role": "creditor", "required": True}])
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
            seen={content_id(late_intent): "2026-11-03T08:00:00Z"})
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
            seen={content_id(early_intent): "2026-11-01T00:00:00Z"})
    exp_commit = signed(variant(commit, created="2026-11-29T00:00:00Z"),
                        t_op, agent_vm, authority=[deleg_ref])
    bad_sig("expired-delegation-backdated",
            "The delegation expires on 30 Nov. A commitment dated 29 Nov but "
            "first seen on 5 Dec is evaluated at 5 Dec.", exp_commit,
            lexis_ltd, seen={content_id(exp_commit): "2026-12-05T00:00:00Z"})
    rev_commit = signed(variant(commit, created="2026-11-05T00:00:00Z"),
                        t_op, agent_vm, authority=[deleg_ref])
    bad_sig("revoked-delegation",
            "The delegation was revoked on 10 Nov. A commitment dated 5 Nov "
            "but first seen on 12 Nov comes after the revocation.",
            rev_commit, lexis_ltd, records=[revocation],
            seen={content_id(rev_commit): "2026-11-12T00:00:00Z"})
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
            seen={content_id(coll_intent): "2026-11-01T00:00:00Z"})
    future = signed(variant(intent), a_op2, amina_vm2,
                    created="2026-10-30T10:30:00Z")
    bad_sig("proof-from-the-future",
            "The proof claims a time more than 300 seconds after the "
            "evidence that it existed.", future, amina,
            seen={content_id(future): "2026-10-30T10:00:00Z"})
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
            "terms": {"price": {"amount": "1", "currency": "USD"}},
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
    return V


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
             "collective_log", "multi_log", "assistant_log")
RECORD_NAMES = ("delegation", "delegation_sub", "delegation_amina", "intent",
                "offer", "commitment_accepted", "receipt",
                "commitment_agents", "collective_charter",
                "commitment_by_steward", "commitment_via_chain", "lineage",
                "participant", "location", "feed_entry", "feed_entry_1",
                "checkpoint", "packet", "ack", "hello")
MINDS = (("amina_log", "amina"), ("lexis_ltd_log", "lexis_ltd"),
         ("lexis_agent_log", "lexis_agent"), ("lexis_fork_log", "lexis_fork"),
         ("lexis_fork2_log", "lexis_fork2"), ("researcher_log", "researcher"),
         ("collective_log", "collective"), ("multi_log", "multi"),
         ("assistant_log", "assistant"))


def verifier_for(c, extra_logs=(), records=(), seen=None) -> Verifier:
    V = Verifier(logs=[c[n] for n in LOG_NAMES],
                 records=[c[n] for n in RECORD_NAMES], seen=seen)
    for log in extra_logs:
        V.add_log(log)
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
    V = verifier_for(c)
    done = []
    for log, mind in MINDS:
        assert did(content_id(c[log][0])) == c[mind]
        V.log(c[mind])
    assert V.log(c["collective"]).height == 1
    done.append("identity logs verify; addresses derive from genesis")
    ids = set()
    _all_ids([VEC["cases"], VEC["valid"]], ids)
    assert ids and all(CID_RE.fullmatch(i) for i in ids), \
        [i for i in ids if not CID_RE.fullmatch(i)]
    done.append(f"all {len(ids)} content IDs use the canonical spelling")
    assert V.log(c["multi"]).latest.next_threshold == 1
    done.append("2-of-3 pre-rotation with distinct keys")
    assert V.lineage(c["lexis_fork"]) == {c["lexis_agent"]: "acknowledged"}
    assert V.lineage(c["lexis_fork2"]) == {c["lexis_agent"]: "acknowledged"}
    done.append("lineage acknowledged by a Fork event and by a Lineage record")
    for name, mind in (("intent", "amina"), ("offer", "lexis_agent"),
                       ("receipt", "amina"), ("packet", "lexis_agent"),
                       ("ack", "amina"), ("hello", "lexis_agent"),
                       ("delegation", "lexis_ltd"),
                       ("delegation_sub", "lexis_agent"),
                       ("delegation_amina", "amina"),
                       ("participant", "lexis_agent"),
                       ("location", "lexis_agent"),
                       ("feed_entry", "lexis_agent"),
                       ("feed_entry_1", "lexis_agent"),
                       ("checkpoint", "lexis_agent"),
                       ("lineage", "lexis_agent")):
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
    assert content_id(acc) == content_id(prop)
    assert V.counts_for(acc, c["amina"]) and V.counts_for(acc, c["lexis_ltd"])
    assert not V.counts_for(prop, c["amina"])
    done.append("co-signing keeps the content ID; delegated party proof")
    rush = c["commitment_agents"]
    assert V.counts_for(rush, c["lexis_ltd"]) and \
        V.counts_for(rush, c["amina"])
    assert content_id(sign(variant_of(rush), rush["proof"][0])) == \
        content_id(rush)
    done.append("two agents sign for their principals, in either order")
    agent_key = Key("lexis-agent-i1")
    for amount, expected in (("120", True), ("500", True), ("500.01", False),
                             ("900", False)):
        doc = resign(prop, agent_key, terms__price={"amount": amount,
                                                    "currency": "USD"})
        assert V.counts_for(doc, c["lexis_agent"])
        assert V.counts_for(doc, c["lexis_ltd"]) is expected, amount
    done.append("delegation policy enforced (120, 500 ok; 500.01, 900 not)")
    chain = c["commitment_via_chain"]
    assert V.counts_for(chain, c["lexis_ltd"])
    over = resign(chain, Key("lexis-fork-i1"),
                  terms__price={"amount": "300", "currency": "USD"})
    assert not V.counts_for(over, c["lexis_ltd"])
    done.append("two-step delegation chain (150 ok; 300 beyond the sub-limit)")
    assert V.counts_for(c["collective_charter"], c["collective"])
    assert V.counts_for(c["commitment_by_steward"], c["collective"])
    done.append("collective signs by 2-of-3 threshold and by a charter role")
    names = {"intent": c["intent"], "offer": c["offer"],
             "intent_withdrawal": c["intent_withdrawal"],
             "intent_edit": c["intent_edit"],
             "commitment_proposed": prop, "commitment_accepted": acc,
             "commitment_agents": rush, "receipt": c["receipt"]}
    fn = {"intent": intent_status, "offer": offer_status,
          "intent_withdrawal": intent_status, "intent_edit": intent_status,
          "commitment_proposed": commitment_status,
          "commitment_accepted": commitment_status,
          "commitment_agents": commitment_status}
    for s in c["status"]:
        got = fn[s["of"]](V, names[s["of"]], [names[n] for n in s["records"]],
                          ts(s["at"]))
        assert got == s["expect"], (s, got)
    done.append("Layer 2 status (satisfied, withdrawn, superseded, open, "
                "expired, proposed, accepted, overdue, fulfilled)")
    assert jcs(c["jcs_example"]["input"]).decode() == \
        c["jcs_example"]["output"]
    done.append("JCS example")
    return done


def _case_verifier(c, case):
    return verifier_for(c, case.get("extraLogs", ()),
                        case.get("extraRecords", ()), case.get("seen"))


def check_valid(VEC) -> list:
    """Cases that look suspicious but must be accepted."""
    c, done = VEC["cases"], []
    for case in VEC["valid"]:
        V = _case_verifier(c, case)
        if case["kind"] == "log":
            verify_log(case["log"], V)
        else:
            assert V.counts_for(case["record"], case["mind"]), case["name"]
        done.append(case["name"])
    return done


def check_negative(VEC) -> list:
    """Every negative case must be rejected."""
    c, done = VEC["cases"], []
    for case in VEC["negative"]:
        V = _case_verifier(c, case)
        kind = case["kind"]
        if kind == "log":
            try:
                verify_log(case["log"], V)
                raise AssertionError(f"accepted: {case['name']}")
            except ValueError:
                pass
        elif kind == "countsFor":
            assert not V.counts_for(case["record"], case["mind"]), \
                f"accepted: {case['name']}"
        elif kind == "status":
            fn = {"Intent": intent_status, "Offer": offer_status,
                  "Commitment": commitment_status}[case["of"]["type"]]
            got = fn(V, case["of"], case["records"], ts(case["at"]))
            assert got == case["expect"], (case["name"], got)
        elif kind == "record":
            assert not record_ok(case["record"]), case["name"]
        done.append(case["name"])
    return done


def check_controls(VEC):
    """The time-based negative cases fail for the stated reason: the same
    records pass when first seen in time."""
    c = VEC["cases"]
    by = {n["name"]: n for n in VEC["negative"]}
    for name, ok_seen in (("removed-key-backdated", "2026-11-01T08:00:05Z"),
                          ("compromised-key-backdated",
                           "2026-10-30T23:00:10Z"),
                          ("expired-delegation-backdated",
                           "2026-11-29T00:00:05Z"),
                          ("revoked-delegation", "2026-11-05T00:00:05Z"),
                          ("removed-member-backdated",
                           "2026-10-30T23:00:05Z")):
        case = dict(by[name])
        case["seen"] = {content_id(case["record"]): ok_seen}
        assert _case_verifier(c, case).counts_for(case["record"],
                                                  case["mind"]), name
    return "time-based negatives pass when first seen in time (controls)"


if __name__ == "__main__":
    out = Path(__file__).with_name("vectors.json")
    if "--check" not in sys.argv:
        out.write_text(json.dumps(build(), indent=2, ensure_ascii=False) +
                       "\n", encoding="utf-8")
    vectors = json.loads(out.read_text(encoding="utf-8"))
    for line in check(vectors):
        print("ok -", line)
    print(f"ok - {len(check_valid(vectors))} must-accept cases accepted")
    print(f"ok - {len(check_negative(vectors))} negative cases rejected")
    print("ok -", check_controls(vectors))
