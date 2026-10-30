#!/usr/bin/env python3
"""
Open Intelligence Protocol (OIP) — draft test-vector generator and checker.

An independent, dependency-light Python implementation of the core OIP
algorithms described in papers/02-technical-architecture.md and spec/:

  * JCS canonicalisation (RFC 8785) for OIP's restricted JSON profile
  * content identifiers (multibase base32 of a SHA-256 multihash)
  * Multikey encoding for Ed25519 / X25519 public keys
  * W3C Data Integrity proofs with the eddsa-jcs-2022 cryptosuite
  * mind addresses (did:oip) derived from a Genesis event
  * identity-log verification with pre-rotation, forks and collectives
  * Layer 2 objects, multi-party commitments and delegation

All keys are derived from fixed seeds, so output is deterministic.
Run:  python3 oip_vectors.py            -> writes vectors.json and verifies it
      python3 oip_vectors.py --check    -> re-verifies an existing vectors.json

Requires only the `cryptography` package. Licensed Apache-2.0.
STATUS: DRAFT. These vectors track spec revision 2026-10-30 and may change.
"""
import base64
import copy
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

OIP_VERSION = "1"
MAX_SAFE_INT = 2**53 - 1
RAW = serialization.Encoding.Raw, serialization.PublicFormat.Raw

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
    in OIP signed objects (decimals travel as strings)."""
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
            raise ValueError("floats are not allowed in OIP objects")
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
    """OIP content ID: 'b' + base32lower(multihash(SHA-256(JCS(obj - proof)))).
    The digest equals eddsa-jcs-2022's transformedDocumentHash."""
    unsecured = {k: v for k, v in obj.items() if k != "proof"}
    return "b" + b32lower(multihash_sha256(jcs(unsecured)))


def key_hash(multikey: str) -> str:
    """Pre-rotation commitment: content-ID encoding of SHA-256(UTF-8 Multikey)."""
    return "b" + b32lower(multihash_sha256(multikey.encode("utf-8")))


def multikey_ed25519(pub: bytes) -> str:
    return "z" + b58encode(b"\xed\x01" + pub)


def multikey_x25519(pub: bytes) -> str:
    return "z" + b58encode(b"\xec\x01" + pub)


def ed25519_pub_from_multikey(mk: str) -> Ed25519PublicKey:
    raw = b58decode(mk[1:])
    if not mk.startswith("z") or raw[:2] != b"\xed\x01" or len(raw) != 34:
        raise ValueError("not an Ed25519 Multikey")
    return Ed25519PublicKey.from_public_bytes(raw[2:])

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
        seed = hashlib.sha256(("oip-test-vector-x25519:" + label).encode()).digest()
        self.sk = X25519PrivateKey.from_private_bytes(seed)
        self.mk = multikey_x25519(self.sk.public_key().public_bytes(*RAW))

# ---------------------------------------------------------------- proofs


def create_proof(doc: dict, key: Key, verification_method: str,
                 purpose: str, created: str, **extra) -> dict:
    """W3C Data Integrity, cryptosuite eddsa-jcs-2022. Each proof in a proof
    set is computed over the document with the whole `proof` member removed,
    so adding a co-signature never changes the content ID or other proofs."""
    unsecured = {k: v for k, v in doc.items() if k != "proof"}
    config = {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022",
              "verificationMethod": verification_method,
              "proofPurpose": purpose, "created": created, **extra}
    if "@context" in unsecured:
        config["@context"] = unsecured["@context"]
    hash_data = hashlib.sha256(jcs(config)).digest() + \
        hashlib.sha256(jcs(unsecured)).digest()
    sig = key.sk.sign(hash_data)
    return {**config, "proofValue": "z" + b58encode(sig)}


def verify_proof(doc: dict, proof: dict, pub_multikey: str) -> bool:
    if proof.get("type") != "DataIntegrityProof" or \
       proof.get("cryptosuite") != "eddsa-jcs-2022":
        return False
    unsecured = {k: v for k, v in doc.items() if k != "proof"}
    config = {k: v for k, v in proof.items() if k != "proofValue"}
    hash_data = hashlib.sha256(jcs(config)).digest() + \
        hashlib.sha256(jcs(unsecured)).digest()
    try:
        ed25519_pub_from_multikey(pub_multikey).verify(
            b58decode(proof["proofValue"][1:]), hash_data)
        return True
    except Exception:
        return False


def sign(doc: dict, *proofs) -> dict:
    out = copy.deepcopy(doc)
    out["proof"] = list(out.get("proof", [])) + list(proofs)
    return out

# ---------------------------------------------------------------- identity


def did(mind_id: str) -> str:
    return "did:oip:" + mind_id


def did_key_vm(mk: str) -> str:
    return f"did:key:{mk}#{mk}"


def version_id(event: dict) -> str:
    return f"{event.get('seq', 0)}-{content_id(event)}"


def op_vm(mind: str, at_event: dict, mk: str) -> str:
    """Verification method for an operational key, pinned to a log version."""
    return f"{mind}?versionId={version_id(at_event)}#{mk}"


def parse_vm(vm: str):
    """-> (did_or_didkey, version_id or None, key fragment)"""
    base, frag = vm.split("#", 1)
    ver = None
    if "?versionId=" in base:
        base, ver = base.split("?versionId=", 1)
    return base, ver, frag


class LogState:
    def __init__(self):
        self.mind = None
        self.kind = None
        self.version = None
        self.seq = -1
        self.head = None
        self.next = []          # key-controlled: committed next-key hashes
        self.next_threshold = 1
        self.members = []       # member-controlled (collectives)
        self.threshold = None
        self.keys = []          # operational signing keys (Multikeys)
        self.agreement = []
        self.homes = []
        self.also_known_as = []
        self.parents = []
        self.children = []
        self.retired = False


class Registry:
    """In-memory store of identity logs, standing in for resolution."""

    def __init__(self):
        self.logs = {}

    def add(self, log):
        self.logs[did(content_id(log[0]))] = log

    def state(self, mind: str, version: str = None) -> LogState:
        return verify_log(self.logs[mind], self, upto_version=version)


def _member_proofs_ok(doc, proofs, members, threshold, registry):
    signers = set()
    for p in proofs:
        base, ver, frag = parse_vm(p["verificationMethod"])
        if base not in members or base in signers:
            continue
        st = registry.state(base, ver)
        if frag in st.keys and verify_proof(doc, p, frag):
            signers.add(base)
    return len(signers) >= threshold, signers


def _control_proofs_ok(event, revealed, prev_state):
    """Every revealed control key must hash into prev.next and sign."""
    if len(revealed) < prev_state.next_threshold:
        return False
    for mk in revealed:
        if key_hash(mk) not in prev_state.next:
            return False
        if not any(p["verificationMethod"] == did_key_vm(mk) and
                   verify_proof(event, p, mk) for p in event.get("proof", [])):
            return False
    return True


def verify_log(log, registry, upto_version=None) -> LogState:
    st = LogState()
    for i, ev in enumerate(log):
        if ev.get("oip") != OIP_VERSION:
            raise ValueError("unknown oip version")
        if i == 0:
            if ev["type"] != "Genesis" or "seq" in ev or "prev" in ev:
                raise ValueError("first event must be a Genesis")
            st.mind = did(content_id(ev))
            st.kind = ev["kind"]
            ctl = ev["controller"]
            if "keys" in ctl:   # key-controlled: all initial keys sign
                for mk in ctl["keys"]:
                    if not any(p["verificationMethod"] == did_key_vm(mk) and
                               verify_proof(ev, p, mk) for p in ev["proof"]):
                        raise ValueError("genesis not signed by its keys")
                st.next = ctl["next"]
                st.next_threshold = ctl.get("nextThreshold", 1)
            else:               # member-controlled: every founder consents
                ok, signers = _member_proofs_ok(
                    ev, ev["proof"], ctl["members"], len(ctl["members"]),
                    registry)
                if not ok:
                    raise ValueError("collective genesis needs all founders")
                st.members = ctl["members"]
                st.threshold = ctl["threshold"]
            st.parents = ev.get("parents", [])
        else:
            if ev["mind"] != st.mind or ev["seq"] != st.seq + 1 or \
               ev["prev"] != st.head:
                raise ValueError(f"broken chain at event {i}")
            ctl = ev.get("controller", {})
            if st.members:      # collective: threshold of current members
                new_members = [m for m in ctl.get("members", [])
                               if m not in st.members]
                ok, _ = _member_proofs_ok(ev, ev["proof"], st.members,
                                          st.threshold, registry)
                ok_new, _ = _member_proofs_ok(ev, ev["proof"], new_members,
                                              len(new_members), registry)
                if not (ok and ok_new):
                    raise ValueError("collective event lacks consent")
                if "members" in ctl:
                    st.members = ctl["members"]
                    st.threshold = ctl["threshold"]
            else:
                if st.retired or not _control_proofs_ok(
                        ev, ctl.get("keys", []), st):
                    raise ValueError(f"bad control proofs at event {i}")
                st.next = ctl["next"]
                st.next_threshold = ctl.get("nextThreshold", 1)
            if ev["type"] == "Fork":
                st.children.append(ev["child"])
            if ev["type"] == "Retire":
                st.retired = True
        for field, attr in (("keys", "keys"), ("agreement", "agreement"),
                            ("homes", "homes"),
                            ("alsoKnownAs", "also_known_as")):
            if field in ev:
                val = ev[field]
                setattr(st, attr, [k["key"] for k in val]
                        if field in ("keys", "agreement") else val)
        st.seq = ev.get("seq", 0)
        st.head = content_id(ev)
        st.version = f"{st.seq}-{st.head}"
        if upto_version and st.version == upto_version:
            return st
    if upto_version and st.version != upto_version:
        raise ValueError("version not found in log")
    return st


def _select(obj, selector):
    """Minimal jq-style selector: '.a.b' -> obj['a']['b'] (None if absent)."""
    cur = obj
    for part in [p for p in selector.split(".") if p]:
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _cmp(a, b):
    """Compare two values; decimal strings compare numerically (OIP rule)."""
    from decimal import Decimal, InvalidOperation
    try:
        return (Decimal(str(a)) > Decimal(str(b))) - \
               (Decimal(str(a)) < Decimal(str(b)))
    except (InvalidOperation, TypeError):
        return (str(a) > str(b)) - (str(a) < str(b))


def policy_ok(policy, obj) -> bool:
    """Evaluate the v1 policy subset: implicit AND of [op, selector, value]."""
    for op, sel, val in policy:
        got = _select(obj, sel)
        if got is None:
            return False
        c = _cmp(got, val)
        if not {"==": c == 0, "!=": c != 0, "<": c < 0, "<=": c <= 0,
                ">": c > 0, ">=": c >= 0}[op]:
            return False
    return True


def command_covers(granted: str, needed: str) -> bool:
    """Path-segment prefix match: '/oip/sign' covers '/oip/sign/Offer'."""
    return needed == granted or needed.startswith(granted.rstrip("/") + "/")


def verify_signed_by(obj, mind, registry, delegations=(), at=None):
    """True if some proof on obj is by an operational key of `mind`
    (at the pinned version), or by a delegate holding a valid root
    delegation from `mind` whose command and policy cover obj."""
    at = at or obj.get("created")
    for p in obj.get("proof", []):
        base, ver, frag = parse_vm(p["verificationMethod"])
        if base == mind:
            st = registry.state(mind, ver)
            if frag in st.keys and verify_proof(obj, p, frag):
                return True
        for d in delegations:
            if d["subject"] != mind or d["author"] != mind or \
               d["delegate"] != base or d.get("chain"):
                continue        # v1 vectors cover root delegations only
            if not verify_signed_by(d, d["author"], registry):
                continue
            if at and d.get("expires") and at > d["expires"]:
                continue
            if not command_covers(d["command"], "/oip/sign/" + obj["type"]):
                continue
            if not policy_ok(d.get("policy", []), obj):
                continue
            st = registry.state(base, ver)
            if frag in st.keys and verify_proof(obj, p, frag):
                return True
    return False

# ---------------------------------------------------------------- scenario

T0 = "2026-10-30T09:00:00Z"


def key_controlled_genesis(kind, control, nxt, op_keys, created=T0,
                           agreement=None, homes=None, parents=None):
    g = {"oip": OIP_VERSION, "type": "Genesis", "kind": kind,
         "created": created,
         "controller": {"keys": [control.mk], "next": [key_hash(nxt.mk)],
                        "nextThreshold": 1},
         "keys": [{"key": k.mk, "label": k.label} for k in op_keys]}
    if agreement:
        g["agreement"] = [{"key": a.mk, "label": "main"} for a in agreement]
    if homes:
        g["homes"] = homes
    if parents:
        g["parents"] = parents
    return sign(g, create_proof(g, control, did_key_vm(control.mk),
                                "capabilityInvocation", created))


def build():
    reg = Registry()
    V = {"spec_revision": "2026-10-30", "status": "draft",
         "note": "Keys derive from SHA-256('oip-test-vector:'+label). "
                 "Never use these keys for anything real.",
         "keys": {}, "cases": {}}

    def k(label):
        key = Key(label)
        V["keys"][label] = {"seed_hex": key.seed_hex, "multikey": key.mk}
        return key

    # --- Amina: a human, key-controlled -------------------------------
    a_c0, a_c1, a_c2 = k("amina-control-0"), k("amina-control-1"), \
        k("amina-control-2")
    a_op1, a_op2 = k("amina-phone"), k("amina-laptop")
    a_x = AgreementKey("amina")
    a_gen = key_controlled_genesis("human", a_c0, a_c1, [a_op1],
                                   agreement=[a_x],
                                   homes=["https://amina.example"])
    amina = did(content_id(a_gen))
    # Update: reveal control-1, add laptop key, commit control-2
    a_upd = {"oip": OIP_VERSION, "type": "Update", "mind": amina, "seq": 1,
             "prev": content_id(a_gen), "created": "2026-10-30T09:05:00Z",
             "controller": {"keys": [a_c1.mk], "next": [key_hash(a_c2.mk)],
                            "nextThreshold": 1},
             "keys": [{"key": a_op1.mk, "label": a_op1.label},
                      {"key": a_op2.mk, "label": a_op2.label}]}
    a_upd = sign(a_upd, create_proof(a_upd, a_c1, did_key_vm(a_c1.mk),
                                     "capabilityInvocation",
                                     a_upd["created"]))
    reg.add([a_gen, a_upd])

    # --- Lexis Ltd (institution) and its translation agent -------------
    l_c0, l_c1 = k("lexisltd-control-0"), k("lexisltd-control-1")
    l_op = k("lexisltd-ops")
    ltd_gen = key_controlled_genesis("institution", l_c0, l_c1, [l_op])
    lexis_ltd = did(content_id(ltd_gen))
    reg.add([ltd_gen])

    t_c0, t_c1, t_c2 = k("lexis-agent-control-0"), \
        k("lexis-agent-control-1"), k("lexis-agent-control-2")
    t_op = k("lexis-agent-i1")
    agent_gen = key_controlled_genesis("agent", t_c0, t_c1, [t_op],
                                       homes=["https://lexis.example"])
    lexis = did(content_id(agent_gen))

    # --- Fork: the agent spawns a specialist child ---------------------
    f_c0, f_c1 = k("lexis-fork-control-0"), k("lexis-fork-control-1")
    f_op = k("lexis-fork-i1")
    child_gen = key_controlled_genesis(
        "agent", f_c0, f_c1, [f_op], created="2026-10-30T09:10:00Z",
        parents=[{"mind": lexis, "at": version_id(agent_gen)}])
    child = did(content_id(child_gen))
    fork_ev = {"oip": OIP_VERSION, "type": "Fork", "mind": lexis, "seq": 1,
               "prev": content_id(agent_gen),
               "created": "2026-10-30T09:11:00Z", "child": child,
               "controller": {"keys": [t_c1.mk],
                              "next": [key_hash(t_c2.mk)],
                              "nextThreshold": 1}}
    fork_ev = sign(fork_ev, create_proof(fork_ev, t_c1, did_key_vm(t_c1.mk),
                                         "capabilityInvocation",
                                         fork_ev["created"]))
    reg.add([agent_gen, fork_ev])
    reg.add([child_gen])

    # --- A collective of three members (2-of-3) -----------------------
    r_c0, r_c1 = k("researcher-control-0"), k("researcher-control-1")
    r_op = k("researcher-ops")
    res_gen = key_controlled_genesis("agent", r_c0, r_c1, [r_op])
    researcher = did(content_id(res_gen))
    reg.add([res_gen])

    coll = {"oip": OIP_VERSION, "type": "Genesis", "kind": "collective",
            "created": "2026-10-30T09:20:00Z",
            "controller": {"members": [amina, lexis, researcher],
                           "threshold": 2}}
    coll = sign(coll,
                create_proof(coll, a_op1, op_vm(amina, a_upd, a_op1.mk),
                             "capabilityInvocation", coll["created"]),
                create_proof(coll, t_op, op_vm(lexis, fork_ev, t_op.mk),
                             "capabilityInvocation", coll["created"]),
                create_proof(coll, r_op, op_vm(researcher, res_gen, r_op.mk),
                             "capabilityInvocation", coll["created"]))
    collective = did(content_id(coll))
    reg.add([coll])

    # --- Delegation: Lexis Ltd authorises its agent to sign commitments
    deleg = {"oip": OIP_VERSION, "type": "Delegation", "author": lexis_ltd,
             "created": "2026-10-30T09:30:00Z", "delegate": lexis,
             "subject": lexis_ltd, "command": "/oip/sign/Commitment",
             "policy": [["<=", ".terms.price.amount", "500"]],
             "expires": "2026-11-30T09:30:00Z", "nonce": "d1"}
    deleg = sign(deleg, create_proof(deleg, l_op,
                                     op_vm(lexis_ltd, ltd_gen, l_op.mk),
                                     "capabilityDelegation",
                                     deleg["created"]))
    deleg_ref = f"{lexis_ltd}/{content_id(deleg)}"

    # --- Layer 2: intent -> offer -> commitment -> receipt -------------
    intent = {"oip": OIP_VERSION, "type": "Intent", "author": amina,
              "created": "2026-10-30T10:00:00Z",
              "expires": "2026-10-31T10:00:00Z",
              "want": "Translate a 12-page Swahili commercial lease into "
                      "English, legally accurate.",
              "constraints": {"deadline": "2026-11-02T17:00:00Z",
                              "budget": {"max": "150", "currency": "USD"}},
              "audience": {"query": {"tags": ["lang:sw", "lang:en",
                                              "domain:legal/*"]}}}
    intent = sign(intent, create_proof(intent, a_op2,
                                       op_vm(amina, a_upd, a_op2.mk),
                                       "assertionMethod", intent["created"]))
    intent_ref = f"{amina}/{content_id(intent)}"

    offer = {"oip": OIP_VERSION, "type": "Offer", "author": lexis,
             "created": "2026-10-30T10:04:00Z",
             "expires": "2026-10-30T22:00:00Z", "answers": intent_ref,
             "provides": "English translation of the lease, reviewed by a "
                         "qualified lawyer.",
             "terms": {"summary": "120 USD, delivered by 1 Nov 18:00 UTC.",
                       "price": {"amount": "120", "currency": "USD"},
                       "deliveryBy": "2026-11-01T18:00:00Z"}}
    offer = sign(offer, create_proof(offer, t_op,
                                     op_vm(lexis, fork_ev, t_op.mk),
                                     "assertionMethod", offer["created"]))
    offer_ref = f"{lexis}/{content_id(offer)}"

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
              "resolves": [intent_ref, offer_ref],
              "authority": [deleg_ref]}
    p_agent = create_proof(commit, t_op, op_vm(lexis, fork_ev, t_op.mk),
                           "assertionMethod", commit["created"])
    p_amina = create_proof(commit, a_op1, op_vm(amina, a_upd, a_op1.mk),
                           "assertionMethod", "2026-10-30T10:22:00Z")
    commit_proposed = sign(commit, p_agent)
    commit_accepted = sign(commit, p_agent, p_amina)
    assert content_id(commit_proposed) == content_id(commit_accepted)
    commit_ref = f"{lexis}/{content_id(commit)}"

    receipt = {"oip": OIP_VERSION, "type": "Receipt", "author": amina,
               "created": "2026-11-01T17:40:00Z", "about": commit_ref,
               "outcome": "fulfilled",
               "statement": "Translation received on time; payment sent.",
               "evidence": [{"kind": "uri",
                             "ref": "https://lexis.example/d/7731.pdf",
                             "digest": "sha256:" + hashlib.sha256(
                                 b"example deliverable").hexdigest()}]}
    receipt = sign(receipt, create_proof(receipt, a_op1,
                                         op_vm(amina, a_upd, a_op1.mk),
                                         "assertionMethod",
                                         receipt["created"]))

    # --- A collective-authored object (2 of 3 members sign) ----------
    charter = {"oip": OIP_VERSION, "type": "Collective", "author": collective,
               "created": "2026-10-30T09:25:00Z",
               "name": "Open Translation Cell",
               "purpose": "Translate and review legal documents.",
               "roles": {"steward": {
                   "purpose": "Accept routine work",
                   "powers": [{"command": "/oip/sign/Commitment",
                               "policy": [["<=", ".terms.price.amount",
                                           "500"]]}]}},
               "assignments": [{"mind": lexis, "role": "steward"}]}
    charter = sign(charter,
                   create_proof(charter, a_op1, op_vm(amina, a_upd, a_op1.mk),
                                "assertionMethod", charter["created"]),
                   create_proof(charter, r_op,
                                op_vm(researcher, res_gen, r_op.mk),
                                "assertionMethod", charter["created"]))

    # --- Context packet carrying the offer ---------------------------
    session = {"oip": OIP_VERSION, "type": "Session",
               "participants": sorted([amina, lexis]), "nonce": "s1",
               "created": "2026-10-30T10:03:00Z"}
    packet = {"oip": OIP_VERSION, "type": "Packet", "from": lexis,
              "to": [amina], "created": "2026-10-30T10:04:05Z",
              "expires": "2026-10-30T22:00:00Z", "nonce": "p1",
              "session": content_id(session), "seq": 0,
              "purpose": {"verb": "propose",
                          "goal": "Offer to translate your lease"},
              "content": {"mediaType": "application/oip+json",
                          "body": offer},
              "constraints": {"retention": "P30D",
                              "prohibitedUses": ["train"]}}
    packet = sign(packet, create_proof(packet, t_op,
                                       op_vm(lexis, fork_ev, t_op.mk),
                                       "assertionMethod",
                                       packet["created"]))

    # --- Layer 1 records for the agent: profile, location, feed entry -
    participant = {
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
        "actsFor": [{"mind": lexis_ltd, "authority": deleg_ref}]}
    participant = sign(participant, create_proof(
        participant, t_op, op_vm(lexis, fork_ev, t_op.mk), "assertionMethod",
        participant["created"]))
    entry = {"oip": OIP_VERSION, "type": "Entry", "author": lexis, "seq": 0,
             "created": "2026-10-30T10:04:01Z",
             "object": content_id(offer), "objectType": "Offer"}
    entry = sign(entry, create_proof(entry, t_op,
                                     op_vm(lexis, fork_ev, t_op.mk),
                                     "assertionMethod", entry["created"]))
    location = {
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
        "feed": {"seq": 0, "head": content_id(entry)}}
    location = sign(location, create_proof(
        location, t_op, op_vm(lexis, fork_ev, t_op.mk), "assertionMethod",
        location["created"]))

    # --- record cases --------------------------------------------------
    V["cases"] = {
        "participant": participant, "location": location,
        "feed_entry": entry,
        "amina_log": [a_gen, a_upd], "amina": amina,
        "lexis_ltd_log": [ltd_gen], "lexis_ltd": lexis_ltd,
        "lexis_agent_log": [agent_gen, fork_ev], "lexis_agent": lexis,
        "lexis_fork_log": [child_gen], "lexis_fork": child,
        "researcher_log": [res_gen], "researcher": researcher,
        "collective_log": [coll], "collective": collective,
        "delegation": deleg, "intent": intent, "offer": offer,
        "commitment_proposed": commit_proposed,
        "commitment_accepted": commit_accepted, "receipt": receipt,
        "collective_charter": charter, "session": session,
        "packet": packet,
        "content_ids": {n: content_id(o) for n, o in [
            ("amina_genesis", a_gen), ("amina_update", a_upd),
            ("delegation", deleg), ("intent", intent), ("offer", offer),
            ("commitment", commit), ("receipt", receipt),
            ("collective_charter", charter), ("session", session),
            ("packet", packet)]},
        "jcs_example": {"input": {"b": 2, "a": [1, "x"], "é": True},
                        "output": jcs({"b": 2, "a": [1, "x"],
                                       "é": True}).decode()},
    }
    return V


def check(V) -> list:
    """Independently re-verify every case. Returns a list of check names."""
    c = V["cases"]
    reg = Registry()
    for name in ("amina_log", "lexis_ltd_log", "lexis_agent_log",
                 "lexis_fork_log", "researcher_log", "collective_log"):
        reg.add(c[name])
    done = []
    # addresses match their genesis
    for log, mind in (("amina_log", "amina"), ("lexis_agent_log",
                      "lexis_agent"), ("collective_log", "collective")):
        assert did(content_id(c[log][0])) == c[mind]
    done.append("addresses derive from genesis")
    for name in ("amina_log", "lexis_agent_log", "collective_log"):
        verify_log(c[name], reg)
    done.append("identity logs verify (pre-rotation, fork, collective)")
    st = reg.state(c["lexis_agent"])
    assert c["lexis_fork"] in st.children
    fork_parent = c["lexis_fork_log"][0]["parents"][0]["mind"]
    assert fork_parent == c["lexis_agent"]
    done.append("fork lineage acknowledged on both sides")
    # tampering: a forged rotation must fail
    bad = copy.deepcopy(c["amina_log"])
    bad[1]["controller"]["next"] = [key_hash(Key("attacker").mk)]
    try:
        verify_log(bad, reg)
        raise AssertionError("tampered log verified")
    except ValueError:
        done.append("tampered rotation rejected")
    # objects
    assert verify_signed_by(c["intent"], c["amina"], reg)
    assert verify_signed_by(c["offer"], c["lexis_agent"], reg)
    assert verify_signed_by(c["receipt"], c["amina"], reg)
    assert verify_signed_by(c["packet"], c["lexis_agent"], reg)
    assert verify_signed_by(c["delegation"], c["lexis_ltd"], reg)
    for name in ("participant", "location", "feed_entry"):
        assert verify_signed_by(c[name], c["lexis_agent"], reg)
    assert c["location"]["feed"]["head"] == content_id(c["feed_entry"])
    done.append("Layer 1/2 object signatures verify")
    # a validly signed, delegated proof outside the policy limit must not
    # count for the delegating party (re-sign with the agent's test key)
    agent_key = Key("lexis-agent-i1")
    agent_vm = c["commitment_accepted"]["proof"][0]["verificationMethod"]
    for amount, expected in (("120", True), ("900", False)):
        doc = {k: v for k, v in copy.deepcopy(
            c["commitment_accepted"]).items() if k != "proof"}
        doc["terms"]["price"]["amount"] = amount
        doc = sign(doc, create_proof(doc, agent_key, agent_vm,
                                     "assertionMethod", doc["created"]))
        assert verify_signed_by(doc, c["lexis_agent"], reg)
        assert verify_signed_by(doc, c["lexis_ltd"], reg,
                                delegations=[c["delegation"]]) is expected
    done.append("delegation policy limit enforced (120 ok, 900 refused)")
    acc = c["commitment_accepted"]
    assert content_id(acc) == content_id(c["commitment_proposed"])
    assert verify_signed_by(acc, c["amina"], reg)
    assert verify_signed_by(acc, c["lexis_ltd"], reg,
                            delegations=[c["delegation"]])
    assert not verify_signed_by(c["commitment_proposed"], c["amina"], reg)
    done.append("commitment co-signing keeps its ID; delegated party proof")
    ok, signers = _member_proofs_ok(c["collective_charter"],
                                    c["collective_charter"]["proof"],
                                    reg.state(c["collective"]).members,
                                    reg.state(c["collective"]).threshold, reg)
    assert ok and len(signers) == 2
    done.append("collective object passes 2-of-3 member threshold")
    assert jcs(c["jcs_example"]["input"]).decode() == \
        c["jcs_example"]["output"]
    done.append("JCS example")
    return done


if __name__ == "__main__":
    out = Path(__file__).with_name("vectors.json")
    if "--check" not in sys.argv:
        out.write_text(json.dumps(build(), indent=2, ensure_ascii=False) +
                       "\n", encoding="utf-8")
    vectors = json.loads(out.read_text(encoding="utf-8"))
    for line in check(vectors):
        print("ok -", line)
