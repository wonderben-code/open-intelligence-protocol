"""Independent re-implementation of OIP spec rules (revision 2026-10-30),
written from spec/*.md only, applied to every record in vectors.json.
Does not import oip_vectors.py."""
import base64, hashlib, json, re, sys
from decimal import Decimal
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

VEC = sys.argv[1]
V = json.load(open(VEC, encoding="utf-8"))
C = V["cases"]
problems = []
def bad(where, msg): problems.append(f"{where}: {msg}")

A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58d(s):
    n = 0
    for ch in s: n = n*58 + A.index(ch)
    body = n.to_bytes((n.bit_length()+7)//8, "big") if n else b""
    return b"\0"*(len(s)-len(s.lstrip("1"))) + body
def b58e(b):
    n = int.from_bytes(b, "big"); o = ""
    while n: n, r = divmod(n, 58); o = A[r]+o
    return "1"*(len(b)-len(b.lstrip(b"\0"))) + o

# --- JCS for the OIP profile (RFC 8785), written independently
def jstr(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"': out.append('\\"')
        elif ch == '\\': out.append('\\\\')
        elif ch == '\b': out.append('\\b')
        elif ch == '\f': out.append('\\f')
        elif ch == '\n': out.append('\\n')
        elif ch == '\r': out.append('\\r')
        elif ch == '\t': out.append('\\t')
        elif o < 0x20: out.append('\\u%04x' % o)
        else: out.append(ch)
    out.append('"'); return "".join(out)
def jcs(v):
    if v is None: return "null"
    if v is True: return "true"
    if v is False: return "false"
    if isinstance(v, int):
        assert abs(v) <= 2**53-1; return str(v)
    if isinstance(v, float): raise ValueError("float")
    if isinstance(v, str): return jstr(v)
    if isinstance(v, list): return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        ks = sorted(v, key=lambda k: [ord(c) for c in k.encode("utf-16-be").decode("latin-1")])
        return "{" + ",".join(jstr(k)+":"+jcs(v[k]) for k in ks) + "}"
    raise TypeError(type(v))
def J(v): return jcs(v).encode("utf-8")
def b32(b): return base64.b32encode(b).decode().lower().rstrip("=")
def cid(r): return "b" + b32(b"\x12\x20" + hashlib.sha256(J({k: x for k, x in r.items() if k != "proof"})).digest())
def keyhash(mk): return "b" + b32(b"\x12\x20" + hashlib.sha256(mk.encode()).digest())

CID_RE = re.compile(r"^b[a-z2-7]{55}$")
TS_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$")
DEC_RE = re.compile(r"^-?(0|[1-9][0-9]*)(\.[0-9]+)?$")
DUR_RE = re.compile(r"^P(\d+D)?(T(\d+H)?(\d+M)?(\d+S)?)?$")
ADDR_RE = re.compile(r"^did:oip:b[a-z2-7]{55}$")
VER_RE = re.compile(r"^(0|[1-9][0-9]*)-b[a-z2-7]{55}$")
B58 = "[1-9A-HJ-NP-Za-km-z]"
KEYREF_RE = re.compile(rf"^did:oip:(b[a-z2-7]{{55}})\?versionId=((?:0|[1-9][0-9]*)-b[a-z2-7]{{55}})#(z{B58}+)$")
CKREF_RE = re.compile(rf"^did:key:(z{B58}+)#(z{B58}+)$")
RREF_RE = re.compile(r"^did:oip:b[a-z2-7]{55}/b[a-z2-7]{55}$")
CMD_RE = re.compile(r"^/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$")
SEL_RE = re.compile(r"^(\.[A-Za-z0-9_]+)+$")

def ts(s):
    s2 = s.replace("Z", "+00:00")
    if "." in s2:
        a, b = s2.split("."); frac, tz = b[:-6], b[-6:]
        s2 = a + "." + (frac + "000000")[:6] + tz
    return datetime.fromisoformat(s2)

def walk_numbers(v, where):
    if isinstance(v, bool) or v is None: return
    if isinstance(v, float): bad(where, "float present")
    elif isinstance(v, int):
        if abs(v) > 2**53-1: bad(where, "int out of range")
    elif isinstance(v, list):
        for i, x in enumerate(v): walk_numbers(x, f"{where}[{i}]")
    elif isinstance(v, dict):
        for k, x in v.items(): walk_numbers(x, f"{where}.{k}")

def multikey(mk, kind):
    raw = b58d(mk[1:])
    pre = {"ed": b"\xed\x01", "x": b"\xec\x01"}[kind]
    ok = mk.startswith("z") and raw[:2] == pre and len(raw) == 34 and b58e(raw) == mk[1:]
    return raw[2:] if ok else None

ALLOWED_PROOF = {"type", "cryptosuite", "verificationMethod", "proofPurpose", "created", "proofValue"}
def check_proof_shape(p, where, purpose_expected, record):
    extra = set(p) - ALLOWED_PROOF - {"challenge", "domain", "@context"}
    if extra: bad(where, f"proof has extra members {extra}")
    for m in ALLOWED_PROOF:
        if m not in p: bad(where, f"proof lacks {m}")
    if p.get("type") != "DataIntegrityProof" or p.get("cryptosuite") != "eddsa-jcs-2022":
        bad(where, "bad type/cryptosuite")
    if p.get("proofPurpose") != purpose_expected:
        bad(where, f"proofPurpose {p.get('proofPurpose')} != {purpose_expected}")
    if not TS_RE.match(p.get("created", "")): bad(where, "proof created not a timestamp")
    if ("challenge" in p or "domain" in p) and p.get("proofPurpose") != "authentication":
        bad(where, "challenge/domain outside authentication")
    if ("@context" in p) != ("@context" in record): bad(where, "@context iff rule")
    rec_created = record.get("created")
    if rec_created and ts(p["created"]) < ts(rec_created):
        bad(where, "proof created earlier than record created (core 5.7 SHOULD NOT)")

def sigok(record, p, mk):
    pub = multikey(mk, "ed")
    if pub is None: return False
    opts = {k: v for k, v in p.items() if k != "proofValue"}
    hd = hashlib.sha256(J(opts)).digest() + hashlib.sha256(J({k: v for k, v in record.items() if k != "proof"})).digest()
    try:
        sig = b58d(p["proofValue"][1:])
        if not p["proofValue"].startswith("z") or len(sig) != 64: return False
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, hd); return True
    except Exception:
        return False

# ---------------- identity logs, written from Layer 1 sections 3-6, 9
LOGS = {}
for name in ("amina_log", "lexis_ltd_log", "lexis_agent_log", "lexis_fork_log", "researcher_log", "collective_log"):
    LOGS["did:oip:" + cid(C[name][0])] = C[name]

class St: pass
def replay(addr, upto=None, depth=0):
    log = LOGS[addr]; st = St()
    st.versions = []; st.keys = []; st.revoked = {}; st.children = []; st.retired = False
    st.members = None; st.threshold = None; st.next = None; st.nt = 1; st.created = []
    for i, e in enumerate(log):
        w = f"{addr[8:20]}..log[{i}]"
        walk_numbers(e, w)
        if e.get("oip") != "1": bad(w, "oip != 1")
        if not TS_RE.match(e.get("created", "")): bad(w, "created")
        if i == 0:
            if e["type"] != "Genesis" or any(k in e for k in ("mind", "seq", "prev")): bad(w, "genesis shape")
            for k in ("oip", "type", "created", "proof", "kind", "controller"):
                if k not in e: bad(w, f"genesis missing {k}")
            ctl = e["controller"]
            if "keys" in ctl:
                if e["kind"] == "collective": bad(w, "collective kind with key controller")
                if not (1 <= len(ctl["keys"]) <= 16): bad(w, "controller.keys count")
                for mk in ctl["keys"]:
                    if multikey(mk, "ed") is None: bad(w, "control key not Ed25519 multikey")
                    if not any(p["verificationMethod"] == f"did:key:{mk}#{mk}" and p["proofPurpose"] == "capabilityInvocation" and sigok(e, p, mk) for p in e["proof"]):
                        bad(w, "genesis control key did not sign")
                st.next = ctl["next"]; st.nt = ctl.get("nextThreshold", 1)
                if st.next and not (1 <= st.nt <= len(st.next)): bad(w, "nextThreshold range")
                for h in st.next:
                    if not CID_RE.match(h): bad(w, "next not key-hash form")
            else:
                ms = ctl["members"]; th = ctl["threshold"]
                if len(set(ms)) != len(ms) or not (1 <= th <= len(ms)): bad(w, "member controller rules")
                signers = member_signers(e, ms, depth)
                if set(signers) != set(ms): bad(w, f"not all founders signed: {signers}")
                st.members, st.threshold = ms, th
            for p in e["proof"]:
                check_proof_shape(p, w+".proof", "capabilityInvocation", e)
        else:
            if e.get("mind") != addr or e.get("seq") != i or e.get("prev") != cid(log[i-1]): bad(w, "chain")
            if st.retired: bad(w, "event after Retire")
            if e["type"] not in ("Update", "Fork", "Merge", "Retire"): bad(w, "unknown event type")
            ctl = e.get("controller")
            if st.members is None:
                if ctl is None: bad(w, "key-controlled event needs controller"); continue
                rev = ctl["keys"]
                if len(set(rev)) < st.nt: bad(w, "too few revealed keys")
                for mk in rev:
                    if keyhash(mk) not in st.next: bad(w, "revealed key not committed")
                    if not any(p["verificationMethod"] == f"did:key:{mk}#{mk}" and p["proofPurpose"] == "capabilityInvocation" and sigok(e, p, mk) for p in e["proof"]):
                        bad(w, "revealed key did not sign")
                st.next = ctl["next"]; st.nt = ctl.get("nextThreshold", 1)
            else:
                signers = member_signers(e, st.members, depth)
                if len(signers) < st.threshold: bad(w, "collective threshold")
            for p in e["proof"]:
                check_proof_shape(p, w+".proof", "capabilityInvocation", e)
            if e["type"] == "Fork": st.children.append(e["child"])
            if e["type"] == "Retire": st.retired = True
        if "keys" in e:
            ks = [k["key"] for k in e["keys"]]
            for k in e["keys"]:
                if multikey(k["key"], "ed") is None: bad(w, "op key not Ed25519")
                if len(k.get("label", "")) > 64: bad(w, "label > 64")
            st.keys = ks
        if "agreement" in e:
            for k in e["agreement"]:
                if multikey(k["key"], "x") is None: bad(w, "agreement key not X25519")
        for r in e.get("revoked", []):
            st.revoked[r["key"]] = r.get("compromisedSince")
            if r["key"] in st.keys and "keys" in e: bad(w, "revoked key still listed")
            if "keys" not in e: st.keys = [k for k in st.keys if k != r["key"]]
        v = f"{e.get('seq', 0)}-{cid(e)}"; st.versions.append(v); st.created.append(e["created"])
        st.version = v
        if upto == v: return st
    if upto and upto not in st.versions: raise ValueError("version not in log")
    return st

def keyvalid(vm, created, current=False, depth=0):
    m = KEYREF_RE.match(vm)
    if not m: return None
    addr = "did:oip:" + m.group(1); ver = m.group(2); k = m.group(3)
    if addr not in LOGS: return None
    st_v = replay(addr, ver, depth+1); latest = replay(addr, None, depth+1)
    if k not in st_v.keys: return None
    cs = latest.revoked.get(k)
    if cs and ts(cs) <= ts(created): return None
    if current and k not in latest.keys: return None
    return addr, k

def member_signers(rec, members, depth):
    if depth > 4: return []
    s = set()
    for p in rec.get("proof", []):
        r = keyvalid(p["verificationMethod"], p["created"], depth=depth)
        if r and r[0] in members and sigok(rec, p, r[1]): s.add(r[0])
    return sorted(s)

for a in LOGS: replay(a)
for nm, log in (("amina", "amina_log"), ("lexis_ltd", "lexis_ltd_log"), ("lexis_agent", "lexis_agent_log"),
                ("lexis_fork", "lexis_fork_log"), ("researcher", "researcher_log"), ("collective", "collective_log")):
    if C[nm] != "did:oip:" + cid(C[log][0]): bad(nm, "address mismatch")
# key hashes in vectors.keys
for label, kv in V["keys"].items():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization as S
    seed = bytes.fromhex(kv["seed_hex"])
    if hashlib.sha256(("oip-test-vector:"+label).encode()).digest() != seed: bad(label, "seed derivation")
    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw)
    if "z" + b58e(b"\xed\x01" + pub) != kv["multikey"]: bad(label, "multikey derivation")

# lineage 8.2
child = C["lexis_fork_log"][0]
par = child["parents"][0]
pst = replay(par["mind"])
if C["lexis_fork"] not in pst.children: bad("lineage", "not acknowledged")
fork_idx = [i for i, e in enumerate(LOGS[par["mind"]]) if e["type"] == "Fork" and e["child"] == C["lexis_fork"]][0]
if int(par["at"].split("-")[0]) > fork_idx or par["at"] not in pst.versions: bad("lineage", "at after fork")

# ---------------- policy (Layer 1 11.3), as written
def is_num(x): return (isinstance(x, int) and not isinstance(x, bool)) or (isinstance(x, str) and DEC_RE.match(x))
MISSING = object()
def sel(obj, s):
    cur = obj
    for part in s.split(".")[1:]:
        if not isinstance(cur, dict) or part not in cur: return MISSING
        cur = cur[part]
    return cur
def stmt(op, s, val, r):
    assert op in ("==", "!=", "<", "<=", ">", ">=") and SEL_RE.match(s)
    got = sel(r, s)
    if got is MISSING: return False
    if is_num(got) and is_num(val):
        a, b = Decimal(str(got)), Decimal(str(val))
    elif op in ("==", "!="):
        return (jcs(got) == jcs(val)) == (op == "==")
    elif isinstance(got, str) and isinstance(val, str):
        a, b = [ord(c) for c in got], [ord(c) for c in val]
    else:
        return False
    return {"==": a == b, "!=": a != b, "<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
def covers(g, c): return c == g or c.startswith(g + "/")

# ---------------- record-level checks
def cf(r, P, now=None):
    """Layer 2 7.1 counts-for, restricted to routes exercisable with the vectors."""
    out = []
    for p in r.get("proof", []):
        if p["proofPurpose"] != "assertionMethod": continue
        kv = keyvalid(p["verificationMethod"], p["created"])
        if not kv or not sigok(r, p, kv[1]): continue
        D = kv[0]
        if D == P: out.append(("own", p["verificationMethod"][-8:]))
        for ref in r.get("authority", []):
            d = C["delegation"] if ref == f"{C['lexis_ltd']}/{cid(C['delegation'])}" else None
            if d is None: continue
            # 11.4 with n = 1
            dp = [q for q in d["proof"] if q["proofPurpose"] == "capabilityDelegation" and keyvalid(q["verificationMethod"], q["created"]) and keyvalid(q["verificationMethod"], q["created"])[0] == d["author"] and sigok(d, q, keyvalid(q["verificationMethod"], q["created"])[1])]
            ok = bool(dp) and d["author"] == d["subject"] == P and d["delegate"] == D
            ok = ok and ts(r["created"]) <= ts(d["expires"]) and ("notBefore" not in d or ts(r["created"]) >= ts(d["notBefore"]))
            ok = ok and covers(d["command"], "/oip/sign/" + r["type"]) and all(stmt(*s, r) for s in d.get("policy", []))
            if ok: out.append(("delegated", D[-6:]))
    return out

def common(r, w, purpose="assertionMethod", author_field="author", signed=True):
    walk_numbers(r, w)
    if r.get("oip") != "1": bad(w, "oip")
    if not TS_RE.match(r.get("created", "")): bad(w, "created")
    if signed:
        if not r.get("proof"): bad(w, "no proof")
        for p in r.get("proof", []): check_proof_shape(p, w+".proof", purpose, r)
    elif "proof" in r: bad(w, "unsigned record carries proof")
    if len(J(r)) > 1 << 20: bad(w, "too large")

# Delegation (L1 11.1)
d = C["delegation"]; common(d, "delegation", "capabilityDelegation")
for k in ("author", "delegate", "subject", "command", "expires", "nonce", "created", "proof"):
    if k not in d: bad("delegation", f"missing {k}")
if not CMD_RE.match(d["command"]) or len(d["nonce"]) > 64: bad("delegation", "command/nonce")
for s in d["policy"]:
    if not SEL_RE.match(s[1]): bad("delegation", "selector")

# Intent / Offer / Commitment / Receipt / Charter
it = C["intent"]; common(it, "intent")
if len(it["want"]) > 4096: bad("intent", "want")
if not DEC_RE.match(it["constraints"]["budget"]["max"]): bad("intent", "budget")
of = C["offer"]; common(of, "offer")
if not RREF_RE.match(of["answers"]) or "summary" not in of["terms"]: bad("offer", "answers/terms")
for nm in ("commitment_proposed", "commitment_accepted"):
    cm = C[nm]; common(cm, nm)
    roles = [p["role"] for p in cm["parties"]]
    if "debtor" not in roles or "creditor" not in roles: bad(nm, "roles")
    if any(p["role"] in ("debtor", "creditor") and not p["required"] for p in cm["parties"]): bad(nm, "required")
    if cid(cm) != C["content_ids"]["commitment"]: bad(nm, "content id")
rc = C["receipt"]; common(rc, "receipt")
if rc["about"].split("/")[1] != C["content_ids"]["commitment"]: bad("receipt", "about")
for ev in rc["evidence"]:
    if ev["kind"] in ("uri", "hash") and not re.match(r"^sha256:[0-9a-f]{64}$", ev.get("digest", "")): bad("receipt", "digest")
ch = C["collective_charter"]; common(ch, "collective_charter")

# Participant, Location, Entry (current-state rule 6.2)
pa = C["participant"]; common(pa, "participant")
lo = C["location"]; common(lo, "location")
en = C["feed_entry"]; common(en, "feed_entry")
for nm in ("participant", "location", "feed_entry"):
    r = C[nm]
    if not any(keyvalid(p["verificationMethod"], p["created"], current=True) for p in r["proof"]): bad(nm, "6.2 current key")
if not (60 <= lo["ttl"] <= 86400) or lo["status"] not in ("active", "paused", "migrating"): bad("location", "ttl/status")
for ep in lo["endpoints"]:
    if not isinstance(ep.get("priority"), int): bad("location", "endpoint priority")
if lo["participant"] != cid(pa) or lo["feed"]["head"] != cid(en): bad("location", "pointers")
if en["object"] != cid(of) or en["objectType"] != "Offer": bad("feed_entry", "object")

# Session and Packet
se = C["session"]; common(se, "session", signed=False)
if se["participants"] != sorted(set(se["participants"])) or not (2 <= len(se["participants"]) <= 256): bad("session", "participants")
pk = C["packet"]; common(pk, "packet")
if not (8 <= len(pk["nonce"]) <= 64): bad("packet", f"nonce {pk['nonce']!r} violates L1 12.1 (8-64 characters)")
if pk.get("session") and pk.get("seq") == 0:
    body = pk["content"].get("body")
    parts = pk["content"].get("parts", [])
    has_session = (isinstance(body, dict) and body.get("type") == "Session") or any(isinstance(x.get("body"), dict) and x["body"].get("type") == "Session" for x in parts)
    if not has_session or pk["purpose"]["verb"] != "open":
        bad("packet", f"first packet in session (seq 0) has verb {pk['purpose']['verb']!r} and no Session record: L1 14.2 requires verb 'open' with the Session (unless already shown)")
if ("session" in pk) and not all(k in pk for k in ("session", "seq", "prev")):
    bad("packet", "L1 12.1 table says session/seq/prev 'together' but prev is absent (14.3 says prev only after the first)")
if pk["session"] != cid(se): bad("packet", "session id")
if pk["from"] not in se["participants"] or not set(pk["to"]) <= set(se["participants"]): bad("packet", "participants")
if not DUR_RE.match(pk["constraints"]["retention"]): bad("packet", "retention")
if not (1 <= len(pk["to"]) <= 64): bad("packet", "to")

# all content_ids
cmap = {"amina_genesis": C["amina_log"][0], "amina_update": C["amina_log"][1], "delegation": d, "intent": it,
        "offer": of, "commitment": C["commitment_accepted"], "receipt": rc, "collective_charter": ch, "session": se, "packet": pk}
for k, r in cmap.items():
    if cid(r) != C["content_ids"][k]: bad("content_ids", k)
    if not CID_RE.match(C["content_ids"][k]): bad("content_ids", k + " format")
if jcs(C["jcs_example"]["input"]) != C["jcs_example"]["output"]: bad("jcs", "example")

# signatures & attribution
print("intent counts for amina:", cf(it, C["amina"]))
print("offer counts for agent:", cf(of, C["lexis_agent"]))
print("receipt counts for amina:", cf(rc, C["amina"]))
for nm in ("commitment_proposed", "commitment_accepted"):
    cm = C[nm]
    acc = {p["mind"]: bool(cf(cm, p["mind"])) for p in cm["parties"] if p["required"]}
    print(nm, "accepted-by-party:", acc, "author-counts:", bool(cf(cm, cm["author"])))
# charter: threshold at latest collective version with created <= record created (9.4)
cst = replay(C["collective"])
ms = cst.members
print("charter member signers:", [m[-6:] for m in member_signers(ch, ms, 0)], "threshold", cst.threshold)

# Commitment status (L2 8.3) at several 'now' values
def status(cm, receipts, now):
    if not all(cf(cm, p["mind"]) for p in cm["parties"] if p["required"]): return "proposed"
    parties = {p["mind"]: p["role"] for p in cm["parties"]}
    R = [x for x in receipts if x["author"] in parties and cf(x, x["author"]) and x["about"].split("/")[1] == cid(cm)]
    canc = [x for x in R if x["outcome"] == "cancelled"]
    if canc and all(any(cf(x, m) for x in canc) for m, rr in parties.items() if rr in ("debtor", "creditor")): return "cancelled"
    F = [x for x in R if x["outcome"] == "fulfilled"]
    cred = [m for m, rr in parties.items() if rr == "creditor"]
    if any(cf(x, m) for x in F for m in cred) or (cm["terms"].get("selfReport") and F): s = "fulfilled"
    elif F: s = "claimed-fulfilled"
    else: s = "accepted"
    outs = {x["outcome"] for x in R}
    if outs & {"broken", "disputed"} and s in ("fulfilled", "claimed-fulfilled"): return "disputed"
    if "broken" in outs and s == "accepted": return "broken"
    if "disputed" in outs and s == "accepted": return "disputed"
    if s == "accepted" and now > ts(cm["terms"]["deadline"]): return "overdue"
    return s
for now in ("2026-10-31T00:00:00Z", "2026-11-02T00:00:00Z"):
    print("status @", now, "proposed:", status(C["commitment_proposed"], [], ts(now)),
          "| accepted, no receipts:", status(C["commitment_accepted"], [], ts(now)),
          "| accepted + receipt:", status(C["commitment_accepted"], [rc], ts(now)))

print("\nPROBLEMS (%d):" % len(problems))
for p in problems: print(" -", p)
