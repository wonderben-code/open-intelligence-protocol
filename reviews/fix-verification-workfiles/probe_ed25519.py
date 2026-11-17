"""Probe: does the checker (OpenSSL via `cryptography`) apply core 4.4?
Edwards25519 arithmetic follows the RFC 8032 reference code."""
import hashlib
import harness as h
ov = h.ov

p = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
d = -121665 * pow(121666, -1, p) % p
I = pow(2, (p - 1) // 4, p)


def inv(x):
    return pow(x, p - 2, p)


def add(P, Q):
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = (Y1 - X1) * (Y2 - X2) % p
    B = (Y1 + X1) * (Y2 + X2) % p
    Cc = 2 * T1 * T2 * d % p
    D = 2 * Z1 * Z2 % p
    E, F, G, H = B - A, D - Cc, D + Cc, B + A
    return (E * F % p, G * H % p, F * G % p, E * H % p)


def mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = add(Q, P)
        P = add(P, P)
        s >>= 1
    return Q


def recover_x(y, sign):
    x2 = (y * y - 1) * inv(d * y * y + 1) % p
    if x2 == 0:
        return 0 if not sign else None
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * I % p
    if (x * x - x2) % p != 0:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


def point(y, sign=0):
    x = recover_x(y, sign)
    return (x, y, 1, x * y % p)


def enc(P):
    X, Y, Z, _ = P
    zi = inv(Z)
    x, y = X * zi % p, Y * zi % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def eq(P, Q):
    return enc(P) == enc(Q)


B = point(4 * inv(5) % p, 0)
O = (0, 1, 1, 0)
# A point of order 8: find one by multiplying a random point by L.
for y0 in range(2, 1000):
    try:
        cand = point(y0, 0)
    except TypeError:
        continue
    if cand[0] is None:
        continue
    T8 = mul(L, cand)
    if not eq(mul(4, T8), O):
        break
assert eq(mul(8, T8), O) and not eq(mul(4, T8), O)


def H(*parts):
    return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "little")


def openssl_ok(pub32, sig, msg):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(pub32).verify(sig, msg)
        return True
    except Exception:
        return False


def in_prime_subgroup(P):
    return eq(mul(L, P), O)


# Case 1: mixed-order public key A = [a]B + T8 with a known scalar a.
a = 0x1234567890abcdef % L
A = add(mul(a, B), T8)
A32 = enc(A)
for i in range(64):
    msg = b"oip-probe-message-%d" % i
    r = H(b"nonce", msg) % L
    R32 = enc(mul(r, B))
    k = H(R32, A32, msg) % L
    if k % 8 == 0:
        S = (r + k * a) % L
        sig = R32 + int.to_bytes(S, 32, "little")
        print("mixed-order public key, k = 0 mod 8: OpenSSL accepts =",
              openssl_ok(A32, sig, msg), "| A in prime-order subgroup =",
              in_prime_subgroup(A), "(core 4.4 requires rejection)")
        break

# Case 2: small-order public key A = T8; no private key at all.
A32 = enc(T8)
for i in range(64):
    msg = b"anyone-can-sign-%d" % i
    s = H(b"s", msg) % L
    R32 = enc(mul(s, B))
    k = H(R32, A32, msg) % L
    if k % 8 == 0:
        sig = R32 + int.to_bytes(s, 32, "little")
        print("order-8 public key, forged without any private key: OpenSSL accepts =",
              openssl_ok(A32, sig, msg), "(core 4.4 requires rejection)")
        break

# Case 3: the identity point (order 1). It is in the prime-order subgroup, so
# core 4.4 as written ACCEPTS it, and anyone can sign any message for it.
A32 = enc(O)
msg = b"any message at all"
s = 7
sig = enc(mul(s, B)) + int.to_bytes(s, 32, "little")
print("identity public key, forged without any private key: OpenSSL accepts =",
      openssl_ok(A32, sig, msg), "| core 4.4 as written also accepts (identity is in the subgroup)")

# Case 4: wire it into OIP: a mind whose operational key is mixed-order signs an
# Intent; the checker counts it.
mk_mixed = ov.multikey_ed25519(enc(add(mul(a, B), T8)))
c0, c1 = h.K("mixed-c0"), h.K("mixed-c1")
g = {"oip": "1", "type": "Genesis", "kind": "agent", "created": "2026-10-30T09:00:00Z",
     "controller": {"keys": [c0.mk], "next": [ov.key_hash(c1.mk)], "nextThreshold": 1},
     "keys": [{"key": mk_mixed}]}
g = ov.sign(g, ov.create_proof(g, c0, ov.did_key_vm(c0.mk), "capabilityInvocation",
                               g["created"]))
mind = ov.did(ov.content_id(g))
vmref = ov.op_vm(mind, g, mk_mixed)
A32 = enc(add(mul(a, B), T8))
for i in range(200):
    rec = {"oip": "1", "type": "Intent", "author": mind,
           "created": "2026-10-30T10:00:%02dZ" % (i % 60), "want": "probe %d" % i}
    opts = {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": vmref, "proofPurpose": "assertionMethod",
            "created": rec["created"]}
    msg = hashlib.sha256(ov.jcs(opts)).digest() + hashlib.sha256(ov.jcs(rec)).digest()
    r = H(b"n", msg) % L
    R32 = enc(mul(r, B))
    k = H(R32, A32, msg) % L
    if k % 8:
        continue
    S = (r + k * a) % L
    rec["proof"] = [dict(opts, proofValue="z" + ov.b58encode(R32 + int.to_bytes(S, 32, "little")))]
    V = ov.Verifier(logs=[[g]])
    print("OIP Intent signed by a mixed-order operational key counts in the checker:",
          V.counts_for(rec, mind))
    break
