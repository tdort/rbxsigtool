"""Patch your join-signing public key into Roblox-era exes (CryptoAPI RSA1 key blob).
  python rbxkeytool.py gen [out.pem]                 -> new 1024-bit keypair (default private.pem)
  python rbxkeytool.py patch <key.pem> <exe> [...]   -> writes <exe>.patched with the public key of key.pem
  python rbxkeytool.py check <key.pem> <exe> [...]   -> says whether each exe already carries that key
  python rbxkeytool.py verify <key.pem> <join.txt>   -> checks a saved Join.ashx response the way the client does
Use the same key.pem your server signs with (e.g. Web/keys/join-private.pem). Patch the player AND every RCC."""
import sys, re, base64, struct
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def load(pem):
    k = serialization.load_pem_private_key(open(pem, "rb").read(), None)
    assert k.key_size == 1024, "exes use 1024-bit keys"
    return k.public_key().public_numbers()

def blobs(d):
    for m in re.finditer(rb"[A-Za-z0-9+/]{60,}={0,2}", d):
        s = m.group()
        try: b = base64.b64decode(s + b"=" * (-len(s) % 4))
        except Exception: continue
        if len(b) == 148 and b[8:12] == b"RSA1" and len(s) == 200:
            yield m.start(), m.end(), b

def make(old, pub):  # keep the exe's own header bytes, swap exponent + modulus
    return old[:12] + struct.pack("<II", 1024, pub.e) + pub.n.to_bytes(128, "little")

def gen(out="private.pem"):
    k = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    open(out, "wb").write(k.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    print("wrote", out)

def patch(pem, paths):
    pub = load(pem)
    for p in paths:
        d = open(p, "rb").read(); found = list(blobs(d))
        if len(found) != 1: print(p, f": expected 1 key blob, found {len(found)} - not patched"); continue
        s, e, old = found[0]
        open(p + ".patched", "wb").write(d[:s] + base64.b64encode(make(old, pub)) + d[e:])
        print(p, ": patched ->", p + ".patched")

def check(pem, paths):
    pub = load(pem)
    for p in paths:
        found = list(blobs(open(p, "rb").read()))
        ok = any(int.from_bytes(b[20:], "little") == pub.n for _, _, b in found)
        print(p, ": has your key" if ok else ": does NOT have your key", f"({len(found)} blob)")

def verify(pem, path):
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    import json
    pub = serialization.load_pem_private_key(open(pem, "rb").read(), None).public_key()
    raw = open(path, "rb").read()
    print("bytes:", len(raw), "| starts with BOM:", raw[:3] == b"\xef\xbb\xbf", "| first 40:", raw[:40])
    m = re.match(rb"(?:\xef\xbb\xbf)?--rbxsig%([A-Za-z0-9+/=]+)%(.*)", raw, re.S)
    if not m: print("NO '--rbxsig%<sig>%' header found - the response is not a signed join script"); return
    sig, rest = base64.b64decode(m.group(1)), m.group(2)
    print("signature bytes:", len(sig), "| body starts with CRLF:", rest[:2] == b"\r\n", "| body length:", len(rest))
    ok = False
    for sname, s in (("reversed", sig[::-1]), ("as-is", sig)):
        for bname, b in (("body as sent", rest), ("body without leading CRLF", rest[2:] if rest[:2] == b"\r\n" else rest), ("body with CRLF added", b"\r\n" + rest)):
            try: pub.verify(s, b, padding.PKCS1v15(), hashes.SHA1()); print("VALID:", sname, "signature,", bname); ok = True
            except Exception: pass
    if not ok: print("no combination verifies against this key - the server signs with a different key than", pem)
    try: print("JSON keys:", sorted(json.loads(rest.decode("utf-8-sig")).keys())[:8], "...")
    except Exception as e: print("body is not valid JSON:", e)

if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["gen"]: gen(*a[1:2])
    elif a[:1] == ["patch"] and len(a) >= 3: patch(a[1], a[2:])
    elif a[:1] == ["check"] and len(a) >= 3: check(a[1], a[2:])
    elif a[:1] == ["verify"] and len(a) == 3: verify(a[1], a[2])
    else: print(__doc__)