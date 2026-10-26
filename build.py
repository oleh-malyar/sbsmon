#!/usr/bin/env python3
"""Шифрує дані моніторингу для сторінки.

Використання: SBSMON_PASS=<пароль> python3 build.py profiles.json posts.json
Записує data.enc.json поруч із цим скриптом. Відкриті дані в репозиторій не потрапляють.
"""
import base64, json, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ITER = 310000

def main():
    pw = os.environ.get("SBSMON_PASS")
    if not pw or len(sys.argv) != 3:
        sys.exit("usage: SBSMON_PASS=... build.py profiles.json posts.json")
    profiles = json.load(open(sys.argv[1], encoding="utf-8"))
    posts = json.load(open(sys.argv[2], encoding="utf-8"))
    keep = ("date", "account", "code", "owner", "type", "likes", "comments", "views", "caption")
    posts = [{k: p.get(k) for k in keep} for p in posts]
    plain = json.dumps({"profiles": profiles, "posts": posts}, ensure_ascii=False, separators=(",", ":")).encode()
    salt, iv = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(pw.encode())
    ct = AESGCM(key).encrypt(iv, plain, None)
    b = lambda x: base64.b64encode(x).decode()
    out = {"v": 1, "iter": ITER, "salt": b(salt), "iv": b(iv), "ct": b(ct)}
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data.enc.json")
    json.dump(out, open(path, "w"), separators=(",", ":"))
    print("ok", path, len(plain), "bytes plain")

if __name__ == "__main__":
    main()
