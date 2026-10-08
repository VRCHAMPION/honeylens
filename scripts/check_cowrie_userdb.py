"""Check cowrie/userdb.txt with Cowrie's OWN UserDB class (run inside the cowrie image).

Usage (from repo root):
  docker run --rm -v "$PWD/cowrie/userdb.txt:/cowrie/cowrie-git/etc/userdb.txt:ro" \
    -v "$PWD/scripts/check_cowrie_userdb.py:/tmp/check.py:ro" cowrie/cowrie:3.1.1 /tmp/check.py
"""
import sys

from cowrie.core.auth import UserDB

ALLOWED = [(b"root", b"admin123"), (b"root", b"xc3511"), (b"admin", b"admin"),
           (b"ubuntu", b"ubuntu"), (b"pi", b"raspberry")]
DENIED = [(b"root", b"root"), (b"root", b"123456"), (b"root", b"password"), (b"root", b"toor"),
          (b"root", b"anything-else"), (b"root", b""), (b"admin", b"password"), (b"admin", b"admin123"),
          (b"ubuntu", b"admin"), (b"pi", b"pi"), (b"user", b"user"), (b"test", b"test"),
          (b"oracle", b"oracle"), (b"*", b"*"), (b"root", b"*")]

db = UserDB()
bad = 0
for u, p in ALLOWED:
    ok = db.checklogin(u, p, "192.0.2.1")
    print(f"ALLOW {u.decode()}/{p.decode()}: {'PASS' if ok else 'FAIL'}")
    bad += not ok
for u, p in DENIED:
    ok = db.checklogin(u, p, "192.0.2.1")
    print(f"DENY  {u.decode()}/{p.decode()}: {'PASS' if not ok else 'FAIL'}")
    bad += bool(ok)
print(f"RESULT: {len(ALLOWED) + len(DENIED) - bad}/{len(ALLOWED) + len(DENIED)} passed")
sys.exit(1 if bad else 0)
