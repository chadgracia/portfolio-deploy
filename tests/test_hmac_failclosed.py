"""HMAC_SECRET has no fallback: with a key, client/seller tokens and the session /
admin / view-as cookies round-trip; with an empty key nothing is signed and
nothing (not even an empty or empty-key-signed value) is accepted.
lambda_function.py reads S3 at import time, so the functions are pulled out with ast.
Run: python3 tests/test_hmac_failclosed.py"""
import ast
import base64
import hashlib
import hmac
import os
import sys
import time

SRC = os.path.join(os.path.dirname(__file__), "..", "lambda_function.py")
NEEDED = {"_b64u", "_b64u_decode", "sign_id", "make_token", "verify_token", "make_seller_token",
          "verify_seller_token", "make_session", "read_session", "make_admin_cookie",
          "read_admin_cookie", "make_view_as_cookie", "read_view_as_cookie"}
tree = ast.parse(open(SRC).read())
nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in NEEDED]
CODE = compile(ast.Module(body=nodes, type_ignores=[]), SRC, "exec")


def load(key):
    ns = {"base64": base64, "hashlib": hashlib, "hmac": hmac, "time": time, "HMAC_SECRET": key,
          "SESSION_DAYS": 365, "ADMIN_DAYS": 365, "VIEW_AS_DAYS": 1, "ADMIN_CLIENT_IDS": {"42"}}
    exec(CODE, ns)
    return ns


failures = 0


def check(name, cond):
    global failures
    print(("PASS: " if cond else "FAIL: ") + name)
    failures += 0 if cond else 1


ns = load("test-hmac-key")
check("source has no literal HMAC_SECRET fallback",
      'os.environ.get("HMAC_SECRET", "")' in open(SRC).read())
check("client token round-trips", ns["verify_token"]("7", ns["make_token"]("7")))
check("wrong token refused", not ns["verify_token"]("7", ns["make_token"]("8")))
check("seller token round-trips", ns["verify_seller_token"]("a1", ns["make_seller_token"]("a1")))
check("session round-trips", ns["read_session"](ns["make_session"]("7")) == "7")
check("admin cookie round-trips", ns["read_admin_cookie"](ns["make_admin_cookie"]("42")) == "42")
check("view-as round-trips", ns["read_view_as_cookie"](ns["make_view_as_cookie"]("42", "7"), "42") == "7")

empty = load("")
forged = base64.urlsafe_b64encode(hmac.new(b"", b"7", hashlib.sha256).digest()).decode().rstrip("=")
check("empty key: no client token minted", empty["make_token"]("7") == "")
check("empty key: empty token refused", not empty["verify_token"]("7", ""))
check("empty key: empty-key-signed token refused", not empty["verify_token"]("7", forged))
check("empty key: seller token refused", not empty["verify_seller_token"]("a1", "")
      and empty["make_seller_token"]("a1") == "")
check("empty key: no session minted / none accepted",
      empty["make_session"]("7") == "" and empty["read_session"](ns["make_session"]("7")) is None)
check("empty key: admin cookie refused",
      empty["make_admin_cookie"]("42") == "" and empty["read_admin_cookie"](ns["make_admin_cookie"]("42")) is None)
check("empty key: view-as refused",
      empty["make_view_as_cookie"]("42", "7") == ""
      and empty["read_view_as_cookie"](ns["make_view_as_cookie"]("42", "7"), "42") is None)

print(f"\n{failures} FAIL")
sys.exit(1 if failures else 0)
