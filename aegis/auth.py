"""Dashboard authentication: user accounts, roles, sessions, CSRF, rate limiting.

Putting a guard in front of the PLC is pointless if anyone on the plant network
can open the dashboard and approve the AI's proposals, or turn the guard off.

  roles      viewer    < operator               < engineer
             read-only   approve AI proposals,     change rules / guard mode /
                         setpoints, permits,       AI autonomy / calibration
                         grab samples              (+ the engineer PIN as a second factor)
  passwords  scrypt (n=2^14, r=8, p=1) with a per-user salt; stored in data/users.json
  sessions   HMAC-signed, expiring token in an HttpOnly, SameSite=Strict cookie
  CSRF       every state-changing request must carry the header  X-Aegis: 1
             (a cross-site form can't set custom headers; SameSite blocks the cookie too)
  brute force  5 failed logins per user or IP per 5 minutes -> locked out for the rest of the window

Create users:   python -m aegis.auth add alice operator
Demo accounts (AEGIS_DEMO=1, the default for the local simulator): operator / operator, engineer / engineer.
"""
from __future__ import annotations

import base64
import getpass
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from collections import defaultdict, deque
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROLES = {"viewer": 0, "operator": 1, "engineer": 2}
SESSION_S = 8 * 3600                 # one shift
MAX_FAILS, FAIL_WINDOW = 5, 300


def _hash(password: str, salt: bytes) -> str:
    return hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32).hex()


class Auth:
    def __init__(self, path: str | Path | None = None, secret: str | None = None, demo: bool = False, clock=time.time):
        self.path = Path(path or os.getenv("AEGIS_USERS", ROOT / "data" / "users.json"))
        self.secret = (secret or os.getenv("AEGIS_SESSION_SECRET") or secrets.token_hex(32)).encode()
        self.clock = clock
        self.users: dict[str, dict] = json.loads(self.path.read_text()) if self.path.exists() else {}
        self.fails: dict[str, deque] = defaultdict(deque)
        if demo and not self.users:
            self.add("operator", "operator", "operator", save=False)
            self.add("engineer", "engineer", "engineer", save=False)
            self.demo = True
        else:
            self.demo = False

    # ---------------------------------------------------------------- users
    def add(self, name: str, password: str, role: str, save: bool = True):
        if role not in ROLES:
            raise ValueError(f"role must be one of {list(ROLES)}")
        if len(password) < 8 and not (name == password and name in ("operator", "engineer")):
            raise ValueError("password must be at least 8 characters")
        salt = secrets.token_bytes(16)
        self.users[name] = {"role": role, "salt": salt.hex(), "hash": _hash(password, salt), "created": time.time()}
        if save:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.users, indent=2))

    def _locked(self, key: str) -> bool:
        dq = self.fails[key]
        now = self.clock()
        while dq and now - dq[0] > FAIL_WINDOW:
            dq.popleft()
        return len(dq) >= MAX_FAILS

    def login(self, name: str, password: str, ip: str = "?") -> tuple[str | None, str]:
        """Returns (token, message). Constant-time compare; failures counted per user and per IP."""
        for k in (f"user:{name}", f"ip:{ip}"):
            if self._locked(k):
                return None, "too many failed attempts; try again in a few minutes"
        u = self.users.get(name)
        ok = False
        if u:
            ok = hmac.compare_digest(_hash(password, bytes.fromhex(u["salt"])), u["hash"])
        else:
            _hash(password, b"x" * 16)          # same cost whether or not the user exists
        if not ok:
            now = self.clock()
            self.fails[f"user:{name}"].append(now)
            self.fails[f"ip:{ip}"].append(now)
            return None, "wrong username or password"
        return self.issue(name, u["role"]), "ok"

    # ---------------------------------------------------------------- sessions
    def issue(self, name: str, role: str) -> str:
        payload = json.dumps({"u": name, "r": role, "exp": int(self.clock() + SESSION_S),
                              "n": secrets.token_hex(8)}, separators=(",", ":")).encode()
        sig = hmac.new(self.secret, payload, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(payload).decode() + "." + base64.urlsafe_b64encode(sig).decode()

    def verify(self, token: str | None) -> dict | None:
        if not token or "." not in token:
            return None
        try:
            p64, s64 = token.split(".", 1)
            payload = base64.urlsafe_b64decode(p64)
            sig = base64.urlsafe_b64decode(s64)
        except Exception:
            return None
        if not hmac.compare_digest(hmac.new(self.secret, payload, hashlib.sha256).digest(), sig):
            return None
        d = json.loads(payload)
        if d["exp"] < self.clock() or d["u"] not in self.users or self.users[d["u"]]["role"] != d["r"]:
            return None      # expired, deleted user, or role changed since login
        return {"user": d["u"], "role": d["r"]}


def allowed(session: dict | None, need: str) -> bool:
    return bool(session) and ROLES[session["role"]] >= ROLES[need]


def main():
    if len(sys.argv) < 4 or sys.argv[1] != "add":
        print("usage: python -m aegis.auth add <username> <viewer|operator|engineer>")
        sys.exit(2)
    pw = getpass.getpass("password (8+ chars): ")
    Auth().add(sys.argv[2], pw, sys.argv[3])
    print(f"added {sys.argv[2]} ({sys.argv[3]})")


if __name__ == "__main__":
    main()
