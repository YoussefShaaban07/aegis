"""Tamper-evident audit log (SQLite, hash-chained).

Every entry stores the SHA-256 of (previous hash + this entry). Editing or
deleting any past row breaks the chain, and verify() pinpoints where. That
matters after an incident: investigators need to trust the record of who
sent what command and what the guard decided.

A plain hash chain only proves *consistency*: someone with write access to
the database file could rewrite every row and recompute every hash. Two
defences against that:
  * keyed chain: set AEGIS_AUDIT_KEY and every link becomes HMAC-SHA256 with
    that secret, so rewriting history needs the key, not just the file;
  * checkpoints: head() returns the newest hash; it is printed in incident
    reports, so a later rewrite won't match an externally held copy;
  * off-box copy: set AEGIS_SYSLOG=host:port and every entry (with its hash) is
    also sent as an RFC 5424 syslog message over UDP to a log server or SIEM.
    Someone who owns the Aegis box can rewrite the local file, not the copy
    that already left it.
Changing or removing the key on an existing database makes verify() fail
(by design): start a new database when you rotate it.
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import os
import socket
import sqlite3
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GENESIS = "0" * 64


def _hash(prev: str, t: float, kind: str, data: str, key: bytes | None = None) -> str:
    msg = f"{prev}|{t:.6f}|{kind}|{data}".encode()
    if key:
        return hmac.new(key, msg, hashlib.sha256).hexdigest()
    return hashlib.sha256(msg).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None = None, key: str | None = None, clock=None):
        """clock: optional callable returning the entry timestamp. Default is wall time; the
        evaluation harness passes its simulated clock so episodes produce a citable, replayable log."""
        self.clock = clock or time.time
        k = key if key is not None else os.getenv("AEGIS_AUDIT_KEY", "")
        self.key = k.encode() if k else None
        self.path = str(path or os.getenv("AEGIS_DB", ROOT / "data" / "audit.db"))
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.execute("""CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT, t REAL, kind TEXT, data TEXT,
            prev_hash TEXT, hash TEXT)""")
        self.db.commit()
        target = os.getenv("AEGIS_SYSLOG", "")
        self.syslog = None
        if target:
            host, _, port = target.rpartition(":")
            self.syslog = (host or "127.0.0.1", int(port or 514))
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def _forward(self, entry_id: int, t: float, kind: str, payload: str, h: str):
        if not self.syslog:
            return
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int((t % 1) * 1e6):06d}Z"
        sev = 2 if kind in ("decision",) and '"allowed": false' in payload else 5        # crit vs notice
        pri = 13 * 8 + sev                                                               # facility 13 (log audit)
        msg = f"<{pri}>1 {ts} {socket.gethostname()} aegis - {kind} [aegis id=\"{entry_id}\" hash=\"{h}\"] {payload}"
        try:
            self._sock.sendto(msg.encode()[:8000], self.syslog)
        except OSError:
            pass                              # forwarding must never block or break the guard

    def append(self, kind: str, data: dict) -> dict:
        with self._lock:
            row = self.db.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
            prev = row[0] if row else GENESIS
            t = float(self.clock())
            payload = json.dumps(data, sort_keys=True, default=str)
            h = _hash(prev, t, kind, payload, self.key)
            cur = self.db.execute("INSERT INTO audit (t, kind, data, prev_hash, hash) VALUES (?,?,?,?,?)",
                                  (t, kind, payload, prev, h))
            self.db.commit()
        self._forward(cur.lastrowid, t, kind, payload, h)
        return {"id": cur.lastrowid, "t": t, "kind": kind, "data": data, "hash": h}

    def recent(self, limit: int = 50, kind: str | None = None) -> list[dict]:
        q = "SELECT id, t, kind, data, hash FROM audit"
        args: tuple = ()
        if kind:
            q += " WHERE kind=?"
            args = (kind,)
        q += " ORDER BY id DESC LIMIT ?"
        with self._lock:
            rows = self.db.execute(q, (*args, limit)).fetchall()
        return [{"id": i, "t": t, "kind": k, "data": json.loads(d), "hash": h} for i, t, k, d, h in rows]

    def verify(self) -> dict:
        prev, n = GENESIS, 0
        with self._lock:
            rows = self.db.execute("SELECT id, t, kind, data, prev_hash, hash FROM audit ORDER BY id").fetchall()
        for i, t, k, d, p, h in rows:
            if p != prev or _hash(prev, t, k, d, self.key) != h:
                return {"ok": False, "entries": len(rows), "broken_at": i,
                        "message": f"Audit chain broken at entry #{i}: record was altered or removed."}
            prev, n = h, n + 1
        return {"ok": True, "entries": n, "keyed": bool(self.key), "head": prev,
                "message": f"All {n} entries verified, chain intact" + (" (keyed)." if self.key else ".")}

    def head(self) -> dict:
        with self._lock:
            row = self.db.execute("SELECT id, hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        return {"id": row[0], "hash": row[1]} if row else {"id": 0, "hash": GENESIS}

    def between(self, since: float = 0, until: float | None = None, kinds: tuple | None = None,
                limit: int = 20000) -> list[dict]:
        """Entries in a time window, oldest first."""
        q, args = "SELECT id, t, kind, data, hash FROM audit WHERE t >= ?", [since]
        if until is not None:
            q += " AND t <= ?"; args.append(until)
        if kinds:
            q += f" AND kind IN ({','.join('?' * len(kinds))})"; args.extend(kinds)
        q += " ORDER BY id LIMIT ?"; args.append(limit)
        with self._lock:
            rows = self.db.execute(q, args).fetchall()
        return [{"id": i, "t": t, "kind": k, "data": json.loads(d), "hash": h} for i, t, k, d, h in rows]

    def after(self, last_id: int, limit: int = 5000) -> list[dict]:
        """Entries with id > last_id, oldest first (for consumers that tail the log, e.g. Sentinel)."""
        with self._lock:
            rows = self.db.execute("SELECT id, t, kind, data, hash FROM audit WHERE id > ? ORDER BY id LIMIT ?",
                                   (last_id, limit)).fetchall()
        return [{"id": i, "t": t, "kind": k, "data": json.loads(d), "hash": h} for i, t, k, d, h in rows]

    def check_rows(self, ids: list[int]) -> dict[int, dict]:
        """Per-entry integrity check, for citing single entries as evidence. For each id: does the row
        exist, does its stored hash match a recomputation from its own contents, and does it link to the
        previous row's hash. (verify() checks the whole chain; this pinpoints individual rows.)"""
        out: dict[int, dict] = {}
        with self._lock:
            for i in ids:
                r = self.db.execute("SELECT id, t, kind, data, prev_hash, hash FROM audit WHERE id=?", (i,)).fetchone()
                if r is None:
                    out[i] = {"exists": False, "hash_ok": False, "link_ok": False}
                    continue
                _, t, k, d, p, h = r
                prev = self.db.execute("SELECT hash FROM audit WHERE id < ? ORDER BY id DESC LIMIT 1", (i,)).fetchone()
                out[i] = {"exists": True, "hash_ok": _hash(p, t, k, d, self.key) == h,
                          "link_ok": p == (prev[0] if prev else GENESIS), "t": t, "kind": k,
                          "data": json.loads(d), "hash": h}
        return out

    def export_csv(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["id", "time_utc", "kind", "data", "hash"])
        with self._lock:
            rows = self.db.execute("SELECT id, t, kind, data, hash FROM audit ORDER BY id").fetchall()
        for i, t, k, d, h in rows:
            w.writerow([i, time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t)), k, d, h])
        return buf.getvalue()
