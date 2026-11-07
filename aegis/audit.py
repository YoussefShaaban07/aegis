"""Tamper-evident audit log (SQLite, hash-chained).

Every entry stores the SHA-256 of (previous hash + this entry). Editing or
deleting any past row breaks the chain, and verify() pinpoints where. That
matters after an incident: investigators need to trust the record of who
sent what command and what the guard decided.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import sqlite3
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GENESIS = "0" * 64


def _hash(prev: str, t: float, kind: str, data: str) -> str:
    return hashlib.sha256(f"{prev}|{t:.6f}|{kind}|{data}".encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None = None):
        self.path = str(path or os.getenv("AEGIS_DB", ROOT / "data" / "audit.db"))
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.execute("""CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT, t REAL, kind TEXT, data TEXT,
            prev_hash TEXT, hash TEXT)""")
        self.db.commit()

    def append(self, kind: str, data: dict) -> dict:
        with self._lock:
            row = self.db.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
            prev = row[0] if row else GENESIS
            t = time.time()
            payload = json.dumps(data, sort_keys=True, default=str)
            h = _hash(prev, t, kind, payload)
            cur = self.db.execute("INSERT INTO audit (t, kind, data, prev_hash, hash) VALUES (?,?,?,?,?)",
                                  (t, kind, payload, prev, h))
            self.db.commit()
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
            if p != prev or _hash(prev, t, k, d) != h:
                return {"ok": False, "entries": len(rows), "broken_at": i,
                        "message": f"Audit chain broken at entry #{i}: record was altered or removed."}
            prev, n = h, n + 1
        return {"ok": True, "entries": n, "message": f"All {n} entries verified, chain intact."}

    def export_csv(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["id", "time_utc", "kind", "data", "hash"])
        with self._lock:
            rows = self.db.execute("SELECT id, t, kind, data, hash FROM audit ORDER BY id").fetchall()
        for i, t, k, d, h in rows:
            w.writerow([i, time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t)), k, d, h])
        return buf.getvalue()
