"""AI proposes, human approves.

In the default "propose" autonomy mode the AI copilot cannot write to the PLC
at all. It files a proposal; the guard pre-checks it (dry run); unsafe ones are
marked BLOCKED immediately and can't be approved. Safe ones wait for the
operator, and on approval the write still goes through the guard, because the
plant may have changed since the proposal was made.
"""
from __future__ import annotations

import itertools
import time

from . import modbus


def _compact(fc: dict | None) -> dict | None:
    """Keep the twin forecast small for the UI: pH and chlorine every 30 min."""
    if not fc:
        return None
    pick = lambda pts: [{"min": x["min"], "ph": x["ph"], "cl": x["chlorine_residual"]}
                        for x in pts if x["min"] % 30 == 0]
    return {"with": pick(fc["with"]), "without": pick(fc["without"])}


MAX_KEPT = 300   # proposals kept in memory


class Proposals:
    def __init__(self, guard, guard_port: int, audit=None, alerter=None, host: str = "127.0.0.1"):
        self.guard, self.guard_port, self.host = guard, guard_port, host
        self.audit, self.alerter = audit, alerter
        self.items: list[dict] = []
        self._ids = itertools.count(1)

    def _log(self, kind, p):
        if self.audit:
            self.audit.append(kind, p)

    def get(self, pid: int) -> dict | None:
        return next((p for p in self.items if p["id"] == pid), None)

    async def propose(self, name: str, value: float, reason: str = "", source: str = "AI copilot") -> dict:
        tag = self.guard.tags.holding.get(name)
        if tag is None:
            return {"status": "rejected", "message": f"unknown setpoint {name}"}
        d = await self.guard.dry_run(name, float(value), source)
        p = {"id": next(self._ids), "t": time.time(), "source": source, "name": name, "label": tag.label,
             "value": float(value), "old": d.old, "unit": tag.unit, "reason": reason or "",
             "status": "pending" if d.allowed else "blocked", "guard": d.reason, "check": d.check,
             "decided_by": None, "techniques": d.techniques,
             "forecast": _compact(d.forecast)}
        self.items.insert(0, p)
        if len(self.items) > MAX_KEPT:   # pending ones always stay; decided ones are in the audit log
            keep = [x for x in self.items[MAX_KEPT:] if x["status"] == "pending"]
            self.items[MAX_KEPT:] = keep
        self._log("proposal", {k: v for k, v in p.items() if k != "forecast"})
        if not d.allowed and self.alerter:
            self.alerter.raise_alert(f"proposal_blocked:{name}", "critical",
                                     f"{source} proposed {name} = {value:g} {tag.unit}; guard blocked it: {d.reason}.")
        return p

    async def approve(self, pid: int, by: str = "operator") -> dict:
        p = self.get(pid)
        if p is None or p["status"] != "pending":
            raise ValueError("proposal is not pending")
        tag = self.guard.tags.holding[p["name"]]
        lim = self.guard.policy["limits"].get(p["name"]) or {}
        if p["value"] in (lim.get("permit_values") or []):
            self.guard.issue_permit(p["name"], p["value"], 1, by=f"{by} (approving AI proposal #{pid})")
        c = await modbus.Client(self.host, self.guard_port, unit=1).connect()
        try:
            await c.write_tag(tag, p["value"])
            p["status"], p["guard"] = "approved", "applied after operator approval"
        except modbus.ModbusError:
            last = self.guard.log[0].reason if self.guard.log else "blocked"
            p["status"], p["guard"] = "failed", f"guard blocked it at apply time: {last}"
        finally:
            await c.close()
        p["decided_by"] = by
        self._log("proposal_decision", {"id": pid, "status": p["status"], "by": by})
        return p

    def reject(self, pid: int, by: str = "operator") -> dict:
        p = self.get(pid)
        if p is None or p["status"] != "pending":
            raise ValueError("proposal is not pending")
        p["status"], p["decided_by"] = "rejected", by
        self._log("proposal_decision", {"id": pid, "status": "rejected", "by": by})
        return p
