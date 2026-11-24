"""Runs Sentinel inside the Aegis server: tails the audit log, investigates ready incidents, serves the API.

  GET  /api/agent/incidents                    list (state, class, confidence)          viewer
  GET  /api/agent/incidents/{id}               full result JSON                         viewer
  GET  /api/agent/incidents/{id}/report        HTML report (?format=md for Markdown)    viewer
  POST /api/agent/incidents/{id}/investigate   re-run                                   engineer
  POST /api/agent/settings                     enable/disable, model or deterministic   engineer
  GET  /api/audit/entry/{id}                   one audit entry + its chain check        viewer

Proposals keep using the existing approve/reject routes (the guard re-checks at approval).
"""
from __future__ import annotations

import asyncio
import os

from fastapi import Depends, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from . import standin
from .casebase import CaseBase
from .incidents import AWAITING_APPROVAL, REPORTED, IncidentManager
from .loop import Sentinel
from .tools import PlantHistory

# demo: seconds, not the spec's minutes; and room for repeated rehearsals (the spec's 6/hour is for real plants)
DEMO_WINDOWS = {"join_window_s": 45, "quiet_s": 20, "reopen_s": 180, "max_per_hour": 120}


class AgentSettings(BaseModel):
    enabled: bool | None = None
    mode: str | None = None          # "llm" | "deterministic"


class Service:
    def __init__(self, audit, alerter, proposals, guard_policy, orders, status_fn, demo: bool, registry_fn=None):
        self.history = PlantHistory()
        self.proposals = proposals
        cfg = DEMO_WINDOWS if demo else None
        if os.getenv("AEGIS_AGENT_QUIET_S"):
            cfg = {**(cfg or {}), "quiet_s": float(os.getenv("AEGIS_AGENT_QUIET_S"))}
        self.incidents = IncidentManager(audit, config=cfg, alerter=alerter)
        from .loop import endpoint, is_local
        key = os.getenv("AEGIS_AGENT_KEY") or os.getenv("GROQ_API_KEY") or os.getenv("AEGIS_LLM_KEY")
        use_standin = demo and not key and not is_local(endpoint())
        self.sentinel = Sentinel(audit, self.history, policy=guard_policy(), proposals=proposals, alerter=alerter,
                                 casebase=CaseBase.load(), transport=standin.transport() if use_standin else None,
                                 model=standin.NAME if use_standin else None, status_fn=status_fn,
                                 work_orders_fn=lambda: list(orders),
                                 # SMS links need the server's public address (e.g. https://aegis-srp7.onrender.com)
                                 report_link=lambda i: f"{os.getenv('AEGIS_BASE_URL', '').rstrip('/')}/api/agent/incidents/{i}/report",
                                 registry_fn=registry_fn)
        self.guard_policy = guard_policy
        self.results: dict[int, dict] = {}
        self.enabled = os.getenv("AEGIS_AGENT", "1") == "1"
        self.running: asyncio.Task | None = None
        self._inflight: set[int] = set()          # incidents an investigation coroutine is working on right now

    def record(self, t, snap, sim_t):
        self.history.record(t, snap, sim_t)

    async def _investigate(self, inc):
        self.sentinel.policy = self.guard_policy()
        self._inflight.add(inc.id)
        try:
            r = await self.sentinel.investigate(inc)
            self.results[inc.id] = r
            self.incidents.finish(inc.id, AWAITING_APPROVAL if r["recovery"].get("steps") else REPORTED,
                                  result={"classification": r["verdict"]["classification"]["primary"]})
        except Exception as ex:                       # never let the agent take the server down
            self.incidents.fallback(inc.id, f"investigation error: {type(ex).__name__}: {ex}"[:200])
        finally:
            self._inflight.discard(inc.id)

    def orphans(self) -> list:
        """Incidents marked INVESTIGATING that nothing is working on. With one investigation at a time, a single
        orphan would stall Sentinel for good, so the caller runs them (watchdog; should never trigger)."""
        return [i for i in self.incidents.incidents.values()
                if i.state == "INVESTIGATING" and i.id not in self._inflight]

    async def poll(self):
        if not self.enabled or (self.running and not self.running.done()):
            return
        for inc in self.orphans() or self.incidents.poll():
            self.running = asyncio.create_task(self._investigate(inc))
            break                                     # one at a time (IncidentManager also enforces this)

    async def investigate_now(self) -> list[int]:
        """Demo only: close every open incident's collection window and investigate them now, in order, so a
        presenter never waits on Sentinel's quiet timer (the expo failure was a step waiting on wall-clock time)."""
        if self.running and not self.running.done():
            await self.running
        started = self.orphans() + list(self.incidents.poll())   # poll() may start one: run it, never drop it
        done = []
        for _ in range(10):
            for inc in self.incidents.incidents.values():
                if inc.state in ("COLLECTING", "REOPENED"):
                    inc.urgent = True
            started = started or self.incidents.tick()
            if not started:
                break
            for inc in started:
                if inc.id not in self._inflight:
                    await self._investigate(inc)
                    done.append(inc.id)
            started = []
        return done

    def _fixes(self, r: dict) -> list[dict]:
        """Live status of each fix this investigation filed (pending / approved / rejected / blocked), so the
        screens never show a fix as waiting after someone approved it."""
        out = []
        for st in (r.get("recovery") or {}).get("steps") or []:
            pid = st.get("proposal_id")
            p = self.proposals.get(pid) if (pid and self.proposals is not None) else None
            if p:
                out.append({"id": pid, "name": p.get("name"), "value": p.get("value"), "old": p.get("old"),
                            "unit": p.get("unit", ""), "status": p.get("status"), "decided_by": p.get("decided_by")})
        return out

    def listing(self) -> list[dict]:
        out = []
        for inc in self.incidents.list()[:30]:
            r = self.results.get(inc.id) or {}
            v = (r.get("verdict") or {}).get("classification") or {}
            out.append({**inc.summary(), "classification": v.get("primary"), "confidence": v.get("confidence"),
                        "summary": (r.get("verdict") or {}).get("summary_for_operator"),
                        "sms": r.get("sms"),
                        "severity": (r.get("report") or {}).get("severity"), "mode": r.get("mode"),
                        "proposals": [s.get("proposal_id") for s in (r.get("recovery") or {}).get("steps") or []],
                        "fixes": self._fixes(r),
                        "validity": (r.get("validation") or {}).get("validity")})
        return out


def attach(app, S: dict, role):
    """Register the routes. S["agent"] is created in the server's lifespan."""

    @app.get("/api/agent/incidents")
    def agent_incidents(who: dict = Depends(role("viewer"))):
        a = S["agent"]
        return {"enabled": a.enabled, "mode": a.sentinel.mode, "model": a.sentinel.model, "incidents": a.listing()}

    @app.get("/api/agent/incidents/{iid}")
    def agent_incident(iid: int, who: dict = Depends(role("viewer"))):
        a = S["agent"]
        inc = a.incidents.get(iid)
        if inc is None:
            raise HTTPException(404, "no such incident")
        r = {k: v for k, v in (a.results.get(iid) or {}).items() if k != "html"}
        return {"incident": inc.summary(), "result": r}

    @app.get("/api/agent/incidents/{iid}/report")
    def agent_report(iid: int, format: str = "html", who: dict = Depends(role("viewer"))):
        r = S["agent"].results.get(iid)
        if not r:
            raise HTTPException(404, "not investigated yet")
        if format == "md":
            return PlainTextResponse(r["report"]["markdown"], media_type="text/markdown")
        return HTMLResponse(r["html"])

    @app.post("/api/agent/investigate-now")
    async def agent_investigate_now(who: dict = Depends(role("operator", demo_only=True))):
        """Demo builds: investigate open incidents now instead of after the quiet window."""
        a = S["agent"]
        ids = await a.investigate_now()
        S["audit"].append("agent_investigate_now", {"incidents": ids, "by": who["user"]})
        # all recent incidents: the background loop may already have investigated the one the caller wants
        return {"investigated": ids, "incidents": a.listing()}

    @app.post("/api/agent/incidents/{iid}/investigate")
    async def agent_rerun(iid: int, who: dict = Depends(role("engineer"))):
        a = S["agent"]
        inc = a.incidents.get(iid)
        if inc is None:
            raise HTTPException(404, "no such incident")
        S["audit"].append("agent_rerun", {"incident": iid, "by": who["user"]})
        await a._investigate(inc)
        return a.listing()[0] if a.listing() else {}

    @app.post("/api/agent/settings")
    def agent_settings(body: AgentSettings, who: dict = Depends(role("engineer"))):
        a = S["agent"]
        if body.enabled is not None:
            a.enabled = body.enabled
        if body.mode in ("llm", "deterministic"):
            if body.mode == "llm" and not (a.sentinel.key or a.sentinel.transport):
                raise HTTPException(400, "no model configured (set GROQ_API_KEY or AEGIS_LLM_KEY)")
            a.sentinel.mode = body.mode
        S["audit"].append("agent_settings", {"enabled": a.enabled, "mode": a.sentinel.mode, "by": who["user"]})
        return {"enabled": a.enabled, "mode": a.sentinel.mode}

    @app.get("/api/audit/entry/{eid}")
    def audit_entry(eid: int, who: dict = Depends(role("viewer"))):
        r = S["audit"].check_rows([eid])[eid]
        if not r["exists"]:
            raise HTTPException(404, "no such entry")
        return {"id": eid, **r, "verified": r["hash_ok"] and r["link_ok"]}
