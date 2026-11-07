"""Operator alerts: text and phone call when something dangerous happens.

At 3 AM nobody is watching the dashboard. When the guard blocks a dangerous
command or the process goes out of range, the on-call operator gets an SMS,
and for critical events a phone call that reads the alert out loud.

Uses Twilio if configured (TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM,
ALERT_TO). Without it, alerts still appear on the dashboard and in the audit log,
marked "SMS not configured", never pretending to have been sent.

Alert fatigue is how real incidents get missed, so alerts are grouped into
INCIDENTS: everything within 15 minutes of the last related alert joins the
open incident, and only the first alert (or an upgrade from warning to
critical) texts anyone. A critical incident nobody acknowledges escalates down
the contact list (ALERT_TO="+1555...,+1555...") every ESCALATE_MIN minutes
(default 10). Acknowledge on the dashboard to stop escalation.
"""
from __future__ import annotations

import asyncio
import os
import time
from collections import deque
from xml.sax.saxutils import escape

import httpx

TWILIO = "https://api.twilio.com/2010-04-01/Accounts/{sid}/{what}.json"


class Alerter:
    def __init__(self, audit=None, throttle_s: float = 60.0, transport=None, clock=time.time,
                 incident_window_s: float = 900, escalate_s: float | None = None):
        self.audit = audit
        self.throttle_s = throttle_s
        self.clock = clock
        self.incident_window_s = incident_window_s
        self.escalate_s = escalate_s if escalate_s is not None else 60 * float(os.getenv("ESCALATE_MIN", 10))
        self.incidents: list[dict] = []
        self.notifications: list[dict] = []     # every text/call we sent (or would have sent)
        self._ids = 0
        self.transport = transport          # tests inject a mock
        self.recent: deque[dict] = deque(maxlen=50)
        self._last: dict[str, float] = {}

    def configured(self) -> bool:
        return all(os.getenv(k) for k in ("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM", "ALERT_TO"))

    def contacts(self) -> list[str]:
        return [c.strip() for c in os.getenv("ALERT_TO", "").split(",") if c.strip()]

    def open_incident(self) -> dict | None:
        now = self.clock()
        for inc in self.incidents:
            if inc["closed"] is None and now - inc["last"] <= self.incident_window_s:
                return inc
        return None

    def raise_alert(self, key: str, severity: str, message: str) -> dict | None:
        """severity: 'warning' (SMS) or 'critical' (SMS + phone call). Throttled per key; grouped into incidents."""
        now = self.clock()
        if now - self._last.get(key, 0) < self.throttle_s:
            return None
        self._last[key] = now
        inc = self.open_incident()
        notify = False
        if inc is None:
            self._ids += 1
            inc = {"id": self._ids, "opened": now, "last": now, "severity": severity, "title": message, "count": 0,
                   "acked_by": None, "acked_at": None, "level": 0, "escalated_at": now, "closed": None}
            self.incidents.insert(0, inc)
            del self.incidents[30:]
            notify = True
        elif severity == "critical" and inc["severity"] != "critical":
            inc["severity"], inc["title"] = "critical", message       # upgrade: tell someone again
            notify = True
        inc["count"] += 1
        inc["last"] = now
        alert = {"t": now, "key": key, "severity": severity, "message": message, "incident": inc["id"],
                 "delivery": ("sending" if self.configured() else "SMS not configured (dashboard only)") if notify
                 else f"grouped into incident #{inc['id']} (no new text)"}
        self.recent.appendleft(alert)
        if self.audit:
            self.audit.append("alert", {k: alert[k] for k in ("key", "severity", "message", "incident")})
        if notify:
            self._notify(inc, alert, contact_index=inc["level"], text=message)
        return alert

    def _notify(self, inc: dict, alert: dict, contact_index: int, text: str):
        cs = self.contacts()
        to = cs[contact_index] if contact_index < len(cs) else None
        self.notifications.append({"t": self.clock(), "incident": inc["id"], "to": to, "severity": inc["severity"],
                                   "text": text, "configured": self.configured()})
        if self.configured() and to:
            try:
                asyncio.get_running_loop().create_task(self._deliver(alert, to, text))
            except RuntimeError:
                asyncio.run(self._deliver(alert, to, text))

    def ack(self, incident_id: int, by: str) -> dict:
        inc = next((i for i in self.incidents if i["id"] == incident_id), None)
        if inc is None:
            raise ValueError("no such incident")
        inc["acked_by"], inc["acked_at"] = by, self.clock()
        if self.audit:
            self.audit.append("alert_ack", {"incident": incident_id, "by": by, "title": inc["title"]})
        return inc

    def tick(self):
        """Escalate unacknowledged critical incidents; close quiet ones. Call every few seconds."""
        now = self.clock()
        for inc in self.incidents:
            if inc["closed"] is not None:
                continue
            if now - inc["last"] > self.incident_window_s and (inc["acked_by"] or inc["severity"] != "critical"):
                inc["closed"] = now
                continue
            if inc["severity"] == "critical" and not inc["acked_by"] and now - inc["escalated_at"] >= self.escalate_s:
                nxt = inc["level"] + 1
                if nxt < max(1, len(self.contacts())):
                    inc["level"], inc["escalated_at"] = nxt, now
                    mins = round((now - inc["opened"]) / 60)
                    text = (f"ESCALATION: not acknowledged for {mins} min. {inc['title']} "
                            f"({inc['count']} related events)")
                    if self.audit:
                        self.audit.append("alert_escalation", {"incident": inc["id"], "level": nxt})
                    self._notify(inc, {"key": f"escalation:{inc['id']}", "severity": "critical", "message": text},
                                 contact_index=nxt, text=text)

    async def _deliver(self, alert: dict, to: str | None = None, text: str | None = None):
        sid, token = os.environ["TWILIO_ACCOUNT_SID"], os.environ["TWILIO_AUTH_TOKEN"]
        frm = os.environ["TWILIO_FROM"]
        to = to or self.contacts()[0]
        body = f"AEGIS {alert['severity'].upper()}: {text or alert['message']}"[:1500]
        results = []
        try:
            async with httpx.AsyncClient(timeout=15, auth=(sid, token), transport=self.transport) as c:
                r = await c.post(TWILIO.format(sid=sid, what="Messages"), data={"From": frm, "To": to, "Body": body})
                results.append("SMS sent" if r.status_code < 300 else f"SMS failed ({r.status_code})")
                if alert["severity"] == "critical":
                    twiml = (f"<Response><Say>Water plant alert. {escape(alert['message'])}</Say>"
                             f"<Pause length=\"1\"/><Say>Repeating. {escape(alert['message'])}</Say></Response>")
                    r = await c.post(TWILIO.format(sid=sid, what="Calls"), data={"From": frm, "To": to, "Twiml": twiml})
                    results.append("call placed" if r.status_code < 300 else f"call failed ({r.status_code})")
        except Exception as e:  # never let alerting crash the guard
            results.append(f"delivery error: {e}")
        alert["delivery"] = ", ".join(results)
        if self.audit:
            self.audit.append("alert_delivery", {"key": alert["key"], "result": alert["delivery"]})
