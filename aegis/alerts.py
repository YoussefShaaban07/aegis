"""Operator alerts: text and phone call when something dangerous happens.

At 3 AM nobody is watching the dashboard. When the guard blocks a dangerous
command or the process goes out of range, the on-call operator gets an SMS,
and for critical events a phone call that reads the alert out loud.

Uses Twilio if configured (TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM,
ALERT_TO). Without it, alerts still appear on the dashboard and in the audit log,
marked "SMS not configured", never pretending to have been sent.
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
    def __init__(self, audit=None, throttle_s: float = 60.0, transport=None):
        self.audit = audit
        self.throttle_s = throttle_s
        self.transport = transport          # tests inject a mock
        self.recent: deque[dict] = deque(maxlen=50)
        self._last: dict[str, float] = {}

    def configured(self) -> bool:
        return all(os.getenv(k) for k in ("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM", "ALERT_TO"))

    def raise_alert(self, key: str, severity: str, message: str) -> dict | None:
        """severity: 'warning' (SMS) or 'critical' (SMS + phone call). Throttled per key."""
        now = time.time()
        if now - self._last.get(key, 0) < self.throttle_s:
            return None
        self._last[key] = now
        alert = {"t": now, "key": key, "severity": severity, "message": message,
                 "delivery": "sending" if self.configured() else "SMS not configured (dashboard only)"}
        self.recent.appendleft(alert)
        if self.audit:
            self.audit.append("alert", {k: alert[k] for k in ("key", "severity", "message")})
        if self.configured():
            try:
                asyncio.get_running_loop().create_task(self._deliver(alert))
            except RuntimeError:
                asyncio.run(self._deliver(alert))
        return alert

    async def _deliver(self, alert: dict):
        sid, token = os.environ["TWILIO_ACCOUNT_SID"], os.environ["TWILIO_AUTH_TOKEN"]
        frm, to = os.environ["TWILIO_FROM"], os.environ["ALERT_TO"]
        body = f"AEGIS {alert['severity'].upper()}: {alert['message']}"[:1500]
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
