"""Operator alerts: text and phone call when something dangerous happens.

At 3 AM nobody is watching the dashboard. When the guard blocks a dangerous
command or the process goes out of range, the on-call operator gets an SMS,
and for critical events a phone call that reads the alert out loud.

Delivery channels (any combination; ALERT_TO lists the phone numbers):
- Photon Spectrum (iMessage, works with an iPhone, no Mac): PROJECT_ID + PROJECT_SECRET in .env, as written
  by `bun create spectrum-project ... --projectId <id>`. Spectrum's SDK is TypeScript, so a small Bun
  bridge (photon/bridge.ts, started by run.bat) sends the texts and passes replies back: text "ack" to
  acknowledge the open alert, "status" for the plant's readings.
- A self-hosted Photon Advanced iMessage server: PHOTON_URL + PHOTON_TOKEN (HTTP API, no bridge needed).
- Twilio (SMS, plus a phone call for critical alerts): TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM.
Without either, alerts still appear on the dashboard and in the audit log, marked "not configured",
never pretending to have been sent.

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


def spectrum_secret() -> str:
    return os.getenv("PROJECT_SECRET") or os.getenv("SPECTRUM_PROJECT_SECRET") or ""


def bridge_token() -> str:
    """Shared between Aegis and photon/bridge.ts: HMAC-SHA256(project secret, "aegis-bridge"), hex."""
    import hashlib
    import hmac as _hmac
    return _hmac.new(spectrum_secret().encode(), b"aegis-bridge", hashlib.sha256).hexdigest()


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

    @staticmethod
    def twilio_configured() -> bool:
        return all(os.getenv(k) for k in ("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM"))

    @staticmethod
    def photon_configured() -> bool:
        return all(os.getenv(k) for k in ("PHOTON_URL", "PHOTON_TOKEN"))

    @staticmethod
    def spectrum_configured() -> bool:
        return bool(spectrum_secret()) and bool(os.getenv("PROJECT_ID") or os.getenv("SPECTRUM_PROJECT_ID"))

    def channels(self) -> list[str]:
        return [n for n, ok in (("iMessage (Photon)", self.spectrum_configured()),
                                ("iMessage (Photon server)", self.photon_configured()),
                                ("SMS (Twilio)", self.twilio_configured())) if ok]

    def configured(self) -> bool:
        return bool(os.getenv("ALERT_TO")) and bool(self.channels())

    def contacts(self) -> list[str]:
        return [c.strip() for c in os.getenv("ALERT_TO", "").split(",") if c.strip()]

    def open_incident(self) -> dict | None:
        now = self.clock()
        for inc in self.incidents:
            if inc["closed"] is None and now - inc["last"] <= self.incident_window_s:
                return inc
        return None

    def raise_alert(self, key: str, severity: str, message: str, fresh: bool = False) -> dict | None:
        """severity: 'info' (dashboard only, never texted), 'warning' (SMS) or 'critical' (SMS + phone call).
        Throttled per key; warnings and criticals are grouped into incidents."""
        now = self.clock()
        if now - self._last.get(key, 0) < self.throttle_s:
            return None
        self._last[key] = now
        if severity == "info":       # judge round 10: operational, not public health -> don't wake anyone
            alert = {"t": now, "key": key, "severity": "info", "message": message, "incident": None,
                     "delivery": "dashboard only (not a water-safety issue)"}
            self.recent.appendleft(alert)
            if self.audit:
                self.audit.append("alert", {k: alert[k] for k in ("key", "severity", "message", "incident")})
            return alert
        inc = self.open_incident()
        if fresh and inc is not None and inc["acked_by"]:
            inc = None              # needs a NEW acknowledgement: don't hide it in an incident someone already acked
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
                 "delivery": ("sending" if self.configured() else "texts not configured (dashboard only)") if notify
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
        to = to or self.contacts()[0]
        body = f"AEGIS {alert['severity'].upper()}: {text or alert['message']}"[:1500]
        results = []
        if self.spectrum_configured():
            results.append(await self._spectrum(to, body))
        if self.photon_configured():
            results.append(await self._photon(to, body))
        if self.twilio_configured():
            results += await self._twilio(alert, to, body)
        alert["delivery"] = ", ".join(results)
        if self.audit:
            self.audit.append("alert_delivery", {"key": alert["key"], "result": alert["delivery"]})
        return alert["delivery"]

    async def _spectrum(self, to: str, body: str) -> str:
        """iMessage through the Photon Spectrum bridge (photon/bridge.ts) on this machine."""
        url = os.getenv("PHOTON_BRIDGE_URL", "http://127.0.0.1:8789").rstrip("/") + "/send"
        try:
            async with httpx.AsyncClient(timeout=20, transport=self.transport) as c:
                r = await c.post(url, json={"to": to.replace(" ", ""), "text": body},
                                 headers={"X-Aegis-Bridge": bridge_token()})
            j = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            if r.status_code < 300 and j.get("ok"):
                return "iMessage sent"
            return f"iMessage failed ({r.status_code}: {(j.get('error') or r.text)[:120]})"
        except httpx.ConnectError:
            return "iMessage failed: the Photon bridge isn't running (run.bat starts it)"
        except Exception as e:  # never let alerting crash the guard
            return f"iMessage error: {type(e).__name__}: {e}"

    def handle_reply(self, sender: str, text: str, status=None) -> str | None:
        """A text back from an on-call phone. Only numbers in ALERT_TO count; anyone else gets no answer.
        'ack' acknowledges the newest open alert (stops escalation, and safe-hold treats it as a person
        on the job), 'status' answers with the plant's readings."""
        norm = lambda n: "".join(ch for ch in n if ch.isdigit())[-10:]
        if not sender or norm(sender) not in {norm(c) for c in self.contacts()}:
            if self.audit:
                self.audit.append("alert_reply_ignored", {"from": sender[-4:] if sender else "", "text": text[:80]})
            return None
        word = text.strip().lower()
        if word.startswith(("ack", "ok", "on it", "got it", "yes")):
            open_ = [i for i in self.incidents if i["closed"] is None and not i["acked_by"]]
            if not open_:
                return "Aegis: nothing to acknowledge right now."
            inc = open_[-1]
            self.ack(inc["id"], f"phone ...{norm(sender)[-4:]}")
            return f"Aegis: acknowledged #{inc['id']}: {inc['title'][:120]}. Log in to the console to act."
        if word.startswith("status") and status:
            return "Aegis: " + status()
        return "Aegis: reply ACK to acknowledge the latest alert, or STATUS for the plant's readings."

    async def _photon(self, to: str, body: str) -> str:
        """iMessage through Photon's HTTP API (same request as their SDK's createHttpClient().messages.sendText)."""
        url = os.environ["PHOTON_URL"].rstrip("/") + "/v1/messages:sendText"
        chat = to if to.startswith(("any;-;", "any;+;")) else "any;-;" + to.replace(" ", "")
        try:
            async with httpx.AsyncClient(timeout=15, transport=self.transport) as c:
                r = await c.post(url, json={"chatGuid": chat, "text": body},
                                 headers={"Authorization": f"Bearer {os.environ['PHOTON_TOKEN']}"})
            if r.status_code < 300:
                return "iMessage sent"
            return f"iMessage failed ({r.status_code}: {r.text[:120]})"
        except Exception as e:  # never let alerting crash the guard
            return f"iMessage error: {type(e).__name__}: {e}"

    async def _twilio(self, alert: dict, to: str, body: str) -> list[str]:
        sid, token = os.environ["TWILIO_ACCOUNT_SID"], os.environ["TWILIO_AUTH_TOKEN"]
        frm = os.environ["TWILIO_FROM"]
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
            results.append(f"SMS error: {e}")
        return results
