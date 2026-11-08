

def test_photon_imessage_delivery_sends_the_same_request_as_photons_sdk(monkeypatch):
    """iPhone alerts through Photon: POST {PHOTON_URL}/v1/messages:sendText, Bearer token,
    {"chatGuid": "any;-;<number>", "text": ...}; the request their SDK's HTTP client makes (captured)."""
    import asyncio
    import json
    import httpx
    from aegis.alerts import Alerter
    for k in ("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM", "PROJECT_ID", "PROJECT_SECRET"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("PHOTON_URL", "https://photon.example/")
    monkeypatch.setenv("PHOTON_TOKEN", "tok")
    monkeypatch.setenv("ALERT_TO", "+1 601 555 0100")
    seen = []

    def server(req):
        seen.append(req)
        return httpx.Response(200, json={"message": {"guid": "m1"}})
    a = Alerter(None, throttle_s=0, transport=httpx.MockTransport(server))
    assert a.configured() and a.channels() == ["iMessage (Photon server)"]
    al = {"key": "k", "severity": "critical", "message": "lye 11100 blocked"}
    assert asyncio.run(a._deliver(al, "+1 601 555 0100", "lye 11100 blocked")) == "iMessage sent"
    r = seen[0]
    assert (r.method, str(r.url)) == ("POST", "https://photon.example/v1/messages:sendText")
    assert r.headers["authorization"] == "Bearer tok"
    assert json.loads(r.content) == {"chatGuid": "any;-;+16015550100", "text": "AEGIS CRITICAL: lye 11100 blocked"}

    a.transport = httpx.MockTransport(lambda req: httpx.Response(401, text="bad token"))
    assert asyncio.run(a._deliver(dict(al), "+16015550100", "x")).startswith("iMessage failed (401")


def test_spectrum_bridge_delivery_and_phone_replies(monkeypatch):
    """Photon Spectrum: Aegis posts to photon/bridge.ts with an HMAC of the project secret; texts back from an
    on-call number acknowledge the newest alert; anyone else is ignored."""
    import asyncio
    import hashlib
    import hmac
    import json
    import httpx
    from aegis.alerts import Alerter
    for k in ("TWILIO_ACCOUNT_SID", "PHOTON_URL", "SPECTRUM_PROJECT_ID", "SPECTRUM_PROJECT_SECRET"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("PROJECT_ID", "p1")
    monkeypatch.setenv("PROJECT_SECRET", "s3cret")
    monkeypatch.setenv("ALERT_TO", "+16015550100,+16015550199")
    seen = []

    def bridge(req):
        seen.append(req)
        return httpx.Response(200, json={"ok": True, "id": "m1"})
    a = Alerter(None, throttle_s=0, transport=httpx.MockTransport(bridge))
    assert a.channels() == ["iMessage (Photon)"]
    assert asyncio.run(a._deliver({"key": "k", "severity": "critical", "message": "m"}, "+16015550100", "m")) == \
        "iMessage sent"
    r = seen[0]
    assert str(r.url) == "http://127.0.0.1:8789/send"
    assert r.headers["x-aegis-bridge"] == hmac.new(b"s3cret", b"aegis-bridge", hashlib.sha256).hexdigest()
    assert json.loads(r.content) == {"to": "+16015550100", "text": "AEGIS CRITICAL: m"}

    def down(req):
        raise httpx.ConnectError("refused")
    a.transport = httpx.MockTransport(down)
    assert "bridge isn't running" in asyncio.run(a._deliver({"key": "k", "severity": "info", "message": "m"}))

    a.raise_alert("x", "warning", "pH forecast above 8.5")
    assert a.handle_reply("+19998887777", "ack") is None                       # stranger: no answer
    assert a.incidents[0]["acked_by"] is None
    assert "acknowledged #1" in a.handle_reply("(601) 555-0100", "ACK")
    assert a.incidents[0]["acked_by"] == "phone ...0100"
    assert "nothing to acknowledge" in a.handle_reply("+16015550199", "ok")
    assert a.handle_reply("+16015550199", "status", lambda: "pH 7.4") == "Aegis: pH 7.4"
    assert "reply ACK" in a.handle_reply("+16015550199", "what?")
