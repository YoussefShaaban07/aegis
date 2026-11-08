

def test_photon_imessage_delivery_sends_the_same_request_as_photons_sdk(monkeypatch):
    """iPhone alerts through Photon: POST {PHOTON_URL}/v1/messages:sendText, Bearer token,
    {"chatGuid": "any;-;<number>", "text": ...}; the request their SDK's HTTP client makes (captured)."""
    import asyncio
    import json
    import httpx
    from aegis.alerts import Alerter
    for k in ("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("PHOTON_URL", "https://photon.example/")
    monkeypatch.setenv("PHOTON_TOKEN", "tok")
    monkeypatch.setenv("ALERT_TO", "+1 601 555 0100")
    seen = []

    def server(req):
        seen.append(req)
        return httpx.Response(200, json={"message": {"guid": "m1"}})
    a = Alerter(None, throttle_s=0, transport=httpx.MockTransport(server))
    assert a.configured() and a.channels() == ["iMessage (Photon)"]
    al = {"key": "k", "severity": "critical", "message": "lye 11100 blocked"}
    assert asyncio.run(a._deliver(al, "+1 601 555 0100", "lye 11100 blocked")) == "iMessage sent"
    r = seen[0]
    assert (r.method, str(r.url)) == ("POST", "https://photon.example/v1/messages:sendText")
    assert r.headers["authorization"] == "Bearer tok"
    assert json.loads(r.content) == {"chatGuid": "any;-;+16015550100", "text": "AEGIS CRITICAL: lye 11100 blocked"}

    a.transport = httpx.MockTransport(lambda req: httpx.Response(401, text="bad token"))
    assert asyncio.run(a._deliver(dict(al), "+16015550100", "x")).startswith("iMessage failed (401")
