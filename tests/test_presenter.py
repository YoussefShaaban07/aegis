"""Presenter lock: during a pitch on the shared public demo, other sessions can watch but not change the plant."""
from aegis import server
from test_server import client  # noqa: F401  (fixture: demo server, signed in as engineer)


def sessions(c):
    """Two browser sessions on the same server, both signed in as the demo engineer."""
    a = c.cookies.get(server.COOKIE)
    c.cookies.clear()
    assert c.post("/api/login", json={"username": "engineer", "password": "engineer"}).status_code == 200
    b = c.cookies.get(server.COOKIE)
    assert a and b and a != b

    def use(tok):
        c.cookies.clear()
        c.cookies.set(server.COOKIE, tok)
    return a, b, use


def test_lock_blocks_other_sessions_not_the_presenter(client):     # noqa: F811
    a, b, use = sessions(client)
    use(a)
    assert client.post("/api/presenter/claim").status_code == 200
    assert client.post("/api/attack/lye").status_code == 200            # the presenter still drives the demo
    use(b)
    st = client.get("/api/state").json()                                 # watching works
    assert st["presenter"]["active"] and not st["presenter"]["mine"]
    for path, body in (("/api/reset", None), ("/api/attack/lye", None), ("/api/scenario/storm", None),
                       ("/api/sim/advance", {"minutes": 5}), ("/api/presenter/claim", None)):
        r = client.post(path, json=body) if body else client.post(path)
        assert r.status_code == 423, (path, r.status_code)
    assert client.post("/api/presenter/release").status_code == 200    # someone else's release does nothing
    assert client.get("/api/state").json()["presenter"]["active"]
    use(a)
    assert client.get("/api/state").json()["presenter"]["mine"]
    client.post("/api/presenter/release")
    use(b)
    assert client.get("/api/state").json()["presenter"] is None
    assert client.post("/api/reset").status_code == 200
    kinds = [e["kind"] for e in client.get("/api/audit").json()["entries"]]
    assert "presenter_lock" in kinds and "presenter_release" in kinds


def test_lock_expires(client, monkeypatch):     # noqa: F811
    a, b, use = sessions(client)
    use(a)
    client.post("/api/presenter/claim")
    server.S["presenter"]["until"] = 0                                  # 15 minutes later
    use(b)
    assert client.post("/api/reset").status_code == 200
    assert client.get("/api/state").json()["presenter"] is None


def test_operator_cannot_claim(client):     # noqa: F811
    client.post("/api/logout")
    client.post("/api/login", json={"username": "operator", "password": "operator"})
    assert client.post("/api/presenter/claim").status_code == 403
