"""If someone gets onto the Aegis box: signed policy file, off-box audit copy, clock changes."""
import json
import socket

import pytest

from aegis.audit import AuditLog
from aegis.config import PolicyError, Tags, load_policy, save_policy, verify_policy_file
from aegis.guard import Guard
from aegis.plant import Plant

TAGS = Tags.load()


def test_policy_signed_on_save_and_disk_edit_detected(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_POLICY_KEY", "engineer-secret")
    path = tmp_path / "policy.json"
    from aegis.config import POLICY_PATH
    raw = json.loads(POLICY_PATH.read_text()); raw.pop("_sig", None)
    save_policy(raw, path)                                     # saved by Aegis -> signed
    assert verify_policy_file(path)[0] and load_policy(TAGS, path)["limits"]["naoh_dose"]["max"] == 250
    d = json.loads(path.read_text())
    d["limits"]["naoh_dose"]["max"] = 20000                    # attacker on the box edits the file
    path.write_text(json.dumps(d))
    ok, msg = verify_policy_file(path)
    assert not ok and "modified outside Aegis" in msg
    with pytest.raises(PolicyError):
        load_policy(TAGS, path)


def test_unsigned_policy_allowed_without_key(tmp_path, monkeypatch):
    monkeypatch.delenv("AEGIS_POLICY_KEY", raising=False)
    from aegis.config import POLICY_PATH
    assert verify_policy_file(POLICY_PATH)[0]


def test_audit_entries_forwarded_off_box_via_syslog(monkeypatch):
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0)); rx.settimeout(2)
    monkeypatch.setenv("AEGIS_SYSLOG", f"127.0.0.1:{rx.getsockname()[1]}")
    a = AuditLog(":memory:")
    e = a.append("decision", {"allowed": False, "register": "naoh_dose", "new": 11100})
    msg = rx.recv(9000).decode()
    assert msg.startswith("<106>1 ") and f'hash="{e["hash"]}"' in msg and "naoh_dose" in msg   # facility 13, crit
    rx.close()


def test_ramp_window_not_reset_by_wall_clock_jump(monkeypatch):
    """Jump the system clock forward a day: the guard's windows run on a monotonic clock."""
    import time as _t
    plant = Plant(noise=False)
    g = Guard(None, plant.snapshot)
    d = g.check("chlorine_dose", 1.9, plant.snapshot(), "x", "h:1"); g._commit(d); plant.set("chlorine_dose", 1.9)
    real = _t.time
    monkeypatch.setattr(_t, "time", lambda: real() + 86400)
    d2 = g.check("chlorine_dose", 2.3, plant.snapshot(), "x", "h:1")
    assert not d2.allowed and d2.check == "ramp"



def test_blocked_write_flood_cannot_fill_the_audit_log():
    import asyncio
    from aegis import modbus

    async def run():
        plant = Plant(noise=False)
        plc = await modbus.serve(plant.handle, "127.0.0.1", 0)
        audit = AuditLog(":memory:")
        g = Guard(modbus.Client("127.0.0.1", plc.sockets[0].getsockname()[1]), plant.snapshot, audit=audit)
        g.policy["max_writes_per_min_per_source"] = 10 ** 9          # let every write reach the range check
        srv = await modbus.serve(g.handle, "127.0.0.1", 0)
        c = await modbus.Client("127.0.0.1", srv.sockets[0].getsockname()[1], unit=66).connect()
        for _ in range(1000):
            try:
                await c.write(1, 11100)
            except modbus.ModbusError:
                pass
        g.flush_suppressed(force=True)
        kinds = [e["kind"] for e in audit.recent(5000)]
        assert kinds.count("decision") <= 6                          # not 1000
        summ = [e for e in audit.recent(5000) if e["kind"] == "decisions_suppressed"]
        assert summ and summ[0]["data"]["suppressed"] == 995
        assert g.counts["blocked"] == 1000 and audit.verify()["ok"]
        await c.close(); plc.close(); srv.close()
    asyncio.run(run())
