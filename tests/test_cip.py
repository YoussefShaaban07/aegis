"""EtherNet/IP + PCCC (the protocol a Rockwell HMI uses with a MicroLogix): same guard, other wire.

The client in most tests is pycomm3's SLCDriver, an independent open-source implementation,
so these tests check Aegis against someone else's reading of the protocol, not just its own."""
import asyncio
import threading

import pytest

from aegis.cip import CIPGuard, CIPRequest, MicroLogixSim, PCCCClient, AddressMap, parse_typed, FNC_MASKED3
from aegis.config import Tags
from aegis.guard import Guard
from aegis.plant import Plant
from aegis.twin import Twin

pycomm3 = pytest.importorskip("pycomm3")


class Rig:
    """Simulated MicroLogix + Aegis CIP guard on a background event loop (pycomm3 is blocking)."""

    def __init__(self, twin=False, sources=None, policy_edit=None):
        self.plant = Plant(noise=False)
        self.tags = Tags.load()
        self.sim = MicroLogixSim(self.plant, self.tags)
        self.guard = Guard(None, self.plant.snapshot, twin=Twin() if twin else None)
        self.guard.ip_sources = sources or {}
        if policy_edit:
            policy_edit(self.guard.policy)
        self.loop = asyncio.new_event_loop()
        self.plc_srv = self.run(self.sim.serve("127.0.0.1", 0))
        self.plc_port = self.plc_srv.sockets[0].getsockname()[1]
        self.proxy = CIPGuard(self.guard, "127.0.0.1", self.plc_port, self.tags)
        self.srv = self.run(self.proxy.serve("127.0.0.1", 0))
        self.port = self.srv.sockets[0].getsockname()[1]
        self.t = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.t.start()

    def run(self, coro):
        if getattr(self, "t", None):
            return asyncio.run_coroutine_threadsafe(coro, self.loop).result(10)
        return self.loop.run_until_complete(coro)

    def slc(self, port=None):
        return pycomm3.SLCDriver(f"127.0.0.1:{port or self.port}")

    def close(self):
        async def shut():
            for srv in (self.srv, self.plc_srv):
                srv.close()
                srv.close_clients() if hasattr(srv, "close_clients") else None
            await asyncio.sleep(0.05)
        self.run(shut())
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.t.join(2)
        self.loop.close()


@pytest.fixture
def rig():
    r = Rig()
    yield r
    r.close()


def test_simulated_micrologix_speaks_real_ethernet_ip(rig):
    """pycomm3 (independent implementation) reads and writes the simulator directly."""
    with rig.slc(rig.plc_port) as plc:
        assert plc.read("N7:0{3}").value == [150, 100, 500]          # chlorine x100, lye, flow
        assert plc.write(("N7:1", 120)).error is None
        assert plc.read("B3:0/1").value is True
        assert plc.write(("B3:0/1", False)).error is None
    assert rig.plant.setpoint("naoh_dose") == 120 and rig.plant.coils[1] == 0


def test_safe_write_passes_oldsmar_write_is_refused(rig):
    with rig.slc() as plc:
        assert plc.read("N7:1").value == 100                          # reads pass through
        ok = plc.write(("N7:1", 120))
        assert ok.error is None and rig.plant.setpoint("naoh_dose") == 120
        bad = plc.write(("N7:1", 11100))                              # the Oldsmar number
        assert bad.error is not None
    assert rig.plant.setpoint("naoh_dose") == 120
    d = rig.guard.log[0]
    assert not d.allowed and d.register == "naoh_dose" and d.check == "range" and "EtherNet/IP" in d.peer
    assert rig.proxy.stats["writes_judged"] == 2


def test_mode_change_and_program_download_are_refused(rig):
    async def go():
        c = PCCCClient("127.0.0.1", rig.port)
        sts = await c.change_mode(program=True)
        await c.close()
        return sts
    assert rig.run(go()) == 0x10
    assert rig.sim.mode == "RUN"                                      # the PLC never saw it
    d = rig.guard.log[0]
    assert not d.allowed and "processor mode" in d.reason and ("T0858", "Change Operating Mode") in d.techniques


def test_unmapped_and_logix_writes_refused():
    r = Rig()
    try:
        with r.slc() as plc:
            assert plc.write(("N7:50", 1)).error is not None          # not a tag Aegis knows
            assert plc.write(("F8:0", 3.5)).error is not None
            res = plc.generic_message(service=0x4D, class_code=b"\x91\x07FAKETAG\x00", instance=b"",
                                      request_data=b"\xc4\x00\x01\x00\x01\x00\x00\x00", connected=False,
                                      name="logix write")
            assert res.error                                         # Logix tag write: refused
        checks = [d.check for d in r.guard.log]
        assert checks.count("allowlist") == 2 and "function" in checks
        assert 50 not in [k[2] for k in r.sim.mem]
    finally:
        r.close()


def test_pump_bit_write_goes_through_interlock_and_permit_checks():
    r = Rig()
    try:
        r.plant.state.tank_level = 95                                  # stopping distribution would overflow
        with r.slc() as plc:
            assert plc.write(("B3:0/1", False)).error is not None
        assert r.plant.coils[1] == 1 and r.guard.log[0].register == "distribution_pump"
    finally:
        r.close()


def test_twin_judges_ethernet_ip_writes_like_modbus_ones():
    r = Rig(twin=True, sources={"127.0.0.1": "Operator HMI"})
    try:
        r.plant.set_scenario("bloom")
        for _ in range(40):
            r.plant.step(1.0)
        with r.slc() as plc:
            assert plc.write(("N7:1", 140)).error is not None          # lye up in a bloom: twin says no
            assert plc.write(("N7:1", 60)).error is None               # lye down: corrective, allowed
        assert r.guard.log[1].check == "predict" and r.guard.log[1].source == "Operator HMI"
    finally:
        r.close()


def test_unknown_hosts_are_read_only_when_policy_says_so():
    r = Rig(policy_edit=lambda p: p.update(unknown_writers="block"))
    try:
        with r.slc() as plc:
            assert plc.read("N7:1").value == 100
            assert plc.write(("N7:1", 110)).error is not None
        assert r.guard.log[0].check == "writer"
    finally:
        r.close()


def test_monitor_mode_logs_but_forwards(rig):
    rig.guard.mode = "monitor"
    with rig.slc() as plc:
        assert plc.write(("N7:1", 11100)).error is None
    assert rig.plant.setpoint("naoh_dose") == 11100 and rig.guard.log[0].would_block


def test_pccc_client_reads_state_and_writes_for_safe_hold(rig):
    async def go():
        c = PCCCClient("127.0.0.1", rig.plc_port)
        st = await c.read_state(rig.tags)
        snaps.append(rig.plant.snapshot())
        await c.write_tag(rig.tags.holding["distribution_rate"], 450)
        await c.write_tag(rig.tags.holding["intake_pump"], 0)
        await c.close()
        return st
    snaps = []
    st = rig.run(go())
    snap = snaps[0]
    for k in ("chlorine_dose", "naoh_dose", "distribution_rate", "intake_pump", "tank_level", "ph"):
        assert abs(st[k] - snap[k]) < 0.02, k
    assert rig.plant.setpoint("distribution_rate") == 450 and rig.plant.coils[0] == 0


def test_masked_partial_write_to_a_setpoint_word_is_refused():
    m = AddressMap(Tags.load())
    p = bytes([2, 7, 0x89, 1, 0]) + (0x00FF).to_bytes(2, "little") + (200).to_bytes(2, "little")
    targets, unmapped = m.write_targets(parse_typed(FNC_MASKED3, p))
    assert targets == [] and "partial-word" in unmapped[0]


def test_unconnected_send_wrapping_is_inspected_too(rig):
    """An attacker wraps the write in an Unconnected Send (0x52) to hide it from a naive filter."""
    from aegis.cip import Frame, SEND_RR, build_cpf, NULL_ADDR, UNCONN_DATA, read_frame, REGISTER
    import struct
    pccc = bytes([7, 9, 16, 1, 2, 3, 4]) + bytes([0x0F, 0, 1, 0, 0xAB]) + bytes([2, 7, 0x89, 1, 0]) + \
        b"\xff\xff" + (11100).to_bytes(2, "little")
    inner = CIPRequest(0x4B, b"\x20\x67\x24\x01", pccc).encode()
    wrapped = CIPRequest(0x52, b"\x20\x06\x24\x01", b"\x07\x9a" + struct.pack("<H", len(inner)) + inner +
                         (b"\x00" if len(inner) % 2 else b"") + b"\x01\x00\x01\x00").encode()

    async def go():
        rd, wr = await asyncio.open_connection("127.0.0.1", rig.port)
        wr.write(Frame(REGISTER, data=b"\x01\x00\x00\x00").encode())
        sess = (await read_frame(rd)).session
        wr.write(Frame(SEND_RR, sess, data=build_cpf([[NULL_ADDR, b""], [UNCONN_DATA, wrapped]])).encode())
        f = await read_frame(rd)
        wr.close()
        return f
    rig.run(go())
    assert rig.plant.setpoint("naoh_dose") == 100 and rig.guard.log[0].check == "range"


def test_gateway_cip_mode_end_to_end():
    """`python -m aegis.gateway --protocol cip`: state is polled over PCCC (not from the simulator object),
    the twin is on, and pycomm3 through the gateway gets the same verdicts as a Modbus HMI would."""
    from aegis.audit import AuditLog
    from aegis.gateway import build, poll_state, make_reader
    plant = Plant(noise=False)
    tags = Tags.load()
    sim = MicroLogixSim(plant, tags)
    loop = asyncio.new_event_loop()
    plc = loop.run_until_complete(sim.serve("127.0.0.1", 0))
    pport = plc.sockets[0].getsockname()[1]
    lines = []
    guard, audit, twin = build("127.0.0.1", pport, audit=AuditLog(":memory:"), printer=lines.append,
                               protocol="cip", ip_sources={"127.0.0.1": "Operator HMI"})
    assert twin is not None
    st = loop.run_until_complete(poll_state(make_reader(guard), tags))
    assert abs(st["ph"] - plant.ph) < 0.02 and st["naoh_dose"] == 100
    gsrv = loop.run_until_complete(CIPGuard(guard, "127.0.0.1", pport).serve("127.0.0.1", 0))
    gport = gsrv.sockets[0].getsockname()[1]
    threading.Thread(target=loop.run_forever, daemon=True).start()
    try:
        with pycomm3.SLCDriver(f"127.0.0.1:{gport}") as c:
            assert c.write(("N7:1", 120)).error is None
            assert c.write(("N7:1", 11100)).error is not None
            assert c.write(("N7:1", 200)).error is not None          # legal range, but the twin says unsafe pH
        assert plant.setpoint("naoh_dose") == 120
        assert [l.split()[1] for l in lines] == ["ALLOW", "BLOCK", "BLOCK"]
    finally:
        async def shut():
            for srv in (gsrv, plc):
                srv.close()
                srv.close_clients()
            await asyncio.sleep(0.05)
        asyncio.run_coroutine_threadsafe(shut(), loop).result(5)
        loop.call_soon_threadsafe(loop.stop)


def test_housekeeping_pass_list_and_discovery():
    """Day one: the HMI also writes alarm-ack words Aegis doesn't guard. Monitor mode shows them,
    the engineer puts them on pass_writes, and they're forwarded (logged, not judged)."""
    r = Rig(policy_edit=lambda p: p.update(pass_writes=["N7:50-N7:59"]))
    try:
        with r.slc() as plc:
            assert plc.write(("N7:52", 1)).error is None             # on the pass list
            assert plc.write(("N7:60", 1)).error is not None         # not on it
            plc.read("N7:0{3}")
        assert r.guard.log[1].check == "pass" and r.guard.log[0].check == "allowlist"
        assert r.sim.mem[("N", 7, 52)] == 1
        assert r.guard.seen["pccc:N7:52"]["writes"] == 1 and r.guard.seen["pccc:N7:1"]["reads"] == 1
        assert r.guard.passes("holding 55") is False and r.guard.passes("N7:59")
    finally:
        r.close()


def test_onboarding_drafts_pccc_tags_from_an_rslogix_export():
    from aegis.onboard import draft
    rows = [{"Address": "N7:0", "Symbol": "CL2_DOSE_SP", "Description": "Chlorine dose setpoint", "Units": "mg/L x100"},
            {"Address": "N7:1", "Symbol": "NAOH_SP", "Description": "Caustic feed setpoint", "Units": "ppm"},
            {"Address": "N7:12", "Symbol": "FIN_PH", "Description": "Finished water pH", "Units": "pH x100"},
            {"Address": "B3:0/1", "Symbol": "HS_PUMP_RUN", "Description": "High service pump run command"},
            {"Address": "N7:50", "Symbol": "ALM_ACK", "Description": "HMI alarm acknowledge word"}]
    d = draft(rows)
    t = d["tags"]
    assert t["holding"]["naoh_dose"]["pccc"] == "N7:1" and t["coils"]["distribution_pump"]["pccc"] == "B3:0/1"
    assert t["input"]["ph"]["pccc"] == "N7:12" and t["holding"]["chlorine_dose"]["scale"] == 100
    assert [u["address"] for u in d["unmapped"]] == ["N7:50"]
    tags = Tags(t)                                                     # loads without Modbus addresses
    assert tags.holding["naoh_dose"].pccc == "N7:1" and tags.by_addr == {}


def test_differential_fuzz_no_unjudged_or_mismatched_plc_change():
    import importlib
    import sys
    sys.argv = ["fuzz", "11", "3000"]
    import scripts.fuzz_cip as fz
    importlib.reload(fz)
    assert fz.main() == []
