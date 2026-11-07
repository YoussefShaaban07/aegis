"""Onboarding: draft a register map from a PLC tag export (+ observed values)."""
import csv
from pathlib import Path

from aegis.config import Tags
from aegis.onboard import draft, parse_address, scale_from_values

EXPORT = Path(__file__).parent / "fixtures" / "plc_tag_export.csv"


def test_address_notation():
    assert parse_address("40001") == ("holding", 0)
    assert parse_address("300010") == ("input", 9)
    assert parse_address("00002") == ("coil", 1)
    assert parse_address("HR:3") == ("holding", 3) and parse_address("IR0") == ("input", 0)
    assert parse_address("%MW10") is None


def test_draft_from_export_with_observed_values():
    rows = list(csv.DictReader(open(EXPORT, newline="")))
    # pH registers have no scale in the export; monitor mode saw raw values 690..760 and 712..738
    disc = {"input:2": {"min": 712, "max": 738}, "input:4": {"min": 688, "max": 702}}
    r = draft(rows, disc)
    t = r["tags"]
    assert t["holding"]["chlorine_dose"]["scale"] == 100 and t["holding"]["naoh_dose"]["address"] == 1
    assert t["input"]["tank_level"]["scale"] == 10 and t["input"]["raw_turbidity"]["scale"] == 10
    assert t["input"]["ph"]["scale"] == 100 and "observed" in t["input"]["ph"]["_scale_source"]
    assert t["coils"]["intake_pump"]["address"] == 0 and t["coils"]["distribution_pump"]["address"] == 1
    assert r["twin_ready"]
    names = {u["name"] for u in r["unmapped"]}
    assert {"ALM_WORD", "FILT1_HL"} <= names                     # left for a human (or --ai) to place
    clean = {k: {n: {kk: vv for kk, vv in e.items() if not kk.startswith("_")} for n, e in v.items()}
             for k, v in t.items()}
    Tags(clean)                                                  # the draft is a valid register map


def test_missing_scale_is_flagged_for_review():
    rows = [{"Address": "30003", "Name": "FIN_PH", "Description": "Finished water pH", "Units": ""}]
    r = draft(rows, {})
    assert r["tags"]["input"]["ph"]["scale"] == 1 and any("usually stored x100" in x for x in r["review"])


def test_scale_from_values():
    assert scale_from_values("ph", 690, 760) == 100
    assert scale_from_values("tank_level", 420, 610) == 10
    assert scale_from_values("naoh_dose", 80, 120) == 1



def test_guard_discovers_registers_on_the_wire():
    import asyncio
    from aegis import modbus
    from aegis.guard import Guard
    from aegis.plant import Plant

    async def run():
        plant = Plant(noise=False)
        plc = await modbus.serve(plant.handle, "127.0.0.1", 0)
        g = Guard(modbus.Client("127.0.0.1", plc.sockets[0].getsockname()[1]), plant.snapshot, mode="monitor")
        srv = await modbus.serve(g.handle, "127.0.0.1", 0)
        c = await modbus.Client("127.0.0.1", srv.sockets[0].getsockname()[1]).connect()
        await c.read_input(0, 8); await c.read_holding(0, 3); await c.write(1, 110); await c.read_coils(0, 2)
        assert g.seen["input:2"]["min"] > 600 and g.seen["holding:1"]["writes"] == 1
        assert g.seen["coil:0"]["max"] == 1
        await c.close(); plc.close(); srv.close()
    asyncio.run(run())
