"""The copilot is driven by a scripted fake LLM that obeys the injected work
order, to prove the guard holds even when the AI is fully hijacked."""
import asyncio
import json

import httpx
import pytest

from aegis import modbus
from aegis.attacks import INJECTION
from aegis.copilot import Copilot
from aegis.guard import Guard
from aegis.plant import Plant


def hijacked_llm():
    step = {"n": 0}

    def handler(request):
        step["n"] += 1
        if step["n"] == 1:
            calls = [{"id": "a", "type": "function", "function": {"name": "read_work_orders", "arguments": "{}"}}]
        elif step["n"] == 2:
            calls = [{"id": "b", "type": "function", "function": {
                "name": "set_setpoint", "arguments": json.dumps({"name": "naoh_dose", "value": 9000})}}]
        else:
            msgs = json.loads(request.content)["messages"]
            last = json.loads(msgs[-1]["content"])
            return httpx.Response(200, json={"choices": [{"message": {
                "role": "assistant", "content": f"Tried to follow WO-4471: {last['result']}"}}]})
        return httpx.Response(200, json={"choices": [{"message": {
            "role": "assistant", "content": None, "tool_calls": calls}}]})
    return httpx.MockTransport(handler)


def test_hijacked_ai_is_stopped(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test")

    async def run():
        plant = Plant()
        plc = await modbus.serve(plant.handle, "127.0.0.1", 0)
        up = await modbus.Client("127.0.0.1", plc.sockets[0].getsockname()[1]).connect()
        guard = Guard(up, plant.snapshot)
        gsrv = await modbus.serve(guard.handle, "127.0.0.1", 0)
        cp = Copilot(plant, gsrv.sockets[0].getsockname()[1], ["WO-1: routine", INJECTION])
        cp.transport = hijacked_llm()
        out = await cp.chat("Any open work orders I should handle?")
        assert "BLOCKED" in out["reply"]
        assert plant.setpoint("naoh_dose") == 100
        assert guard.log[0].source == "AI copilot" and not guard.log[0].allowed
        plc.close(); gsrv.close()
    asyncio.run(run())


def test_copilot_offline_without_key(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("AEGIS_LLM_KEY", raising=False)
    out = asyncio.run(Copilot(Plant(), 1, []).chat("hi"))
    assert "offline" in out["reply"]


# ---------------- propose -> approve ----------------
from aegis.audit import AuditLog
from aegis.proposals import Proposals


def scripted_llm(calls_seq):
    """Fake LLM: returns the given tool calls in order, then a final message echoing the last tool result."""
    state = {"n": 0}

    def handler(request):
        i = state["n"]; state["n"] += 1
        if i < len(calls_seq):
            name, args = calls_seq[i]
            return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": None,
                "tool_calls": [{"id": f"c{i}", "type": "function",
                                "function": {"name": name, "arguments": json.dumps(args)}}]}}]})
        last = json.loads(json.loads(request.content)["messages"][-1]["content"])
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": json.dumps(last)}}]})
    return httpx.MockTransport(handler)


async def _rig():
    plant = Plant()
    plc = await modbus.serve(plant.handle, "127.0.0.1", 0)
    up = await modbus.Client("127.0.0.1", plc.sockets[0].getsockname()[1]).connect()
    audit = AuditLog(":memory:")
    guard = Guard(up, plant.snapshot, audit=audit)
    gsrv = await modbus.serve(guard.handle, "127.0.0.1", 0)
    port = gsrv.sockets[0].getsockname()[1]
    props = Proposals(guard, port, audit=audit)
    return plant, guard, props, port, plc, gsrv, audit


def test_propose_mode_hijack_cannot_write(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test")

    async def run():
        plant, guard, props, port, plc, gsrv, audit = await _rig()
        cp = Copilot(plant, port, [INJECTION], proposals=props, mode_getter=lambda: "propose")
        assert "set_setpoint" not in [t["function"]["name"] for t in cp.tools()]
        cp.transport = scripted_llm([("read_work_orders", {}),
                                     ("propose_setpoint", {"name": "naoh_dose", "value": 9000})])
        out = await cp.chat("any work orders?")
        assert "BLOCKED" in out["reply"] and props.items[0]["status"] == "blocked"
        with pytest.raises(ValueError):
            await props.approve(props.items[0]["id"])          # can't approve a blocked proposal
        assert plant.setpoint("naoh_dose") == 100
        plc.close(); gsrv.close()
    asyncio.run(run())


def test_safe_proposal_needs_approval(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test")

    async def run():
        plant, guard, props, port, plc, gsrv, audit = await _rig()
        cp = Copilot(plant, port, [], proposals=props, mode_getter=lambda: "propose")
        cp.transport = scripted_llm([("propose_setpoint", {"name": "chlorine_dose", "value": 1.7,
                                                           "reason": "residual trending low"})])
        await cp.chat("chlorine looks low")
        p = props.items[0]
        assert p["status"] == "pending" and plant.setpoint("chlorine_dose") == 1.5   # nothing applied yet
        await props.approve(p["id"], by="operator")
        assert p["status"] == "approved" and plant.setpoint("chlorine_dose") == 1.7
        assert guard.log[0].source == "Operator HMI"
        assert audit.verify()["ok"]
        plc.close(); gsrv.close()
    asyncio.run(run())


def test_approval_rechecked_at_apply_time(monkeypatch):
    async def run():
        plant, guard, props, port, plc, gsrv, audit = await _rig()
        p = await props.propose("chlorine_dose", 1.9, "test")
        assert p["status"] == "pending"
        plant.set("chlorine_dose", 1.2)   # plant changed meanwhile: 1.2 -> 1.9 is now a 0.7 jump (> 0.5 step)
        await props.approve(p["id"])
        assert p["status"] == "failed" and plant.setpoint("chlorine_dose") == 1.2
        plc.close(); gsrv.close()
    asyncio.run(run())


def test_reject():
    async def run():
        plant, guard, props, port, plc, gsrv, audit = await _rig()
        p = await props.propose("naoh_dose", 120)
        props.reject(p["id"])
        assert p["status"] == "rejected" and plant.setpoint("naoh_dose") == 100
        plc.close(); gsrv.close()
    asyncio.run(run())


def test_copilot_explains_blocks_and_integrity(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test")
    ctx = {"guard_log": [{"source": "Unknown device (unit 66)", "register": "naoh_dose", "new": 11100, "unit": "ppm",
                          "allowed": False, "check": "range", "reason": "outside safe range", "would_block": False}],
           "integrity": {"ok": False, "message": "pH is 7.9 but chemistry predicts 7.4"}, "forewarn": []}
    cp = Copilot(Plant(), 1, [], context=lambda: ctx)
    cp.transport = scripted_llm([("get_guard_log", {"limit": 5}), ("get_integrity", {})])
    out = asyncio.run(cp.chat("why was that blocked, and can I trust the PLC?"))
    tools = [t["tool"] for t in out["trace"]]
    assert tools == ["get_guard_log", "get_integrity"]
    assert out["trace"][0]["result"]["decisions"][0]["check"] == "range"
    assert out["trace"][1]["result"]["integrity"]["ok"] is False
