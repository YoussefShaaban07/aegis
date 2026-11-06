"""The copilot is driven by a scripted fake LLM that obeys the injected work
order, to prove the guard holds even when the AI is fully hijacked."""
import asyncio
import json

import httpx

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
