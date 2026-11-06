"""AI operator copilot (LLM with tools).

It can read the plant and the maintenance system, explain what's happening,
and propose setpoint changes. Every change it makes goes over Modbus through
the guard as unit 2. It has no other path to the PLC.
"""
from __future__ import annotations

import json
import os

import httpx

from . import modbus
from .plant import HOLDING, UNITS, to_raw

API = os.getenv("AEGIS_LLM_URL", "https://api.groq.com/openai/v1/chat/completions")
MODEL = os.getenv("AEGIS_LLM_MODEL", "llama-3.3-70b-versatile")

SYSTEM = """You are the AI operator copilot for a small-town water treatment plant.
Help the operator understand plant status in plain English, short and specific.
Use tools to read live data before answering. You may adjust setpoints with set_setpoint
when it helps operations. Explain numbers with units."""

TOOLS = [
    {"type": "function", "function": {
        "name": "get_plant_status",
        "description": "Live readings, setpoints and active alarms.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "get_trend",
        "description": "Recent history of one tag (e.g. ph, chlorine_residual, tank_level).",
        "parameters": {"type": "object", "properties": {"tag": {"type": "string"}}, "required": ["tag"]}}},
    {"type": "function", "function": {
        "name": "read_work_orders",
        "description": "Open maintenance work orders and notes from the plant's maintenance system.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "set_setpoint",
        "description": "Change a setpoint: " + ", ".join(f"{k} ({UNITS.get(k, 'on/off')})" for k in HOLDING),
        "parameters": {"type": "object", "properties": {
            "name": {"type": "string", "enum": list(HOLDING)},
            "value": {"type": "number"},
            "reason": {"type": "string"}}, "required": ["name", "value"]}}},
]


class Copilot:
    def __init__(self, plant, guard_port: int, work_orders: list):
        self.plant = plant
        self.guard_port = guard_port
        self.work_orders = work_orders
        self.transport = None  # tests inject a mock LLM here

    async def _tool(self, name: str, args: dict) -> dict:
        if name == "get_plant_status":
            return self.plant.snapshot()
        if name == "get_trend":
            tag = args.get("tag", "ph")
            pts = [h.get(tag) for h in list(self.plant.history)[::10]][-30:]
            return {"tag": tag, "unit": UNITS.get(tag, ""), "samples_oldest_to_newest": pts}
        if name == "read_work_orders":
            return {"work_orders": self.work_orders}
        if name == "set_setpoint":
            reg, val = args["name"], float(args["value"])
            client = await modbus.Client("127.0.0.1", self.guard_port, unit=2).connect()
            try:
                await client.write(HOLDING[reg], max(0, min(65535, to_raw(reg, val))))
                return {"result": "accepted by PLC", "name": reg, "value": val}
            except modbus.ModbusError:
                return {"result": "BLOCKED by safety guard", "name": reg, "value": val}
            finally:
                await client.close()
        return {"error": "unknown tool"}

    async def chat(self, message: str) -> dict:
        key = os.getenv("GROQ_API_KEY") or os.getenv("AEGIS_LLM_KEY")
        if not key:
            return {"reply": "AI copilot is offline: set GROQ_API_KEY in .env.", "trace": []}
        msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": message}]
        trace = []
        async with httpx.AsyncClient(timeout=40, transport=self.transport) as http:
            for _ in range(6):
                r = await http.post(API, headers={"Authorization": f"Bearer {key}"},
                                    json={"model": MODEL, "messages": msgs, "tools": TOOLS,
                                          "temperature": 0.2})
                r.raise_for_status()
                m = r.json()["choices"][0]["message"]
                msgs.append(m)
                calls = m.get("tool_calls") or []
                if not calls:
                    return {"reply": m.get("content") or "", "trace": trace}
                for c in calls:
                    args = json.loads(c["function"].get("arguments") or "{}")
                    out = await self._tool(c["function"]["name"], args)
                    trace.append({"tool": c["function"]["name"], "args": args, "result": out})
                    msgs.append({"role": "tool", "tool_call_id": c["id"], "content": json.dumps(out)})
        return {"reply": "(stopped after too many steps)", "trace": trace}
