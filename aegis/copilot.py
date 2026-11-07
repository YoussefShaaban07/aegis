"""AI operator copilot (LLM with tools).

It reads the plant and the maintenance system and explains what's happening.
Changes depend on the autonomy mode:
  propose (default)  it can only file proposals; a human approves them
  direct             it may write, but only via Modbus through the guard (unit 2)
Either way it has no path to the PLC that skips the guard.
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
Use tools to read live data before answering. Explain numbers with units.
{mode}"""
MODE_TEXT = {
    "propose": "To change a setpoint, call propose_setpoint; a human operator reviews and approves it.",
    "direct": "You may change setpoints with set_setpoint when it helps operations.",
}

_SP = ", ".join(f"{k} ({UNITS.get(k, '')})" for k in HOLDING)
READ_TOOLS = [
    {"type": "function", "function": {
        "name": "get_plant_status", "description": "Live readings, setpoints and active alarms.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "get_trend", "description": "Recent history of one tag (ph, chlorine_residual, tank_level, flow_out).",
        "parameters": {"type": "object", "properties": {"tag": {"type": "string"}}, "required": ["tag"]}}},
    {"type": "function", "function": {
        "name": "read_work_orders", "description": "Open maintenance work orders and notes.",
        "parameters": {"type": "object", "properties": {}}}},
]
_SET_PARAMS = {"type": "object", "properties": {
    "name": {"type": "string", "enum": list(HOLDING)}, "value": {"type": "number"},
    "reason": {"type": "string"}}, "required": ["name", "value"]}
PROPOSE_TOOL = {"type": "function", "function": {
    "name": "propose_setpoint", "description": f"Propose a setpoint change for operator approval: {_SP}",
    "parameters": _SET_PARAMS}}
SET_TOOL = {"type": "function", "function": {
    "name": "set_setpoint", "description": f"Change a setpoint immediately: {_SP}", "parameters": _SET_PARAMS}}


class Copilot:
    def __init__(self, plant, guard_port: int, work_orders: list, proposals=None, mode_getter=None):
        self.plant = plant
        self.guard_port = guard_port
        self.work_orders = work_orders
        self.proposals = proposals
        self.mode = mode_getter or (lambda: "direct" if proposals is None else "propose")
        self.transport = None  # tests inject a mock LLM here

    def tools(self) -> list:
        return READ_TOOLS + [SET_TOOL if self.mode() == "direct" else PROPOSE_TOOL]

    async def _tool(self, name: str, args: dict) -> dict:
        if name == "get_plant_status":
            return self.plant.snapshot()
        if name == "get_trend":
            tag = args.get("tag", "ph")
            pts = [h.get(tag) for h in list(self.plant.history)[::10]][-30:]
            return {"tag": tag, "unit": UNITS.get(tag, ""), "samples_oldest_to_newest": pts}
        if name == "read_work_orders":
            return {"work_orders": self.work_orders}
        if name == "propose_setpoint" and self.proposals is not None:
            p = await self.proposals.propose(args["name"], float(args["value"]), args.get("reason", ""))
            if p.get("status") == "blocked":
                return {"result": "BLOCKED by safety guard", "why": p["guard"], "proposal_id": p["id"]}
            return {"result": "proposal filed, waiting for operator approval", "proposal_id": p.get("id")}
        if name == "set_setpoint" and self.mode() == "direct":
            reg, val = args["name"], float(args["value"])
            client = await modbus.Client("127.0.0.1", self.guard_port, unit=2).connect()
            try:
                await client.write(HOLDING[reg], max(0, min(65535, to_raw(reg, val))))
                return {"result": "accepted by PLC", "name": reg, "value": val}
            except modbus.ModbusError:
                return {"result": "BLOCKED by safety guard", "name": reg, "value": val}
            finally:
                await client.close()
        return {"error": f"tool {name} not available in '{self.mode()}' mode"}

    async def chat(self, message: str) -> dict:
        key = os.getenv("GROQ_API_KEY") or os.getenv("AEGIS_LLM_KEY")
        if not key:
            return {"reply": "AI copilot is offline: set GROQ_API_KEY in .env.", "trace": []}
        msgs = [{"role": "system", "content": SYSTEM.format(mode=MODE_TEXT[self.mode()])},
                {"role": "user", "content": message}]
        trace = []
        async with httpx.AsyncClient(timeout=40, transport=self.transport) as http:
            for _ in range(6):
                r = await http.post(API, headers={"Authorization": f"Bearer {key}"},
                                    json={"model": MODEL, "messages": msgs, "tools": self.tools(),
                                          "temperature": 0.2})
                r.raise_for_status()
                m = r.json()["choices"][0]["message"]
                msgs.append({k: v for k, v in m.items() if k in ("role", "content", "tool_calls")})
                calls = m.get("tool_calls") or []
                if not calls:
                    return {"reply": m.get("content") or "", "trace": trace}
                for c in calls:
                    try:
                        args = json.loads(c["function"].get("arguments") or "{}")
                        out = await self._tool(c["function"]["name"], args)
                    except Exception as e:  # malformed tool call from the model
                        args, out = {}, {"error": f"tool failed: {e}"}
                    trace.append({"tool": c["function"]["name"], "args": args, "result": out})
                    msgs.append({"role": "tool", "tool_call_id": c["id"], "content": json.dumps(out)})
        return {"reply": "(stopped after too many steps)", "trace": trace}
