"""Scripted stand-in model (clearly labelled; not a real LLM).

Speaks the OpenAI chat format through an httpx MockTransport so the real loop code runs end to end in
demos and tests without an API key: it calls a fixed set of read-only tools, then returns the draft
verdict it was given. Tests also use `script()` to feed the loop arbitrary (including bad) replies.
"""
from __future__ import annotations

import json

import httpx

PLAN = ["get_decisions", "get_human_activity", "get_integrity", "get_ai_activity", "get_forecast_warnings",
        "verify_evidence"]
NAME = "scripted-stand-in"


def _reply(message: dict) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", **message}}]})


def _call(name: str, args: dict) -> httpx.Response:
    return _reply({"content": None, "tool_calls": [{"id": f"s{name}", "type": "function",
                                                     "function": {"name": name, "arguments": json.dumps(args)}}]})


def transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        msgs = body["messages"]
        ctx = json.loads(next(m["content"] for m in msgs if m["role"] == "user"))
        done = [m for m in msgs if m["role"] == "tool"]
        if len(done) < len(PLAN) and body.get("tools"):
            name = PLAN[len(done)]
            args = {}
            if name == "get_decisions":
                args = {"only_blocked": True, "limit": 20}
            if name == "verify_evidence":
                ids = []
                for c in ctx["draft_verdict"]["classification"]["rationale"]:
                    ids += c["cite"]
                args = {"ids": sorted(set(ids))[:50] or [0]}
            return _call(name, args)
        return _reply({"content": json.dumps(ctx["draft_verdict"])})
    return httpx.MockTransport(handler)


def script(replies: list) -> httpx.MockTransport:
    """Return the given replies in order: a dict {"tool": name, "args": {...}} or a string answer."""
    it = iter(replies)

    def handler(request: httpx.Request) -> httpx.Response:
        r = next(it, "")
        if isinstance(r, dict) and "tool" in r:
            return _call(r["tool"], r.get("args", {}))
        if isinstance(r, Exception):
            raise r
        return _reply({"content": r if isinstance(r, str) else json.dumps(r)})
    return httpx.MockTransport(handler)
