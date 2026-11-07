"""Incident report from the audit log.

After an attack, a small utility has to explain what happened to its board,
its state drinking-water program, and often CISA or the FBI. Aegis already has
every command and decision in a tamper-evident log, so it writes the first
draft: what was attempted, by whom, what was blocked and why, mapped to MITRE
ATT&CK for ICS, with the audit chain's verification result and head hash so
the report can be checked against the log later.

Deterministic: built from log entries only, no AI, no invented facts.
"""
from __future__ import annotations

import html
import time
from collections import Counter, defaultdict

KINDS = ("decision", "decisions_suppressed", "alert", "alert_delivery", "policy_change", "guard_mode", "guard_toggle",
         "auth_failure", "proposal", "proposal_decision", "settings", "scenario", "demo_reset", "startup")


def _ts(t: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))


def build(entries: list[dict], verify: dict, head: dict, plant: str, since: float, until: float) -> dict:
    dec = [e for e in entries if e["kind"] == "decision"]
    blocked = [e for e in dec if not e["data"].get("allowed")]
    would = [e for e in dec if e["data"].get("would_block")]
    unusual = [e for e in dec if e["data"].get("check") == "unusual"]
    allowed = [e for e in dec if e["data"].get("allowed") and not e["data"].get("would_block")]
    alerts = [e for e in entries if e["kind"] == "alert"]
    deliveries = [e for e in entries if e["kind"] == "alert_delivery"]
    admin = [e for e in entries if e["kind"] in ("policy_change", "guard_mode", "guard_toggle", "settings")]
    auth = [e for e in entries if e["kind"] == "auth_failure"]
    props = [e for e in entries if e["kind"] == "proposal"]
    pdec = {e["data"]["id"]: e["data"] for e in entries if e["kind"] == "proposal_decision"}
    suppressed = sum(e["data"]["suppressed"] for e in entries if e["kind"] == "decisions_suppressed")

    by_source = defaultdict(Counter)
    techniques = Counter()
    for e in blocked + would:
        d = e["data"]
        by_source[d["source"]][d["check"]] += 1
        for t in d.get("techniques") or []:
            techniques[(t[0], t[1])] += 1
    severity = "HIGH" if any(e["data"]["source"] != "Operator HMI" for e in blocked) else (
        "MEDIUM" if blocked or would else "LOW")

    L = []
    L.append(f"# Aegis incident report: {plant}")
    L.append(f"Window: **{_ts(since)}** to **{_ts(until)}** (local time). Generated {_ts(time.time())}.")
    L.append("")
    L.append("## Summary")
    L.append(f"- Assessed severity: **{severity}** "
             "(HIGH = blocked commands from a non-operator source; rule-based, review before sending)")
    L.append(f"- Write commands seen: {len(dec) + suppressed}; allowed {len(allowed)}; **blocked {len(blocked) + suppressed}**"
             + (f" ({suppressed} repeats summarised to protect the log)" if suppressed else "")
             + f"; would-block in monitor mode {len(would)}; unusual-but-allowed {len(unusual)}")
    L.append(f"- Operator alerts raised: {len(alerts)}; engineer/admin changes: {len(admin)}; "
             f"failed PIN attempts: {len(auth)}; AI proposals: {len(props)}")
    if blocked:
        first = blocked[0]["data"]
        L.append(f"- First blocked command: {_ts(blocked[0]['t'])}, {first['source']} -> "
                 f"{first['register']} = {first['new']:g} {first.get('unit', '')} ({first['check']})")
    L.append("")
    L.append("## Sources of blocked commands")
    if by_source:
        L.append("| Source | Blocked / would-block | Checks triggered |")
        L.append("|---|---|---|")
        for src, c in sorted(by_source.items(), key=lambda kv: -sum(kv[1].values())):
            L.append(f"| {src} | {sum(c.values())} | {', '.join(f'{k} x{v}' for k, v in c.most_common())} |")
    else:
        L.append("None.")
    L.append("")
    L.append("## MITRE ATT&CK for ICS techniques observed")
    if techniques:
        for (tid, name), n in techniques.most_common():
            url = f"https://attack.mitre.org/techniques/{tid}/" if tid.startswith("T") else \
                "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
            L.append(f"- [{tid}]({url}) {name}: {n}")
    else:
        L.append("None.")
    L.append("")
    L.append("## Timeline of blocked and flagged commands")
    if blocked or would or unusual:
        L.append("| Time | Source | Peer | Setpoint | Value | Check | Guard's reason |")
        L.append("|---|---|---|---|---|---|---|")
        for e in sorted(blocked + would + unusual, key=lambda e: e["id"])[:300]:
            d = e["data"]
            L.append(f"| {_ts(e['t'])} | {d['source']} | {d.get('peer', '')} | {d['register']} | "
                     f"{d['new']:g} {d.get('unit', '')} | {d['check']}{' (monitor)' if d.get('would_block') else ''} | "
                     f"{d['reason'].replace('|', '/')} |")
    else:
        L.append("None.")
    L.append("")
    L.append("## AI copilot proposals")
    if props:
        L.append("| Time | Proposed | Guard pre-check | Outcome | Decided by |")
        L.append("|---|---|---|---|---|")
        for e in props:
            d = e["data"]
            out = pdec.get(d["id"], {})
            L.append(f"| {_ts(e['t'])} | {d['name']} = {d['value']:g} {d.get('unit', '')} | {d['status']}: "
                     f"{d.get('guard', '').replace('|', '/')} | {out.get('status', d['status'])} | {out.get('by', '-')} |")
    else:
        L.append("None.")
    L.append("")
    L.append("## Configuration and access events")
    if admin or auth:
        for e in admin + auth:
            d = e["data"]
            what = {"policy_change": "safety rules changed", "guard_mode": f"guard mode -> {d.get('mode')}",
                    "guard_toggle": f"guard enabled={d.get('enabled')}", "settings": f"AI autonomy -> {d.get('autonomy')}",
                    "auth_failure": "failed engineer PIN"}[e["kind"]]
            L.append(f"- {_ts(e['t'])}: {what}" + (f" by {d['by']}" if d.get("by") else ""))
    else:
        L.append("None.")
    L.append("")
    L.append("## Operator notifications")
    if alerts:
        sent = Counter(e["data"]["result"] for e in deliveries)
        L.append(f"{len(alerts)} alerts raised. Delivery results: "
                 + (", ".join(f"{k} x{v}" for k, v in sent.items()) if sent else "SMS/call not configured (dashboard only)."))
    else:
        L.append("None.")
    L.append("")
    L.append("## Evidence integrity")
    L.append(f"- Audit chain: **{'VERIFIED' if verify.get('ok') else 'BROKEN'}**: {verify.get('message')}")
    L.append(f"- Chain type: {'keyed (HMAC-SHA256)' if verify.get('keyed') else 'unkeyed SHA-256 (set AEGIS_AUDIT_KEY for keyed)'}")
    L.append(f"- Head at report time: entry #{head['id']}, hash `{head['hash']}`. Keep this line: a later "
             "rewrite of the log will not reproduce this hash.")
    L.append(f"- Entries in this window: {len(entries)} (ids {entries[0]['id']}-{entries[-1]['id']})" if entries else
             "- No entries in this window.")
    L.append("")
    L.append("## What this report does not establish")
    L.append("- Who the attacker is. Modbus unit IDs are labels the sender chooses; peer IP addresses can be "
             "spoofed or belong to a compromised internal machine.")
    L.append("- Activity that did not pass through Aegis (e.g. someone at the PLC's own panel, or a path that "
             "bypasses the gateway).")
    md = "\n".join(L)
    return {"markdown": md, "html": to_html(md, plant), "severity": severity,
            "counts": {"writes": len(dec) + suppressed, "blocked": len(blocked) + suppressed, "would_block": len(would),
                       "unusual": len(unusual), "alerts": len(alerts)}}


def to_html(md: str, title: str) -> str:
    """Tiny markdown -> HTML (headings, bullets, tables, bold, code, links) for the browser view."""
    import re

    def inline(s):
        s = html.escape(s)
        s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
        s = re.sub(r"`(.+?)`", r"<code>\1</code>", s)
        s = re.sub(r"\[(.+?)\]\((https?://[^)]+)\)", r'<a href="\2">\1</a>', s)
        return s

    out, in_ul, in_tbl = [], False, False
    for line in md.split("\n"):
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if set("".join(cells)) <= set("-"):
                continue
            if not in_tbl:
                out.append("<table>"); in_tbl = True
                out.append("<tr>" + "".join(f"<th>{inline(c)}</th>" for c in cells) + "</tr>")
            else:
                out.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in cells) + "</tr>")
            continue
        if in_tbl:
            out.append("</table>"); in_tbl = False
        if line.startswith("- "):
            if not in_ul:
                out.append("<ul>"); in_ul = True
            out.append(f"<li>{inline(line[2:])}</li>")
            continue
        if in_ul:
            out.append("</ul>"); in_ul = False
        if line.startswith("## "):
            out.append(f"<h2>{inline(line[3:])}</h2>")
        elif line.startswith("# "):
            out.append(f"<h1>{inline(line[2:])}</h1>")
        elif line.strip():
            out.append(f"<p>{inline(line)}</p>")
    if in_ul: out.append("</ul>")
    if in_tbl: out.append("</table>")
    css = ("body{font:14px/1.5 system-ui,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;color:#111}"
           "table{border-collapse:collapse;width:100%;margin:8px 0}td,th{border:1px solid #ccc;padding:4px 6px;"
           "text-align:left;vertical-align:top;font-size:12.5px}th{background:#f2f2f2}code{font-size:12px;"
           "word-break:break-all}h2{margin-top:28px;border-bottom:1px solid #ddd}@media print{a{color:#000}}")
    return (f"<!doctype html><meta charset=utf-8><title>{html.escape(title)} incident report</title>"
            f"<style>{css}</style>" + "\n".join(out))
