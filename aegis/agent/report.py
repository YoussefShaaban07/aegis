"""Sentinel's incident report (spec section 10): verdict, timeline, scope, reasoning, impact, ATT&CK,
recovery, open questions, and an appendix with the deterministic report, chain checkpoints and the
agent's own step log. Citations render as [#id]; in the HTML they link to the audit entry.
"""
from __future__ import annotations

import html
import re
import time

from .. import report as base_report
from .baseline import severity
from .tools import ip_of, label_text

NAMES = {"external_attack": "External attack", "compromised_trusted_source": "Compromised trusted source (HMI PC)",
         "operator_error": "Operator error", "process_or_weather": "Process / weather",
         "plc_or_sensor_integrity": "PLC or sensor integrity", "ai_manipulation": "AI copilot manipulation",
         "benign_false_positive": "False positive (block was not needed)",
         "insufficient_evidence": "Insufficient evidence"}
TECH_URL = "https://attack.mitre.org/techniques/{}/"


def _ts(t: float, sim: bool) -> str:
    if sim:
        return f"T+{t / 60:.0f} min"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))


def _cite(ids) -> str:
    return " " + " ".join(f"[#{i}]" for i in ids) if ids else ""


def build(ev, result: dict) -> dict:
    """result: what the loop produced (verdict dict, validation, recovery, baseline, learned, steps...)."""
    v = result["verdict"]
    cls = v["classification"]
    sim = ev.window[1] < 10 * 365 * 86400            # simulated clock (evaluation) vs wall time
    L = []
    L.append(f"# Sentinel incident report #{ev.incident.id}")
    L.append(f"Investigated {result.get('mode', '')} · model `{result.get('model', 'n/a')}` · "
             f"{result.get('elapsed_s', 0):.1f} s · {result.get('tool_calls', 0)} tool calls")
    L.append("")
    L.append("## 1. Verdict")
    L.append(f"- **{NAMES.get(cls['primary'], cls['primary'])}** · confidence **{cls['confidence']}** · "
             f"severity **{severity(cls['primary'])}**"
             + (f" · also: {NAMES.get(cls['secondary'], cls['secondary'])}" if cls.get("secondary") else ""))
    for c in cls.get("rationale") or []:
        L.append(f"- {c['text']}{_cite(c['cite'])}")
    rr = result.get("baseline", {}).get("remaining_risk")
    if rr:
        L.append(f"- Remaining risk: **{NAMES.get(rr, rr)}**: the forecast stays unsafe even without the "
                 "incident's writes.")
    L.append(f"- Operator summary: {' / '.join(x.strip() for x in v['summary_for_operator'].splitlines() if x.strip())}")
    b, lm = result.get("baseline") or {}, result.get("learned") or {}
    L.append(f"- Cross-checks: rule baseline says **{b.get('primary')}** ({b.get('rule')}); learned classifier says "
             f"**{lm.get('primary', 'n/a')}** (p={lm.get('p', 'n/a')}).")
    L.append("")
    L.append("## 2. What happened")
    dec = [e for e in ev.of("decision") if e["id"] in set(ev.incident.entry_ids)]
    other = [ev.by_id[i] for i in ev.incident.trigger_ids if i in ev.by_id and ev.by_id[i]["kind"] != "decision"]
    rows = sorted(dec + other, key=lambda e: e["id"])
    if rows:
        L.append("| Time | Source | IP | Action | Guard result | Entry |")
        L.append("|---|---|---|---|---|---|")
        shown = rows if len(rows) <= 40 else rows[:25] + rows[-10:]
        for e in shown:
            d = e["data"]
            if e["kind"] == "decision":
                act = f"{d.get('register')} {d.get('old')} → {d.get('new')}"
                res = ("allowed" if d.get("allowed") and not d.get("would_block") else
                       f"BLOCKED ({d.get('check')})" if not d.get("allowed") else f"would block ({d.get('check')})")
            else:
                act, res = e["kind"], str(d.get("message") or d.get("status") or d.get("why") or "")[:80]
            src = html.escape(label_text(d.get("source") or d.get("sender") or ""))[:40]
            L.append(f"| {_ts(e['t'], sim)} | {src} | {ip_of(d.get('peer'))} | {act} | {res.replace('|', '/')} | "
                     f"[#{e['id']}] |")
        if len(rows) > len(shown):
            L.append(f"\n{len(rows) - len(shown)} more rows in the audit log (ids {rows[0]['id']}–{rows[-1]['id']}).")
    L.append("")
    L.append("## 3. Scope")
    sc = v.get("scope") or {}
    L.append(f"- Sources: {', '.join(sc.get('sources') or []) or 'none'}; IPs: {', '.join(sc.get('ips') or []) or 'none'}; "
             f"registers: {', '.join(sc.get('registers') or []) or 'none'}")
    for c in sc.get("writes_allowed_from_source") or []:
        L.append(f"- Got through: {c['text']}{_cite(c['cite'])}")
    if not sc.get("writes_allowed_from_source"):
        L.append("- No write from the suspicious source got through.")
    L.append(f"- Still active: **{'yes' if sc.get('still_active') else 'no'}**")
    L.append("")
    L.append("## 4. Why we think so")
    for h in v.get("hypotheses") or []:
        L.append(f"- **{h['name']}**: {h['status']}")
        for c in h.get("for") or []:
            L.append(f"- {h['name']}, for: {c['text']}{_cite(c['cite'])}")
        for c in h.get("against") or []:
            L.append(f"- {h['name']}, against: {c['text']}{_cite(c['cite'])}")
    L.append("")
    L.append("## 5. Impact")
    cf = result.get("counterfactual")
    if cf and not cf.get("error"):
        L.append(f"- Prevented: if blocked write [#{cf['decision_id']}] ({cf['register']} = {cf['blocked_value']:g}) "
                 f"had landed, the twin predicts it {cf['summary']}.")
    else:
        L.append("- No blocked setpoint write to replay.")
    L.append("")
    L.append("## 6. MITRE ATT&CK for ICS")
    for t in v.get("attack_techniques") or []:
        url = TECH_URL.format(t["id"]) if t["id"].startswith("T") else \
            "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
        L.append(f"- [{t['id']}]({url}) {t['name']}{_cite(t['cite'])}")
    if not v.get("attack_techniques"):
        L.append("None.")
    L.append("")
    L.append("## 7. Recovery")
    rec = result.get("recovery") or {}
    for s in rec.get("steps") or []:
        pid = s.get("proposal_id")
        L.append(f"- Proposal{f' #{pid}' if pid else ''}: {s['register']} → {s['value']:g} ({s['why']})"
                 f"{_cite(s.get('cite'))}; status {s.get('proposal_status', 'not filed')}")
    if not rec.get("steps"):
        L.append(f"- No setpoint changes proposed. {rec.get('note', '')}")
    for s in rec.get("rejected") or []:
        L.append(f"- Not proposed: {s['register']} → {s['value']:g}: {s['rejected_because']}")
    pf = rec.get("plan_forecast")
    if pf:
        L.append(f"- Twin forecast for the plan (6 h): {pf['verdict']}; excursion {pf['with']['excursion']:g} "
                 f"vs {pf['without']['excursion']:g} doing nothing.")
    for c in rec.get("containment") or []:
        L.append(f"- Containment (do this by hand): {c}")
    L.append("")
    L.append("## 8. Open questions")
    for q in v.get("open_questions") or []:
        L.append(f"- {q}")
    if not v.get("open_questions"):
        L.append("None.")
    L.append("")
    L.append("## 9. Appendix")
    val = result.get("validation") or {}
    L.append(f"- Citation check: {val.get('passed', 0)}/{val.get('checked', 0)} claims verified"
             f" (validity {100 * val.get('validity', 1):.0f}%); repair rounds: {result.get('repairs', 0)}.")
    for o in result.get("overridden") or []:
        L.append(f"- Safety override: {o}")
    for x in result.get("removed") or []:
        L.append(f"- Removed: unsupported: \"{x['text'][:120]}\" ({'; '.join(x['errors'])[:160]})")
    L.append(f"- Evidence frozen at entry #{ev.head.get('id')} hash `{ev.head.get('hash')}`; chain "
             f"{'VERIFIED' if ev.verify.get('ok') else 'BROKEN'} at start.")
    end = result.get("chain_end") or {}
    if end:
        L.append(f"- At report time: entry #{end.get('head', {}).get('id')} hash `{end.get('head', {}).get('hash')}`; "
                 f"chain {'VERIFIED' if end.get('ok') else 'BROKEN'}.")
    L.append(f"- Reply guard on the operator text: {'ok' if (result.get('reply_check') or {}).get('ok', True) else 'FLAGGED: ' + '; '.join(result['reply_check']['flags'])}")
    if result.get("similar"):
        L.append("- Similar past incidents (training library): " + ", ".join(
            f"{s['label']} (d={s['distance']})" for s in result["similar"][:5]))
    for s in result.get("steps") or []:
        L.append(f"- Step: {s.get('tool') or s.get('kind')} {str(s.get('args') or '')[:120]} → {s.get('summary', '')[:120]}")
    det = base_report.build(ev.entries, ev.verify, ev.head, "plant", ev.window[0], ev.window[1])
    md = "\n".join(L) + "\n\n---\n\n" + det["markdown"].replace("# Aegis incident report", "## Deterministic report")
    return {"markdown": md, "html": to_html(md, f"Sentinel incident #{ev.incident.id}"),
            "severity": severity(cls["primary"])}


def to_html(md: str, title: str) -> str:
    h = base_report.to_html(md, title)
    return re.sub(r"\[#(\d+)\]", r'<a class="cite" href="/api/audit/entry/\1" title="audit entry \1">[#\1]</a>', h)


def sms(v: dict, n_props: int, link: str = "") -> str:
    """At most 3 short lines, plain words."""
    lines = [x.strip() for x in (v.get("summary_for_operator") or "").splitlines() if x.strip()][:2]
    tail = (f"{n_props} fix{'es' if n_props != 1 else ''} waiting for your approval." if n_props else
            "No setpoint changes proposed.") + (f" Report: {link}" if link else "")
    return "\n".join(lines + [tail])[:480]
