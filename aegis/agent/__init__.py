"""Sentinel: an autonomous incident-response agent for Aegis.

It watches the audit log, opens incidents when something suspicious happens, investigates them with
read-only tools, and writes a report in which every factual sentence cites a hash-verified audit entry.
It has no path to the PLC: its only side effects are audit entries, proposals (which the guard
re-checks and a human approves), alerts and report files. See docs/ and the design spec.
"""
