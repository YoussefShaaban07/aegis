"""Judge round 18: the expo itself (long unattended booth runs)."""
import asyncio
from aegis import proposals as P


class FakeDecision:
    def __init__(self, allowed):
        self.allowed, self.old, self.reason, self.check, self.techniques, self.forecast = allowed, 100, "x", "range", [], None


class FakeGuard:
    class tags:
        class _T: label, unit = "Lye", "ppm"
        holding = {"naoh_dose": _T()}

    def __init__(self): self.n = 0

    async def dry_run(self, name, value, source):
        self.n += 1
        return FakeDecision(self.n <= 3)       # the first three stay pending, the rest are blocked


def test_proposals_are_bounded_but_pending_ones_are_never_dropped():
    props = P.Proposals(FakeGuard(), 0)
    async def go():
        for i in range(P.MAX_KEPT + 400):
            await props.propose("naoh_dose", 9000)
    asyncio.run(go())
    assert len(props.items) == P.MAX_KEPT + 3
    assert sum(p["status"] == "pending" for p in props.items) == 3
    assert props.items[0]["id"] == P.MAX_KEPT + 400          # newest first
