"""Load/validate the register map (tags.json) and safety policy (policy.json)."""
from __future__ import annotations

import copy
import json
import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TAGS_PATH = Path(os.getenv("AEGIS_TAGS", ROOT / "config" / "tags.json"))
POLICY_PATH = Path(os.getenv("AEGIS_POLICY", ROOT / "config" / "policy.json"))


@dataclass(frozen=True)
class Tag:
    name: str
    address: int
    scale: float
    unit: str
    label: str
    writable: bool

    def to_raw(self, value: float) -> int:
        return int(round(value * self.scale))

    def from_raw(self, raw: int) -> float:
        v = raw / self.scale
        return int(v) if self.scale == 1 else v


class Tags:
    def __init__(self, data: dict):
        self.holding = {n: Tag(n, d["address"], d.get("scale", 1), d.get("unit", ""), d.get("label", n), True)
                        for n, d in data["holding"].items()}
        self.input = {n: Tag(n, d["address"], d.get("scale", 1), d.get("unit", ""), d.get("label", n), False)
                      for n, d in data["input"].items()}
        self.by_address = {t.address: t for t in self.holding.values()}

    @classmethod
    def load(cls, path: Path = TAGS_PATH) -> "Tags":
        return cls(json.loads(Path(path).read_text()))

    def span(self, table: dict) -> tuple[int, int]:
        addrs = [t.address for t in table.values()]
        return min(addrs), max(addrs) - min(addrs) + 1


class PolicyError(ValueError):
    pass


def validate_policy(p: dict, tags: Tags) -> dict:
    p = copy.deepcopy(p)
    if not isinstance(p.get("limits"), dict):
        raise PolicyError("policy needs a 'limits' object")
    for name, lim in p["limits"].items():
        if name not in tags.holding:
            raise PolicyError(f"'{name}' is not a writable tag")
        for k in ("min", "max"):
            if not isinstance(lim.get(k), (int, float)):
                raise PolicyError(f"{name}: '{k}' must be a number")
        if lim["min"] > lim["max"]:
            raise PolicyError(f"{name}: min ({lim['min']}) is above max ({lim['max']})")
        for k in ("max_step", "max_change_per_min"):
            if lim.get(k) is not None and (not isinstance(lim[k], (int, float)) or lim[k] <= 0):
                raise PolicyError(f"{name}: '{k}' must be a positive number or empty")
    for il in p.get("interlocks", []):
        if il.get("op") not in (">", "<") or il.get("register") not in tags.holding:
            raise PolicyError(f"bad interlock: {il}")
    w = p.get("max_writes_per_min_per_source", 20)
    if not isinstance(w, int) or w < 1:
        raise PolicyError("max_writes_per_min_per_source must be a positive integer")
    p["max_writes_per_min_per_source"] = w
    return p


def load_policy(tags: Tags, path: Path = POLICY_PATH) -> dict:
    return validate_policy(json.loads(Path(path).read_text()), tags)


def save_policy(p: dict, path: Path = POLICY_PATH):
    Path(path).write_text(json.dumps(p, indent=2))
