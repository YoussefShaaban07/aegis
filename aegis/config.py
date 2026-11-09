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
PROCESS_PATH = Path(os.getenv("AEGIS_PROCESS", ROOT / "config" / "process.json"))


@dataclass(frozen=True)
class Tag:
    name: str
    address: int
    scale: float
    unit: str
    label: str
    table: str          # coil | holding | input | discrete
    pccc: str | None = None   # MicroLogix / SLC data-file address (EtherNet/IP), e.g. "N7:1" or "B3:0/1"

    @property
    def writable(self) -> bool:
        return self.table in ("coil", "holding")

    def to_raw(self, value: float) -> int:
        if self.table in ("coil", "discrete"):
            return 1 if value else 0
        return int(round(value * self.scale))

    def from_raw(self, raw: int) -> float:
        if self.table in ("coil", "discrete"):
            return 1 if raw else 0
        v = raw / self.scale
        return int(v) if self.scale == 1 else v


class Tags:
    """Register map. `holding` here means *every writable tag* (coils and holding
    registers), because that's what the policy and the AI care about; use
    `.table` on a Tag, or `by_addr[(table, address)]`, for the wire details."""

    TABLES = {"coils": "coil", "holding": "holding", "input": "input", "discrete": "discrete"}

    def __init__(self, data: dict):
        self.all: dict[str, Tag] = {}
        for key, table in self.TABLES.items():
            for n, d in (data.get(key) or {}).items():
                if n in self.all:
                    raise ValueError(f"tag '{n}' defined twice")
                if "address" not in d and not d.get("pccc"):
                    raise ValueError(f"tag '{n}' needs a Modbus 'address' or a 'pccc' data-file address")
                self.all[n] = Tag(n, int(d.get("address", -1)), d.get("scale", 1), d.get("unit", ""),
                                  d.get("label", n), table, d.get("pccc"))
        self.holding = {n: t for n, t in self.all.items() if t.writable}
        self.input = {n: t for n, t in self.all.items() if not t.writable}
        self.by_addr = {(t.table, t.address): t for t in self.all.values() if t.address >= 0}

    def table(self, name: str) -> dict:
        return {n: t for n, t in self.all.items() if t.table == name}

    @classmethod
    def load(cls, path: Path = TAGS_PATH) -> "Tags":
        return cls(json.loads(Path(path).read_text()))

    @staticmethod
    def span(table: dict) -> tuple[int, int]:
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
        nb = lim.get("normal")
        if nb is not None and (not isinstance(nb, list) or len(nb) != 2 or not lim["min"] <= nb[0] <= nb[1] <= lim["max"]):
            raise PolicyError(f"{name}: 'normal' must be [low, high] inside min..max")
        pv = lim.get("permit_values")
        if pv is not None and (not isinstance(pv, list) or not all(isinstance(v, (int, float)) and lim["min"] <= v <= lim["max"] for v in pv)):
            raise PolicyError(f"{name}: 'permit_values' must be a list of values inside min..max")
        for k in ("max_step", "max_change_per_min"):
            if lim.get(k) is not None and (not isinstance(lim[k], (int, float)) or lim[k] <= 0):
                raise PolicyError(f"{name}: '{k}' must be a positive number or empty")
    for il in p.get("interlocks", []):
        if il.get("op") not in (">", "<") or il.get("register") not in tags.holding:
            raise PolicyError(f"bad interlock: {il}")
    pred = p.get("prediction")
    if pred is not None:
        if not isinstance(pred.get("horizon_min"), (int, float)) or not 5 <= pred["horizon_min"] <= 24 * 60:
            raise PolicyError("prediction.horizon_min must be between 5 and 1440")
        for var, band in (pred.get("limits") or {}).items():
            if (not isinstance(band, list) or len(band) not in (2, 3) or band[0] >= band[1]
                    or (len(band) == 3 and not 5 <= band[2] <= 24 * 60)):
                raise PolicyError(f"prediction limit for {var} must be [low, high] or [low, high, horizon_min]")
    br = (p.get("prediction") or {}).get("block_registers")
    if br is not None and (not isinstance(br, list) or any(r not in tags.holding for r in br)):
        raise PolicyError("prediction.block_registers must list writable setpoints")
    uw = p.get("unknown_writers", "allow")
    if uw not in ("allow", "block"):
        raise PolicyError("unknown_writers must be 'allow' or 'block'")
    sh = p.get("safe_hold")
    if sh is not None:
        if not isinstance(sh, dict):
            raise PolicyError("safe_hold must be an object")
        for k in ("after_min", "lookback_min", "hold_min", "ack_valid_min"):
            if k in sh and (not isinstance(sh[k], (int, float)) or sh[k] <= 0):
                raise PolicyError(f"safe_hold.{k} must be a positive number")
        if any(r not in tags.holding or tags.holding[r].table == "coil" for r in sh.get("registers", [])):
            raise PolicyError("safe_hold.registers must list writable holding-register setpoints (not pumps)")
    ld = p.get("lockdown")
    if ld is not None:
        if not isinstance(ld, dict) or not isinstance(ld.get("after_blocks", 6), int) or ld.get("after_blocks", 6) < 2 \
                or not ld.get("window_min", 60) > 0:
            raise PolicyError("lockdown: after_blocks must be an integer >= 2 and window_min > 0")
    pw = p.get("pass_writes") or []
    if not isinstance(pw, list) or not all(isinstance(x, str) for x in pw):
        raise PolicyError("pass_writes must be a list of addresses, e.g. [\"N7:50-N7:59\", \"holding 40-49\"]")
    for x in pw:
        if x in p.get("limits", {}) or x in tags.all:
            raise PolicyError(f"pass_writes: {x} is a guarded tag; it can't be on the pass list")
    for name, cfg in (p.get("lab_inputs") or {}).items():
        if name not in ("raw_ph", "raw_alkalinity", "raw_turbidity", "water_temp"):
            raise PolicyError(f"lab_inputs: {name} is not a twin input that can come from the lab")
        if not isinstance(cfg, dict) or not isinstance(cfg.get("max_age_h", 36), (int, float)) or cfg.get("max_age_h", 36) <= 0:
            raise PolicyError(f"lab_inputs.{name}.max_age_h must be a positive number")
    for key in ("max_reversals_per_10min", "max_large_reversals_per_hour"):
        rc = p.get(key)
        if rc is not None and (not isinstance(rc, int) or rc < 1):
            raise PolicyError(f"{key} must be a positive integer or absent")
    rc = p.get("max_reversals_per_10min")
    if rc is not None and (not isinstance(rc, int) or rc < 1):
        raise PolicyError("max_reversals_per_10min must be a positive integer or absent")
    w = p.get("max_writes_per_min_per_source", 20)
    if not isinstance(w, int) or w < 1:
        raise PolicyError("max_writes_per_min_per_source must be a positive integer")
    p["max_writes_per_min_per_source"] = w
    return p


def _policy_sig(p: dict, key: bytes) -> str:
    import hashlib
    import hmac
    body = json.dumps({k: v for k, v in p.items() if k != "_sig"}, sort_keys=True, separators=(",", ":"))
    return hmac.new(key, body.encode(), hashlib.sha256).hexdigest()


def policy_key() -> bytes | None:
    k = os.getenv("AEGIS_POLICY_KEY", "")
    return k.encode() if k else None


def verify_policy_file(path: Path = POLICY_PATH) -> tuple[bool, str]:
    """If AEGIS_POLICY_KEY is set, the policy file must carry a valid signature made by Aegis itself
    (i.e. saved through the dashboard by an engineer). An edit on disk breaks it."""
    key = policy_key()
    if key is None:
        return True, "unsigned (set AEGIS_POLICY_KEY to detect edits made outside Aegis)"
    p = json.loads(Path(path).read_text())
    if not p.get("_sig"):
        return False, "policy file is not signed"
    import hmac
    if not hmac.compare_digest(p["_sig"], _policy_sig(p, key)):
        return False, "policy file was modified outside Aegis (signature mismatch)"
    return True, "signed, signature valid"


def load_policy(tags: Tags, path: Path = POLICY_PATH) -> dict:
    ok, msg = verify_policy_file(path)
    if not ok:
        raise PolicyError(msg)
    p = json.loads(Path(path).read_text())
    p.pop("_sig", None)
    return validate_policy(p, tags)


def save_policy(p: dict, path: Path = POLICY_PATH):
    out = {k: v for k, v in p.items() if k != "_sig"}
    key = policy_key()
    if key is not None:
        out["_sig"] = _policy_sig(out, key)
    Path(path).write_text(json.dumps(out, indent=2))


def load_process(path: Path = PROCESS_PATH) -> dict:
    p = {k: v for k, v in json.loads(Path(path).read_text()).items() if not k.startswith("_")}
    choices = {"alkali": ("naoh", "lime", "soda_ash", "bicarbonate"), "chlorine_source": ("hypochlorite", "gas"),
               "fluoride_chemical": ("fsa", "na2sif6", "naf")}
    for key, ok in choices.items():
        if key in p and p[key] not in ok:
            raise ValueError(f"process.json: {key} must be one of {', '.join(ok)} (got {p[key]!r})")
    return p
