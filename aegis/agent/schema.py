"""The model's output contract (spec section 5.3), validated with pydantic.

Every model turn is either a tool call or one JSON object matching Verdict. Every factual claim is
{"text": ..., "cite": [audit entry ids]}; the citation validator checks each one.
"""
from __future__ import annotations

import json
import re
import warnings
from typing import Literal

from pydantic import BaseModel, Field, ValidationError, field_validator

Class = Literal["external_attack", "compromised_trusted_source", "operator_error", "process_or_weather",
                "plc_or_sensor_integrity", "ai_manipulation", "benign_false_positive", "insufficient_evidence"]
CLASSES = Class.__args__


class Claim(BaseModel):
    text: str = Field(max_length=400)
    cite: list[int] = Field(default_factory=list, max_length=20)


class Classification(BaseModel):
    primary: Class
    secondary: Class | None = None
    confidence: Literal["low", "medium", "high"]
    rationale: list[Claim] = Field(default_factory=list, max_length=8)


class Hypothesis(BaseModel):
    name: str = Field(max_length=80)
    status: Literal["supported", "rejected", "open"]
    for_: list[Claim] = Field(default_factory=list, alias="for", max_length=6)
    against: list[Claim] = Field(default_factory=list, max_length=6)
    model_config = {"populate_by_name": True}


class Scope(BaseModel):
    sources: list[str] = Field(default_factory=list, max_length=10)
    ips: list[str] = Field(default_factory=list, max_length=16)
    registers: list[str] = Field(default_factory=list, max_length=10)
    writes_allowed_from_source: list[Claim] = Field(default_factory=list, max_length=10)
    still_active: bool = False


class Technique(BaseModel):
    id: str = Field(pattern=r"^(T0\d{3}|LLM\d{2})$")
    name: str = Field(max_length=60)
    cite: list[int] = Field(default_factory=list, max_length=20)


warnings.filterwarnings("ignore", message='Field name "register"')


class Step(BaseModel):
    register: str
    value: float
    why: str = Field(default="", max_length=300)
    cite: list[int] = Field(default_factory=list, max_length=20)


class Verdict(BaseModel):
    classification: Classification
    hypotheses: list[Hypothesis] = Field(default_factory=list, max_length=6)
    scope: Scope = Field(default_factory=Scope)
    attack_techniques: list[Technique] = Field(default_factory=list, max_length=10)
    recovery: list[Step] = Field(default_factory=list, max_length=6)
    open_questions: list[str] = Field(default_factory=list, max_length=6)
    summary_for_operator: str = Field(max_length=400)

    @field_validator("summary_for_operator")
    @classmethod
    def three_lines(cls, v: str) -> str:
        if len([x for x in v.splitlines() if x.strip()]) > 3:
            raise ValueError("summary_for_operator must be at most 3 lines")
        return v


def json_schema() -> dict:
    return Verdict.model_json_schema(by_alias=True)


_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.M)


def parse(text: str) -> tuple[Verdict | None, str | None]:
    """-> (verdict, None) or (None, error message for the one retry the model gets)."""
    if not text or not text.strip():
        return None, "empty answer: reply with one JSON object matching the schema"
    s = _FENCE.sub("", text.strip())
    a, b = s.find("{"), s.rfind("}")
    if a < 0 or b <= a:
        return None, "no JSON object found"
    try:
        obj = json.loads(s[a:b + 1])
    except json.JSONDecodeError as e:
        return None, f"invalid JSON: {e.msg} at char {e.pos}"
    try:
        return Verdict.model_validate(obj), None
    except ValidationError as e:
        errs = "; ".join(f"{'.'.join(str(x) for x in er['loc'])}: {er['msg']}" for er in e.errors()[:8])
        return None, f"schema errors: {errs}"


def claims(v: Verdict) -> list[tuple[str, Claim]]:
    """Every (path, claim) that the citation validator must check."""
    out = [(f"classification.rationale[{i}]", c) for i, c in enumerate(v.classification.rationale)]
    for i, h in enumerate(v.hypotheses):
        out += [(f"hypotheses[{i}].for[{j}]", c) for j, c in enumerate(h.for_)]
        out += [(f"hypotheses[{i}].against[{j}]", c) for j, c in enumerate(h.against)]
    out += [(f"scope.writes_allowed_from_source[{i}]", c) for i, c in enumerate(v.scope.writes_allowed_from_source)]
    return out
