"""YAML-driven tool & data permission policy engine."""

from __future__ import annotations

import re
from importlib import resources
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from agentshield.guards.output import domain_allowed
from agentshield.models import SessionContext, ToolCall, ToolDecision, ToolVerdict, TrustLevel

RiskLevel = Literal["low", "medium", "high", "critical"]
RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+")
EMAIL_RE = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")


class Threshold(BaseModel):
    review: float
    block: float


class ArgConstraint(BaseModel):
    egress: Literal["url", "email"] | None = None
    max_length: int | None = None
    max: float | None = None
    min: float | None = None
    pattern: str | None = None
    enum: list[Any] | None = None
    deny_patterns: list[str] = Field(default_factory=list)


class ToolPolicy(BaseModel):
    risk: RiskLevel = "low"
    require_approval: bool = False
    args: dict[str, ArgConstraint] = Field(default_factory=dict)


class RolePolicy(BaseModel):
    tools: list[str] = Field(default_factory=list)


class TaintPolicy(BaseModel):
    min_taint: float = 0.3
    risk_at_or_above: RiskLevel = "medium"


class Policy(BaseModel):
    version: int = 1
    thresholds: dict[TrustLevel, Threshold]
    ml_weight: float = 0.85
    egress: dict[str, list[str]] = Field(default_factory=lambda: {"allowed_domains": []})
    roles: dict[str, RolePolicy] = Field(default_factory=dict)
    tools: dict[str, ToolPolicy] = Field(default_factory=dict)
    taint: TaintPolicy = Field(default_factory=TaintPolicy)
    default_tool_action: Literal["deny", "require_approval"] = "deny"

    @property
    def allowed_domains(self) -> list[str]:
        return [d.lower() for d in self.egress.get("allowed_domains", [])]

    @classmethod
    def load(cls, path: str | Path | None = None) -> Policy:
        if path is None:
            raw = resources.files("agentshield.policies").joinpath("default.yaml").read_text("utf-8")
        else:
            raw = Path(path).read_text("utf-8")
        return cls.model_validate(yaml.safe_load(raw))


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list | tuple):
        return [s for v in value for s in _strings(v)]
    return []


class PolicyEngine:
    def __init__(self, policy: Policy | None = None) -> None:
        self.policy = policy or Policy.load()

    def role_allows(self, role: str, tool: str) -> bool:
        rp = self.policy.roles.get(role)
        return bool(rp) and ("*" in rp.tools or tool in rp.tools)

    def _check_arg(self, name: str, value: Any, c: ArgConstraint) -> list[str]:
        problems: list[str] = []
        sval = value if isinstance(value, str) else str(value)
        if c.egress == "url":
            for url in URL_RE.findall(sval) or [sval]:
                if not domain_allowed(url, self.policy.allowed_domains):
                    problems.append(f"arg '{name}': URL domain not in egress allowlist ({url[:60]})")
        if c.egress == "email":
            for addr in re.split(r"[,;\s]+", sval):
                m = EMAIL_RE.fullmatch(addr.strip())
                if addr.strip() and (not m or not domain_allowed("https://" + m.group(1), self.policy.allowed_domains)):
                    problems.append(f"arg '{name}': recipient domain not in egress allowlist ({addr[:60]})")
        if c.max_length is not None and len(sval) > c.max_length:
            problems.append(f"arg '{name}': length {len(sval)} > {c.max_length}")
        if c.max is not None or c.min is not None:
            try:
                num = float(value)
                if c.max is not None and num > c.max:
                    problems.append(f"arg '{name}': {num} exceeds max {c.max}")
                if c.min is not None and num < c.min:
                    problems.append(f"arg '{name}': {num} below min {c.min}")
            except (TypeError, ValueError):
                problems.append(f"arg '{name}': not a number")
        if c.pattern and not re.fullmatch(c.pattern, sval):
            problems.append(f"arg '{name}': does not match required pattern")
        if c.enum is not None and value not in c.enum:
            problems.append(f"arg '{name}': not one of {c.enum}")
        for dp in c.deny_patterns:
            if re.search(dp, sval, re.I):
                problems.append(f"arg '{name}': matches denied pattern /{dp}/")
        return problems

    def evaluate(self, call: ToolCall, ctx: SessionContext) -> ToolDecision:
        tp = self.policy.tools.get(call.name)
        if tp is None:
            verdict = ToolVerdict(self.policy.default_tool_action)
            return ToolDecision(call=call, verdict=verdict, risk="critical",
                                reasons=[f"tool '{call.name}' has no policy (default: {verdict.value})"])
        if not self.role_allows(ctx.role, call.name):
            return ToolDecision(call=call, verdict=ToolVerdict.DENY, risk=tp.risk,
                                reasons=[f"role '{ctx.role}' may not call '{call.name}'"])
        reasons: list[str] = []
        for arg, c in tp.args.items():
            if arg in call.args:
                reasons += self._check_arg(arg, call.args[arg], c)
        # Defense in depth: any URL in *any* argument must respect the egress allowlist.
        constrained_url_args = {a for a, c in tp.args.items() if c.egress}
        for arg, val in call.args.items():
            if arg in constrained_url_args:
                continue
            for s in _strings(val):
                for url in URL_RE.findall(s):
                    if not domain_allowed(url, self.policy.allowed_domains):
                        reasons.append(f"arg '{arg}': embedded URL to non-allowlisted domain ({url[:60]})")
        if reasons:
            return ToolDecision(call=call, verdict=ToolVerdict.DENY, risk=tp.risk, reasons=reasons)
        if tp.require_approval:
            return ToolDecision(call=call, verdict=ToolVerdict.REQUIRE_APPROVAL, risk=tp.risk,
                                reasons=[f"'{call.name}' is {tp.risk}-risk and always needs approval"])
        tpol = self.policy.taint
        if ctx.taint >= tpol.min_taint and RISK_ORDER[tp.risk] >= RISK_ORDER[tpol.risk_at_or_above]:
            return ToolDecision(
                call=call, verdict=ToolVerdict.REQUIRE_APPROVAL, risk=tp.risk,
                reasons=[f"context tainted by suspicious untrusted content (taint={ctx.taint:.2f}, "
                         f"sources={ctx.tainted_sources}); {tp.risk}-risk tool needs approval"],
            )
        return ToolDecision(call=call, verdict=ToolVerdict.ALLOW, risk=tp.risk, reasons=["policy ok"])
