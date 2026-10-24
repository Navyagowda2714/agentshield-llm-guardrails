"""The Shield: orchestrates guards, policy, HITL gate, output guard and audit logging."""

from __future__ import annotations

import functools
import inspect
import logging
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from agentshield.audit import AuditLogger, preview, sha256
from agentshield.guards.base import Guard, verdict_for
from agentshield.guards.classifier import MLInjectionGuard
from agentshield.guards.content import (
    SECRET_DETECTORS,
    PIIGuard,
    SecretsGuard,
    UnsafeContentGuard,
    find_entities,
)
from agentshield.guards.output import OutputGuard
from agentshield.guards.rules import InjectionRuleGuard
from agentshield.hitl import ApprovalGate, Approver
from agentshield.ingest import from_source
from agentshield.models import (
    ContentItem,
    Finding,
    GuardResult,
    OutputResult,
    ScanResult,
    SessionContext,
    Severity,
    ToolCall,
    ToolDecision,
    ToolVerdict,
    TrustLevel,
    Verdict,
)
from agentshield.policy import Policy, PolicyEngine

log = logging.getLogger(__name__)
F = TypeVar("F", bound=Callable[..., Any])

INJECTION_GUARDS = {"injection_rules", "injection_ml", "injection_llm_judge"}


class ShieldError(Exception):
    pass


class InputBlocked(ShieldError):
    def __init__(self, result: ScanResult) -> None:
        super().__init__(f"input blocked ({result.verdict.value}, risk={result.risk_score:.2f}): "
                         + "; ".join(result.reasons[:3]))
        self.result = result


class ToolBlocked(ShieldError):
    def __init__(self, decision: ToolDecision) -> None:
        super().__init__(f"tool '{decision.call.name}' {decision.verdict.value}: " + "; ".join(decision.reasons))
        self.decision = decision


class Shield:
    def __init__(
        self,
        guards: list[Guard] | None = None,
        policy: Policy | None = None,
        approver: Approver | None = None,
        audit: AuditLogger | None = None,
    ) -> None:
        self.policy = policy or Policy.load()
        self.engine = PolicyEngine(self.policy)
        self.guards: list[Guard] = guards if guards is not None else default_guards()
        self.output_guard = OutputGuard(allowed_domains=self.policy.allowed_domains)
        self.gate = ApprovalGate(approver)
        self.audit = audit or AuditLogger()

    @classmethod
    def default(
        cls,
        *,
        policy_path: str | Path | None = None,
        audit_path: str | Path | None = None,
        approver: Approver | None = None,
        use_ml: bool = True,
        use_llm_judge: bool = False,
    ) -> Shield:
        return cls(
            guards=default_guards(use_ml=use_ml, use_llm_judge=use_llm_judge),
            policy=Policy.load(policy_path),
            approver=approver,
            audit=AuditLogger(audit_path),
        )

    # ------------------------------------------------------------------ input scanning
    def _run_guard(self, guard: Guard, item: ContentItem, ctx: SessionContext | None) -> GuardResult:
        try:
            return guard.scan(item, ctx)
        except Exception as exc:  # fail closed, never crash the agent
            log.exception("guard %s failed", guard.name)
            score = 1.0 if item.trust_level is TrustLevel.UNTRUSTED else 0.5
            return GuardResult(guard=guard.name, score=score, verdict=Verdict.REVIEW, findings=[
                Finding(rule_id="GUARD-ERROR", category="guard_error", severity=Severity.HIGH,
                        message=f"guard raised {type(exc).__name__}; failing closed", score=score)])

    def scan(self, text: str, source: str = "user_message", ctx: SessionContext | None = None,
             **prov: Any) -> ScanResult:
        return self.scan_item(from_source(text, source, **prov), ctx)

    def scan_item(self, item: ContentItem, ctx: SessionContext | None = None) -> ScanResult:
        t0 = time.perf_counter()
        results: list[GuardResult] = []
        sanitized = item.text
        for guard in self.guards:
            target = item if guard.name in INJECTION_GUARDS else item.model_copy(update={"text": sanitized})
            res = self._run_guard(guard, target, ctx)
            if res.sanitized_text is not None:
                sanitized = res.sanitized_text
            results.append(res)
        th = self.policy.thresholds[item.trust_level]
        inj_scores = [
            r.score * (self.policy.ml_weight if r.guard == "injection_ml" else 1.0)
            for r in results if r.guard in INJECTION_GUARDS
        ]
        risk = max(inj_scores, default=0.0)
        verdict = verdict_for(risk, th.review, th.block)
        for r in results:
            if r.guard in INJECTION_GUARDS:
                r.verdict = verdict_for(r.score, th.review, th.block)
            elif r.verdict.rank > verdict.rank:
                verdict = r.verdict
        if verdict is Verdict.ALLOW and sanitized != item.text:
            verdict = Verdict.REDACT
        result = ScanResult(
            item_id=item.id, source=item.source, trust=item.trust_level, verdict=verdict,
            risk_score=round(risk, 4), guards=results, sanitized_text=sanitized,
            latency_ms=(time.perf_counter() - t0) * 1000,
        )
        if ctx is not None and item.trust_level is TrustLevel.UNTRUSTED and verdict.rank < Verdict.REVIEW.rank:
            # Admitted untrusted content taints the session proportionally to its risk.
            if risk > ctx.taint:
                ctx.taint = risk
            if risk >= self.policy.taint.min_taint:
                ctx.tainted_sources.append(item.id)
        self.audit.log(
            "input_scan", request_id=result.request_id, session_id=ctx.session_id if ctx else None,
            item_id=item.id, source=item.source.value, trust=item.trust_level.value,
            provenance={k: v for k, v in item.provenance.items() if v is not None},
            verdict=verdict.value, risk=result.risk_score,
            guard_scores={r.guard: r.score for r in results},
            reasons=result.reasons[:10], content_sha256=sha256(item.text), preview=preview(item.text),
            latency_ms=round(result.latency_ms, 3),
        )
        return result

    # ------------------------------------------------------------------ tool calls
    def check_tool_call(self, call: ToolCall, ctx: SessionContext) -> ToolDecision:
        """Policy evaluation only (no human in the loop)."""
        dec = self.engine.evaluate(call, ctx)
        secrets = [d.kind for d, _ in find_entities(
            " ".join(str(v) for v in call.args.values()), SECRET_DETECTORS)]
        if secrets:
            dec.verdict = ToolVerdict.DENY
            dec.reasons.append(f"secret material in tool arguments: {sorted(set(secrets))}")
        return dec

    def authorize(self, call: ToolCall, ctx: SessionContext) -> ToolDecision:
        """Policy + HITL: returns ALLOW only if the call may execute now."""
        dec = self.check_tool_call(call, ctx)
        if dec.verdict is ToolVerdict.REQUIRE_APPROVAL:
            req, outcome = self.gate.request(call, ctx, dec.risk, dec.reasons)
            self.audit.log("approval", session_id=ctx.session_id, approval_id=req.id, tool=call.name,
                           approved=outcome.approved, approver=outcome.approver, note=outcome.note)
            if outcome.approved:
                dec.verdict, dec.approved_by = ToolVerdict.ALLOW, outcome.approver
                dec.reasons.append(f"approved by {outcome.approver}")
            else:
                dec.reasons.append(f"not approved ({outcome.approver})")
        self.audit.log("tool_check", session_id=ctx.session_id, role=ctx.role, tool=call.name,
                       args_preview=preview(str(call.args)), verdict=dec.verdict.value, risk=dec.risk,
                       reasons=dec.reasons, taint=round(ctx.taint, 3))
        return dec

    # ------------------------------------------------------------------ output
    def check_output(self, text: str, ctx: SessionContext) -> OutputResult:
        res = self.output_guard.check(text, ctx)
        self.audit.log("output_check", session_id=ctx.session_id, verdict=res.verdict.value,
                       reasons=[f"{f.rule_id}: {f.message}" for f in res.findings],
                       content_sha256=sha256(text))
        return res

    # ------------------------------------------------------------------ decorators
    def protect_tool(self, name: str | None = None,
                     ctx: SessionContext | Callable[[], SessionContext] | None = None) -> Callable[[F], F]:
        """Decorator: route every call of a Python function through the tool policy + HITL gate."""

        def deco(fn: F) -> F:
            sig = inspect.signature(fn)

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                c = ctx() if callable(ctx) else (ctx or SessionContext())
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                dec = self.authorize(ToolCall(name=name or fn.__name__, args=dict(bound.arguments)), c)
                if dec.verdict is not ToolVerdict.ALLOW:
                    raise ToolBlocked(dec)
                return fn(*args, **kwargs)

            return wrapper  # type: ignore[return-value]

        return deco

    def guard_input(self, param: str, source: str = "user_message") -> Callable[[F], F]:
        """Decorator: scan one text argument; raise on block/review, pass sanitized text through."""

        def deco(fn: F) -> F:
            sig = inspect.signature(fn)

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                bound = sig.bind(*args, **kwargs)
                res = self.scan(str(bound.arguments[param]), source=source)
                if res.blocked:
                    raise InputBlocked(res)
                bound.arguments[param] = res.sanitized_text
                return fn(*bound.args, **bound.kwargs)

            return wrapper  # type: ignore[return-value]

        return deco


def default_guards(use_ml: bool = True, use_llm_judge: bool = False) -> list[Guard]:
    guards: list[Guard] = [SecretsGuard(), PIIGuard(), UnsafeContentGuard(), InjectionRuleGuard()]
    if use_ml:
        guards.append(MLInjectionGuard())
    if use_llm_judge:
        from agentshield.guards.llm_judge import LLMJudgeGuard

        guards.append(LLMJudgeGuard())
    return guards
